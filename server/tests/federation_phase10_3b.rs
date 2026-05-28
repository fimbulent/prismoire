//! Phase-10.3b integration tests: §13.3 step-4 post-move data recovery.
//!
//! Spec gates exercised here (`docs/federation-protocol.md` §14.5 /
//! §14.6 / §14.7, `docs/federation-impl-plan.md` Phase 10.3b):
//!
//! - **Layer 1 — primary happy path.** D registered K with A as the
//!   confirmed prior home. A holds one K-authored outbound trust-edge
//!   (K→X) AND one inbound trust-edge (X→K). `drive_recovery` walks
//!   §14.5 + §14.6 against A, both surfaces hit `complete: true`,
//!   `primary_complete = true`, and the recovered bytes land in D's
//!   `signed_objects`.
//! - **Layer 1 — A-offline fallback.** D registered K with A as the
//!   confirmed prior home, but A is disconnected from the transport
//!   before `drive_recovery` runs. D falls back to §10.5.1 against
//!   peer C (which holds an X→K trust-edge). `primary_attempted =
//!   true` but `primary_complete = false`; `fallback_attempted =
//!   true`; the bytes from C show up in D's `signed_objects`.
//! - **Layer 1 — best_effort_incomplete telemetry.** D registered K
//!   with A but both A AND D's only peer C are disconnected. Neither
//!   layer can produce bytes; the recovery returns with both
//!   `_complete` flags `false` — i.e. the `recovery:
//!   best_effort_incomplete` log line fires (we check the flag combo
//!   directly since tracing capture isn't wired here).

#![cfg(feature = "test-auth")]

mod common;

use ed25519_dalek::SigningKey;
use prismoire_server::federation::prior_home_recovery::{RecoveryStats, drive_recovery};
use prismoire_server::signed::TrustStance;
use prismoire_server::signing::{SigningOutput, sign_trust_edge_with_key};
use rand::rngs::OsRng;
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering};

// ---------------------------------------------------------------------------
// Fixture helpers — same shape as Phase 10.2's, copied locally so this test
// crate stays self-contained.
// ---------------------------------------------------------------------------

/// Insert a `users` row whose `public_key` is `pubkey`. The user
/// counts as "local" for §14.5 / §14.6 (`signup_method != 'federated'
/// AND home_instance IS NULL`). Returns the generated UUID.
async fn insert_local_user(db: &SqlitePool, display_name: &str, pubkey: &[u8; 32]) -> String {
    let id = Uuid::new_v4().to_string();
    let skeleton = display_name.to_lowercase();
    let pubkey_slice: &[u8] = pubkey.as_slice();
    sqlx::query!(
        "INSERT INTO users (id, display_name, signup_method, public_key, display_name_skeleton) \
         VALUES (?, ?, 'admin', ?, ?)",
        id,
        display_name,
        pubkey_slice,
        skeleton,
    )
    .execute(db)
    .await
    .expect("insert user");
    id
}

/// Sign + seed a trust edge from `signer` to `target_pub` and insert
/// both the `signed_objects` row and the `trust_edges` projection.
/// `received_at` is fixed to a deterministic ISO timestamp derived
/// from `ts_ms` so the §10.5.2 keyset pagination order is stable
/// across runs.
#[allow(clippy::too_many_arguments)]
async fn seed_signed_edge(
    db: &SqlitePool,
    signer: &SigningKey,
    source_user_id: &str,
    target_user_id: &str,
    target_pub: &[u8; 32],
    stance: TrustStance,
    ts_ms: u64,
    prior: Option<[u8; 32]>,
) -> SigningOutput {
    let signed = sign_trust_edge_with_key(signer, target_pub, stance, ts_ms, prior);

    let secs = (ts_ms / 1000) as i64;
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .expect("timestamp in range")
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let payload_slice: &[u8] = signed.payload.as_slice();
    let signature_slice: &[u8] = signed.signature.as_slice();
    sqlx::query!(
        "INSERT INTO signed_objects \
            (canonical_hash, inner_class, payload, signature, received_at) \
         VALUES (?, 'trust-edge', ?, ?, ?)",
        hash_slice,
        payload_slice,
        signature_slice,
        dt,
    )
    .execute(db)
    .await
    .expect("insert signed_objects (trust-edge)");

    let edge_id = Uuid::new_v4().to_string();
    let trust_type = match stance {
        TrustStance::Trust => "trust",
        TrustStance::Distrust => "distrust",
        TrustStance::Neutral => "neutral",
    };
    sqlx::query(
        "INSERT INTO trust_edges \
            (id, source_user, target_user, trust_type, canonical_hash, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&edge_id)
    .bind(source_user_id)
    .bind(target_user_id)
    .bind(trust_type)
    .bind(hash_slice)
    .bind(&dt)
    .execute(db)
    .await
    .expect("insert trust_edges");
    signed
}

/// Count the rows in `signed_objects` whose canonical_hash matches
/// `hash`. Recovery is best-effort and additive, so the success
/// signal in tests is "the bytes are now on D" rather than any
/// projection-side effect.
async fn count_signed_object(db: &SqlitePool, hash: &[u8; 32]) -> i64 {
    let hash_slice: &[u8] = hash.as_slice();
    sqlx::query_scalar!(
        "SELECT COUNT(*) FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(db)
    .await
    .expect("count signed_objects")
}

// ---------------------------------------------------------------------------
// Layer-1 tests
// ---------------------------------------------------------------------------

/// Primary happy path: D=a, A=b (prior home). A holds one K-authored
/// outbound edge (K→X for §14.5) and one inbound edge (X→K for §14.6).
/// `drive_recovery` walks both surfaces against A, hits
/// `complete: true` on both, and the bytes land in D's signed_objects.
#[tokio::test]
async fn primary_path_recovers_content_and_inbound_edges() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let d = harness.instance("a");
    let a = harness.instance("b");

    // K is a synthetic local user on A (we own K's signing key so the
    // §14.1 response signature verifies under the same pubkey we
    // attach to the users row).
    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    let k_uid = insert_local_user(&a.state.db, "kara", &k_pub).await;

    // X — the other endpoint of both edges. Identity doesn't matter
    // beyond satisfying the trust_edges FK.
    let x_key = SigningKey::generate(&mut OsRng);
    let x_pub: [u8; 32] = *x_key.verifying_key().as_bytes();
    let x_uid = insert_local_user(&a.state.db, "xeno", &x_pub).await;

    // Outbound edge K→X — §14.5 surface.
    let edge_kx = seed_signed_edge(
        &a.state.db,
        &k_key,
        &k_uid,
        &x_uid,
        &x_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    )
    .await;

    // Inbound edge X→K — §14.6 surface.
    let edge_xk = seed_signed_edge(
        &a.state.db,
        &x_key,
        &x_uid,
        &k_uid,
        &k_pub,
        TrustStance::Trust,
        1_700_000_001_000,
        None,
    )
    .await;

    // Drive the recovery — D's confirmed prior home is A.
    let confirmed = Some((
        *a.state.instance_key.public_bytes(),
        a.state.instance_domain.clone(),
    ));
    let stats: RecoveryStats =
        drive_recovery(d.state.clone(), k_pub, k_key.clone(), confirmed).await;

    assert!(stats.primary_attempted, "confirmed peer was Some");
    assert!(
        stats.primary_complete,
        "both §14.5 + §14.6 should reach complete:true on a 1-row surface; stats={stats:?}",
    );
    // Primary completed both surfaces, so the fallback layer should
    // not even fire — saves us from a noisy peer sweep.
    assert!(
        !stats.fallback_attempted,
        "fallback must skip when primary completed; stats={stats:?}",
    );
    assert!(
        stats.objects_seen >= 2,
        "at least the K→X content + X→K edge bytes were piped through ingest; stats={stats:?}",
    );

    // The bytes themselves should now exist on D.
    assert_eq!(
        count_signed_object(&d.state.db, &edge_kx.canonical_hash).await,
        1,
        "K→X (§14.5) should have landed on D",
    );
    assert_eq!(
        count_signed_object(&d.state.db, &edge_xk.canonical_hash).await,
        1,
        "X→K (§14.6) should have landed on D",
    );
}

/// A-offline fallback: D=a, A=b, peer=c. A is disconnected before
/// recovery runs, so the §14.5 / §14.6 calls fail at the transport
/// layer. C holds an X→K trust-edge that the §10.5.1 fallback
/// `edges-by-key?direction=both` route can serve. The recovery
/// surfaces those bytes on D and reports
/// `primary_attempted && !primary_complete && fallback_attempted`.
#[tokio::test]
async fn fallback_recovers_from_peer_when_prior_home_offline() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // K and X both have rows on C — needed because §10.5.1
    // `edges-by-key` resolves the queried `key` against C's `users`
    // table before walking trust_edges. The same edge fixture as the
    // happy path: X→K, so direction=both surfaces it under
    // `target_user=K`.
    let c = harness.instance("c");
    let k_uid = insert_local_user(&c.state.db, "kara", &k_pub).await;
    let x_key = SigningKey::generate(&mut OsRng);
    let x_pub: [u8; 32] = *x_key.verifying_key().as_bytes();
    let x_uid = insert_local_user(&c.state.db, "xeno", &x_pub).await;
    let edge_xk = seed_signed_edge(
        &c.state.db,
        &x_key,
        &x_uid,
        &k_uid,
        &k_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    )
    .await;

    // Snapshot A's identity before disconnecting so the recovery call
    // still believes A is the confirmed prior home.
    let a = harness.instance("b");
    let a_key = *a.state.instance_key.public_bytes();
    let a_domain = a.state.instance_domain.clone();
    harness.disconnect("b").await;

    let d = harness.instance("a");
    let stats: RecoveryStats = drive_recovery(
        d.state.clone(),
        k_pub,
        k_key.clone(),
        Some((a_key, a_domain)),
    )
    .await;

    assert!(stats.primary_attempted);
    assert!(
        !stats.primary_complete,
        "A is disconnected; §14.5/§14.6 calls must fail at transport; stats={stats:?}",
    );
    assert!(
        stats.fallback_attempted,
        "primary incomplete must trigger fallback; stats={stats:?}",
    );
    assert!(
        stats.objects_seen >= 1,
        "fallback should pipe at least the X→K bytes through ingest; stats={stats:?}",
    );
    assert_eq!(
        count_signed_object(&d.state.db, &edge_xk.canonical_hash).await,
        1,
        "X→K (§10.5.1 edges-by-key) should have landed on D via peer C",
    );
}

/// Zero-active-peers fallback: D=a, A=b. A is disconnected, and D
/// has no peer rows beyond A. The fallback runs but `list_active_peers`
/// returns empty (A's row was placed by the handshake but its `status`
/// flips to `active` only on a successful peering, which we then
/// remove via `disconnect`... actually `disconnect` only clears the
/// transport registry — the `peers` row stays `active`. So we instead
/// stand up D alone with no peering at all, which is the more honest
/// "D has zero active peers" shape.) Asserts that this case reports
/// `fallback_attempted = true && fallback_complete = false` (so
/// operators see `best_effort_incomplete`, not "all swept peers
/// completed").
#[tokio::test]
async fn fallback_with_zero_active_peers_reports_incomplete() {
    // Single instance — no peering established at all.
    let harness = MultiInstanceHarness::new(1).await;
    let d = harness.instance("a");

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // No confirmed prior home, so primary is skipped entirely.
    let stats: RecoveryStats = drive_recovery(d.state.clone(), k_pub, k_key, None).await;

    assert!(!stats.primary_attempted, "no confirmed peer was provided");
    assert!(
        stats.fallback_attempted,
        "fallback always runs when primary didn't complete"
    );
    assert!(
        !stats.fallback_complete,
        "zero active peers must NOT be reported as 'all peers swept complete'; \
         see `RecoveryStats::fallback_complete` doc; stats={stats:?}",
    );
    assert_eq!(stats.objects_seen, 0);
}

/// best_effort_incomplete telemetry: D=a, A=b, peer=c. BOTH A and the
/// only peer C are disconnected before recovery runs, so neither
/// surface can produce bytes. `drive_recovery` must still return
/// (best-effort posture), but the stats reflect
/// `primary_attempted && !primary_complete && fallback_attempted &&
/// !fallback_complete` — the exact combination the recovery driver
/// reports as `recovery: best_effort_incomplete` in tracing.
#[tokio::test]
async fn best_effort_incomplete_when_neither_layer_completes() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // Snapshot A's identity before disconnect, then take down both A
    // and C so primary + fallback both fail at the transport layer.
    let a = harness.instance("b");
    let a_key = *a.state.instance_key.public_bytes();
    let a_domain = a.state.instance_domain.clone();
    harness.disconnect("b").await;
    harness.disconnect("c").await;

    let d = harness.instance("a");
    let stats: RecoveryStats =
        drive_recovery(d.state.clone(), k_pub, k_key, Some((a_key, a_domain))).await;

    assert!(stats.primary_attempted);
    assert!(!stats.primary_complete);
    assert!(stats.fallback_attempted);
    assert!(
        !stats.fallback_complete,
        "C disconnected → §10.5.1 GET fails → fallback_all_complete=false; stats={stats:?}",
    );
    // Mirrors the private `RecoveryStats::is_incomplete` predicate.
    let primary_ok = stats.primary_attempted && stats.primary_complete;
    let fallback_ok = stats.fallback_attempted && stats.fallback_complete;
    assert!(
        !(primary_ok || fallback_ok),
        "neither layer succeeded → recovery: best_effort_incomplete; stats={stats:?}",
    );
}
