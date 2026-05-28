//! Phase-10.3a integration tests: §13.3 step-1 prior-home probe fan-out.
//!
//! Spec gates exercised here (`docs/federation-protocol.md` §13.3,
//! `docs/federation-impl-plan.md` §10.3):
//!
//! - **Layer 1 — strategy 1 (user-declared) hit.** Registering
//!   instance D probes only the declared peer B; B holds K, returns
//!   `has_activity = true`; `discover_prior_home` surfaces B.
//! - **Layer 1 — strategy 1 authoritative miss is terminal.** D
//!   declares B as the prior home, B is reachable and answers
//!   `has_activity = false`. Even though peer C *does* hold K,
//!   `discover_prior_home` returns `None` — we never silently
//!   override an authoritative declared-peer answer.
//! - **Layer 1 — strategy 1 unreachable peer falls through.** D
//!   declares B as the prior home but B is disconnected from the
//!   transport before the probe runs. C holds K. Fan-out kicks in
//!   and surfaces C. This is the case the user flagged after the
//!   first 10.3a pass: an unreachable declared peer must not strand
//!   the user.
//! - **Layer 1 — strategy 1 unknown-domain falls through.** Declared
//!   domain isn't even in D's `peers` table. We can't probe it at
//!   all, so we fall through to fan-out, which finds K on C.
//! - **Layer 1 — strategy 2 (local lookup) hit.** D has previously
//!   hydrated a `signup_method='federated'` stub for K with
//!   `home_instance = pubkey(B)`. With no declared domain,
//!   `discover_prior_home` probes only B and finds K there.
//! - **Layer 1 — strategy 3 (bounded fan-out) short-circuits on
//!   first hit.** No declaration, no local hint, multiple peers; the
//!   one peer that holds K is surfaced.
//! - **Layer 1 — fan-out cap.** With 18 active peers but the
//!   K-holder placed beyond `PRIOR_HOME_PROBE_FANOUT_MAX = 16`,
//!   `discover_prior_home` returns `None`.
//! - **Layer 1 — stale-home exclusion.** A peer that used to hold K
//!   but now has K's `users.home_instance` set (K moved out) returns
//!   `has_activity = false` per the probe handler's filter, so
//!   `discover_prior_home` does not surface that peer.

#![cfg(feature = "test-auth")]

mod common;

use ed25519_dalek::SigningKey;
use prismoire_server::federation::registration::{
    PRIOR_HOME_PROBE_FANOUT_MAX, discover_prior_home,
};
use rand::rngs::OsRng;
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Insert a locally-homed user row that will make the §14.2 probe
/// handler answer `has_activity = true` for `pubkey`. The handler's
/// SELECT filters by `signup_method != 'federated' AND home_instance
/// IS NULL AND deleted_at IS NULL`, so anything matching those three
/// predicates suffices.
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
    .expect("insert local user");
    id
}

/// Insert a user row for K with `home_instance` set, simulating a
/// peer that *was* K's home but K has since moved out. The §14.2
/// probe handler filters on `home_instance IS NULL`, so this row
/// answers `has_activity = false`.
async fn insert_moved_out_user(
    db: &SqlitePool,
    display_name: &str,
    pubkey: &[u8; 32],
    new_home_pubkey: &[u8; 32],
) -> String {
    let id = Uuid::new_v4().to_string();
    let skeleton = display_name.to_lowercase();
    let pubkey_slice: &[u8] = pubkey.as_slice();
    let new_home_slice: &[u8] = new_home_pubkey.as_slice();
    sqlx::query!(
        "INSERT INTO users \
            (id, display_name, signup_method, public_key, display_name_skeleton, home_instance) \
         VALUES (?, ?, 'admin', ?, ?, ?)",
        id,
        display_name,
        pubkey_slice,
        skeleton,
        new_home_slice,
    )
    .execute(db)
    .await
    .expect("insert moved-out user");
    id
}

/// Insert a `signup_method = 'federated'` stub on `db` with
/// `home_instance = home_pubkey`. Phase 9.5 produces rows like this
/// when an inbound profile-rev or trust-edge surfaces a peer-homed
/// identity locally. The §13.3 strategy-2 lookup in
/// `discover_prior_home` keys on exactly this column.
async fn insert_federated_stub_with_home(
    db: &SqlitePool,
    display_name: &str,
    pubkey: &[u8; 32],
    home_pubkey: &[u8; 32],
) -> String {
    let id = Uuid::new_v4().to_string();
    let skeleton = display_name.to_lowercase();
    let pubkey_slice: &[u8] = pubkey.as_slice();
    let home_slice: &[u8] = home_pubkey.as_slice();
    sqlx::query!(
        "INSERT INTO users \
            (id, display_name, signup_method, public_key, display_name_skeleton, home_instance) \
         VALUES (?, ?, 'federated', ?, ?, ?)",
        id,
        display_name,
        pubkey_slice,
        skeleton,
        home_slice,
    )
    .execute(db)
    .await
    .expect("insert federated stub");
    id
}

// ---------------------------------------------------------------------------
// Strategy 1 — user-declared candidate
// ---------------------------------------------------------------------------

/// Strategy-1 happy path: D declares B as the prior home, B holds K,
/// `discover_prior_home` surfaces B without consulting any other peer.
#[tokio::test]
async fn declared_hit_surfaces_declared_peer() {
    let harness = MultiInstanceHarness::new(3).await;
    // D = "a", B = "b", C = "c"
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // K lives on B (the declared one) AND on C — so a regression that
    // dropped the declared-peer short-circuit and fell through to
    // fan-out would silently surface C instead of B. We assert B.
    let b = harness.instance("b");
    let c = harness.instance("c");
    insert_local_user(&b.state.db, "kara", &k_pub).await;
    insert_local_user(&c.state.db, "kara", &k_pub).await;

    let d = harness.instance("a");
    let hit = discover_prior_home(&d.state, &k_pub, &k_key, Some(&b.state.instance_domain)).await;
    let (hit_key, hit_domain) = hit.expect("declared hit must surface");
    assert_eq!(
        hit_key,
        *b.state.instance_key.public_bytes(),
        "declared peer (B) must win, not the fan-out alt (C)",
    );
    assert_eq!(hit_domain, b.state.instance_domain);
}

/// Strategy-1 authoritative miss: declared peer B responds but says
/// `has_activity = false`. Even though C holds K, we must NOT surface
/// C — B's "no" is authoritative and silently overriding it would
/// betray the user's claim.
#[tokio::test]
async fn declared_authoritative_miss_is_terminal() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // K is NOT on B (so B will answer has_activity=false), but IS on C.
    // If discover_prior_home falls through, it would surface C.
    let c = harness.instance("c");
    insert_local_user(&c.state.db, "kara", &k_pub).await;

    let d = harness.instance("a");
    let b = harness.instance("b");
    let hit = discover_prior_home(&d.state, &k_pub, &k_key, Some(&b.state.instance_domain)).await;
    assert!(
        hit.is_none(),
        "declared authoritative miss must terminate, even if another peer holds K",
    );
}

/// Strategy-1 unreachable peer falls through to fan-out. D declares B
/// as the prior home, but B is disconnected from the transport before
/// the probe runs (simulating "B permanently went offline"). C holds K
/// and is reachable; fan-out must locate C and surface it. This is
/// strictly weaker than "authoritative miss is terminal" — the
/// distinction is the whole point of the tri-state probe
/// classification.
#[tokio::test]
async fn declared_unreachable_falls_through_to_fanout() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // K is on C only; B has no row at all but is also unreachable, so
    // the probe to B errors out (Unreachable) rather than answering
    // has_activity=false (AuthoritativeMiss).
    let c = harness.instance("c");
    insert_local_user(&c.state.db, "kara", &k_pub).await;

    // Snapshot B's domain before disconnecting so the test can still
    // ask "did we fall through past B?" without touching the harness.
    let b_domain = harness.instance("b").state.instance_domain.clone();
    harness.disconnect("b").await;

    let d = harness.instance("a");
    let hit = discover_prior_home(&d.state, &k_pub, &k_key, Some(&b_domain)).await;
    let (hit_key, hit_domain) = hit.expect("fan-out must locate K on C after B is unreachable");
    assert_eq!(
        hit_key,
        *c.state.instance_key.public_bytes(),
        "unreachable declared peer (B) must not block surfacing C",
    );
    assert_eq!(hit_domain, c.state.instance_domain);
}

/// Strategy-1 unknown domain falls through. The user declared a domain
/// that isn't even in our `peers` table; we have no peer to probe, so
/// there is no "user said X and X said no" to honour. Fan-out runs and
/// surfaces C.
#[tokio::test]
async fn declared_unknown_domain_falls_through_to_fanout() {
    // 2 instances: D="a", C="b". The declared domain is a third name
    // we never registered as a peer, so resolve_peer_by_domain returns
    // Ok(None) and the discovery falls through.
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    let c = harness.instance("b");
    insert_local_user(&c.state.db, "kara", &k_pub).await;

    let d = harness.instance("a");
    let hit = discover_prior_home(&d.state, &k_pub, &k_key, Some("ghost.example.invalid")).await;
    let (hit_key, _) = hit.expect("fan-out must run when declared domain isn't peered");
    assert_eq!(hit_key, *c.state.instance_key.public_bytes());
}

// ---------------------------------------------------------------------------
// Strategy 2 — local-lookup via users.home_instance
// ---------------------------------------------------------------------------

/// Strategy-2 happy path: D holds a Phase-9.5 federated stub for K
/// with `home_instance = pubkey(B)`. With no declared domain,
/// `discover_prior_home` probes B and finds K. Verifies the
/// `users.home_instance`-keyed shortcut works end-to-end.
#[tokio::test]
async fn local_lookup_uses_home_instance_pointer() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // K is on B only — the strategy must steer the probe at B.
    let b = harness.instance("b");
    insert_local_user(&b.state.db, "kara", &k_pub).await;

    // Pre-seed D's federated stub for K with home_instance = B's
    // pubkey. (Phase 9.5's hydration produces rows in this shape.)
    let d = harness.instance("a");
    insert_federated_stub_with_home(
        &d.state.db,
        "kara",
        &k_pub,
        b.state.instance_key.public_bytes(),
    )
    .await;

    let hit = discover_prior_home(&d.state, &k_pub, &k_key, None).await;
    let (hit_key, _) = hit.expect("local home_instance lookup must succeed");
    assert_eq!(hit_key, *b.state.instance_key.public_bytes());
}

// ---------------------------------------------------------------------------
// Strategy 3 — bounded fan-out
// ---------------------------------------------------------------------------

/// Strategy-3 happy path: no declaration, no local hint, two peers in
/// D's fan-out set, one holds K. `discover_prior_home` surfaces it.
#[tokio::test]
async fn fanout_finds_holder_among_active_peers() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    let c = harness.instance("c");
    insert_local_user(&c.state.db, "kara", &k_pub).await;

    let d = harness.instance("a");
    let hit = discover_prior_home(&d.state, &k_pub, &k_key, None).await;
    let (hit_key, _) = hit.expect("fan-out must locate K");
    assert_eq!(hit_key, *c.state.instance_key.public_bytes());
}

/// Fan-out cap: with `PRIOR_HOME_PROBE_FANOUT_MAX + 2 = 18` active
/// peers but the K-holder pinned to be the *oldest* peer (so it sorts
/// past the cap under `ORDER BY COALESCE(last_handshake, first_seen)
/// DESC`), `discover_prior_home` returns `None`.
///
/// We control ordering by `UPDATE`-ing `last_handshake` to a fixed
/// timestamp on every peer, then bumping the non-holders to a strictly
/// later timestamp so they win the ORDER BY DESC and the holder sorts
/// last. Otherwise the harness establishes all peerings within the
/// same wall-clock second and the SQL tiebreaker is undefined.
#[tokio::test]
async fn fanout_respects_cap() {
    // 1 registering (D) + 18 candidates = 19 instances.
    let n_candidates = PRIOR_HOME_PROBE_FANOUT_MAX + 2;
    let harness = MultiInstanceHarness::new(1 + n_candidates).await;

    // Establish peering between D = "a" and every other instance.
    for i in 0..n_candidates {
        let label = char::from(b'b' + i as u8).to_string();
        establish_active_peering(&harness, "a", &label).await;
    }

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // Pick one candidate beyond the cap to hold K. We'll force this
    // candidate to sort *last* in D's peers ORDER BY by writing the
    // oldest last_handshake to its row.
    let holder_label = char::from(b'b' + (n_candidates - 1) as u8).to_string();
    let holder = harness.instance(&holder_label);
    insert_local_user(&holder.state.db, "kara", &k_pub).await;

    // Force a deterministic ordering on D's peers: holder = OLDEST,
    // everyone else = NEWEST. ORDER BY DESC then visits non-holders
    // first; the holder sits in position 19 of 19 and is beyond the
    // cap of 16.
    let d = harness.instance("a");
    let holder_pubkey: &[u8] = holder.state.instance_key.public_bytes().as_slice();
    sqlx::query!(
        "UPDATE peers SET last_handshake = '2000-01-01T00:00:00Z' \
         WHERE instance_pubkey = ?",
        holder_pubkey,
    )
    .execute(&d.state.db)
    .await
    .expect("UPDATE holder last_handshake");
    sqlx::query!(
        "UPDATE peers SET last_handshake = '2030-01-01T00:00:00Z' \
         WHERE instance_pubkey != ?",
        holder_pubkey,
    )
    .execute(&d.state.db)
    .await
    .expect("UPDATE non-holder last_handshake");

    // Sanity-check our ordering assumption before running the probe —
    // a failure here means the test is mis-set-up, not that the cap
    // logic is wrong.
    let limit = PRIOR_HOME_PROBE_FANOUT_MAX as i64;
    let head: Vec<Vec<u8>> = sqlx::query_scalar!(
        "SELECT instance_pubkey AS \"instance_pubkey!: Vec<u8>\" \
         FROM peers WHERE status = 'active' \
         ORDER BY COALESCE(last_handshake, first_seen) DESC \
         LIMIT ?",
        limit,
    )
    .fetch_all(&d.state.db)
    .await
    .expect("SELECT head of peers fan-out");
    assert!(
        !head.iter().any(|p| p.as_slice() == holder_pubkey),
        "test mis-set-up: holder leaked into the first {} peers \
         (UPDATE last_handshake assumption broke)",
        PRIOR_HOME_PROBE_FANOUT_MAX,
    );

    let hit = discover_prior_home(&d.state, &k_pub, &k_key, None).await;
    assert!(
        hit.is_none(),
        "K-holder past the fan-out cap must NOT be surfaced \
         (cap = {}, candidates = {})",
        PRIOR_HOME_PROBE_FANOUT_MAX,
        n_candidates,
    );
}

// ---------------------------------------------------------------------------
// Stale-home exclusion
// ---------------------------------------------------------------------------

/// A peer that used to hold K but has since seen K move out — the
/// `users` row exists with `home_instance` set to the new home —
/// answers `has_activity = false` per §14.2 semantics. The discovery
/// orchestrator therefore must not surface it as the prior home, even
/// when it's the only candidate.
#[tokio::test]
async fn stale_home_is_not_surfaced() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // B has a row for K but K moved out — home_instance points
    // somewhere else (we use a synthetic 32-byte placeholder; the
    // probe handler only checks `home_instance IS NULL`, not its
    // contents).
    let b = harness.instance("b");
    let elsewhere_key: [u8; 32] = [0x77; 32];
    insert_moved_out_user(&b.state.db, "kara", &k_pub, &elsewhere_key).await;

    let d = harness.instance("a");
    let hit = discover_prior_home(&d.state, &k_pub, &k_key, None).await;
    assert!(
        hit.is_none(),
        "moved-out peer must answer has_activity=false; \
         discover_prior_home must not surface it",
    );
}
