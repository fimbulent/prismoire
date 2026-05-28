//! Phase-9.8 integration tests: durable `pending_trust_edges`
//! orphan buffer + autonomous §9.3 backfill on first orphan.
//!
//! Spec gates (`docs/federation-protocol.md` §9.1 `deferred`, §9.3
//! chain backfill, §9.6 `DEFERRED_ORPHAN_TTL` / `MAX_BACKFILL_RATE`):
//!
//! - **Layer 0** — TTL eviction prunes only rows older than the TTL;
//!   fresh rows survive. (Drives the §9.6 TTL sweep directly.)
//! - **Layer 0** — when `sweep_pending_projections` projects an edge
//!   whose hash matches a buffered orphan's `prior_edge_hash`, the
//!   sweep's drain extension promotes the orphan in the same tx.
//! - **Layer 1** — a `deferred` push response is backed by a fresh
//!   row in `pending_trust_edges` keyed on `(source, prior)`.
//! - **Layer 1** — re-pushing the same orphan for the same gap does
//!   not double-enqueue (`INSERT OR IGNORE` dedup; §9.6
//!   `MAX_BACKFILL_RATE` budget alignment).
//! - **Layer 1** — when the predecessor arrives via a subsequent
//!   push, `drain_pending_orphans_after` promotes the buffered
//!   orphan into `trust_edges` + `signed_objects` atomically with
//!   the trigger, deleting the pending row.
//! - **Layer 1** — the first orphan for a gap triggers an
//!   autonomous `GET /edges/backfill` against the source's home
//!   instance, and the response feeds back through the receive path
//!   to close the chain.

#![cfg(feature = "test-auth")]

mod common;

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use prismoire_server::federation::edges::DEFERRED_ORPHAN_TTL;
use prismoire_server::federation::remote_users::{
    evict_expired_pending_trust_edges, hydrate_stub_user, sweep_pending_projections,
};
use prismoire_server::signed::TrustStance;
use prismoire_server::signing::{sign_trust_edge_with_key, store_signed_object};
use rand::SeedableRng;
use rand::rngs::StdRng;
use sqlx::SqlitePool;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};
use common::test_app;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn seeded_signer(seed: u8) -> SigningKey {
    let mut rng = StdRng::seed_from_u64(seed as u64);
    SigningKey::generate(&mut rng)
}

fn pubkey_of(k: &SigningKey) -> [u8; 32] {
    *k.verifying_key().as_bytes()
}

/// Push body builder mirroring the Phase-5 helper.
fn encode_edges_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("edges".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + wires.iter().map(|w| w.len()).sum::<usize>());
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// WireFormat `{ "p", "s" }` encoder. Same shape as
/// `envelope::encode_signed_object`.
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

/// Pull `(canonical_hash, status, reason?)` triples out of a §9.1
/// results body.
fn parse_results_body(body: &[u8]) -> Vec<([u8; 32], String, Option<String>)> {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("results body is not a map");
    };
    let Some(results) = m.into_iter().find_map(|(k, v)| match k {
        Value::Text(t) if t == "results" => Some(v),
        _ => None,
    }) else {
        panic!("missing `results` field");
    };
    let Value::Array(arr) = results else {
        panic!("`results` is not an array");
    };
    arr.into_iter()
        .map(|entry| {
            let Value::Map(fields) = entry else {
                panic!("result entry not a map");
            };
            let mut hash: Option<[u8; 32]> = None;
            let mut status: Option<String> = None;
            let mut reason: Option<String> = None;
            for (k, v) in fields {
                if let Value::Text(name) = k {
                    match (name.as_str(), v) {
                        ("canonical_hash", Value::Bytes(b)) => {
                            hash = Some(b.as_slice().try_into().expect("32 bytes"));
                        }
                        ("status", Value::Text(s)) => status = Some(s),
                        ("reason", Value::Text(s)) => reason = Some(s),
                        _ => {}
                    }
                }
            }
            (hash.expect("hash"), status.expect("status"), reason)
        })
        .collect()
}

/// Local-user insert with a known pubkey. Mirrors the Phase-5 helper.
async fn insert_user_with_pubkey(db: &SqlitePool, id: &str, display_name: &str, pubkey: &[u8; 32]) {
    let pubkey_slice: &[u8] = pubkey.as_slice();
    let skeleton = display_name.to_lowercase();
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
}

/// Count rows in `pending_trust_edges` keyed on `(source, prior)`.
async fn pending_row_count(db: &SqlitePool, source: &[u8; 32], prior: &[u8; 32]) -> i64 {
    let s: &[u8] = source.as_slice();
    let p: &[u8] = prior.as_slice();
    sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM pending_trust_edges \
         WHERE source_pubkey = ? AND prior_edge_hash = ?",
        s,
        p,
    )
    .fetch_one(db)
    .await
    .expect("pending count")
}

/// Count rows in `trust_edges` matching `canonical_hash`.
async fn trust_edge_present(db: &SqlitePool, canonical_hash: &[u8; 32]) -> bool {
    let h: &[u8] = canonical_hash.as_slice();
    let n: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM trust_edges WHERE canonical_hash = ?",
        h,
    )
    .fetch_one(db)
    .await
    .expect("trust_edges count");
    n > 0
}

/// `signed_objects` payload present (live row, not erased).
async fn signed_object_live(db: &SqlitePool, canonical_hash: &[u8; 32]) -> bool {
    let h: &[u8] = canonical_hash.as_slice();
    let n: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects \
         WHERE canonical_hash = ? AND payload IS NOT NULL",
        h,
    )
    .fetch_one(db)
    .await
    .expect("signed_objects count");
    n > 0
}

/// Poll `predicate` up to `timeout_ms`. Mirrors the Phase-5 helper
/// — the autonomous backfill spawn is asynchronous from the
/// `send_envelope_signed` return, so we need a bounded wait rather
/// than a single sleep.
async fn poll_until<F, Fut>(timeout_ms: u64, mut predicate: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        if predicate().await {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// Layer 0 — TTL eviction
// ---------------------------------------------------------------------------

/// `evict_expired_pending_trust_edges` deletes only rows whose
/// `received_at` is more than `ttl_ms` behind `now_ms`. Fresh rows
/// survive. Drives §9.6 `DEFERRED_ORPHAN_TTL` directly.
#[tokio::test]
async fn evict_drops_expired_pending_rows_and_preserves_fresh() {
    let (_app, state) = test_app().await;

    // Two synthetic pending rows: one ancient (received 2h ago), one
    // fresh (received "now"). Insert via raw SQL — the public surface
    // doesn't expose the enqueue path directly, and we only need the
    // row shape, not the receive-path machinery, for this test.
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let two_hours_ago = now_ms - 2 * 3600 * 1000;
    let source_old = [0x11u8; 32];
    let source_new = [0x22u8; 32];
    let target = [0x33u8; 32];
    let prior_old = [0x44u8; 32];
    let prior_new = [0x55u8; 32];
    let canonical_old = [0x66u8; 32];
    let canonical_new = [0x77u8; 32];

    for (source, prior, canonical, received_at) in [
        (&source_old, &prior_old, &canonical_old, two_hours_ago),
        (&source_new, &prior_new, &canonical_new, now_ms),
    ] {
        let s: &[u8] = source.as_slice();
        let t: &[u8] = target.as_slice();
        let p: &[u8] = prior.as_slice();
        let c: &[u8] = canonical.as_slice();
        let payload: &[u8] = &[0xAB, 0xCD];
        let signature: &[u8] = &[0xEF, 0x01];
        sqlx::query!(
            "INSERT INTO pending_trust_edges \
                (source_pubkey, target_pubkey, prior_edge_hash, canonical_hash, \
                 payload, signature, received_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            s,
            t,
            p,
            c,
            payload,
            signature,
            received_at,
        )
        .execute(&state.db)
        .await
        .expect("insert pending");
    }

    let ttl_ms = DEFERRED_ORPHAN_TTL.as_millis() as i64;
    let evicted = evict_expired_pending_trust_edges(&state.db, now_ms, ttl_ms)
        .await
        .expect("evict");
    assert_eq!(evicted, 1, "exactly the ancient row should be evicted");

    assert_eq!(
        pending_row_count(&state.db, &source_old, &prior_old).await,
        0,
        "ancient row gone",
    );
    assert_eq!(
        pending_row_count(&state.db, &source_new, &prior_new).await,
        1,
        "fresh row preserved",
    );
}

// ---------------------------------------------------------------------------
// Layer 0 — sweep drain extension
// ---------------------------------------------------------------------------

/// `sweep_pending_projections` projects a stored predecessor edge and
/// — via the Phase 9.8 drain extension — promotes the orphan that
/// was buffered against that predecessor in the same transaction.
/// Verifies the cascade closes atomically: E1 lands in `trust_edges`,
/// E2 promotes from `pending_trust_edges` into `trust_edges` +
/// `signed_objects`, and the pending row is deleted.
#[tokio::test]
async fn sweep_projection_drains_buffered_orphan_chain() {
    let (_app, state) = test_app().await;

    let from_signer = seeded_signer(0xa1);
    let to_signer = seeded_signer(0xa2);
    let from_key = pubkey_of(&from_signer);
    let to_key = pubkey_of(&to_signer);
    let home = [0xa3u8; 32];

    // Both endpoints get federated stubs so the projection's FK
    // resolution finds users rows.
    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &from_key, "alice", &home)
            .await
            .expect("from stub");
        hydrate_stub_user(&mut tx, &to_key, "bob", &home)
            .await
            .expect("to stub");
        tx.commit().await.expect("commit");
    }

    // Build E1 (root, prior=None) and E2 (chains off E1).
    let e1 = sign_trust_edge_with_key(
        &from_signer,
        &to_key,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let e2 = sign_trust_edge_with_key(
        &from_signer,
        &to_key,
        TrustStance::Distrust,
        1_700_000_000_001,
        Some(e1.canonical_hash),
    );

    // Stage E1 in `signed_objects` *unprojected* — sweep is supposed
    // to find it. Stage E2 in `pending_trust_edges` keyed on
    // `(from_key, e1.canonical_hash)` — the drain trigger.
    {
        let mut tx = state.db.begin().await.expect("begin");
        store_signed_object(
            &mut *tx,
            "trust-edge",
            &e1.payload,
            &e1.signature,
            &e1.canonical_hash,
        )
        .await
        .expect("store e1");

        // Direct INSERT into pending_trust_edges — `enqueue_pending_trust_edge`
        // is pub(crate), but the row shape is stable and the test
        // exercises the projection-cascade contract, not the enqueue
        // wire path (covered at Layer 1).
        let now_ms = chrono::Utc::now().timestamp_millis();
        let source_slice: &[u8] = from_key.as_slice();
        let target_slice: &[u8] = to_key.as_slice();
        let prior_slice: &[u8] = e1.canonical_hash.as_slice();
        let canonical_slice: &[u8] = e2.canonical_hash.as_slice();
        let payload_slice: &[u8] = e2.payload.as_slice();
        let signature_slice: &[u8] = e2.signature.as_slice();
        sqlx::query!(
            "INSERT INTO pending_trust_edges \
                (source_pubkey, target_pubkey, prior_edge_hash, canonical_hash, \
                 payload, signature, received_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            source_slice,
            target_slice,
            prior_slice,
            canonical_slice,
            payload_slice,
            signature_slice,
            now_ms,
        )
        .execute(&mut *tx)
        .await
        .expect("insert pending");

        tx.commit().await.expect("commit");
    }

    // Pre-sweep: E1 stored, E2 only in pending, neither in trust_edges.
    assert!(signed_object_live(&state.db, &e1.canonical_hash).await);
    assert!(!signed_object_live(&state.db, &e2.canonical_hash).await);
    assert!(!trust_edge_present(&state.db, &e1.canonical_hash).await);
    assert!(!trust_edge_present(&state.db, &e2.canonical_hash).await);
    assert_eq!(
        pending_row_count(&state.db, &from_key, &e1.canonical_hash).await,
        1,
    );

    // Run the sweep. E1 projects via the Phase 9.6 fixed-point loop;
    // the Phase 9.8 drain extension then promotes E2 from the pending
    // buffer.
    {
        let mut tx = state.db.begin().await.expect("begin");
        sweep_pending_projections(&mut tx, &from_key)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
    }

    assert!(
        trust_edge_present(&state.db, &e1.canonical_hash).await,
        "E1 must project via the sweep",
    );
    assert!(
        trust_edge_present(&state.db, &e2.canonical_hash).await,
        "E2 must promote from pending via the drain extension",
    );
    assert!(
        signed_object_live(&state.db, &e2.canonical_hash).await,
        "promoted orphan's bytes must land in signed_objects too",
    );
    assert_eq!(
        pending_row_count(&state.db, &from_key, &e1.canonical_hash).await,
        0,
        "pending row deleted after drain",
    );
}

// ---------------------------------------------------------------------------
// Layer 1 — pending buffer wired through the wire-level receive path
// ---------------------------------------------------------------------------

/// A `deferred` push response is backed by a freshly-inserted row in
/// `pending_trust_edges` keyed on `(source, prior)`. The phantom
/// predecessor never arrives, so the row stays put.
#[tokio::test]
async fn deferred_push_buffers_orphan_in_pending_table() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice = SigningKey::generate(&mut rand::rngs::OsRng);
    let bob = SigningKey::generate(&mut rand::rngs::OsRng);
    let alice_pub = alice.verifying_key().to_bytes();
    let bob_pub = bob.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;

    let phantom_prior = [0x42u8; 32];
    let signed = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        Some(phantom_prior),
    );
    let body = encode_edges_body(&[encode_wire(&signed.payload, &signed.signature)]);

    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "request-level OK");
    let results = parse_results_body(&resp_body);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, "deferred", "orphan must defer");

    // Pending row landed under the spec-mandated key shape.
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &phantom_prior).await,
        1,
        "single pending row keyed on (source, prior)",
    );

    // Deferred specifically does NOT store the bytes in signed_objects
    // — the pending buffer is the sole durable layer until promotion.
    assert!(
        !signed_object_live(&b.state.db, &signed.canonical_hash).await,
        "deferred bytes must not double-land in signed_objects",
    );
    assert!(
        !trust_edge_present(&b.state.db, &signed.canonical_hash).await,
        "deferred orphan must not project",
    );
}

/// Re-pushing the same orphan (or pushing a sibling with the same
/// `(source, prior)` gap) does NOT double-enqueue — `INSERT OR IGNORE`
/// on the pending PK collapses retries into the existing row.
/// Both responses are `deferred`.
#[tokio::test]
async fn duplicate_orphan_for_same_gap_does_not_double_enqueue() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice = SigningKey::generate(&mut rand::rngs::OsRng);
    let bob = SigningKey::generate(&mut rand::rngs::OsRng);
    let alice_pub = alice.verifying_key().to_bytes();
    let bob_pub = bob.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;

    let phantom_prior = [0x42u8; 32];
    let signed = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        Some(phantom_prior),
    );
    let body = encode_edges_body(&[encode_wire(&signed.payload, &signed.signature)]);

    // First push: enqueues, status `deferred`.
    let (status1, b1) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(parse_results_body(&b1)[0].1, "deferred");
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &phantom_prior).await,
        1,
    );

    // Second push of the exact same bytes: still `deferred`, still
    // exactly one row buffered.
    let (status2, b2) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(parse_results_body(&b2)[0].1, "deferred");
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &phantom_prior).await,
        1,
        "INSERT OR IGNORE collapses retries to one pending row",
    );

    // Sibling with the same prior but a different stance — still
    // shares the gap, still does not double-enqueue. (The dedup is
    // keyed on (source, prior), not on canonical_hash.)
    let sibling = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Distrust,
        1_700_000_000_001,
        Some(phantom_prior),
    );
    let body2 = encode_edges_body(&[encode_wire(&sibling.payload, &sibling.signature)]);
    let (status3, b3) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body2,
    )
    .await;
    assert_eq!(status3, StatusCode::OK);
    assert_eq!(parse_results_body(&b3)[0].1, "deferred");
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &phantom_prior).await,
        1,
        "sibling for same gap collapses into the existing pending row",
    );
}

/// E2 arrives first (orphan, deferred); E1 arrives second. The
/// receive-path drain extension projects E2 atomically with E1's
/// projection, deletes the pending row, and persists E2's canonical
/// bytes in `signed_objects` for future relay / audit.
#[tokio::test]
async fn root_push_drains_buffered_orphan_chain() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice = SigningKey::generate(&mut rand::rngs::OsRng);
    let bob = SigningKey::generate(&mut rand::rngs::OsRng);
    let alice_pub = alice.verifying_key().to_bytes();
    let bob_pub = bob.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;

    let e1 = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let e2 = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Distrust,
        1_700_000_000_001,
        Some(e1.canonical_hash),
    );

    // Push E2 first — orphan, defers.
    let body_e2 = encode_edges_body(&[encode_wire(&e2.payload, &e2.signature)]);
    let (s1, b1) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body_e2,
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(parse_results_body(&b1)[0].1, "deferred");
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &e1.canonical_hash).await,
        1,
    );
    assert!(!trust_edge_present(&b.state.db, &e2.canonical_hash).await);
    assert!(!signed_object_live(&b.state.db, &e2.canonical_hash).await);

    // Push E1 — applies, and the same-tx drain promotes E2.
    let body_e1 = encode_edges_body(&[encode_wire(&e1.payload, &e1.signature)]);
    let (s2, b2) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body_e1,
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(parse_results_body(&b2)[0].1, "applied");

    assert!(
        trust_edge_present(&b.state.db, &e1.canonical_hash).await,
        "E1 projects on E1's own push",
    );
    assert!(
        trust_edge_present(&b.state.db, &e2.canonical_hash).await,
        "E2 promotes from pending via drain on E1's projection",
    );
    assert!(
        signed_object_live(&b.state.db, &e2.canonical_hash).await,
        "drain persists the orphan's bytes into signed_objects",
    );
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &e1.canonical_hash).await,
        0,
        "pending row deleted after promotion",
    );
}

/// Autonomous §9.3 backfill: B receives an orphan whose source key
/// has its home_instance pointing at A. B fires
/// `request_edge_predecessor` after the receive tx commits, A serves
/// the predecessor over `/edges/backfill`, B feeds it back through
/// the receive path, and the buffered orphan promotes.
///
/// This is the round-trip test for the §9.1 `deferred` promise:
/// "the receiver holds the orphan and autonomously issues §9.3 chain
/// backfill to recover the missing predecessor". The whole loop runs
/// without an additional sender push.
#[tokio::test]
async fn autonomous_backfill_recovers_chain_from_source_home() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_peer = *a.peer_id.as_bytes();

    // Both alice and bob exist as local users on A so A's
    // /edges/backfill handler can join trust_edges + signed_objects
    // and serve the chain.
    let alice = SigningKey::generate(&mut rand::rngs::OsRng);
    let bob = SigningKey::generate(&mut rand::rngs::OsRng);
    let alice_pub = alice.verifying_key().to_bytes();
    let bob_pub = bob.verifying_key().to_bytes();
    insert_user_with_pubkey(&a.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&a.state.db, "user-bob", "bob", &bob_pub).await;

    let e1 = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let e2 = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Distrust,
        1_700_000_000_001,
        Some(e1.canonical_hash),
    );

    // Bring A to a state where it has E1 and E2 both projected:
    // push both from B → A (B is the active peer, envelope sender).
    let body_both = encode_edges_body(&[
        encode_wire(&e1.payload, &e1.signature),
        encode_wire(&e2.payload, &e2.signature),
    ]);
    let (sa, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/edges",
        &body_both,
    )
    .await;
    assert_eq!(sa, StatusCode::OK, "seed push to A");
    assert!(trust_edge_present(&a.state.db, &e1.canonical_hash).await);
    assert!(trust_edge_present(&a.state.db, &e2.canonical_hash).await);

    // On B: bob is a local user; alice is a federated stub whose
    // home_instance points at A, so B's autonomous backfill issuer
    // resolves alice's home to A's peer_id.
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;
    {
        let mut tx = b.state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &alice_pub, "alice", &a_peer)
            .await
            .expect("alice stub");
        tx.commit().await.expect("commit");
    }

    // Push only E2 to B. B sees the orphan, defers, enqueues, and
    // spawns the autonomous backfill aimed at A.
    let body_e2 = encode_edges_body(&[encode_wire(&e2.payload, &e2.signature)]);
    let (sb, body_b) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body_e2,
    )
    .await;
    assert_eq!(sb, StatusCode::OK);
    assert_eq!(parse_results_body(&body_b)[0].1, "deferred");
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &e1.canonical_hash).await,
        1,
        "orphan buffered before the backfill round-trips",
    );

    // The spawned backfill task: GET /edges/backfill?source=alice&target=bob
    // → A returns E1 → B re-feeds → E1 projects on B → drain promotes E2.
    // Asynchronous from the push's perspective; poll with a bounded
    // wait. 2s is generous for in-process transport.
    let db = b.state.db.clone();
    let e1_hash = e1.canonical_hash;
    let e2_hash = e2.canonical_hash;
    let alice_pub_copy = alice_pub;
    let e1_hash_copy = e1.canonical_hash;
    let ok = poll_until(2000, move || {
        let db = db.clone();
        async move {
            trust_edge_present(&db, &e1_hash).await
                && trust_edge_present(&db, &e2_hash).await
                && pending_row_count(&db, &alice_pub_copy, &e1_hash_copy).await == 0
        }
    })
    .await;
    assert!(
        ok,
        "autonomous backfill did not close the chain within deadline: \
         E1 projected={} E2 projected={} pending={}",
        trust_edge_present(&b.state.db, &e1.canonical_hash).await,
        trust_edge_present(&b.state.db, &e2.canonical_hash).await,
        pending_row_count(&b.state.db, &alice_pub, &e1.canonical_hash).await,
    );

    // After the round-trip, E1's bytes are stored on B and E2's
    // bytes were promoted out of pending into signed_objects.
    assert!(signed_object_live(&b.state.db, &e1.canonical_hash).await);
    assert!(signed_object_live(&b.state.db, &e2.canonical_hash).await);
}
