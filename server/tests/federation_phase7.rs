//! Phase-7 Layer-1 integration tests: §12 Move declarations + §12.3
//! move-chain backfill.
//!
//! Pins the Phase-7 done-when criteria from
//! `docs/federation-impl-plan.md`:
//!
//! - `POST /federation/v1/moves` accepts a §12.1 body from an active
//!   peer, dispatches the per-object state machine, and projects an
//!   `applied` move into `signed_objects` + `user_moves` + `user_homes`.
//! - The §12.4 latest-wins-by-timestamp resolution surfaces a stale
//!   replay as `superseded` — chain row written, but `user_homes`
//!   reflects the newer move.
//! - The §12.7 `MAX_CLOCK_SKEW` gate rejects a future-dated move with
//!   `skew_exceeded` and does not persist it.
//! - §12.1 chain-grounding returns `deferred` (no persist, no forward)
//!   for a move whose `prior_move_hash` predecessor is absent locally.
//! - The §10.6 fold-in (Phase 7 / Task #7) per-source rolling-hour cap
//!   rejects an over-budget batch with `rate_limited` before any
//!   per-object work.
//! - `GET /federation/v1/moves/backfill` walks the §12.3 chain for a
//!   known key, paginates by `(created_at, canonical_hash)`, and
//!   returns `unknown_chain` for a key this instance has never seen.
//!
//! Cross-instance registration (§13) Layer-1 coverage is not in this
//! file: the §13 complete path runs `webauthn-rs`'s
//! `finish_passkey_registration`, which requires a real browser-side
//! attestation. The same constraint that forces the bypass routes for
//! ordinary signup applies here — Layer-0 unit tests in
//! `federation/registration.rs` cover the §13.2 constant pins and the
//! hex-decode helper; the wire-level happy path is covered by the
//! existing handler tests + the Layer-2 smoke suite (which speaks real
//! WebAuthn end-to-end).

#![cfg(feature = "test-auth")]

mod common;

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use prismoire_server::federation::moves::{
    MAX_CLOCK_SKEW_MS, MAX_MOVE_BATCH, MAX_MOVE_OBJECTS_PER_HOUR,
};
use prismoire_server::signing::sign_move_with_key;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};

// ---------------------------------------------------------------------------
// Wire-format helpers (mirrored from `phase5` since the WireFormat
// `{ "p", "s" }` shape is the same for any signed-object class).
// ---------------------------------------------------------------------------

/// Encode a §6.3 WireFormat `{ "p", "s" }` blob from a (payload, sig).
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

/// Build the `POST /federation/v1/moves` body: `{ "moves": [bstr, ...] }`.
fn encode_moves_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("moves".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + wires.iter().map(|w| w.len()).sum::<usize>());
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// Decode `{ "results": [{ canonical_hash, status, reason? }, …] }` →
/// `Vec<(hash, status, reason)>`.
fn parse_results_body(body: &[u8]) -> Vec<([u8; 32], String, Option<String>)> {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("results body is not a map");
    };
    let results = m
        .into_iter()
        .find_map(|(k, v)| match k {
            Value::Text(t) if t == "results" => Some(v),
            _ => None,
        })
        .expect("missing `results` field");
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

/// Decode the §12.3 backfill body
/// `{ "objects": [bstr, …], "next_cursor"?: bstr, "complete": bool }`.
struct BackfillBody {
    objects: Vec<Vec<u8>>,
    next_cursor: Option<Vec<u8>>,
    complete: bool,
}

fn parse_backfill_body(body: &[u8]) -> BackfillBody {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("backfill body is not a map");
    };
    let mut objects: Vec<Vec<u8>> = Vec::new();
    let mut next_cursor: Option<Vec<u8>> = None;
    let mut complete: Option<bool> = None;
    for (k, v) in m {
        let Value::Text(name) = k else {
            continue;
        };
        match (name.as_str(), v) {
            ("objects", Value::Array(arr)) => {
                for item in arr {
                    let Value::Bytes(b) = item else {
                        panic!("object entry not bstr");
                    };
                    objects.push(b);
                }
            }
            ("next_cursor", Value::Bytes(b)) => next_cursor = Some(b),
            ("complete", Value::Bool(b)) => complete = Some(b),
            _ => {}
        }
    }
    BackfillBody {
        objects,
        next_cursor,
        complete: complete.expect("complete field"),
    }
}

/// Pull the `error` field from a request-level 400 body.
fn parse_error_body(body: &[u8]) -> String {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("error body is not a map");
    };
    for (k, v) in m {
        if let (Value::Text(t), Value::Text(s)) = (&k, v)
            && t == "error"
        {
            return s;
        }
    }
    panic!("missing `error` field");
}

// ---------------------------------------------------------------------------
// Test-side move-signing helpers
// ---------------------------------------------------------------------------

/// Generate a fresh Ed25519 keypair for a synthetic federated user K.
fn fresh_user_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Current wall clock in Unix ms. Matches the receiver's `now_ms`
/// source so a move minted "now" sits comfortably inside `MAX_CLOCK_SKEW`.
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Mint a signed Move payload from K, declaring `from_domain` → `to_domain`
/// with the given `created_at_ms` and optional `prior_move_hash`. Returns
/// the (canonical_hash, wire-bytes) so the test can assert on the hash and
/// send the wire-bytes verbatim.
fn mint_move(
    user_key: &SigningKey,
    from_key: &[u8; 32],
    from_domain: &str,
    to_key: &[u8; 32],
    to_domain: &str,
    created_at_ms: u64,
    prior: Option<&[u8; 32]>,
) -> ([u8; 32], Vec<u8>) {
    let signed = sign_move_with_key(
        user_key,
        from_key,
        from_domain,
        to_key,
        to_domain,
        created_at_ms,
        prior,
    );
    let wire = encode_wire(&signed.payload, &signed.signature);
    (signed.canonical_hash, wire)
}

// ---------------------------------------------------------------------------
// DB-introspection helpers (assert the projections that `apply_one_move`
// writes — these are the read paths the rest of the server consults).
// ---------------------------------------------------------------------------

async fn read_user_home(db: &SqlitePool, user_key: &[u8; 32]) -> Option<(Vec<u8>, String, i64)> {
    let key: &[u8] = user_key.as_slice();
    sqlx::query!(
        "SELECT current_move_hash AS \"current_move_hash!: Vec<u8>\", \
                current_home_domain AS \"current_home_domain!: String\", \
                current_created_at AS \"current_created_at!: i64\" \
         FROM user_homes WHERE user_key = ?",
        key,
    )
    .fetch_optional(db)
    .await
    .expect("query user_homes")
    .map(|r| {
        (
            r.current_move_hash,
            r.current_home_domain,
            r.current_created_at,
        )
    })
}

async fn count_user_moves(db: &SqlitePool, user_key: &[u8; 32]) -> i64 {
    let key: &[u8] = user_key.as_slice();
    sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"n!: i64\" FROM user_moves WHERE user_key = ?",
        key,
    )
    .fetch_one(db)
    .await
    .expect("count user_moves")
}

async fn signed_object_present(db: &SqlitePool, canonical_hash: &[u8; 32]) -> bool {
    let h: &[u8] = canonical_hash.as_slice();
    sqlx::query_scalar!(
        "SELECT 1 AS \"n!: i64\" FROM signed_objects \
         WHERE canonical_hash = ? AND payload IS NOT NULL LIMIT 1",
        h,
    )
    .fetch_optional(db)
    .await
    .expect("query signed_objects")
    .is_some()
}

// ---------------------------------------------------------------------------
// §12.1 push handler — happy path
// ---------------------------------------------------------------------------

/// Done-when (1): a chain-grounded move from active-peer A applies on B,
/// the canonical bytes land in `signed_objects`, the chain row lands in
/// `user_moves`, and `user_homes` reflects the new home.
#[tokio::test]
async fn move_push_applies_and_projects_into_user_homes_and_user_moves() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    // No prior_move_hash — this is the user's first move ever.
    let created = now_ms();
    let (canonical_hash, wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        created,
        None,
    );

    let body = encode_moves_body(&[wire]);
    let (status, body_bytes) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/moves",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "push accepted");

    let results = parse_results_body(&body_bytes);
    assert_eq!(results.len(), 1, "one result per move");
    assert_eq!(results[0].0, canonical_hash);
    assert_eq!(results[0].1, "applied");
    assert_eq!(results[0].2, None, "no reason on `applied`");

    // signed_objects holds the canonical bytes.
    assert!(
        signed_object_present(&b.state.db, &canonical_hash).await,
        "signed_objects has the move payload"
    );

    // user_moves projects exactly one chain row for K.
    assert_eq!(
        count_user_moves(&b.state.db, &user_pub).await,
        1,
        "exactly one user_moves row"
    );

    // user_homes resolves to the move's `to_instance` / `to_instance_key`.
    let home = read_user_home(&b.state.db, &user_pub)
        .await
        .expect("user_homes row created");
    assert_eq!(
        home.0,
        canonical_hash.to_vec(),
        "home points at this move's hash"
    );
    assert_eq!(
        home.1, b.state.instance_domain,
        "home_domain copied verbatim"
    );
    assert_eq!(home.2, created as i64, "created_at copied verbatim");
}

// ---------------------------------------------------------------------------
// §12.7 MAX_CLOCK_SKEW gate
// ---------------------------------------------------------------------------

/// Done-when (2): a future-dated move outside `MAX_CLOCK_SKEW_MS` is
/// rejected with `skew_exceeded` and is NOT persisted (neither in
/// `signed_objects` nor in any §12 projection).
#[tokio::test]
async fn move_push_with_skew_is_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    // 2× the cap into the future — well past any plausible legit drift.
    let far_future = now_ms() + MAX_CLOCK_SKEW_MS * 2;
    let (canonical_hash, wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        far_future,
        None,
    );

    let body = encode_moves_body(&[wire]);
    let (status, body_bytes) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/moves",
        &body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "request-level OK; per-object reject"
    );

    let results = parse_results_body(&body_bytes);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, canonical_hash);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("skew_exceeded"));

    // Nothing landed.
    assert!(!signed_object_present(&b.state.db, &canonical_hash).await);
    assert_eq!(count_user_moves(&b.state.db, &user_pub).await, 0);
    assert!(read_user_home(&b.state.db, &user_pub).await.is_none());
}

// ---------------------------------------------------------------------------
// §12.4 latest-wins resolution
// ---------------------------------------------------------------------------

/// Done-when (3): after applying a newer move, an older move for the
/// same K is `superseded` — the older chain row is persisted (chain
/// evidence per §12.5) but `user_homes` keeps the newer entry.
#[tokio::test]
async fn older_move_after_newer_is_superseded() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();

    // First push: newer move (now). This applies and pins user_homes.
    let newer_ts = now_ms();
    let (newer_hash, newer_wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        newer_ts,
        None,
    );
    let body = encode_moves_body(&[newer_wire]);
    let (status, body_bytes) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/moves",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let r = parse_results_body(&body_bytes);
    assert_eq!(r[0].1, "applied");

    // Second push: an older move (60 seconds earlier). §12.4 latest-wins
    // says this one loses — `superseded`. The chain row still lands in
    // `user_moves` so §12.3 backfill can serve both branches of the fork.
    let older_ts = newer_ts.saturating_sub(60_000);
    let (older_hash, older_wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        older_ts,
        None,
    );
    let body = encode_moves_body(&[older_wire]);
    let (status, body_bytes) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/moves",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let r = parse_results_body(&body_bytes);
    assert_eq!(r[0].0, older_hash);
    assert_eq!(r[0].1, "superseded");

    // user_homes still pins the newer move.
    let home = read_user_home(&b.state.db, &user_pub)
        .await
        .expect("user_homes still populated");
    assert_eq!(
        home.0,
        newer_hash.to_vec(),
        "user_homes pinned to newer move's hash"
    );
    assert_eq!(home.2, newer_ts as i64);

    // user_moves carries both rows — §12.5 chain evidence.
    assert_eq!(
        count_user_moves(&b.state.db, &user_pub).await,
        2,
        "both newer and superseded land in user_moves"
    );
    assert!(signed_object_present(&b.state.db, &newer_hash).await);
    assert!(signed_object_present(&b.state.db, &older_hash).await);
}

// ---------------------------------------------------------------------------
// §12.1 chain-grounding → deferred
// ---------------------------------------------------------------------------

/// Done-when (4): a move whose `prior_move_hash` predecessor is not
/// present locally returns `deferred` — Phase 7 ships the one-shot
/// status; Phase 8 adds the pending-validation buffer + autonomous
/// backfill issuance. Critically: the deferred move is NOT persisted
/// (neither `signed_objects` nor `user_moves` nor `user_homes`).
#[tokio::test]
async fn move_with_missing_prior_is_deferred_and_not_persisted() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();

    // Concoct a synthetic prior-hash that B has definitely never seen
    // (we never push a predecessor). SHA-256 of a known-unique nonce
    // gives us a 32-byte value with no chance of accidental collision.
    let fake_prior: [u8; 32] = Sha256::digest(b"phase7-test-no-such-predecessor").into();

    let (canonical_hash, wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        now_ms(),
        Some(&fake_prior),
    );
    let body = encode_moves_body(&[wire]);
    let (status, body_bytes) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/moves",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let results = parse_results_body(&body_bytes);
    assert_eq!(results[0].0, canonical_hash);
    assert_eq!(results[0].1, "deferred");
    assert_eq!(results[0].2, None);

    // Nothing persisted.
    assert!(!signed_object_present(&b.state.db, &canonical_hash).await);
    assert_eq!(count_user_moves(&b.state.db, &user_pub).await, 0);
    assert!(read_user_home(&b.state.db, &user_pub).await.is_none());
}

// ---------------------------------------------------------------------------
// Request-level rejects: batch_too_large, rate_limited
// ---------------------------------------------------------------------------

/// `batch_too_large`: a push with `MAX_MOVE_BATCH + 1` entries is
/// rejected at request-level (single `{"error": "batch_too_large"}`
/// body, no per-object results). This guards against a hostile peer
/// trying to amplify per-batch DB write pressure.
#[tokio::test]
async fn move_push_batch_too_large_rejected_with_error_body() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();

    // MAX + 1 fresh moves. Each one needs a distinct user key because
    // `user_homes` is keyed on K and we want to keep the cost minimal —
    // but the handler rejects at the batch-size check before any per-
    // object work, so the actual key contents are immaterial. Reuse one
    // key across all entries; the request-level reject fires first.
    let user = fresh_user_key();
    let mut wires = Vec::with_capacity(MAX_MOVE_BATCH + 1);
    for i in 0..=MAX_MOVE_BATCH {
        // Vary `created_at` by 1 ms per entry so the canonical bytes
        // differ across entries (otherwise every move shares a hash
        // and a hypothetical future "batch-size after dedup" change
        // would mask this test).
        let ts = now_ms() + i as u64;
        let (_h, wire) = mint_move(
            &user,
            &from_key,
            &a.state.instance_domain,
            &to_key,
            &b.state.instance_domain,
            ts,
            None,
        );
        wires.push(wire);
    }
    let body = encode_moves_body(&wires);
    let (status, body_bytes) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/moves",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&body_bytes), "batch_too_large");
}

/// `rate_limited`: a push whose batch size + already-consumed budget
/// exceeds `MAX_MOVE_OBJECTS_PER_HOUR` is rejected at request-level.
/// Pre-fill the limiter via a separate push to the same peer, then
/// send one more move and assert the whole batch is rejected.
#[tokio::test]
async fn move_push_rate_limited_when_budget_exhausted() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Drive the limiter directly to one-under-budget. The handler
    // routes a real batch through this exact instance, so consuming it
    // here counts against the same source-keyed window. Filling via
    // `check_and_count` (true → counter incremented) is the same
    // operation the handler performs on inbound.
    let sender = *a.state.instance_key.public_bytes();
    let admitted = b
        .state
        .move_rate_limiter
        .check_and_count(sender, MAX_MOVE_OBJECTS_PER_HOUR);
    assert!(admitted, "pre-fill should fit within the empty window");

    // Now send one more move. Budget is exhausted → whole-batch reject.
    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    let (canonical_hash, wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        now_ms(),
        None,
    );
    let body = encode_moves_body(&[wire]);
    let (status, body_bytes) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/moves",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&body_bytes), "rate_limited");

    // Nothing landed.
    assert!(!signed_object_present(&b.state.db, &canonical_hash).await);
    assert_eq!(count_user_moves(&b.state.db, &user_pub).await, 0);
}

// ---------------------------------------------------------------------------
// §12.3 backfill
// ---------------------------------------------------------------------------

/// Done-when (5): `GET /federation/v1/moves/backfill?key=<hex>` walks
/// the §12.3 chain for a key that has at least one accepted move.
/// Single-page round-trip: one applied move → one object in the body,
/// `complete: true`, no `next_cursor`.
#[tokio::test]
async fn move_backfill_returns_chain_for_known_key() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Seed B with one applied move via the §12.1 push path.
    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    let (move_hash, wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        now_ms(),
        None,
    );
    let push_body = encode_moves_body(std::slice::from_ref(&wire));
    let (status, _) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/moves",
        &push_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Now A asks B for the chain. The signed envelope is over the
    // *path-without-query*; we dispatch against the query-bearing URI
    // so the `Query` extractor sees it. See `send_envelope_signed_split`.
    let key_hex: String = user_pub.iter().map(|b| format!("{b:02x}")).collect();
    let path = "/federation/v1/moves/backfill";
    let uri = format!("{path}?key={key_hex}");
    let (status, body_bytes) = common::federation::send_envelope_signed_split(
        &harness,
        "a",
        "b",
        Method::GET,
        path,
        &uri,
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "backfill returns OK");

    let parsed = parse_backfill_body(&body_bytes);
    assert_eq!(parsed.objects.len(), 1, "one object in the chain");
    assert!(parsed.complete, "single-page response is complete");
    assert!(parsed.next_cursor.is_none(), "no next_cursor when complete");

    // The returned object's wire bytes hash to the same canonical hash
    // we computed at mint time (re-derive: pop the payload back out and
    // SHA-256 it — `encode_signed_object` puts the canonical payload in
    // the `p` field).
    let v: Value = ciborium::de::from_reader(parsed.objects[0].as_slice()).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("object not a map");
    };
    let payload = m
        .into_iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(t), Value::Bytes(b)) if t == "p" => Some(b),
            _ => None,
        })
        .expect("payload field");
    let got_hash: [u8; 32] = Sha256::digest(&payload).into();
    assert_eq!(
        got_hash, move_hash,
        "returned payload re-hashes to move hash"
    );
}

/// Done-when (6): backfill for a key this instance has never seen
/// returns `unknown_chain` (request-level 400). Distinguishes
/// "never-moved key" from "you have everything we have" (the latter
/// returns `complete: true` mid-walk).
#[tokio::test]
async fn move_backfill_returns_unknown_chain_for_never_seen_key() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // A key whose owner has never pushed a move through B.
    let stranger = fresh_user_key();
    let key_hex: String = stranger
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let path = "/federation/v1/moves/backfill";
    let uri = format!("{path}?key={key_hex}");
    let (status, body_bytes) = common::federation::send_envelope_signed_split(
        &harness,
        "a",
        "b",
        Method::GET,
        path,
        &uri,
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&body_bytes), "unknown_chain");
}
