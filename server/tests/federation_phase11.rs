//! Phase-11 Layer-1 integration tests: §16 user-status, §17
//! thread-status, §18 reports — receive side.
//!
//! Pins the done-when criteria from `docs/federation-impl-plan.md`
//! Phase 11 against the real Axum router + DB + envelope middleware:
//!
//! - **§16.1 user-status push.** An active peer that is the subject's
//!   home-at-`created_at` gets `applied` and the `user_statuses`
//!   projection flips. A `signing_instance` that doesn't match the
//!   sender's recorded domain is `rejected/unauthorized_signer`; a
//!   subject with no local home record is
//!   `rejected/unknown_subject_home`.
//! - **§16.3 user-status by-hash.** A stored object's canonical bytes
//!   come back in `objects`; an unheld hash lands in `missing`.
//! - **§17.1 thread-status push.** The thread's home gets `applied`
//!   and the §17.4 mirror drives `threads.locked`. A thread we have no
//!   local `thread-create` for is `deferred` (reception-only —
//!   autonomous backfill is the documented follow-up).
//! - **§18.1 reports push.** A report from the reporter's home against
//!   a locally-hosted author is `applied` and queued in
//!   `federated_reports`; a re-push of the same `(post_id, reporter)`
//!   is `duplicate`; a target we don't host is
//!   `rejected/wrong_recipient`.
//!
//! Layer-0 invariants (status-tag round-trip, body-decoder edge cases)
//! live in the in-module `#[cfg(test)]` blocks of the three handler
//! modules.

#![cfg(feature = "test-auth")]

mod common;

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use prismoire_server::federation::push_rate_limit::{
    REPORTS_RPM_PER_PEER, THREAD_STATUS_RPM_PER_PEER, USER_STATUS_RPM_PER_PEER,
};
use prismoire_server::signed::{ReportReason, ThreadStatusKind, UserStatusKind};
use prismoire_server::signing::{
    SigningOutput, sign_report_with_key, sign_thread_status_with_key, sign_user_status_with_key,
};
use rand::rngs::OsRng;
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};

// ---------------------------------------------------------------------------
// Body / response helpers
// ---------------------------------------------------------------------------

/// Pack a single signed object's WireFormat into the `{ "objects":
/// [bstr, ...] }` push body shared by all three Phase-11 push routes.
fn encode_push_body(signed: &[&SigningOutput]) -> Vec<u8> {
    let arr: Vec<Value> = signed
        .iter()
        .map(|s| Value::Bytes(encode_wire(&s.payload, &s.signature)))
        .collect();
    let body = Value::Map(vec![(Value::Text("objects".into()), Value::Array(arr))]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&body, &mut buf).expect("ser objects body");
    buf
}

/// Encode a `{ "hashes": [bstr(32), ...] }` by-hash request body.
fn encode_hashes_body(hashes: &[[u8; 32]]) -> Vec<u8> {
    let arr: Vec<Value> = hashes.iter().map(|h| Value::Bytes(h.to_vec())).collect();
    let body = Value::Map(vec![(Value::Text("hashes".into()), Value::Array(arr))]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&body, &mut buf).expect("ser hashes body");
    buf
}

/// Encode a §6.3 WireFormat `{ "p", "s" }`.
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&m, &mut buf).expect("ser wire");
    buf
}

/// Decode the `{ "results": [...] }` per-object shape into a flat vec
/// of `(canonical_hash, status, reason?)`.
fn parse_results(body: &[u8]) -> Vec<([u8; 32], String, Option<String>)> {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("results body is not a map");
    };
    let results = m
        .into_iter()
        .find_map(|(k, v)| matches!(&k, Value::Text(t) if t == "results").then_some(v))
        .expect("missing `results`");
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

/// Decode the by-hash `{ "objects": [...], "missing": [...] }` shape
/// into the count of returned objects and the list of missing hashes.
fn parse_by_hash(body: &[u8]) -> (usize, Vec<[u8; 32]>) {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("by-hash body not a map");
    };
    let mut objects = 0usize;
    let mut missing: Vec<[u8; 32]> = Vec::new();
    for (k, val) in m {
        let Value::Text(name) = k else { continue };
        match (name.as_str(), val) {
            ("objects", Value::Array(a)) => objects = a.len(),
            ("missing", Value::Array(a)) => {
                missing = a
                    .into_iter()
                    .map(|e| match e {
                        Value::Bytes(b) => b.as_slice().try_into().expect("32 bytes"),
                        _ => panic!("missing entry not bstr"),
                    })
                    .collect();
            }
            _ => {}
        }
    }
    (objects, missing)
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Insert a `users` row with a known Ed25519 public key. `home` is the
/// recorded `home_instance`: `None` = local to this DB, `Some(key)` =
/// federated, home is `key`. Returns the generated UUID.
async fn insert_user(
    db: &SqlitePool,
    display_name: &str,
    pubkey: &[u8; 32],
    home: Option<&[u8; 32]>,
) -> String {
    let id = Uuid::new_v4().to_string();
    let skeleton = display_name.to_lowercase();
    let pubkey_slice: &[u8] = pubkey.as_slice();
    let signup = if home.is_some() { "federated" } else { "admin" };
    let home_slice: Option<&[u8]> = home.map(|h| h.as_slice());
    sqlx::query!(
        "INSERT INTO users (id, display_name, signup_method, public_key, \
                            display_name_skeleton, home_instance) \
         VALUES (?, ?, ?, ?, ?, ?)",
        id,
        display_name,
        signup,
        pubkey_slice,
        skeleton,
        home_slice,
    )
    .execute(db)
    .await
    .expect("insert user");
    id
}

/// Ensure the `general` room exists (idempotent).
async fn ensure_general_room(db: &SqlitePool, created_by: &str) {
    let exists: Option<String> =
        sqlx::query_scalar!("SELECT id FROM rooms WHERE id = 'general' LIMIT 1")
            .fetch_optional(db)
            .await
            .expect("room lookup");
    if exists.is_none() {
        sqlx::query!(
            "INSERT INTO rooms (id, slug, created_by) VALUES ('general', 'general', ?)",
            created_by,
        )
        .execute(db)
        .await
        .expect("insert room");
    }
}

/// Insert a `threads` row with caller-controlled `home_instance`.
/// `home = Some(key)` marks the thread as hosted by a remote instance
/// (the §17 home authority); `None` = locally hosted.
async fn insert_thread(
    db: &SqlitePool,
    thread_id: &Uuid,
    author_id: &str,
    home: Option<&[u8; 32]>,
) {
    let id_text = thread_id.to_string();
    let home_slice: Option<&[u8]> = home.map(|h| h.as_slice());
    sqlx::query!(
        "INSERT INTO threads (id, title, author, room, home_instance) \
         VALUES (?, 'phase 11 fixture thread', ?, 'general', ?)",
        id_text,
        author_id,
        home_slice,
    )
    .execute(db)
    .await
    .expect("insert thread");
}

// ---------------------------------------------------------------------------
// §16.1 user-status push
// ---------------------------------------------------------------------------

/// Happy path: A is the subject K's home-at-T (recorded on B as K's
/// `home_instance`). A pushes a `banned` user-status; B applies it and
/// the `user_statuses` projection reflects the ban.
#[tokio::test]
async fn user_status_push_from_home_applies() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pub = *a.state.instance_key.public_bytes();

    // Subject K — a federated user on B whose home is A.
    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    insert_user(&b.state.db, "kara", &k_pub, Some(&a_pub)).await;

    let signed = sign_user_status_with_key(
        &a.state.instance_key,
        &k_pub,
        UserStatusKind::Banned,
        None,
        &a.state.instance_domain,
        Some("ban evasion"),
        1_700_000_000_000,
        None,
    );

    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/user-status",
        &encode_push_body(&[&signed]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    let results = parse_results(&body);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, signed.canonical_hash);
    assert_eq!(results[0].1, "applied", "reason: {:?}", results[0].2);

    // Projection flipped to `banned`.
    let subject_slice: &[u8] = k_pub.as_slice();
    let row = sqlx::query!(
        "SELECT status, reason FROM user_statuses WHERE subject = ?",
        subject_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("user_statuses row");
    assert_eq!(row.status, "banned");
    assert_eq!(row.reason.as_deref(), Some("ban evasion"));
}

/// A `signing_instance` that doesn't match the sender's recorded
/// `peers.instance_domain` is `rejected/unauthorized_signer` even when
/// every other gate (signature, home) would pass.
#[tokio::test]
async fn user_status_push_signing_instance_mismatch_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pub = *a.state.instance_key.public_bytes();

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    insert_user(&b.state.db, "kara", &k_pub, Some(&a_pub)).await;

    let signed = sign_user_status_with_key(
        &a.state.instance_key,
        &k_pub,
        UserStatusKind::Suspended,
        Some(1_800_000_000_000),
        "evil.example", // does not match A's recorded domain
        None,
        1_700_000_000_000,
        None,
    );

    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/user-status",
        &encode_push_body(&[&signed]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    let results = parse_results(&body);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("unauthorized_signer"));
}

/// A subject with no local home record at all → `unknown_subject_home`.
#[tokio::test]
async fn user_status_push_unknown_subject_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    // K is never inserted on B, so its home cannot be resolved.
    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    let signed = sign_user_status_with_key(
        &a.state.instance_key,
        &k_pub,
        UserStatusKind::Banned,
        None,
        &a.state.instance_domain,
        None,
        1_700_000_000_000,
        None,
    );

    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/user-status",
        &encode_push_body(&[&signed]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    let results = parse_results(&body);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("unknown_subject_home"));
}

/// §16.3 by-hash: a stored user-status comes back in `objects`; an
/// unheld hash is reported in `missing`.
#[tokio::test]
async fn user_status_by_hash_serves_stored_and_reports_missing() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pub = *a.state.instance_key.public_bytes();

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    insert_user(&b.state.db, "kara", &k_pub, Some(&a_pub)).await;

    let signed = sign_user_status_with_key(
        &a.state.instance_key,
        &k_pub,
        UserStatusKind::Banned,
        None,
        &a.state.instance_domain,
        None,
        1_700_000_000_000,
        None,
    );
    let (push_status, _) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/user-status",
        &encode_push_body(&[&signed]),
    )
    .await;
    assert_eq!(push_status, StatusCode::OK);

    let unheld = [0xABu8; 32];
    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/user-status/by-hash",
        &encode_hashes_body(&[signed.canonical_hash, unheld]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    let (objects, missing) = parse_by_hash(&body);
    assert_eq!(objects, 1, "the stored user-status should be served");
    assert_eq!(missing, vec![unheld], "the unheld hash should be missing");
}

// ---------------------------------------------------------------------------
// §17.1 thread-status push
// ---------------------------------------------------------------------------

/// Happy path: B hosts a federated thread whose home is A. A pushes a
/// `locked` thread-status; B applies it, the `thread_statuses`
/// projection records `locked`, and the §17.4 mirror sets
/// `threads.locked = 1`.
#[tokio::test]
async fn thread_status_push_from_home_applies_and_mirrors_lock() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pub = *a.state.instance_key.public_bytes();

    // A local author + room so the threads FK holds, then a thread
    // whose home_instance is A.
    let author_key = SigningKey::generate(&mut OsRng);
    let author_pub: [u8; 32] = *author_key.verifying_key().as_bytes();
    let author_id = insert_user(&b.state.db, "auth", &author_pub, None).await;
    ensure_general_room(&b.state.db, &author_id).await;
    let thread_uuid = Uuid::new_v4();
    insert_thread(&b.state.db, &thread_uuid, &author_id, Some(&a_pub)).await;

    let signed = sign_thread_status_with_key(
        &a.state.instance_key,
        thread_uuid.as_bytes(),
        ThreadStatusKind::Locked,
        &a.state.instance_domain,
        Some("off-topic spiral"),
        1_700_000_000_000,
        None,
    );

    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/thread-status",
        &encode_push_body(&[&signed]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    let results = parse_results(&body);
    assert_eq!(results[0].1, "applied", "reason: {:?}", results[0].2);

    // §17.4 mirror: threads.locked flipped.
    let id_text = thread_uuid.to_string();
    let locked: bool = sqlx::query_scalar!(
        "SELECT locked AS \"locked: bool\" FROM threads WHERE id = ?",
        id_text,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("thread row");
    assert!(locked, "federated lock must mirror into threads.locked");
}

/// A thread with no local `thread-create` (no `threads` row) is
/// `deferred` — reception-only, autonomous backfill is the documented
/// follow-up.
#[tokio::test]
async fn thread_status_push_unknown_thread_deferred() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    let thread_uuid = Uuid::new_v4();
    let signed = sign_thread_status_with_key(
        &a.state.instance_key,
        thread_uuid.as_bytes(),
        ThreadStatusKind::Locked,
        &a.state.instance_domain,
        None,
        1_700_000_000_000,
        None,
    );

    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/thread-status",
        &encode_push_body(&[&signed]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    let results = parse_results(&body);
    assert_eq!(results[0].1, "deferred", "reason: {:?}", results[0].2);
}

// ---------------------------------------------------------------------------
// §18.1 reports push
// ---------------------------------------------------------------------------

/// Happy path: reporter R is hosted by A; target author T is local to
/// B. A pushes R's report against T's post; B queues it (`applied`).
/// A re-push of the same `(post_id, reporter)` is `duplicate`.
#[tokio::test]
async fn report_push_applies_then_dedups() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pub = *a.state.instance_key.public_bytes();

    // Reporter R — federated user homed at A.
    let r_key = SigningKey::generate(&mut OsRng);
    let r_pub: [u8; 32] = *r_key.verifying_key().as_bytes();
    insert_user(&b.state.db, "reporter", &r_pub, Some(&a_pub)).await;

    // Target author T — local user on B (B is their home).
    let t_key = SigningKey::generate(&mut OsRng);
    let t_pub: [u8; 32] = *t_key.verifying_key().as_bytes();
    insert_user(&b.state.db, "target", &t_pub, None).await;

    let post_id = Uuid::new_v4();
    let signed = sign_report_with_key(
        &r_key,
        post_id.as_bytes(),
        &t_pub,
        ReportReason::Spam,
        Some("repeated unsolicited links"),
        1_700_000_000_000,
    );

    // First push → applied + a federated_reports row.
    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/reports",
        &encode_push_body(&[&signed]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert_eq!(parse_results(&body)[0].1, "applied");

    let post_id_db: Vec<u8> = post_id.as_bytes().to_vec();
    let reporter_db: Vec<u8> = r_pub.to_vec();
    let count = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM federated_reports WHERE post_id = ? AND reporter = ?",
        post_id_db,
        reporter_db,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count reports");
    assert_eq!(count, 1);

    // Second push of the same (post_id, reporter) → duplicate, no new row.
    let (status2, body2) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/reports",
        &encode_push_body(&[&signed]),
    )
    .await;
    assert_eq!(status2, StatusCode::OK, "body: {body2:?}");
    assert_eq!(parse_results(&body2)[0].1, "duplicate");

    let count2 = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM federated_reports WHERE post_id = ? AND reporter = ?",
        post_id_db,
        reporter_db,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count reports");
    assert_eq!(count2, 1, "duplicate must not insert a second row");
}

/// A report whose `target_author` is not hosted by us is
/// `rejected/wrong_recipient` (§18.1) — reports only flow to the target
/// post's home.
#[tokio::test]
async fn report_push_wrong_recipient_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pub = *a.state.instance_key.public_bytes();

    let r_key = SigningKey::generate(&mut OsRng);
    let r_pub: [u8; 32] = *r_key.verifying_key().as_bytes();
    insert_user(&b.state.db, "reporter", &r_pub, Some(&a_pub)).await;

    // Target T is homed at A (not B), so B is not the recipient.
    let t_key = SigningKey::generate(&mut OsRng);
    let t_pub: [u8; 32] = *t_key.verifying_key().as_bytes();
    insert_user(&b.state.db, "target", &t_pub, Some(&a_pub)).await;

    let post_id = Uuid::new_v4();
    let signed = sign_report_with_key(
        &r_key,
        post_id.as_bytes(),
        &t_pub,
        ReportReason::RulesViolation,
        None,
        1_700_000_000_000,
    );

    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/reports",
        &encode_push_body(&[&signed]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    let results = parse_results(&body);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("wrong_recipient"));
}

// ---------------------------------------------------------------------------
// §16.5 / §17.5 / §18.5 per-peer per-minute rate limits
// ---------------------------------------------------------------------------

/// §16.5: once a peer exceeds `USER_STATUS_RPM_PER_PEER` requests inside
/// the window, further user-status pushes are shed with `429` before any
/// per-object work. Each push here is a well-formed (if `rejected`)
/// object that still returns `200` and burns one request token, so the
/// `(N+1)`th push is the one that trips the limiter.
#[tokio::test]
async fn user_status_push_rate_limited_per_peer() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    // Unknown subject → `rejected/unknown_subject_home`, but still a
    // 200 that consumes a rate-limit token.
    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    let signed = sign_user_status_with_key(
        &a.state.instance_key,
        &k_pub,
        UserStatusKind::Banned,
        None,
        &a.state.instance_domain,
        None,
        1_700_000_000_000,
        None,
    );
    let body = encode_push_body(&[&signed]);

    for i in 0..USER_STATUS_RPM_PER_PEER {
        let (status, b) = send_envelope_signed(
            &harness,
            "a",
            "b",
            Method::POST,
            "/federation/v1/user-status",
            &body,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "request {i} body: {b:?}");
    }

    let (status, _) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/user-status",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

/// §17.5: once a peer exceeds `THREAD_STATUS_RPM_PER_PEER` requests, the
/// thread-status route sheds with `429`. Unknown-thread pushes return a
/// `deferred` 200 and burn a token, so the `(N+1)`th trips the limiter.
#[tokio::test]
async fn thread_status_push_rate_limited_per_peer() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    let thread_uuid = Uuid::new_v4();
    let signed = sign_thread_status_with_key(
        &a.state.instance_key,
        thread_uuid.as_bytes(),
        ThreadStatusKind::Locked,
        &a.state.instance_domain,
        None,
        1_700_000_000_000,
        None,
    );
    let body = encode_push_body(&[&signed]);

    for i in 0..THREAD_STATUS_RPM_PER_PEER {
        let (status, b) = send_envelope_signed(
            &harness,
            "a",
            "b",
            Method::POST,
            "/federation/v1/thread-status",
            &body,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "request {i} body: {b:?}");
    }

    let (status, _) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/thread-status",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

/// §18.5: the reports route has the tightest ceiling
/// (`REPORTS_RPM_PER_PEER`) because the sender can vary `post_id` to
/// flood the moderation queue. Re-pushing the same report returns a
/// `duplicate` 200 and burns a token, so the `(N+1)`th push trips the
/// limiter.
#[tokio::test]
async fn report_push_rate_limited_per_peer() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pub = *a.state.instance_key.public_bytes();

    let r_key = SigningKey::generate(&mut OsRng);
    let r_pub: [u8; 32] = *r_key.verifying_key().as_bytes();
    insert_user(&b.state.db, "reporter", &r_pub, Some(&a_pub)).await;
    let t_key = SigningKey::generate(&mut OsRng);
    let t_pub: [u8; 32] = *t_key.verifying_key().as_bytes();
    insert_user(&b.state.db, "target", &t_pub, None).await;

    let post_id = Uuid::new_v4();
    let signed = sign_report_with_key(
        &r_key,
        post_id.as_bytes(),
        &t_pub,
        ReportReason::Spam,
        None,
        1_700_000_000_000,
    );
    let body = encode_push_body(&[&signed]);

    for i in 0..REPORTS_RPM_PER_PEER {
        let (status, b) = send_envelope_signed(
            &harness,
            "a",
            "b",
            Method::POST,
            "/federation/v1/reports",
            &body,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "request {i} body: {b:?}");
    }

    let (status, _) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/reports",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}
