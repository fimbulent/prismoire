#![cfg(feature = "test-auth")]
//! Status-object federation integration tests (§16 / §17 / §18).
//!
//! Consolidates the Phase-11 single-hop reception suite and the
//! Phase-11.5 multi-hop gossip suite into the one protocol surface they
//! share: signed status objects (user-status, thread-status, reports)
//! flowing between instances, authority always bound to the
//! subject/thread's resolved **home** pubkey rather than the transport
//! sender. Sections:
//!
//! - **§16.1 user-status push (receive).** An active peer that is the
//!   subject's home-at-`created_at` gets `applied` and the
//!   `user_statuses` projection flips. A `signing_instance` that doesn't
//!   match the sender's recorded domain is `rejected/unauthorized_signer`;
//!   a subject with no local home record is `rejected/unknown_subject_home`.
//!   §16.3 by-hash serves a stored object and reports an unheld hash as
//!   `missing`.
//! - **§17.1 thread-status push (receive).** The thread's home gets
//!   `applied`, the §17.4 mirror drives `threads.locked`; a thread we
//!   have no local `thread-create` for is `deferred`.
//! - **§18.1 reports push (receive + produce).** A report from the
//!   reporter's home against a locally-hosted author is `applied` and
//!   queued in `federated_reports`; a re-push of the same `(post_id,
//!   reporter)` is `duplicate`; a target we don't host is
//!   `rejected/wrong_recipient`. The producer (`dispatch_local_report`)
//!   federates a report only when the target author is homed on a peer —
//!   a locally-authored post stays in the local admin queue.
//! - **§16.5 / §17.5 / §18.5 per-peer rate limit.** Once a peer exceeds
//!   the per-minute ceiling, further pushes are shed with `429` before any
//!   per-object work.
//! - **§16.2 / §17.2 selective multi-hop gossip.** A status originated at
//!   a subject/thread's home A reaches a non-adjacent *interested* peer C
//!   over the §7.5 forwarder (A → B → C); the bloom filter, not mere
//!   adjacency, gates delivery; and a forwarder that re-signs with its own
//!   key is `rejected/invalid_signature`.
//! - **Producer locality gate.** Admin ban / lock against a target homed
//!   on another instance is `403 remote_moderation_target`.
//!
//! Layer-0 invariants (status-tag round-trip, body-decoder edge cases)
//! live in the in-module `#[cfg(test)]` blocks of the handler modules.
//!
//! Convergence-driven relay scenarios use the [`settle`] harness driver
//! rather than the old `poll_until` waits: `settle` round-robins the
//! trust-graph rebuild, an inline `frontier_fanout_once` pass, and the
//! outbound drain across all instances until quiescent, so a multi-hop
//! relay lands deterministically with no spawn-loop race.

mod common;

use std::time::Duration;

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use rand::rngs::OsRng;
use serde_json::json;
use sqlx::SqlitePool;
use uuid::Uuid;

use prismoire_server::federation::bloom::BloomFilter;
use prismoire_server::federation::frontier::{FilterSpec, FrontierAnnounce};
use prismoire_server::federation::push_rate_limit::USER_STATUS_RPM_PER_PEER;
use prismoire_server::federation::reports::dispatch_local_report;
use prismoire_server::federation::routing::Mode;
use prismoire_server::federation::thread_status::dispatch_local_thread_status;
use prismoire_server::federation::user_status::dispatch_local_user_status;
use prismoire_server::signed::{ReportReason, ThreadStatusKind, UserStatusKind};
use prismoire_server::signing::{
    SigningOutput, sign_profile_revision_with_key, sign_report_with_key,
    sign_thread_create_with_key, sign_thread_status_with_key, sign_user_status_with_key,
};

use common::federation::{
    MultiInstanceHarness, establish_active_peering, send_envelope_signed, settle,
};
use common::{body_json, json_request, send, setup_admin, signup_as};

// ---------------------------------------------------------------------------
// Body / response helpers
// ---------------------------------------------------------------------------

/// Pack signed objects into the `{ "objects": [bstr, ...] }` push body
/// shared by all three status push routes.
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

/// Decode the `{ "results": [...] }` per-object shape into a flat vec of
/// `(canonical_hash, status, reason?)`.
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

/// Decode the by-hash `{ "objects": [...], "missing": [...] }` shape into
/// the count of returned objects and the list of missing hashes.
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
         VALUES (?, 'status fixture thread', ?, 'general', ?)",
        id_text,
        author_id,
        home_slice,
    )
    .execute(db)
    .await
    .expect("insert thread");
}

/// Build a §8.3 `FrontierAnnounce` whose `visible_filter` carries
/// `interested_keys`. The content filter is the gate for both the §16
/// user-status OR-filter (`visible || expansion`) and the §17
/// thread-status filter (`visible`), so populating it alone makes the
/// announcer interested in both classes keyed on those bytes.
/// `expansion_filter` is a real but empty bloom.
fn announce_with_visible_keys(interested_keys: &[&[u8; 32]]) -> FrontierAnnounce {
    let cap = interested_keys.len().max(1) as u64;
    let mut content = BloomFilter::new_empty(7, 1024, cap, 0.01).expect("build content filter");
    for k in interested_keys {
        content.insert(k.as_slice());
    }
    let edge = BloomFilter::new_empty(7, 1024, 1, 0.01).expect("build edge filter");
    FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: FilterSpec::from_bloom(&content),
        expansion_filter: FilterSpec::from_bloom(&edge),
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
}

/// User-status projection string for `subject` on `db`, if any.
async fn user_status_for(db: &SqlitePool, subject: &[u8; 32]) -> Option<String> {
    let subj: &[u8] = subject.as_slice();
    sqlx::query!("SELECT status FROM user_statuses WHERE subject = ?", subj)
        .fetch_optional(db)
        .await
        .expect("query user_statuses")
        .map(|r| r.status)
}

/// Decode a 64-char lowercase hex string into raw 32-byte form — recovers
/// the Ed25519 public key from a [`Session`](common::Session)`.public_key_hex`
/// so a `setup_admin` / `signup_as` user's pubkey can drive the status
/// surface (which keys on raw pubkeys, not user ids).
fn hex32(s: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect();
    bytes.as_slice().try_into().expect("32 bytes")
}

/// Push one signed content object `from`→`to` over `/federation/v1/content`
/// and assert it lands `applied`. Profiles and thread-creates share the
/// `{ "objects": [WireFormat] }` push body with the status routes, so
/// [`encode_push_body`] round-trips here too; [`parse_results`] reads the
/// §10.1 per-object status tag back.
async fn push_content_applied(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    signed: &SigningOutput,
) {
    let (status, resp) = send_envelope_signed(
        harness,
        from,
        to,
        Method::POST,
        "/federation/v1/content",
        &encode_push_body(&[signed]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "content push not 200: {resp:?}");
    let results = parse_results(&resp);
    assert_eq!(
        results[0].1, "applied",
        "content push not applied: {:?}",
        results[0].2
    );
}

/// Project a federated user onto instance `to` by pushing their signed
/// profile from active-peer `from`. The §10 profile projection stamps
/// `home_instance = from` (the envelope sender), so the resulting `users`
/// row is exactly the "federated user homed at `from`" precondition the
/// status-receive home-resolution gates inspect — minted through the real
/// receive path rather than a raw INSERT.
async fn project_federated_user(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    key: &SigningKey,
    display_name: &str,
) {
    let profile =
        sign_profile_revision_with_key(key, display_name, "", None, 1_700_000_000_000, None);
    push_content_applied(harness, from, to, &profile).await;
}

/// Project a federated thread (author stub + thread-create) onto instance
/// `to` from active-peer `from`. The thread-create projection homes the
/// thread at `from` and auto-creates the `general` room if absent, so the
/// result is a real federated-mirror thread whose §17 home authority is
/// `from`.
async fn project_federated_thread(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    author_key: &SigningKey,
    thread_id: &Uuid,
    op_post_id: &Uuid,
) {
    project_federated_user(harness, from, to, author_key, "remote-author").await;
    let thread_create = sign_thread_create_with_key(
        author_key,
        thread_id,
        "general",
        "remote thread",
        None,
        op_post_id,
        1_700_000_000_000,
    );
    push_content_applied(harness, from, to, &thread_create).await;
}

// ---------------------------------------------------------------------------
// §16.1 user-status push (receive)
//
// Single-instance request/response tests: they assert on the handler
// response and the resulting projection, so no convergence driver is
// involved.
// ---------------------------------------------------------------------------

/// Happy path: A is the subject K's home-at-T (recorded on B as K's
/// `home_instance`). A pushes a `banned` user-status; B applies it and the
/// `user_statuses` projection reflects the ban.
#[tokio::test]
async fn user_status_push_from_home_applies() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Subject K — a federated user on B whose home is A, projected through
    // A's real profile push (home_instance = the pushing peer, A).
    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    project_federated_user(&harness, "a", "b", &k_key, "kara").await;

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

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    project_federated_user(&harness, "a", "b", &k_key, "kara").await;

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

/// §16.3 by-hash: a stored user-status comes back in `objects`; an unheld
/// hash is reported in `missing`.
#[tokio::test]
async fn user_status_by_hash_serves_stored_and_reports_missing() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    project_federated_user(&harness, "a", "b", &k_key, "kara").await;

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
// §17.1 thread-status push (receive)
// ---------------------------------------------------------------------------

/// Happy path: B hosts a federated thread whose home is A. A pushes a
/// `locked` thread-status; B applies it, the `thread_statuses` projection
/// records `locked`, and the §17.4 mirror sets `threads.locked = 1`.
#[tokio::test]
async fn thread_status_push_from_home_applies_and_mirrors_lock() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // A federated-mirror thread on B whose home is A: push the author stub +
    // thread-create from A so the projection homes the thread at A (the §17
    // authority) through the real receive path.
    let author_key = SigningKey::generate(&mut OsRng);
    let thread_uuid = Uuid::new_v4();
    let op_post_id = Uuid::new_v4();
    project_federated_thread(&harness, "a", "b", &author_key, &thread_uuid, &op_post_id).await;

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

/// A thread with no local `thread-create` (no `threads` row) is `deferred`
/// — reception-only, autonomous backfill is the documented follow-up.
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
// §18.1 reports push (receive)
// ---------------------------------------------------------------------------

/// Happy path: reporter R is hosted by A; target author T is local to B. A
/// pushes R's report against T's post; B queues it (`applied`). A re-push
/// of the same `(post_id, reporter)` is `duplicate`.
#[tokio::test]
async fn report_push_applies_then_dedups() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    // Target author T — a real local user on B (B is their home). Created
    // first, while B has no admin, then its server-held pubkey becomes the
    // report's target.
    let target = setup_admin(&b.router, "target").await;
    let t_pub = hex32(&target.public_key_hex);

    // Reporter R — federated user homed at A, projected via A's profile push.
    let r_key = SigningKey::generate(&mut OsRng);
    let r_pub: [u8; 32] = *r_key.verifying_key().as_bytes();
    project_federated_user(&harness, "a", "b", &r_key, "reporter").await;

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

    // Reporter R — federated user homed at A.
    let r_key = SigningKey::generate(&mut OsRng);
    project_federated_user(&harness, "a", "b", &r_key, "reporter").await;

    // Target T is also homed at A (not B), so B is not the recipient.
    let t_key = SigningKey::generate(&mut OsRng);
    let t_pub: [u8; 32] = *t_key.verifying_key().as_bytes();
    project_federated_user(&harness, "a", "b", &t_key, "target").await;

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
// §18.1 reports producer (origination): reporter's home → target's home
// ---------------------------------------------------------------------------

/// Producer happy path: a local reporter on A files a report against a
/// post authored by a user homed at B. `dispatch_local_report` signs with
/// the reporter's credential key and enqueues a point-to-point push to B;
/// once A's outbound queue drains, B has applied the report (a
/// `federated_reports` row keyed on `(post_id, reporter)` appears).
#[tokio::test]
async fn report_producer_dispatches_to_target_home() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pub = *a.state.instance_key.public_bytes();
    let b_pub = *b.state.instance_key.public_bytes();

    // Reporter R — a real local user on A. Reports are user-signed, so the
    // producer loads R's credential key through the normal active-key path;
    // `setup_admin` stores exactly that key, so the dispatched report is
    // signed as production would sign it (no synthetic key injection).
    let reporter = setup_admin(&a.router, "reporter").await;
    let r_pub = hex32(&reporter.public_key_hex);

    // Target author T — a real local user on B (B is their home).
    let target = setup_admin(&b.router, "target").await;
    let t_pub = hex32(&target.public_key_hex);

    // Minimal carve-out seed (the only state with no real-API producer): the
    // cross-instance mirror rows. A user that is local-with-a-server-held-key
    // on one instance AND federated on the other cannot be minted by a single
    // profile push — profiles always home at their arrival sender, and we
    // don't hold these server-generated private keys to re-sign one. So on A
    // we record T as federated-homed-at-B (so the producer federates), and on
    // B we record R as federated-homed-at-A (so the receiver's reporter-home
    // check passes). The function under test — `dispatch_local_report` plus
    // the real receive path — runs against these legitimate mirror rows.
    insert_user(&a.state.db, "target", &t_pub, Some(&b_pub)).await;
    insert_user(&b.state.db, "reporter", &r_pub, Some(&a_pub)).await;

    let post_id = Uuid::new_v4();
    dispatch_local_report(
        &a.state,
        &reporter.user_id,
        &post_id,
        &t_pub,
        ReportReason::Spam,
        Some("repeated unsolicited links"),
    )
    .await
    .expect("dispatch_local_report");

    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(2))
            .await,
        "A's outbound queue did not drain within 2s",
    );

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
    assert_eq!(count, 1, "B must have applied the dispatched report");
}

/// Producer no-op: when the reported post is authored by a *local* user,
/// there is nothing to federate — the local admin queue is the authority.
/// `dispatch_local_report` returns `Ok` without enqueuing, so the peer
/// never receives anything.
#[tokio::test]
async fn report_producer_no_dispatch_for_local_author() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Reporter R — a real local admin on A (stored credential key).
    let reporter = setup_admin(&a.router, "reporter").await;

    // Target author T — a real *local* user on A (home is A itself), created
    // through the real invite/signup path.
    let target = signup_as(&a.router, &reporter, "target").await;
    let t_pub = hex32(&target.public_key_hex);

    let post_id = Uuid::new_v4();
    dispatch_local_report(
        &a.state,
        &reporter.user_id,
        &post_id,
        &t_pub,
        ReportReason::Spam,
        None,
    )
    .await
    .expect("dispatch_local_report");

    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(2))
            .await,
        "A's outbound queue did not drain within 2s",
    );

    let post_id_db: Vec<u8> = post_id.as_bytes().to_vec();
    let count = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM federated_reports WHERE post_id = ?",
        post_id_db,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count reports");
    assert_eq!(count, 0, "a locally-authored post must not be federated");
}

// ---------------------------------------------------------------------------
// §16.5 / §17.5 / §18.5 per-peer per-minute rate limit
//
// One representative push route: the limiter is shared `PushRateLimiter`
// machinery, so the user-status case below pins the shed-on-`(N+1)`th
// behaviour for all three classes (the thread-status / reports routes wire
// the same limiter against `THREAD_STATUS_RPM_PER_PEER` /
// `REPORTS_RPM_PER_PEER`).
// ---------------------------------------------------------------------------

/// §16.5: once a peer exceeds `USER_STATUS_RPM_PER_PEER` requests inside
/// the window, further user-status pushes are shed with `429` before any
/// per-object work. Each push here is a well-formed (if `rejected`) object
/// that still returns `200` and burns one request token, so the `(N+1)`th
/// push is the one that trips the limiter.
#[tokio::test]
async fn user_status_push_rate_limited_per_peer() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    // Unknown subject → `rejected/unknown_subject_home`, but still a 200
    // that consumes a rate-limit token.
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

// ---------------------------------------------------------------------------
// §16.2 / §17.2 selective multi-hop gossip relay
//
// Convergence-driven: A originates at the home, the object must traverse
// the §7.5 forwarder to a non-adjacent interested peer. `settle` pumps the
// trust-graph rebuild + inline frontier fan-out + outbound drain across all
// instances until quiescent, replacing the old `poll_until` waits.
// ---------------------------------------------------------------------------

/// §16.2: A originates a `banned` user-status for subject S (homed at A). B
/// is adjacent to A and interested in S; C is adjacent only to B and also
/// interested. The status must traverse A → B → C and flip C's
/// `user_statuses` projection, proving the §7.5 forwarder relays status
/// objects to a non-adjacent interested peer.
#[tokio::test]
async fn user_status_relays_to_non_adjacent_interested_peer() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "b", "c").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let c = harness.instance("c");
    let a_pub = *a.state.instance_key.public_bytes();

    // Subject S — a federated user (home A) known to both B and C so the
    // §16.2 home resolution succeeds on each hop and the projection lands.
    //
    // Minimal carve-out seed (no real-API producer for this precondition):
    // S must be homed at A on *both* B and C, but C is not peered with A, so
    // a profile push can only reach C via the A→B→C content relay — which is
    // the very forwarder under test, and would re-home S at B on C (home =
    // arrival sender). Seeding S as the A-homed federated stub directly keeps
    // the test isolated to the status-relay path it asserts on.
    let s_key = SigningKey::generate(&mut OsRng);
    let s_pub: [u8; 32] = *s_key.verifying_key().as_bytes();
    insert_user(&b.state.db, "subj", &s_pub, Some(&a_pub)).await;
    insert_user(&c.state.db, "subj", &s_pub, Some(&a_pub)).await;

    // B announces interest in S to A; C announces interest in S to B. Each
    // announce records the downstream peer's frontier in the upstream's
    // `peer_frontiers`, so `peers_interested_in` returns the next hop for a
    // UserStatus keyed on S.
    let announce = announce_with_visible_keys(&[&s_pub]).encode();
    let (st, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "B → A announce must apply");
    let (st, _) = send_envelope_signed(
        &harness,
        "c",
        "b",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "C → B announce must apply");

    // A issues the ban as S's home authority and originates the fan-out.
    dispatch_local_user_status(
        &a.state,
        &s_pub,
        UserStatusKind::Banned,
        None,
        Some("ban evasion"),
    )
    .await
    .expect("dispatch_local_user_status");

    // Drive the A → B → C relay to quiescence: B must apply before
    // re-emitting, then C applies the relayed object.
    settle(&harness).await;

    assert_eq!(
        user_status_for(&c.state.db, &s_pub).await.as_deref(),
        Some("banned"),
        "forwarder did not relay the user-status to non-adjacent C",
    );
    // B (the relay) also has the projection — it had to apply before
    // re-emitting, confirming the tier-2 forward fired from B.
    assert_eq!(
        user_status_for(&b.state.db, &s_pub).await.as_deref(),
        Some("banned"),
        "relay B must apply the user-status before re-emitting",
    );
}

/// §17.2: A originates a `locked` thread-status for a thread it homes; B
/// and C host a federated mirror of that thread (home A) and announce
/// interest in the OP author (the §17.2 routing key). The lock must reach
/// the non-adjacent C and mirror into `threads.locked` (§17.4).
#[tokio::test]
async fn thread_status_relays_to_non_adjacent_interested_peer() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "b", "c").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let c = harness.instance("c");
    let a_pub = *a.state.instance_key.public_bytes();

    // OP author — the routing key. Generated once; same pubkey on every
    // instance. On A the author + thread are locally homed (so A may
    // issue); on B/C they are a federated mirror homed at A.
    //
    // Minimal carve-out seed (no real-API producer for this precondition):
    // the A-homed thread must already exist as a federated mirror on the
    // non-adjacent C, which only the A→B→C content relay (the forwarder under
    // test) could deliver — and that would re-home it at B on C. Seeding the
    // mirror rows directly keeps the test isolated to the §17 status relay.
    let author_key = SigningKey::generate(&mut OsRng);
    let author_pub: [u8; 32] = *author_key.verifying_key().as_bytes();
    let thread_uuid = Uuid::new_v4();

    let a_author = insert_user(&a.state.db, "auth", &author_pub, None).await;
    ensure_general_room(&a.state.db, &a_author).await;
    insert_thread(&a.state.db, &thread_uuid, &a_author, None).await;

    for inst in [b, c] {
        let author_id = insert_user(&inst.state.db, "auth", &author_pub, Some(&a_pub)).await;
        ensure_general_room(&inst.state.db, &author_id).await;
        insert_thread(&inst.state.db, &thread_uuid, &author_id, Some(&a_pub)).await;
    }

    // Interest keyed on the OP author pubkey: B → A, C → B.
    let announce = announce_with_visible_keys(&[&author_pub]).encode();
    let (st, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "B → A announce must apply");
    let (st, _) = send_envelope_signed(
        &harness,
        "c",
        "b",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "C → B announce must apply");

    dispatch_local_thread_status(
        &a.state,
        &thread_uuid,
        ThreadStatusKind::Locked,
        Some("off-topic"),
    )
    .await
    .expect("dispatch_local_thread_status");

    // Drive the A → B → C relay to quiescence; the §17.4 mirror on the
    // non-adjacent C proves the relay reached it.
    settle(&harness).await;

    let id_text = thread_uuid.to_string();
    let mirrored: bool = sqlx::query_scalar!(
        "SELECT locked AS \"locked: bool\" FROM threads WHERE id = ?",
        id_text,
    )
    .fetch_optional(&c.state.db)
    .await
    .expect("query threads on c")
    .unwrap_or(false);
    assert!(
        mirrored,
        "forwarder did not relay the thread-status lock to non-adjacent C",
    );
}

// ---------------------------------------------------------------------------
// Interest gate (negative)
// ---------------------------------------------------------------------------

/// A peer that announces a frontier *not* covering subject S receives
/// nothing when A originates a user-status for S — adjacency alone does not
/// earn delivery; the bloom filter is the gate.
#[tokio::test]
async fn user_status_not_forwarded_to_uninterested_peer() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Subject S — a federated user homed at A, projected via A's real profile
    // push (B is the sole downstream, so there is no relay to re-home it).
    let s_key = SigningKey::generate(&mut OsRng);
    let s_pub: [u8; 32] = *s_key.verifying_key().as_bytes();
    project_federated_user(&harness, "a", "b", &s_key, "subj").await;

    // B announces interest in some *other* key — its filter does not cover
    // S, so A's `peers_interested_in` must exclude B for S.
    let other_key = SigningKey::generate(&mut OsRng);
    let other_pub: [u8; 32] = *other_key.verifying_key().as_bytes();
    let announce = announce_with_visible_keys(&[&other_pub]).encode();
    let (st, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "B → A announce must apply");

    dispatch_local_user_status(
        &a.state,
        &s_pub,
        UserStatusKind::Banned,
        None,
        Some("ban evasion"),
    )
    .await
    .expect("dispatch_local_user_status");

    // Settle the harness to quiescence; if the gate held, B never projects
    // a status for S even after all outbound work has drained.
    settle(&harness).await;
    assert!(
        user_status_for(&b.state.db, &s_pub).await.is_none(),
        "uninterested peer B must not receive the user-status",
    );
}

// ---------------------------------------------------------------------------
// Auth flip under gossip (negative)
// ---------------------------------------------------------------------------

/// A forwarder that re-signs a user-status with its *own* key — rather than
/// relaying the home's signed bytes verbatim — is
/// `rejected/invalid_signature`. Under §16.2 the inner signature is
/// verified against the subject's resolved home pubkey (A), never the
/// transport sender (B), so B cannot forge authority for an A-homed subject
/// by signing fresh bytes.
#[tokio::test]
async fn forwarded_user_status_wrong_inner_signer_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Subject S is a real *local* user on A — so A resolves S's home to
    // itself and the authority pubkey is A's own instance key. We only need
    // S's pubkey here (B forges the inner signature with B's key), so a
    // `setup_admin` user supplies it without any key injection.
    let subj = setup_admin(&a.router, "subj").await;
    let s_pub = hex32(&subj.public_key_hex);

    // A real local user carries a §12.8 genesis `move` stamped at birth
    // (≈ now), so `resolve_subject_home_at_t` only finds S's self-home for a
    // `created_at` at or after that move. Sign the forged status at the
    // current wall clock so home-resolution lands on A (self) and the test
    // exercises the home-pubkey signature gate rather than tripping the
    // earlier `unknown_subject_home` no-move-before-`t` branch.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64;

    // B signs the user-status with B's *own* instance key but truthfully
    // labels `signing_instance` as B's domain. The label is consistent; the
    // only defect is that the inner signer is not S's home (A). The
    // home-pubkey signature check (step 5) must reject it before the
    // advisory domain cross-check (step 6) is even reached.
    let signed = sign_user_status_with_key(
        &b.state.instance_key,
        &s_pub,
        UserStatusKind::Banned,
        None,
        &b.state.instance_domain,
        Some("forged ban"),
        now_ms,
        None,
    );

    // B pushes its forged object straight to A. A homes S, so it resolves
    // the home pubkey = A and verifies the inner signature against it.
    let (status, body) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/user-status",
        &encode_push_body(&[&signed]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    let results = parse_results(&body);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("invalid_signature"));

    // And the forged bytes were not persisted.
    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let persisted = sqlx::query_scalar!(
        "SELECT 1 AS \"n!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_optional(&a.state.db)
    .await
    .expect("query signed_objects")
    .is_some();
    assert!(
        !persisted,
        "rejected forgery must not land in signed_objects",
    );
}

// ---------------------------------------------------------------------------
// Producer locality gate: admins moderate only locally-homed targets, so a
// local admin can never issue a status object for content homed elsewhere.
// ---------------------------------------------------------------------------

/// Banning a user homed on another instance is `403
/// remote_moderation_target`. (The suspend route shares this user-moderation
/// gate.)
#[tokio::test]
async fn admin_ban_remote_user_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "b", "a").await;
    let a = harness.instance("a");
    let admin = setup_admin(&a.router, "admin").await;

    // A federated user whose home is another instance (B) — projected onto A
    // through the real §10 profile-receive path, which stamps
    // home_instance = the pushing peer (B).
    let user_key = SigningKey::generate(&mut OsRng);
    let user_pub: [u8; 32] = *user_key.verifying_key().as_bytes();
    project_federated_user(&harness, "b", "a", &user_key, "remote").await;

    // Resolve the projected user's id for the admin route (raw SELECT).
    let user_pub_slice: &[u8] = user_pub.as_slice();
    let uid: String =
        sqlx::query_scalar!("SELECT id FROM users WHERE public_key = ?", user_pub_slice)
            .fetch_one(&a.state.db)
            .await
            .expect("projected user id");

    let req = json_request(
        Method::POST,
        &format!("/api/admin/users/{uid}/ban"),
        Some(&admin.cookie),
        &json!({ "reason": "spam" }),
    );
    let resp = send(&a.router, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "remote_moderation_target");
}

/// Locking a thread homed on another instance is `403
/// remote_moderation_target`.
#[tokio::test]
async fn admin_lock_remote_thread_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "b", "a").await;
    let a = harness.instance("a");
    let admin = setup_admin(&a.router, "admin").await;

    // A thread homed on another instance (B) — author stub + thread-create
    // projected onto A through the real receive path, so A records
    // home_instance = B for the thread.
    let author_key = SigningKey::generate(&mut OsRng);
    let thread_uuid = Uuid::new_v4();
    let op_post_id = Uuid::new_v4();
    project_federated_thread(&harness, "b", "a", &author_key, &thread_uuid, &op_post_id).await;

    let req = json_request(
        Method::POST,
        &format!("/api/admin/threads/{thread_uuid}/lock"),
        Some(&admin.cookie),
        &json!({ "reason": "off-topic" }),
    );
    let resp = send(&a.router, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "remote_moderation_target");
}
