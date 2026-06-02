#![cfg(feature = "test-auth")]
//! Cross-instance content-propagation integration tests (§10 / §10.4 / §10.5).
//!
//! Consolidates four formerly-separate phase files into the single
//! protocol surface they all exercise — signed content objects crossing
//! the instance boundary, their on-receipt erasure cascades, the
//! local-origin fanout wiring, the per-peer outbound queue that carries
//! them, and the pull-backfill backstop that heals partitions:
//!
//! - **§10.1 content receive path.** An active peer's
//!   `POST /federation/v1/content` stores canonical bytes for a `post-rev`
//!   in `signed_objects` with `applied`; on-receipt erasure cascades fire
//!   (`retract` NULLs the matching `post-rev` payload, `deactivate` NULLs
//!   every payload by the target user); replays return `duplicate`; a bad
//!   signature is `invalid_signature` and not persisted; a `trust-edge`
//!   on `/content` is `wrong_class`; an oversize blob is a per-object
//!   `object_too_large` reject that doesn't sink the rest of the batch;
//!   and request-level failures (malformed, empty batch, batch too large)
//!   400 with a single `{ error }` body.
//! - **§10.4 admin-rm precedence + advisory route.** An applied admin-rm
//!   projects into `admin_rm_authorities` and blocks subsequent
//!   `post-rev` for the same `post_id` with `admin_removed`; an admin-rm
//!   against a *locally hosted* user is `wrong_route`; a signing-instance
//!   mismatch is `unauthorized_signer`. `POST /admin-rm-report` queues an
//!   advisory when we host the target (deduped by `post_id`) and rejects
//!   `not_authoritative_home` when we don't.
//! - **§10 local-origin fanout.** The seven origin handlers
//!   (`create_thread` OP `post-rev` + `thread-create`, `create_reply`,
//!   edit, retract, profile update, admin-rm, deactivate) each invoke
//!   `forward_signed_object`, so the canonical bytes land on an interested
//!   peer's `signed_objects`.
//! - **§7.5 per-peer outbound queue.** Originate-while-disconnected then
//!   reconnect drains the backlog; scripted-503 retries back off until the
//!   inner transport recovers; a sustained flood past the per-peer object
//!   cap evicts drop-oldest while staying bounded.
//! - **§10.5 pull-backfill backstop.** `POST /backfill/by-hash` returns
//!   `410 Gone` carrying the §10.5.2 `authority` WireFormat for an erased
//!   row (plus the receiver-local `erased_at` and any same-batch available
//!   row carried along in `objects`); an unknown hash collapses to
//!   `200 OK` empty + `complete: true`; the §10.5.5 per-peer RPM gate
//!   fires `429` once a peer exhausts its minute budget.
//!
//! Layer-0 invariants (status-tag round-trip, body decoders, queue-state
//! caps/backoff/staleness, by-hash cursor round-trips) live in the
//! in-module `#[cfg(test)]` blocks in `src/federation/content.rs`,
//! `src/federation/outbound_queue.rs`, and `src/federation/backfill.rs`.
//!
//! These scenarios drive the per-peer outbound queue's deterministic
//! `wait_idle` drain hook directly (the function under test), so they do
//! not use the [`settle`](common::federation::settle) convergence driver
//! — there is no `frontier_fanout_loop` + poll race to replace here.

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::Request;
use prismoire_server::federation::backfill_rate_limit::BACKFILL_RPM_PER_PEER;
use prismoire_server::federation::bloom::BloomFilter;
use prismoire_server::federation::content::{MAX_CONTENT_BATCH, MAX_POSTREV_SIZE};
use prismoire_server::federation::frontier::{FilterSpec, FrontierAnnounce};
use prismoire_server::federation::outbound_queue::OutboundQueueConfig;
use prismoire_server::federation::routing::Mode;
use prismoire_server::signed::TrustStance;
use prismoire_server::signing::{
    SigningOutput, sign_admin_removal_with_instance_key, sign_deactivation_with_key,
    sign_post_revision_with_key, sign_retraction_with_key, sign_trust_edge_with_key,
    store_signed_object,
};
use rand::rngs::OsRng;
use serde_json::{Value as JsonValue, json};
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{
    FlakeyTransport, MultiInstanceHarness, establish_active_peering, send_envelope_signed,
};
use common::{body_json, json_request, send, setup_admin};

// ---------------------------------------------------------------------------
// CBOR body / response helpers
// ---------------------------------------------------------------------------

/// Wrap each WireFormat blob in `{ "p": payload, "s": signature }` and
/// pack the lot under `{ "objects": [bstr, ...] }` per §10.1.
fn encode_content_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("objects".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + wires.iter().map(|w| w.len()).sum::<usize>());
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// Encode a §6.3 WireFormat `{ "p", "s" }`.
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

/// Decode the §10.1 `{ "results": [...] }` shape into a flat vector of
/// `(canonical_hash, status, reason)`.
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

/// Pull `{ canonical_hash, status }` from a `/admin-rm-report` 200.
fn parse_report_body(body: &[u8]) -> ([u8; 32], String) {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("report body is not a map");
    };
    let mut hash: Option<[u8; 32]> = None;
    let mut status: Option<String> = None;
    for (k, v) in m {
        if let Value::Text(name) = k {
            match (name.as_str(), v) {
                ("canonical_hash", Value::Bytes(b)) => {
                    hash = Some(b.as_slice().try_into().expect("32 bytes"));
                }
                ("status", Value::Text(s)) => status = Some(s),
                _ => {}
            }
        }
    }
    (hash.expect("hash"), status.expect("status"))
}

/// Encode the §10.4 advisory body `{ "object": WireFormat }`.
fn encode_report_body(wire: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![(
        Value::Text("object".into()),
        Value::Bytes(wire.to_vec()),
    )]);
    let mut buf = Vec::with_capacity(wire.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

/// Insert a `users` row with a known Ed25519 public key so a remote
/// author key is locally projectable.
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

/// Insert a `posts` row referencing an existing user + thread so the
/// admin-rm advisory handler's `post_not_found` check sees the target.
async fn insert_post_with_id(db: &SqlitePool, post_id: &Uuid, author_id: &str, thread_id: &Uuid) {
    let post_id_text = post_id.to_string();
    let thread_id_text = thread_id.to_string();
    let room_exists: Option<String> =
        sqlx::query_scalar!("SELECT id FROM rooms WHERE id = 'general' LIMIT 1")
            .fetch_optional(db)
            .await
            .expect("room lookup");
    if room_exists.is_none() {
        sqlx::query!(
            "INSERT INTO rooms (id, slug, created_by) VALUES ('general', 'general', ?)",
            author_id,
        )
        .execute(db)
        .await
        .expect("insert room");
    }
    sqlx::query!(
        "INSERT INTO threads (id, title, author, room) \
         VALUES (?, 'placeholder', ?, 'general')",
        thread_id_text,
        author_id,
    )
    .execute(db)
    .await
    .expect("insert thread");
    sqlx::query!(
        "INSERT INTO posts (id, author, thread) VALUES (?, ?, ?)",
        post_id_text,
        author_id,
        thread_id_text,
    )
    .execute(db)
    .await
    .expect("insert post");
}

// ===========================================================================
// §10.1 content receive path: persist, erase cascades, rejections
// ===========================================================================

/// Done-when: a single `post-rev` push from active-peer A reaches B and
/// the canonical bytes land in `signed_objects` with `applied`. No
/// `post_revisions` projection is asserted — the wire bytes are the
/// durable artefact while remote-user stub hydration waits on a later
/// phase. (Representative happy path; `profile` and `thread-create` push
/// identically — bytes land, `inner_class` set, status `applied`.)
#[tokio::test]
async fn content_push_post_rev_persists_signed_object() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice_key = SigningKey::generate(&mut OsRng);
    let post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();
    let signed = sign_post_revision_with_key(
        &alice_key,
        &post_id,
        &thread_id,
        None,
        0,
        "hello federation",
        1_700_000_000_000,
        Vec::new(),
    );
    let wire = encode_wire(&signed.payload, &signed.signature);
    let body = encode_content_body(&[wire]);

    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "200 OK (body: {:?})", resp_body);

    let results = parse_results_body(&resp_body);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, signed.canonical_hash);
    assert_eq!(results[0].1, "applied");
    assert!(results[0].2.is_none());

    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let stored = sqlx::query!(
        "SELECT inner_class, payload FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("signed_objects row");
    assert_eq!(stored.inner_class, "post-rev");
    assert_eq!(stored.payload.as_deref(), Some(signed.payload.as_slice()));
}

/// `retract`: the canonical bytes land and any matching `post-rev`
/// payload for the same `post_id` is NULLed per §10.1 on-receipt erasure
/// (the §3 chain-walk artifacts — signature, hash, prior link — remain).
#[tokio::test]
#[ignore = "fakes setup state via raw INSERT; rewrite to drive real APIs before re-enabling"]
async fn content_push_retract_erases_post_rev_payload() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();

    // The erase helper subqueries `posts` joined to `post_revisions`, so
    // both rows must exist locally for the NULL to land on the right
    // `signed_objects.canonical_hash`.
    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_post_with_id(&b.state.db, &post_id, "user-alice", &thread_id).await;

    let post_rev = sign_post_revision_with_key(
        &alice_key,
        &post_id,
        &thread_id,
        None,
        0,
        "to be retracted",
        1_700_000_000_000,
        Vec::new(),
    );
    let post_rev_hash_db: Vec<u8> = post_rev.canonical_hash.to_vec();
    let post_rev_sig_db: Vec<u8> = post_rev.signature.clone();
    let post_id_text = post_id.to_string();
    sqlx::query!(
        "INSERT INTO post_revisions \
         (post_id, revision, body, signature, canonical_hash, created_at) \
         VALUES (?, 0, 'to be retracted', ?, ?, '2024-01-01T00:00:00Z')",
        post_id_text,
        post_rev_sig_db,
        post_rev_hash_db,
    )
    .execute(&b.state.db)
    .await
    .expect("seed post_revisions");

    // Push the post-rev so its canonical bytes are persisted.
    let wire = encode_wire(&post_rev.payload, &post_rev.signature);
    let body = encode_content_body(&[wire]);
    let (status, _) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Now the retract.
    let retract = sign_retraction_with_key(&alice_key, &post_id, 1_700_000_000_500);
    let wire = encode_wire(&retract.payload, &retract.signature);
    let body = encode_content_body(&[wire]);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse_results_body(&resp_body)[0].1, "applied");

    // The retract's own row is present with payload intact.
    let retract_hash: &[u8] = retract.canonical_hash.as_slice();
    let retract_row = sqlx::query!(
        "SELECT inner_class, payload FROM signed_objects WHERE canonical_hash = ?",
        retract_hash,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("retract row");
    assert_eq!(retract_row.inner_class, "retract");
    assert!(retract_row.payload.is_some());

    // The post-rev row still exists but the payload was NULLed.
    let post_rev_hash: &[u8] = post_rev.canonical_hash.as_slice();
    let pr_row = sqlx::query!(
        "SELECT payload, erased_at FROM signed_objects WHERE canonical_hash = ?",
        post_rev_hash,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("post-rev row");
    assert!(pr_row.payload.is_none(), "post-rev payload must be NULLed");
    assert!(pr_row.erased_at.is_some(), "erased_at must be set");
}

/// `deactivate`: the canonical bytes land and every previously-stored
/// signed object whose inner author key is the deactivating user has its
/// payload NULLed. Asserts the cascade by pushing a `post-rev` first,
/// then the `deactivate`.
#[tokio::test]
#[ignore = "fakes setup state via raw INSERT; rewrite to drive real APIs before re-enabling"]
async fn content_push_deactivate_erases_user_payloads() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();

    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_post_with_id(&b.state.db, &post_id, "user-alice", &thread_id).await;

    let post_rev = sign_post_revision_with_key(
        &alice_key,
        &post_id,
        &thread_id,
        None,
        0,
        "to be erased",
        1_700_000_000_000,
        Vec::new(),
    );
    let post_rev_hash_db: Vec<u8> = post_rev.canonical_hash.to_vec();
    let post_rev_sig_db: Vec<u8> = post_rev.signature.clone();
    let post_id_text = post_id.to_string();
    sqlx::query!(
        "INSERT INTO post_revisions \
         (post_id, revision, body, signature, canonical_hash, created_at) \
         VALUES (?, 0, 'to be erased', ?, ?, '2024-01-01T00:00:00Z')",
        post_id_text,
        post_rev_sig_db,
        post_rev_hash_db,
    )
    .execute(&b.state.db)
    .await
    .expect("seed post_revisions");

    let wire = encode_wire(&post_rev.payload, &post_rev.signature);
    let body = encode_content_body(&[wire]);
    let (status, _) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Push the deactivate.
    let deact = sign_deactivation_with_key(&alice_key, 1_700_000_001_000);
    let wire = encode_wire(&deact.payload, &deact.signature);
    let body = encode_content_body(&[wire]);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse_results_body(&resp_body)[0].1, "applied");

    // The post-rev payload has been NULLed.
    let post_rev_hash: &[u8] = post_rev.canonical_hash.as_slice();
    let pr_row = sqlx::query!(
        "SELECT payload, erased_at FROM signed_objects WHERE canonical_hash = ?",
        post_rev_hash,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("post-rev row");
    assert!(pr_row.payload.is_none(), "post-rev payload must be NULLed");
    assert!(pr_row.erased_at.is_some(), "erased_at must be set");
}

/// Replaying the same WireFormat bytes returns `duplicate` per §10.1 —
/// same redelivery semantics as edges.
#[tokio::test]
async fn content_push_replay_returns_duplicate() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let alice_key = SigningKey::generate(&mut OsRng);
    let post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();
    let signed = sign_post_revision_with_key(
        &alice_key,
        &post_id,
        &thread_id,
        None,
        0,
        "replay me",
        1_700_000_000_000,
        Vec::new(),
    );
    let wire = encode_wire(&signed.payload, &signed.signature);
    let body = encode_content_body(&[wire]);

    let (s1, b1) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(parse_results_body(&b1)[0].1, "applied");

    let (s2, b2) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(parse_results_body(&b2)[0].1, "duplicate");
}

/// `invalid_signature`: WireFormat parses but the Ed25519 sig fails
/// verification → `rejected/invalid_signature`, not persisted.
#[tokio::test]
async fn content_push_bad_signature_rejected_and_not_persisted() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice_key = SigningKey::generate(&mut OsRng);
    let post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();
    let signed = sign_post_revision_with_key(
        &alice_key,
        &post_id,
        &thread_id,
        None,
        0,
        "tampered",
        1_700_000_000_000,
        Vec::new(),
    );
    let mut tampered = signed.signature.clone();
    tampered[0] ^= 0xFF;
    let wire = encode_wire(&signed.payload, &tampered);
    let body = encode_content_body(&[wire]);

    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let results = parse_results_body(&resp_body);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("invalid_signature"));

    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count");
    assert_eq!(count, 0);
}

/// `wrong_class`: a `trust-edge` arrives on `/content` (it belongs on
/// `/edges`). The receiver tags it `rejected/wrong_class` and does not
/// persist.
#[tokio::test]
async fn content_push_trust_edge_returns_wrong_class() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_pub = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let signed = sign_trust_edge_with_key(
        &alice_key,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let wire = encode_wire(&signed.payload, &signed.signature);
    let body = encode_content_body(&[wire]);

    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let results = parse_results_body(&resp_body);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("wrong_class"));

    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count");
    assert_eq!(count, 0);
}

/// `object_too_large`: a WireFormat blob exceeding `MAX_POSTREV_SIZE` is
/// rejected per-object; the rest of the batch must still apply. Pairs the
/// oversize object with a valid `post-rev` and checks the small one
/// applies.
#[tokio::test]
async fn content_push_object_too_large_is_per_object_reject() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // Oversize WireFormat: rejected on the size check before any decode,
    // so the bytes don't have to be CBOR-valid.
    let big = vec![0u8; MAX_POSTREV_SIZE + 1];

    let alice_key = SigningKey::generate(&mut OsRng);
    let post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();
    let small = sign_post_revision_with_key(
        &alice_key,
        &post_id,
        &thread_id,
        None,
        0,
        "ok",
        1_700_000_000_000,
        Vec::new(),
    );
    let small_wire = encode_wire(&small.payload, &small.signature);
    let body = encode_content_body(&[big, small_wire]);

    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let results = parse_results_body(&resp_body);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("object_too_large"));
    assert_eq!(results[1].1, "applied");
}

/// Request-level errors collapse to 400 with a single `error` field per
/// the §10.1 vocabulary that mirrors §9.1.
#[tokio::test]
async fn content_push_request_level_errors() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // malformed body.
    let (status, b1) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &[0xffu8; 16],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&b1), "malformed");

    // empty_batch.
    let body = encode_content_body(&[]);
    let (status, b2) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&b2), "empty_batch");

    // batch_too_large. Dummy entries — receiver short-circuits on length
    // before per-object validation.
    let dummy = vec![0u8; 4];
    let body = encode_content_body(&vec![dummy; MAX_CONTENT_BATCH + 1]);
    let (status, b3) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&b3), "batch_too_large");
}

// ===========================================================================
// §10.4 admin-rm: precedence, wrong_route, unauthorized_signer, advisory
// ===========================================================================

/// §10.4 receive-time admin-rm precedence: once an authoritative admin-rm
/// has been applied for a `post_id`, any subsequent `post-rev` or
/// `retract` naming the same `post_id` is rejected `admin_removed`.
#[tokio::test]
async fn content_push_admin_rm_blocks_subsequent_post_rev() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    // No local user row for the target → A's admin-rm is authoritative
    // by B (the "not_hosted_by_us" branch).
    let alice_key = SigningKey::generate(&mut OsRng);
    let post_id = Uuid::new_v4();

    // A signs the admin-rm with A's instance signing key. The
    // `signing_instance` must equal A's recorded `instance_domain` on B.
    let a = harness.instance("a");
    let admin_rm = sign_admin_removal_with_instance_key(
        &a.state.instance_key,
        &post_id,
        &alice_key.verifying_key().to_bytes(),
        &a.state.instance_domain,
        1_700_000_000_000,
        Some("violates rules"),
    );
    let wire = encode_wire(&admin_rm.payload, &admin_rm.signature);
    let body = encode_content_body(&[wire]);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let results = parse_results_body(&resp_body);
    assert_eq!(results[0].1, "applied", "admin-rm must apply");

    // `admin_rm_authorities` row exists.
    let pid_slice: &[u8] = post_id.as_bytes().as_slice();
    let auth_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM admin_rm_authorities WHERE post_id = ?",
        pid_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count");
    assert_eq!(auth_count, 1);

    // A post-rev for the same post_id must be rejected `admin_removed`.
    let thread_id = Uuid::new_v4();
    let post_rev = sign_post_revision_with_key(
        &alice_key,
        &post_id,
        &thread_id,
        None,
        0,
        "should be blocked",
        1_700_000_001_000,
        Vec::new(),
    );
    let wire = encode_wire(&post_rev.payload, &post_rev.signature);
    let body = encode_content_body(&[wire]);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let results = parse_results_body(&resp_body);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("admin_removed"));

    // post-rev not persisted.
    let pr_hash: &[u8] = post_rev.canonical_hash.as_slice();
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        pr_hash,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count");
    assert_eq!(count, 0, "blocked post-rev must not be persisted");
}

/// `wrong_route`: an admin-rm whose target is *locally hosted* cannot be
/// authoritative from anyone but us; the sender should have used the
/// §10.4 advisory route. Returns `rejected/wrong_route`.
#[tokio::test]
#[ignore = "fakes setup state via raw INSERT; rewrite to drive real APIs before re-enabling"]
async fn content_push_admin_rm_against_local_user_is_wrong_route() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");
    let a = harness.instance("a");

    // B hosts the target user.
    let target_key = SigningKey::generate(&mut OsRng);
    let target_pub = target_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-target", "target", &target_pub).await;

    let post_id = Uuid::new_v4();
    let admin_rm = sign_admin_removal_with_instance_key(
        &a.state.instance_key,
        &post_id,
        &target_pub,
        &a.state.instance_domain,
        1_700_000_000_000,
        None,
    );
    let wire = encode_wire(&admin_rm.payload, &admin_rm.signature);
    let body = encode_content_body(&[wire]);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let results = parse_results_body(&resp_body);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("wrong_route"));
}

/// `unauthorized_signer`: the inner admin-rm payload's `signing_instance`
/// field does not match the envelope sender's recorded
/// `peers.instance_domain`. Receiver rejects without persisting.
#[tokio::test]
async fn content_push_admin_rm_signing_instance_mismatch_unauthorized() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");
    let a = harness.instance("a");

    let target_pub = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let post_id = Uuid::new_v4();
    // Sign with a `signing_instance` string that doesn't match A's domain.
    let admin_rm = sign_admin_removal_with_instance_key(
        &a.state.instance_key,
        &post_id,
        &target_pub,
        "imposter.example",
        1_700_000_000_000,
        None,
    );
    let wire = encode_wire(&admin_rm.payload, &admin_rm.signature);
    let body = encode_content_body(&[wire]);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let results = parse_results_body(&resp_body);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("unauthorized_signer"));

    let hash_slice: &[u8] = admin_rm.canonical_hash.as_slice();
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count");
    assert_eq!(count, 0);
}

/// Happy path: B hosts the target user, A pushes an advisory admin-rm.
/// Receiver returns `queued`, the row lands in `admin_rm_reports`, and a
/// replay deduplicates by `post_id`.
#[tokio::test]
#[ignore = "fakes setup state via raw INSERT; rewrite to drive real APIs before re-enabling"]
async fn admin_rm_report_queued_for_local_target() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");
    let a = harness.instance("a");

    let target_key = SigningKey::generate(&mut OsRng);
    let target_pub = target_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-target", "target", &target_pub).await;

    let post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();
    insert_post_with_id(&b.state.db, &post_id, "user-target", &thread_id).await;

    let admin_rm = sign_admin_removal_with_instance_key(
        &a.state.instance_key,
        &post_id,
        &target_pub,
        &a.state.instance_domain,
        1_700_000_000_000,
        Some("violates community guidelines"),
    );
    let wire = encode_wire(&admin_rm.payload, &admin_rm.signature);
    let body = encode_report_body(&wire);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/admin-rm-report",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {:?}", resp_body);
    let (hash, st) = parse_report_body(&resp_body);
    assert_eq!(hash, admin_rm.canonical_hash);
    assert_eq!(st, "queued");

    // Row landed in admin_rm_reports.
    let pid_slice: &[u8] = post_id.as_bytes().as_slice();
    let row = sqlx::query!(
        "SELECT signing_instance, reason FROM admin_rm_reports WHERE post_id = ?",
        pid_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("report row");
    assert_eq!(row.signing_instance, a.state.instance_domain);
    assert_eq!(row.reason.as_deref(), Some("violates community guidelines"));

    // Replay deduplicates → `duplicate`.
    let (status2, resp_body2) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/admin-rm-report",
        &body,
    )
    .await;
    assert_eq!(status2, StatusCode::OK);
    let (_, st2) = parse_report_body(&resp_body2);
    assert_eq!(st2, "duplicate");
}

/// `not_authoritative_home`: we don't host the target user, so an
/// advisory report has nowhere to go. Receiver returns 400.
#[tokio::test]
async fn admin_rm_report_not_authoritative_home() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    let target_pub = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let post_id = Uuid::new_v4();
    let admin_rm = sign_admin_removal_with_instance_key(
        &a.state.instance_key,
        &post_id,
        &target_pub,
        &a.state.instance_domain,
        1_700_000_000_000,
        None,
    );
    let wire = encode_wire(&admin_rm.payload, &admin_rm.signature);
    let body = encode_report_body(&wire);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/admin-rm-report",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&resp_body), "not_authoritative_home");
}

// ===========================================================================
// §10 local-origin fanout: each origin handler forwards its signed object
// ===========================================================================

/// Build a §8.3 `FrontierAnnounce` whose both filters are the all-ones
/// sentinel — every routing key matches, so the receiver sees every
/// Authored or TrustEdge object the sender fans out.
fn announce_all_ones() -> FrontierAnnounce {
    FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: FilterSpec::from_bloom(&BloomFilter::all_ones_sentinel()),
        expansion_filter: FilterSpec::from_bloom(&BloomFilter::all_ones_sentinel()),
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
}

/// Count `signed_objects` rows of a given inner class on a peer's DB.
async fn count_class(db: &SqlitePool, class: &str) -> i64 {
    sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE inner_class = ?",
        class,
    )
    .fetch_one(db)
    .await
    .expect("count signed_objects by class")
}

/// Wait for A's outbound queue to fully drain (the deterministic
/// `wait_idle` hook — the function under test here, not a poll-loop),
/// asserting drain completed within the timeout.
async fn wait_outbound_idle(harness: &MultiInstanceHarness, label: &str) {
    let a = harness.instance(label);
    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(2))
            .await,
        "outbound queue from {label} did not drain within 2s",
    );
}

/// Two-instance harness with active peering and B's all-ones frontier
/// announced to A — A's `peers_interested_in` returns B for every routing
/// key, so any origin-side fanout from A targets B.
async fn setup_tripwire() -> MultiInstanceHarness {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let (status, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce_all_ones().encode(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "B → A frontier announce must apply");
    harness
}

/// Create a thread via the real `POST /api/threads` handler and return
/// `(thread_id, op_post_id)`.
async fn create_thread_as(
    router: &axum::Router,
    cookie: &str,
    room: &str,
    title: &str,
    body: &str,
) -> (String, String) {
    let response = send(
        router,
        json_request(
            Method::POST,
            "/api/threads",
            Some(cookie),
            &json!({ "room": room, "title": title, "body": body }),
        ),
    )
    .await;
    let status = response.status();
    let json = body_json(response).await;
    assert_eq!(status, StatusCode::CREATED, "create_thread failed: {json}");
    let thread_id = json["id"].as_str().expect("thread.id").to_string();
    let post_id = json["post"]["id"].as_str().expect("post.id").to_string();
    (thread_id, post_id)
}

/// Create a reply via the real `POST /api/threads/{id}/posts` handler and
/// return the new post id.
async fn create_reply_as(
    router: &axum::Router,
    cookie: &str,
    thread_id: &str,
    parent_id: &str,
    body: &str,
) -> String {
    let response = send(
        router,
        json_request(
            Method::POST,
            &format!("/api/threads/{thread_id}/posts"),
            Some(cookie),
            &json!({ "parent_id": parent_id, "body": body }),
        ),
    )
    .await;
    let status = response.status();
    let json: JsonValue = body_json(response).await;
    assert_eq!(status, StatusCode::CREATED, "create_reply failed: {json}");
    json["id"].as_str().expect("reply.id").to_string()
}

/// `POST /api/threads` must fan out both the OP `post-rev` and the paired
/// `thread-create` (signed-payload-format.md §5.9) to B.
#[tokio::test]
async fn create_thread_fans_out_post_rev_and_thread_create() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let _ = create_thread_as(&a.router, &alice.cookie, "general", "tripwire", "hello").await;

    wait_outbound_idle(&harness, "a").await;
    let post_rev = count_class(&b.state.db, "post-rev").await;
    assert_eq!(
        post_rev, 1,
        "post-rev did not fan out to B (count={post_rev})"
    );
    let thread_create = count_class(&b.state.db, "thread-create").await;
    assert_eq!(
        thread_create, 1,
        "thread-create did not fan out to B (count={thread_create})",
    );
}

/// `POST /api/threads/{id}/posts` must fan out the reply `post-rev`.
/// After create_thread (1 post-rev) + reply (1 post-rev), B holds 2.
#[tokio::test]
async fn create_reply_fans_out_post_rev() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let (thread_id, op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "with-reply", "op body").await;
    let _ = create_reply_as(&a.router, &alice.cookie, &thread_id, &op_id, "reply body").await;

    wait_outbound_idle(&harness, "a").await;
    let post_rev = count_class(&b.state.db, "post-rev").await;
    assert_eq!(
        post_rev, 2,
        "reply post-rev did not fan out to B (count={post_rev})",
    );
}

/// `PATCH /api/posts/{id}` must fan out the new revision's `post-rev`.
/// After create + edit, B holds 2 `post-rev` rows (revision 0 OP,
/// revision 1 edit).
#[tokio::test]
async fn edit_post_fans_out_post_rev() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let (_thread_id, op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "to-edit", "original").await;
    let response = send(
        &a.router,
        json_request(
            Method::PATCH,
            &format!("/api/posts/{op_id}"),
            Some(&alice.cookie),
            &json!({ "body": "edited" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "edit_post failed");

    wait_outbound_idle(&harness, "a").await;
    let post_rev = count_class(&b.state.db, "post-rev").await;
    assert_eq!(
        post_rev, 2,
        "edit post-rev did not fan out to B (count={post_rev})",
    );
}

/// `DELETE /api/posts/{id}` must fan out a `retract`. We retract a reply
/// rather than the OP so any future "OP retract → thread implicitly
/// retracted" behaviour doesn't perturb the assertion.
#[tokio::test]
async fn retract_post_fans_out_retract() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let (thread_id, op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "to-retract", "op body").await;
    let reply_id =
        create_reply_as(&a.router, &alice.cookie, &thread_id, &op_id, "reply body").await;

    let response = send(
        &a.router,
        Request::builder()
            .method(Method::DELETE)
            .uri(format!("/api/posts/{reply_id}"))
            .header(axum::http::header::COOKIE, &alice.cookie)
            .header(axum::http::header::ORIGIN, common::TEST_ORIGIN)
            .body(axum::body::Body::empty())
            .expect("build retract request"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "retract failed");

    wait_outbound_idle(&harness, "a").await;
    let retract = count_class(&b.state.db, "retract").await;
    assert_eq!(retract, 1, "retract did not fan out to B (count={retract})");
}

/// `PATCH /api/users/{pubkey_hex}` (update_bio) must fan out a `profile`
/// revision.
#[tokio::test]
async fn update_bio_fans_out_profile() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let response = send(
        &a.router,
        json_request(
            Method::PATCH,
            &format!("/api/users/{}", alice.public_key_hex),
            Some(&alice.cookie),
            &json!({ "bio": "new bio text" }),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "update_bio failed",
    );

    wait_outbound_idle(&harness, "a").await;
    let profile = count_class(&b.state.db, "profile").await;
    assert_eq!(profile, 1, "profile did not fan out to B (count={profile})");
}

/// `DELETE /api/admin/posts/{id}` (admin-rm) must fan out an `admin-rm`.
/// Alice is admin (via setup_admin) so she can remove her own post.
#[tokio::test]
async fn admin_remove_post_fans_out_admin_rm() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let (_thread_id, op_id) = create_thread_as(
        &a.router,
        &alice.cookie,
        "general",
        "to-admin-rm",
        "op body",
    )
    .await;

    // admin::remove_post requires a JSON body with `reason` — that string
    // is bound into the §10.1 `admin-rm` signed payload.
    let response = send(
        &a.router,
        json_request(
            Method::DELETE,
            &format!("/api/admin/posts/{op_id}"),
            Some(&alice.cookie),
            &json!({ "reason": "tripwire" }),
        ),
    )
    .await;
    let status = response.status();
    assert!(
        status.is_success() || status == StatusCode::NO_CONTENT,
        "admin remove_post failed: {status}",
    );

    wait_outbound_idle(&harness, "a").await;
    let admin_rm = count_class(&b.state.db, "admin-rm").await;
    assert_eq!(
        admin_rm, 1,
        "admin-rm did not fan out to B (count={admin_rm})",
    );
}

/// `DELETE /api/me` (soft_delete_user) must fan out the `deactivate`
/// umbrella. Alice has no posts so no `retract` rows are emitted — the
/// assertion is purely on the deactivate object.
#[tokio::test]
async fn deactivate_fans_out_deactivate() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let response = send(
        &a.router,
        Request::builder()
            .method(Method::DELETE)
            .uri("/api/me")
            .header(axum::http::header::COOKIE, &alice.cookie)
            .header(axum::http::header::ORIGIN, common::TEST_ORIGIN)
            .body(axum::body::Body::empty())
            .expect("build delete-me request"),
    )
    .await;
    let status = response.status();
    assert!(
        status.is_success() || status == StatusCode::NO_CONTENT,
        "delete_my_account failed: {status}",
    );

    wait_outbound_idle(&harness, "a").await;
    let deactivate = count_class(&b.state.db, "deactivate").await;
    assert_eq!(
        deactivate, 1,
        "deactivate did not fan out to B (count={deactivate})",
    );
}

// ===========================================================================
// §7.5 per-peer outbound queue: backlog drain, backoff, overflow eviction
// ===========================================================================

/// Two-instance harness for the queue scenarios: active peering + B's
/// all-ones frontier announced to A.
async fn setup_a_to_b() -> MultiInstanceHarness {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let (status, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce_all_ones().encode(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "B → A frontier announce must apply");
    harness
}

/// While B is disconnected, originate several posts on A → A's outbound
/// queue to B grows (no successful drains, items requeue on `UnknownPeer`
/// transient errors). Reconnect B; assert `wait_idle` returns true and B's
/// `signed_objects` table is populated.
#[tokio::test]
async fn kill_and_restart_peer_drains_backlog() {
    let harness = setup_a_to_b().await;
    let a = harness.instance("a");
    let b_peer_id = harness.instance("b").peer_id;
    let alice = setup_admin(&a.router, "alice").await;

    // Originate one thread while B is online — this seeds A's
    // forwarding-LRU and creates an OP to reply to.
    let (thread_id, op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "backlog", "op body").await;

    // Drain whatever's already in flight from the create_thread call.
    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(2))
            .await,
        "initial create_thread should drain to B"
    );

    // Disconnect B and originate N replies. Each enqueue lands on A's
    // outbound queue to B, the drain worker fails transiently
    // (UnknownPeer), re-queues, and backs off. The queue depth grows.
    harness.disconnect("b").await;

    const N: usize = 8;
    for i in 0..N {
        create_reply_as(
            &a.router,
            &alice.cookie,
            &thread_id,
            &op_id,
            &format!("reply {i}"),
        )
        .await;
    }

    // Reconnect B and let the queue drain. The drain-worker backoff window
    // is at most `BackoffPolicy::test_fast().max` = 100ms, so a 5-second
    // cap is plenty.
    harness.reconnect("b").await;
    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(5))
            .await,
        "queue did not drain after B reconnected (depth={:?})",
        a.state.outbound_queues.depth_for(b_peer_id.as_bytes()),
    );

    // B should now hold N replies + the original OP = N+1 post-revs.
    let b = harness.instance("b");
    let post_rev = count_class(&b.state.db, "post-rev").await;
    assert_eq!(
        post_rev,
        (N as i64) + 1,
        "B should have received all {} post-revs (got {post_rev})",
        N + 1,
    );
}

/// A Layer-1 reproduction of the deterministic Layer-0
/// `backoff_grows_until_success` unit test in `outbound_queue.rs`. Scripts
/// A's outbound transport to return 503 for the first three drain
/// attempts, then proxies through to B's real router. With the `test_fast`
/// backoff (initial=10ms, max=100ms) the worker reaches success in well
/// under the 5-second cap; we assert all three scripted failures were
/// consumed (the retry path actually ran) and that B ultimately received
/// the post-rev.
#[tokio::test]
async fn backoff_retries_then_succeeds() {
    // Build A with a FlakeyTransport wrapping its InProcessTransport. The
    // script starts empty so the active-peering handshake proxies through
    // cleanly; we push 503s only after handshake completes.
    let mut harness = MultiInstanceHarness::new(0).await;
    let script = std::sync::Arc::new(std::sync::Mutex::new(None));
    let script_setter = script.clone();
    harness
        .spawn_with_outbound_config_and_transport(
            "a",
            OutboundQueueConfig::test_fast(),
            move |inner| {
                let (flakey, handle) = FlakeyTransport::new(inner);
                *script_setter.lock().unwrap() = Some(handle);
                std::sync::Arc::new(flakey)
            },
        )
        .await;
    harness.spawn("b").await;
    let script = script.lock().unwrap().clone().expect("flakey script set");

    establish_active_peering(&harness, "a", "b").await;
    let (status, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce_all_ones().encode(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let a = harness.instance("a");
    let alice = setup_admin(&a.router, "alice").await;

    // Script three transient failures BEFORE originating the post. The
    // worker then sees 503 → backoff → 503 → backoff → 503 → backoff →
    // real dispatch. Pushing after create-thread would race the worker,
    // which usually succeeds on the first dispatch before the test wakes.
    script.push_n(3, StatusCode::SERVICE_UNAVAILABLE);

    let (_thread_id, _op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "retry", "op body").await;

    // The thread-create call enqueued the post-rev push; wait_idle covers
    // the retry + backoff cycle.
    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(5))
            .await,
        "queue did not drain under scripted-503 retries",
    );

    assert_eq!(
        script.remaining(),
        0,
        "all three scripted 503s should have been consumed by retries",
    );

    let b = harness.instance("b");
    let post_rev = count_class(&b.state.db, "post-rev").await;
    assert_eq!(
        post_rev, 1,
        "B should have received the OP post-rev after retries succeeded",
    );
}

/// Per-peer object cap evicts oldest under sustained flood. Builds a
/// harness with `objects_per_peer = 5`, disconnects B, originates 10
/// replies on A, asserts: (1) A's queue depth to B never exceeds 5;
/// (2) after reconnect B receives at most cap+OP = 6 post-revs;
/// (3) drop-OLDEST — the surviving replies are the newer 5 ("evict 5"..
/// "evict 9"), not the older 5.
#[tokio::test]
async fn overflow_evicts_oldest_per_peer() {
    // Shrunken cap: only 5 queued objects per peer. Everything else stays
    // at the spec defaults so this remains a realistic shape minus one knob.
    let mut shrunken = OutboundQueueConfig::test_fast();
    shrunken.objects_per_peer = 5;

    let harness = MultiInstanceHarness::new_with_outbound_config(2, shrunken).await;
    establish_active_peering(&harness, "a", "b").await;
    let (status, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce_all_ones().encode(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let a = harness.instance("a");
    let b_peer_id = harness.instance("b").peer_id;
    let alice = setup_admin(&a.router, "alice").await;
    let (thread_id, op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "overflow", "op body").await;
    let _ = a
        .state
        .outbound_queues
        .wait_idle(Duration::from_secs(2))
        .await;

    harness.disconnect("b").await;

    // Originate 10 replies — twice the cap. Each new enqueue past the 5th
    // must drop the oldest pending item from A's queue to B.
    const N: usize = 10;
    for i in 0..N {
        create_reply_as(
            &a.router,
            &alice.cookie,
            &thread_id,
            &op_id,
            &format!("evict {i}"),
        )
        .await;
    }

    let (depth_objects, _) = a.state.outbound_queues.depth_for(b_peer_id.as_bytes());
    assert!(
        depth_objects <= 5,
        "per-peer object cap (5) violated: depth={depth_objects}",
    );

    // Reconnect B and let what's left drain. With the cap at 5, B sees at
    // most 5 post-revs plus the OP from before the disconnect.
    harness.reconnect("b").await;
    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(5))
            .await,
        "queue did not drain after reconnect",
    );

    let b = harness.instance("b");
    let post_rev = count_class(&b.state.db, "post-rev").await;
    assert!(
        post_rev <= 6,
        "B should receive at most cap+OP = 6 post-revs (got {post_rev}); \
         the cap evicted older replies before B reconnected",
    );
    assert!(
        post_rev >= 1,
        "B should at minimum still have the OP from before the disconnect (got {post_rev})",
    );

    // The load-bearing claim is drop-OLDEST. With objects_per_peer = 5 and
    // N = 10, the queue should retain the last 5 replies ("evict 5".."evict
    // 9") and evict the first 5. Phase 6 doesn't project post_revisions on
    // receivers, so map body → canonical_hash on A (origin) then check
    // which of those hashes arrived in B's signed_objects.
    let body_to_hash: Vec<(String, Vec<u8>)> = sqlx::query!(
        "SELECT pr.body AS \"body!: String\", pr.canonical_hash AS \"canonical_hash!: Vec<u8>\" \
         FROM post_revisions pr \
         JOIN posts p ON p.id = pr.post_id \
         WHERE p.parent IS NOT NULL AND pr.body LIKE 'evict %'",
    )
    .fetch_all(&a.state.db)
    .await
    .expect("query A's reply hashes")
    .into_iter()
    .map(|r| (r.body, r.canonical_hash))
    .collect();
    assert_eq!(
        body_to_hash.len(),
        N,
        "A should hold all 10 originated replies"
    );

    let mut survivors: Vec<usize> = Vec::new();
    for (body, hash) in &body_to_hash {
        let n: usize = body
            .strip_prefix("evict ")
            .and_then(|n| n.parse().ok())
            .expect("evict-N body");
        let arrived = sqlx::query_scalar!(
            "SELECT 1 AS \"x!: i64\" FROM signed_objects \
             WHERE canonical_hash = ? AND inner_class = 'post-rev'",
            hash,
        )
        .fetch_optional(&b.state.db)
        .await
        .expect("query B for reply hash")
        .is_some();
        if arrived {
            survivors.push(n);
        }
    }
    survivors.sort_unstable();
    assert_eq!(
        survivors,
        vec![5, 6, 7, 8, 9],
        "drop-oldest should retain the newer 5 replies, not the older 5",
    );
}

// ===========================================================================
// §10.5 pull-backfill backstop: by-hash 410/200, authority, rate limit
// ===========================================================================

/// Seed a `signed_objects` row directly via the production helper. The
/// row lands with `payload IS NOT NULL` and `erased_at IS NULL`.
async fn store_object(db: &SqlitePool, inner_class: &str, signed: &SigningOutput) {
    store_signed_object(
        db,
        inner_class,
        &signed.payload,
        &signed.signature,
        &signed.canonical_hash,
    )
    .await
    .expect("store_signed_object");
}

/// Stamp an existing `signed_objects` row as erased, linking it to
/// `authority_hash` so the by-hash handler can resolve the §10.5.2
/// `authority` WireFormat in O(1) via `erased_by`. Mirrors the production
/// erase helpers but bypasses the projection JOINs.
async fn mark_erased(db: &SqlitePool, canonical_hash: &[u8; 32], authority_hash: &[u8; 32]) {
    let hash_slice: &[u8] = canonical_hash.as_slice();
    let auth_slice: &[u8] = authority_hash.as_slice();
    sqlx::query!(
        "UPDATE signed_objects \
         SET payload = NULL, \
             erased_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
             erased_by = COALESCE(erased_by, ?) \
         WHERE canonical_hash = ?",
        auth_slice,
        hash_slice,
    )
    .execute(db)
    .await
    .expect("mark erased");
}

/// Build the §10.5.1 by-hash request body: `{ "hashes": [bstr(32), ...] }`.
fn encode_by_hash_body(hashes: &[[u8; 32]]) -> Vec<u8> {
    let arr: Vec<Value> = hashes.iter().map(|h| Value::Bytes(h.to_vec())).collect();
    let body = Value::Map(vec![(Value::Text("hashes".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + hashes.len() * 36);
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// Decoded shape of a `200 OK` body: `{ objects, [next_cursor], complete }`.
/// `objects` entries are raw §6.3 WireFormat blobs.
struct OkBody {
    objects: Vec<Vec<u8>>,
    complete: bool,
}

fn parse_ok_body(bytes: &[u8]) -> OkBody {
    let v: Value = ciborium::de::from_reader(bytes).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("ok body is not a map");
    };
    let mut objects: Option<Vec<Vec<u8>>> = None;
    let mut complete: Option<bool> = None;
    for (k, v) in m {
        if let Value::Text(t) = &k {
            match (t.as_str(), v) {
                ("objects", Value::Array(arr)) => {
                    let mut out = Vec::with_capacity(arr.len());
                    for entry in arr {
                        let Value::Bytes(b) = entry else {
                            panic!("objects entry must be bstr");
                        };
                        out.push(b);
                    }
                    objects = Some(out);
                }
                ("complete", Value::Bool(b)) => complete = Some(b),
                _ => {}
            }
        }
    }
    OkBody {
        objects: objects.expect("missing `objects`"),
        complete: complete.expect("missing `complete`"),
    }
}

/// Decoded shape of a `410 Gone` body:
/// `{ erased: [{canonical_hash, [authority,] erased_at}], objects: [...] }`.
struct GoneBody {
    erased: Vec<ErasedEntry>,
    /// Same-batch hashes that *were* available (cross-batch carry-along
    /// per §10.5.2).
    objects: Vec<Vec<u8>>,
}

struct ErasedEntry {
    canonical_hash: Vec<u8>,
    authority: Option<Vec<u8>>,
    erased_at_ms: u64,
}

fn parse_gone_body(bytes: &[u8]) -> GoneBody {
    let v: Value = ciborium::de::from_reader(bytes).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("gone body is not a map");
    };
    let mut erased: Option<Vec<ErasedEntry>> = None;
    let mut objects: Option<Vec<Vec<u8>>> = None;
    for (k, v) in m {
        if let Value::Text(t) = &k {
            match (t.as_str(), v) {
                ("erased", Value::Array(arr)) => {
                    let mut out = Vec::with_capacity(arr.len());
                    for entry in arr {
                        out.push(parse_erased_entry(entry));
                    }
                    erased = Some(out);
                }
                ("objects", Value::Array(arr)) => {
                    let mut out = Vec::with_capacity(arr.len());
                    for entry in arr {
                        let Value::Bytes(b) = entry else {
                            panic!("objects entry must be bstr");
                        };
                        out.push(b);
                    }
                    objects = Some(out);
                }
                _ => {}
            }
        }
    }
    GoneBody {
        erased: erased.expect("missing `erased`"),
        objects: objects.expect("missing `objects`"),
    }
}

fn parse_erased_entry(v: Value) -> ErasedEntry {
    let Value::Map(m) = v else {
        panic!("erased entry is not a map");
    };
    let mut canonical_hash: Option<Vec<u8>> = None;
    let mut authority: Option<Vec<u8>> = None;
    let mut erased_at_ms: Option<u64> = None;
    for (k, v) in m {
        if let Value::Text(t) = &k {
            match (t.as_str(), v) {
                ("canonical_hash", Value::Bytes(b)) => canonical_hash = Some(b),
                ("authority", Value::Bytes(b)) => authority = Some(b),
                ("erased_at", Value::Integer(i)) => {
                    let n: i128 = i.into();
                    erased_at_ms = Some(n.max(0) as u64);
                }
                _ => {}
            }
        }
    }
    ErasedEntry {
        canonical_hash: canonical_hash.expect("missing canonical_hash"),
        authority,
        erased_at_ms: erased_at_ms.expect("missing erased_at"),
    }
}

/// Partition-heal contract (Phase 8 done-when): when A has erased a
/// post-rev under a retract, D can pull the canonical_hash and recover
/// (a) the fact of erasure, (b) the retract's WireFormat as the
/// cryptographic authority, and (c) the receiver-local erased_at — without
/// leaking the erased payload itself.
#[tokio::test]
async fn by_hash_returns_410_with_authority_for_erased_row() {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;
    let a = harness.instance("a");

    let author_key = SigningKey::generate(&mut OsRng);
    let post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();

    // 1. Seed the post-rev as the erasure target.
    let post_rev = sign_post_revision_with_key(
        &author_key,
        &post_id,
        &thread_id,
        None,
        1,
        "this revision will be erased",
        1_700_000_000_000,
        vec![],
    );
    store_object(&a.state.db, "post-rev", &post_rev).await;

    // 2. Seed the retract that authorises the erasure.
    let retract = sign_retraction_with_key(&author_key, &post_id, 1_700_000_001_000);
    store_object(&a.state.db, "retract", &retract).await;

    // 3. Stamp the post-rev row as erased, with `erased_by` pointing at
    //    the retract — exactly the state a real retract dispatch leaves.
    mark_erased(
        &a.state.db,
        &post_rev.canonical_hash,
        &retract.canonical_hash,
    )
    .await;

    // 4. D asks A for the post-rev by hash. Expect 410 Gone with the
    //    retract's WireFormat as the authority.
    let body = encode_by_hash_body(&[post_rev.canonical_hash]);
    let (status, resp) = send_envelope_signed(
        &harness,
        "d",
        "a",
        Method::POST,
        "/federation/v1/backfill/by-hash",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::GONE, "erased row must be 410");

    let parsed = parse_gone_body(&resp);
    assert_eq!(parsed.erased.len(), 1, "exactly one erased entry");
    assert!(
        parsed.objects.is_empty(),
        "no same-batch available rows to carry along",
    );

    let entry = &parsed.erased[0];
    assert_eq!(
        entry.canonical_hash,
        post_rev.canonical_hash.to_vec(),
        "echoes back the canonical_hash that was asked about",
    );
    assert_eq!(
        entry.authority.as_deref(),
        Some(encode_wire(&retract.payload, &retract.signature).as_slice()),
        "authority must be the retract wrapped as §6.3 WireFormat",
    );
    assert!(
        entry.erased_at_ms > 0,
        "erased_at must be the receiver-local Unix-ms (got {})",
        entry.erased_at_ms,
    );
}

/// Hashes A has never seen at all collapse to `200 OK` + empty `objects` +
/// `complete: true` — distinct from "had it but erased". Per §10.5.2 the
/// sender treats this as "ask another peer".
#[tokio::test]
async fn by_hash_returns_200_empty_for_unknown_hash() {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;

    // Random 32 bytes — A has no signed_objects row keyed on this.
    let stranger: [u8; 32] = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

    let body = encode_by_hash_body(&[stranger]);
    let (status, resp) = send_envelope_signed(
        &harness,
        "d",
        "a",
        Method::POST,
        "/federation/v1/backfill/by-hash",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "all-unknown collapses to 200");
    let parsed = parse_ok_body(&resp);
    assert!(
        parsed.objects.is_empty(),
        "no objects served for unknown hash"
    );
    assert!(
        parsed.complete,
        "complete must be true on an all-unknown response"
    );
}

/// Mixed batch: one hash is available, one is erased. §10.5.2 requires the
/// response to be `410 Gone` (any erasure dominates) with the available
/// row's bytes still carried in `objects` alongside the erased entry — so
/// the sender doesn't have to re-ask for the non-erased ones. This also
/// exercises the available-row WireFormat serialization (the `objects`
/// carry-along) end-to-end.
#[tokio::test]
async fn by_hash_mixed_batch_returns_410_with_both_arrays() {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;
    let a = harness.instance("a");

    let author_key = SigningKey::generate(&mut OsRng);
    let kept_post_id = Uuid::new_v4();
    let erased_post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();

    // Kept post-rev — stays with payload.
    let kept = sign_post_revision_with_key(
        &author_key,
        &kept_post_id,
        &thread_id,
        None,
        1,
        "kept",
        1_700_000_000_000,
        vec![],
    );
    store_object(&a.state.db, "post-rev", &kept).await;

    // Erased post-rev plus its authorising retract.
    let doomed = sign_post_revision_with_key(
        &author_key,
        &erased_post_id,
        &thread_id,
        None,
        1,
        "doomed",
        1_700_000_002_000,
        vec![],
    );
    store_object(&a.state.db, "post-rev", &doomed).await;
    let retract = sign_retraction_with_key(&author_key, &erased_post_id, 1_700_000_003_000);
    store_object(&a.state.db, "retract", &retract).await;
    mark_erased(&a.state.db, &doomed.canonical_hash, &retract.canonical_hash).await;

    let body = encode_by_hash_body(&[kept.canonical_hash, doomed.canonical_hash]);
    let (status, resp) = send_envelope_signed(
        &harness,
        "d",
        "a",
        Method::POST,
        "/federation/v1/backfill/by-hash",
        &body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::GONE,
        "any erasure in the batch escalates the whole response to 410",
    );

    let parsed = parse_gone_body(&resp);
    assert_eq!(parsed.erased.len(), 1, "one erased entry");
    assert_eq!(
        parsed.erased[0].canonical_hash,
        doomed.canonical_hash.to_vec(),
    );
    assert_eq!(
        parsed.erased[0].authority.as_deref(),
        Some(encode_wire(&retract.payload, &retract.signature).as_slice()),
    );
    assert_eq!(
        parsed.objects.len(),
        1,
        "same-batch available row must still be carried in `objects`",
    );
    assert_eq!(
        parsed.objects[0],
        encode_wire(&kept.payload, &kept.signature),
    );
}

/// §10.5.5 receiver-side rate-limit gate fires on the 101st request from
/// the same peer inside a rolling minute. The handler shortcuts to `429`
/// + `Retry-After: 60` after well-formed pre-checks but before any DB work.
#[tokio::test]
async fn by_hash_returns_429_when_per_peer_rpm_exhausted() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // Random bytes — every request hits the "unknown hash" path and 200 OK
    // with empty `objects`. We're driving the limiter's counter past 100.
    let stranger: [u8; 32] = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let body = encode_by_hash_body(&[stranger]);

    // Saturate the per-peer minute budget.
    for i in 0..BACKFILL_RPM_PER_PEER {
        let (status, _resp) = send_envelope_signed(
            &harness,
            "b",
            "a",
            Method::POST,
            "/federation/v1/backfill/by-hash",
            &body,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "request {i} should still admit");
    }

    // 101st request from the same peer trips the limiter.
    let (status, _resp) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/backfill/by-hash",
        &body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "post-saturation request must be 429",
    );
}
