//! Phase-6 Layer-1 integration tests: §10 content + admin-rm push.
//!
//! Pins Task #23 / #24's done-when criteria from
//! `docs/federation-impl-plan.md`:
//!
//! - `POST /federation/v1/content` accepts a §10.1 batch from an
//!   active peer and stores canonical bytes for each of the six inner
//!   classes (`post-rev`, `retract`, `admin-rm`, `profile`,
//!   `thread-create`, `deactivate`).
//! - On-receipt erasure cascades fire: `retract` NULLs the matching
//!   `post-rev` payload; `admin-rm` does the same and projects into
//!   `admin_rm_authorities`; `deactivate` NULLs every payload by the
//!   target user.
//! - §10.4 receive-time precedence: once an `admin_rm_authorities`
//!   row exists for a `post_id`, subsequent `post-rev` / `retract`
//!   for the same id are rejected `admin_removed`.
//! - `wrong_class` (e.g. a `trust-edge` arriving on `/content`),
//!   `wrong_route` (advisory `admin-rm` against a locally-hosted
//!   user), `unauthorized_signer` (signing_instance ≠ sender domain),
//!   and request-level `batch_too_large` all surface with the §10.1
//!   vocabulary.
//! - `POST /federation/v1/admin-rm-report` (§10.4): queues an
//!   advisory report when we host the target, rejects
//!   `not_authoritative_home` when we don't, and de-duplicates by
//!   `post_id`.
//!
//! Layer-0 invariants (status-tag round-trip, body decoder edge
//! cases) live in the in-module `#[cfg(test)]` block in
//! `src/federation/content.rs`.

#![cfg(feature = "test-auth")]

mod common;

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use prismoire_server::federation::content::{MAX_CONTENT_BATCH, MAX_POSTREV_SIZE};
use prismoire_server::signed::TrustStance;
use prismoire_server::signing::{
    sign_admin_removal_with_instance_key, sign_deactivation_with_key, sign_post_revision_with_key,
    sign_profile_revision_with_key, sign_retraction_with_key, sign_thread_create_with_key,
    sign_trust_edge_with_key,
};
use rand::rngs::OsRng;
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};

// ---------------------------------------------------------------------------
// Body / response helpers
// ---------------------------------------------------------------------------

/// Wrap each WireFormat blob in `{ "p": payload, "s": signature }` and
/// pack the lot under `{ "objects": [bstr, ...] }`. Mirrors the
/// `encode_edges_body` shape from phase5 with `objects` as the
/// outer key per §10.1.
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

/// Decode the §10.1 `{ "results": [...] }` shape into a flat vector.
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

/// Insert a `users` row with a known Ed25519 public key. Mirrors the
/// phase5 fixture used to make a remote-author key locally projectable.
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
    // The advisory handler only checks `posts.id` exists; a minimal
    // row threads through fine. We need a thread + room first so the
    // FK chain holds.
    let post_id_text = post_id.to_string();
    let thread_id_text = thread_id.to_string();
    // Reuse an existing room if one is around, else create one.
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
    // Thread row (minimum columns).
    sqlx::query!(
        "INSERT INTO threads (id, title, author, room) \
         VALUES (?, 'placeholder', ?, 'general')",
        thread_id_text,
        author_id,
    )
    .execute(db)
    .await
    .expect("insert thread");
    // Post row referencing the same thread.
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

// ---------------------------------------------------------------------------
// Happy path: each of the six inner classes lands in signed_objects
// ---------------------------------------------------------------------------

/// Done-when: a single `post-rev` push from active-peer A reaches B
/// and the canonical bytes land in `signed_objects` with `applied`.
/// Per the Phase-6 punt, no `post_revisions` projection is asserted —
/// the wire bytes are the durable artefact while remote-user stub
/// hydration waits on a later phase.
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
/// payload for the same `post_id` is NULLed per §10.1 on-receipt
/// erasure (the §3 chain-walk artifacts — signature, hash, prior link
/// — must remain). To exercise the cascade we first push a `post-rev`
/// for the post and then push the corresponding `retract`.
#[tokio::test]
async fn content_push_retract_erases_post_rev_payload() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();

    // The erase helper subqueries `posts` joined to `post_revisions`,
    // so we need both rows to exist locally for the NULL to land on
    // the right `signed_objects.canonical_hash`. Seed users + posts
    // + post_revisions so `erase_post_rev_payloads` resolves the row.
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
    // Seed the `post_revisions` row that the erase helper enumerates.
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

    // Push the post-rev so its canonical bytes are persisted in
    // signed_objects.
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

    // The post-rev row still exists (hash, signature retained per
    // §10.1) but the payload was NULLed by the cascade.
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

/// `profile`: minimum-viable happy path. Bytes land, status applied.
#[tokio::test]
async fn content_push_profile_persists_signed_object() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice_key = SigningKey::generate(&mut OsRng);
    let signed =
        sign_profile_revision_with_key(&alice_key, "Alice", "hello", None, 1_700_000_000_000, None);
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
    assert_eq!(parse_results_body(&resp_body)[0].1, "applied");

    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let row = sqlx::query!(
        "SELECT inner_class FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("row");
    assert_eq!(row.inner_class, "profile");
}

/// `thread-create`: minimum-viable happy path.
#[tokio::test]
async fn content_push_thread_create_persists_signed_object() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice_key = SigningKey::generate(&mut OsRng);
    let thread_id = Uuid::new_v4();
    let op_post_id = Uuid::new_v4();
    let signed = sign_thread_create_with_key(
        &alice_key,
        &thread_id,
        "general",
        "First thread",
        None,
        &op_post_id,
        1_700_000_000_000,
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
    assert_eq!(parse_results_body(&resp_body)[0].1, "applied");

    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let row = sqlx::query!(
        "SELECT inner_class FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("row");
    assert_eq!(row.inner_class, "thread-create");
}

/// `deactivate`: the canonical bytes land and every previously-stored
/// signed object whose inner author key is the deactivating user has
/// its payload NULLed. Asserts the cascade by pushing a `post-rev`
/// first, then the `deactivate`, and confirming the post-rev payload
/// has been erased.
#[tokio::test]
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

// ---------------------------------------------------------------------------
// admin-rm on /content: precedence, wrong_route, unauthorized_signer
// ---------------------------------------------------------------------------

/// §10.4 receive-time admin-rm precedence: once an authoritative
/// admin-rm has been applied for a `post_id`, any subsequent
/// `post-rev` or `retract` naming the same `post_id` is rejected
/// `admin_removed`.
#[tokio::test]
async fn content_push_admin_rm_blocks_subsequent_post_rev() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    // No local user row for the target → A's admin-rm is treated as
    // authoritative by B (the "not_hosted_by_us" branch).
    let alice_key = SigningKey::generate(&mut OsRng);
    let post_id = Uuid::new_v4();

    // A signs the admin-rm with A's instance signing key. The
    // `signing_instance` must equal A's recorded `instance_domain` on
    // B (the harness sets `{label}.test.local`).
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

    // Now a post-rev for the same post_id must be rejected
    // `admin_removed`.
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

/// `wrong_route`: an admin-rm whose target is *locally hosted* (we
/// have a `users` row with that public_key) cannot be authoritative
/// from anyone but us; the sender should have used the §10.4
/// advisory route. Returns `rejected/wrong_route`.
#[tokio::test]
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

/// `unauthorized_signer`: the inner admin-rm payload's
/// `signing_instance` field does not match the envelope sender's
/// recorded `peers.instance_domain`. Receiver rejects without
/// persisting.
#[tokio::test]
async fn content_push_admin_rm_signing_instance_mismatch_unauthorized() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");
    let a = harness.instance("a");

    let target_pub = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let post_id = Uuid::new_v4();
    // Sign with a `signing_instance` string that doesn't match A's
    // domain on B (`a.test.local`).
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

// ---------------------------------------------------------------------------
// dedup, bad signature, wrong class, request-level errors
// ---------------------------------------------------------------------------

/// Replaying the same WireFormat bytes returns `duplicate` per §10.1
/// — same redelivery semantics as edges.
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
/// `/edges`). The receiver tags it `rejected/wrong_class` and does
/// not persist.
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

/// `object_too_large`: a WireFormat blob exceeding `MAX_POSTREV_SIZE`
/// is rejected per-object; the rest of the batch must still apply.
/// We pair the oversize object with a valid `post-rev` and check that
/// the small one applies.
#[tokio::test]
async fn content_push_object_too_large_is_per_object_reject() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // Oversize WireFormat: a bstr too large to be a valid signed
    // object. The handler rejects on the size check before any
    // decode, so the bytes don't have to be CBOR-valid.
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

/// Request-level errors collapse to 400 with a single `error` field
/// per the §10.1 vocabulary that mirrors §9.1.
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

    // batch_too_large. Dummy entries — receiver short-circuits on
    // length before per-object validation.
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

// ---------------------------------------------------------------------------
// /admin-rm-report (§10.4)
// ---------------------------------------------------------------------------

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

/// Happy path: B hosts the target user, A pushes an advisory
/// admin-rm. Receiver returns `queued` and the row lands in
/// `admin_rm_reports`. No propagation.
#[tokio::test]
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
