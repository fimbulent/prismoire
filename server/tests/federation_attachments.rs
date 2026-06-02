#![cfg(feature = "test-auth")]
//! Cross-instance attachment-blob integration tests (§11).
//!
//! Consolidates two formerly-separate phase files into the single
//! surface they both exercise — attachment blobs crossing the instance
//! boundary, from the origin's serve gate through the receiver's
//! fetch-on-demand pipeline:
//!
//! - **§11.5 origin serve gate.** `GET /federation/v1/attachments/{hash}`
//!   returns `200 OK` with the raw blob bytes and the stored
//!   `Content-Type` only when the hash maps to a locally-resident blob
//!   bound to the *current* revision of a locally-authored,
//!   non-retracted, non-deleted-author, locally-homed post. Every other
//!   case — malformed hex, unknown hash, `blob IS NULL`, resident bytes
//!   with no local binding (forwarding-cache rule), a retracted post, a
//!   binding on a prior revision, a tombstoned author, or a post stamped
//!   with a remote `home_instance` — collapses to the same `404`
//!   `attachment_not_found` per §11.4.
//! - **§11.3 / §11.4 receiver fetch-on-demand.** The synchronous serve
//!   trigger `try_fetch_for_serve` resolves the §11 origin from
//!   `posts.home_instance`, signs a §11.2 envelope GET, hash-verifies
//!   the response per §11.3, and stores the bytes — clearing any failure
//!   row on success. A hash mismatch records a terminal `mismatch`
//!   failure (bumping the §20 counter once) that short-circuits further
//!   fetches; an unavailable origin records a `transient` failure that
//!   honours the retry backoff; a hash with no remote binding resolves
//!   to no origin and writes no failure row.
//! - **§11.6 serve-side rate limiting.** The origin serve route 429s
//!   once the requesting peer exhausts its per-peer request budget or
//!   per-peer byte budget, keyed on the envelope sender's instance
//!   pubkey.
//!
//! Layer-0 invariants (the §11.5 SQL gate in isolation, the failure
//! table's conflict-upsert semantics, hash-verification helpers) live in
//! the in-module `#[cfg(test)]` blocks in `src/federation/attachments.rs`
//! and `src/federation/attachment_fetch.rs`.
//!
//! These scenarios drive the serve handler and the fetch trigger (the
//! functions under test) directly, so they do not use the
//! [`settle`](common::federation::settle) convergence driver — there is
//! no `frontier_fanout_loop` + poll race to replace here. (The serve-gate
//! fixtures also seed synthetic non-UUID user ids like `user_alice`,
//! which `settle`'s `refresh_trust_graph` rebuild would panic parsing.)

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::http::{Method, StatusCode};
use ciborium::value::Value;
use prismoire_server::AppState;
use prismoire_server::federation::attachment_fetch::try_fetch_for_serve;
use prismoire_server::federation::attachments::{
    ATTACHMENT_BYTES_PER_MIN_PER_PEER, ATTACHMENT_RPM_PER_PEER,
};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};

// ---------------------------------------------------------------------------
// Shared hash / hex helpers — keep this crate self-contained without a
// `hex` dep.
// ---------------------------------------------------------------------------

/// Lowercase hex of a byte slice — the §3 URL form of a content hash.
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of `bytes` — the content-address a real binding would carry.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Build a fixed-content 32-byte hash from a test-local seed byte.
/// Avoids hashing real bytes when a scenario only needs distinct,
/// non-colliding hashes between cases.
fn seeded_hash(seed: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = seed;
    // Sprinkle a non-zero byte so the hex form isn't all-zeros (purely
    // cosmetic — the handler doesn't care).
    h[31] = seed.wrapping_add(0x5a);
    h
}

/// Pull the CBOR error code out of a non-200 attachment response body.
/// The handler emits `{ "error": <code> }` per §1.7.
fn parse_error_code(bytes: &[u8]) -> String {
    let v: Value = ciborium::de::from_reader(bytes).expect("cbor parse");
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
// §11.5 serve-gate fixtures
//
// The origin-only check only fires for *local* authorship, so every
// serve-gate scenario seeds a local user + thread + post + post_revision
// + attachment binding via direct SQL on the serving instance, then has a
// *peer* instance issue the envelope-signed GET. The peer is a known peer
// (active peering established) so `verify_known_peer` admits the request.
// ---------------------------------------------------------------------------

/// Minimum `users` row. `signup_method='admin'` matches the fixture style
/// elsewhere in the suite. `public_key` is seeded from the id so a
/// duplicate-user collision surfaces as a UNIQUE violation rather than
/// silent reuse.
async fn insert_local_user(db: &SqlitePool, id: &str, display_name: &str) {
    let skeleton = display_name.to_lowercase();
    let mut pubkey = [0u8; 32];
    for (i, b) in id.as_bytes().iter().take(32).enumerate() {
        pubkey[i] = *b;
    }
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
}

/// Mark a previously-inserted user as deleted by stamping `deleted_at`.
/// Used by the §11.5 author-deleted gate test.
async fn mark_user_deleted(db: &SqlitePool, id: &str) {
    sqlx::query!(
        "UPDATE users SET deleted_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?",
        id,
    )
    .execute(db)
    .await
    .expect("mark user deleted");
}

/// Ensure the `general` room exists. Idempotent: every serve-gate test
/// targets the same room so the helper can be called freely.
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

/// Insert a thread row referencing the `general` room.
async fn insert_thread(db: &SqlitePool, thread_id: &Uuid, author_id: &str) {
    let thread_id_text = thread_id.to_string();
    sqlx::query!(
        "INSERT INTO threads (id, title, author, room) \
         VALUES (?, 'attachment fixture thread', ?, 'general')",
        thread_id_text,
        author_id,
    )
    .execute(db)
    .await
    .expect("insert thread");
}

/// Insert a `posts` row with caller-controlled `revision_count`,
/// `retracted_at`, and `home_instance`. The §11.5 check joins
/// `post_attachments.revision` against `posts.revision_count - 1`, so the
/// current revision is `revision_count - 1`. `home_instance = None` means
/// locally-authored; passing `Some(pubkey)` simulates a post that arrived
/// via gossip-forwarding with the remote home stamped on the row.
async fn insert_post(
    db: &SqlitePool,
    post_id: &Uuid,
    author_id: &str,
    thread_id: &Uuid,
    revision_count: i64,
    retracted: bool,
    home_instance: Option<&[u8]>,
) {
    let post_id_text = post_id.to_string();
    let thread_id_text = thread_id.to_string();
    let retracted_at: Option<String> = if retracted {
        Some("2024-01-01T00:00:00Z".to_string())
    } else {
        None
    };
    sqlx::query!(
        "INSERT INTO posts (id, author, thread, revision_count, retracted_at, home_instance) \
         VALUES (?, ?, ?, ?, ?, ?)",
        post_id_text,
        author_id,
        thread_id_text,
        revision_count,
        retracted_at,
        home_instance,
    )
    .execute(db)
    .await
    .expect("insert post");
}

/// Insert a `post_revisions` row. Caller decides which revision number to
/// write; `post_attachments` FKs into `(post_id, revision)` so each
/// binding needs its own revision row.
async fn insert_post_revision(db: &SqlitePool, post_id: &Uuid, revision: i64) {
    let post_id_text = post_id.to_string();
    // Stand-in canonical_hash and signature — required NOT NULL but never
    // inspected by the attachment-fetch handler.
    let sig = vec![0u8; 64];
    let hash = vec![0u8; 32];
    sqlx::query!(
        "INSERT INTO post_revisions \
             (post_id, revision, body, signature, canonical_hash, created_at) \
         VALUES (?, ?, 'fixture body', ?, ?, '2024-01-01T00:00:00Z')",
        post_id_text,
        revision,
        sig,
        hash,
    )
    .execute(db)
    .await
    .expect("insert post_revision");
}

/// Insert an `attachment_blobs` row. `blob = None` exercises the
/// fetch-pending / cache-evicted §11.5 NULL branch.
async fn insert_attachment_blob(
    db: &SqlitePool,
    content_hash: &[u8; 32],
    blob: Option<&[u8]>,
    content_type: &str,
    uploader: Option<&str>,
) {
    let hash_slice: &[u8] = content_hash.as_slice();
    let size = blob.map(|b| b.len() as i64).unwrap_or(0);
    sqlx::query!(
        "INSERT INTO attachment_blobs (content_hash, blob, content_type, size, uploader) \
         VALUES (?, ?, ?, ?, ?)",
        hash_slice,
        blob,
        content_type,
        size,
        uploader,
    )
    .execute(db)
    .await
    .expect("insert attachment_blob");
}

/// Insert a `post_attachments` binding row. The AFTER INSERT trigger bumps
/// `attachment_blobs.refcount` so the binding semantics match what the
/// production bind path produces.
async fn insert_post_attachment(
    db: &SqlitePool,
    post_id: &Uuid,
    revision: i64,
    position: i64,
    content_hash: &[u8; 32],
    filename: &str,
) {
    let post_id_text = post_id.to_string();
    let hash_slice: &[u8] = content_hash.as_slice();
    sqlx::query!(
        "INSERT INTO post_attachments (post_id, revision, position, content_hash, filename) \
         VALUES (?, ?, ?, ?, ?)",
        post_id_text,
        revision,
        position,
        hash_slice,
        filename,
    )
    .execute(db)
    .await
    .expect("insert post_attachment");
}

/// Seed a 4-instance harness with active peering between "a" (the serving
/// instance) and "d" (the requesting peer). Tests drop bytes / rows
/// directly into `harness.instance("a").state.db`.
async fn harness_with_peering() -> MultiInstanceHarness {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;
    harness
}

// ---------------------------------------------------------------------------
// §11.3 / §11.4 receiver-side fixtures
//
// Two-instance harness: **A** is the §11 origin (a locally-authored post
// binds the attachment and A holds the bytes, so A's §11.5 serve gate
// passes); **B** is the receiver, holding the same content_hash as a
// fetch-pending `attachment_blobs` row (`blob = NULL`) plus a remote post
// binding. The serve trigger resolves the origin from `posts.home_instance`,
// signs a §11.2 envelope GET to A, verifies per §11.3, and stores the bytes.
// ---------------------------------------------------------------------------

/// Seed the full FK chain a serve-able §11 origin needs on `db`: local
/// user → general room → local thread → local post (rev 0, `home_instance
/// NULL`) → post_revision → `attachment_blobs` row holding `blob` under
/// key `content_hash` → current-revision binding. With `home_instance
/// NULL`, this satisfies the §11.5 serve gate so A returns 200.
async fn seed_origin(db: &SqlitePool, content_hash: &[u8; 32], blob: &[u8], content_type: &str) {
    let author = Uuid::new_v4().to_string();
    let thread = Uuid::new_v4().to_string();
    let post = Uuid::new_v4().to_string();
    let author_pub = [0xA1u8; 32];
    let author_pub_slice: &[u8] = &author_pub;
    sqlx::query!(
        "INSERT INTO users (id, display_name, signup_method, public_key, display_name_skeleton) \
         VALUES (?, 'origin-author', 'admin', ?, 'origin-author')",
        author,
        author_pub_slice,
    )
    .execute(db)
    .await
    .expect("insert origin user");
    sqlx::query!(
        "INSERT INTO rooms (id, slug, created_by) VALUES ('general', 'general', ?)",
        author,
    )
    .execute(db)
    .await
    .expect("insert room");
    sqlx::query!(
        "INSERT INTO threads (id, title, author, room) VALUES (?, 'fixture', ?, 'general')",
        thread,
        author,
    )
    .execute(db)
    .await
    .expect("insert thread");
    sqlx::query!(
        "INSERT INTO posts (id, author, thread, revision_count, home_instance) \
         VALUES (?, ?, ?, 1, NULL)",
        post,
        author,
        thread,
    )
    .execute(db)
    .await
    .expect("insert post");
    sqlx::query!(
        "INSERT INTO post_revisions (post_id, revision, body, signature, canonical_hash, created_at) \
         VALUES (?, 0, 'body', X'00', X'01', '2026-01-01T00:00:00Z')",
        post,
    )
    .execute(db)
    .await
    .expect("insert revision");
    let hash_vec: Vec<u8> = content_hash.to_vec();
    let size = blob.len() as i64;
    sqlx::query!(
        "INSERT INTO attachment_blobs (content_hash, blob, content_type, size, uploader) \
         VALUES (?, ?, ?, ?, NULL)",
        hash_vec,
        blob,
        content_type,
        size,
    )
    .execute(db)
    .await
    .expect("insert origin blob");
    sqlx::query!(
        "INSERT INTO post_attachments (post_id, revision, position, content_hash, filename) \
         VALUES (?, 0, 0, ?, 'a.png')",
        post,
        hash_vec,
    )
    .execute(db)
    .await
    .expect("insert origin binding");
}

/// Seed the receiver state Phase A's projection produces on `db`: a
/// federated user/thread/post homed at `origin_pub`, plus a fetch-pending
/// `attachment_blobs` row (`blob = NULL`) and its current-revision
/// binding. `resolve_origins` reads `origin_pub` back off the post to find
/// the §11 origin to fetch from.
async fn seed_pending_receiver(
    db: &SqlitePool,
    content_hash: &[u8; 32],
    content_type: &str,
    size: i64,
    origin_pub: &[u8; 32],
) {
    let author = Uuid::new_v4().to_string();
    let thread = Uuid::new_v4().to_string();
    let post = Uuid::new_v4().to_string();
    let author_pub = [0xB2u8; 32];
    let author_pub_slice: &[u8] = &author_pub;
    let origin_slice: &[u8] = origin_pub.as_slice();
    sqlx::query!(
        "INSERT INTO users (id, display_name, signup_method, public_key, \
                            display_name_skeleton, home_instance) \
         VALUES (?, 'remote-author', 'federated', ?, 'remote-author', ?)",
        author,
        author_pub_slice,
        origin_slice,
    )
    .execute(db)
    .await
    .expect("insert remote user");
    sqlx::query!(
        "INSERT INTO rooms (id, slug, created_by) VALUES ('general', 'general', ?)",
        author,
    )
    .execute(db)
    .await
    .expect("insert room");
    sqlx::query!(
        "INSERT INTO threads (id, title, author, room, home_instance) \
         VALUES (?, 'fixture', ?, 'general', ?)",
        thread,
        author,
        origin_slice,
    )
    .execute(db)
    .await
    .expect("insert thread");
    sqlx::query!(
        "INSERT INTO posts (id, author, thread, revision_count, home_instance) \
         VALUES (?, ?, ?, 1, ?)",
        post,
        author,
        thread,
        origin_slice,
    )
    .execute(db)
    .await
    .expect("insert remote post");
    sqlx::query!(
        "INSERT INTO post_revisions (post_id, revision, body, signature, canonical_hash, created_at) \
         VALUES (?, 0, 'body', X'00', X'02', '2026-01-01T00:00:00Z')",
        post,
    )
    .execute(db)
    .await
    .expect("insert remote revision");
    let hash_vec: Vec<u8> = content_hash.to_vec();
    sqlx::query!(
        "INSERT INTO attachment_blobs (content_hash, blob, content_type, size, uploader) \
         VALUES (?, NULL, ?, ?, NULL)",
        hash_vec,
        content_type,
        size,
    )
    .execute(db)
    .await
    .expect("insert pending blob");
    sqlx::query!(
        "INSERT INTO post_attachments (post_id, revision, position, content_hash, filename) \
         VALUES (?, 0, 0, ?, 'a.png')",
        post,
        hash_vec,
    )
    .execute(db)
    .await
    .expect("insert pending binding");
}

/// Read back the stored blob bytes for `content_hash` (NULL → None).
async fn stored_blob(db: &SqlitePool, content_hash: &[u8; 32]) -> Option<Vec<u8>> {
    let hash_vec: Vec<u8> = content_hash.to_vec();
    sqlx::query!(
        "SELECT blob FROM attachment_blobs WHERE content_hash = ?",
        hash_vec,
    )
    .fetch_one(db)
    .await
    .expect("read blob")
    .blob
}

/// Read back the durable failure row for `content_hash` as
/// `(kind, last_attempt_at)`, or `None` if no row exists.
async fn failure_row(db: &SqlitePool, content_hash: &[u8; 32]) -> Option<(String, i64)> {
    let hash_vec: Vec<u8> = content_hash.to_vec();
    sqlx::query!(
        "SELECT kind, last_attempt_at FROM attachment_fetch_failures WHERE content_hash = ?",
        hash_vec,
    )
    .fetch_optional(db)
    .await
    .expect("read failure row")
    .map(|r| (r.kind, r.last_attempt_at))
}

/// Establish mutual active peering so B's signed GET passes A's
/// `verify_known_peer`, and return `(receiver_state, origin_pubkey)`.
async fn peered_pair(harness: &MultiInstanceHarness) -> (Arc<AppState>, [u8; 32]) {
    establish_active_peering(harness, "b", "a").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    (b.state.clone(), *a.state.instance_key.public_bytes())
}

// ---------------------------------------------------------------------------
// §11.5 origin serve gate — GET /federation/v1/attachments/{hash}
// ---------------------------------------------------------------------------

/// Happy path: locally-authored, non-retracted post with a current-
/// revision binding whose blob bytes are resident on the serving instance
/// → 200 OK with the raw bytes and the stored Content-Type.
#[tokio::test]
async fn attachment_fetch_returns_200_with_bytes_for_local_origin() {
    let harness = harness_with_peering().await;
    let a = harness.instance("a");
    let db = &a.state.db;

    let author_id = "user_alice";
    insert_local_user(db, author_id, "alice").await;
    ensure_general_room(db, author_id).await;
    let thread_id = Uuid::new_v4();
    insert_thread(db, &thread_id, author_id).await;
    let post_id = Uuid::new_v4();
    insert_post(db, &post_id, author_id, &thread_id, 1, false, None).await;
    insert_post_revision(db, &post_id, 0).await;

    let hash = seeded_hash(0x01);
    let bytes = b"PNG-ISH BLOB BYTES \xff\x00\x01\x02";
    insert_attachment_blob(db, &hash, Some(bytes), "image/png", Some(author_id)).await;
    insert_post_attachment(db, &post_id, 0, 0, &hash, "fixture.png").await;

    let path = format!("/federation/v1/attachments/{}", hex_lower(&hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "local-origin blob with a current binding must serve 200",
    );
    assert_eq!(resp.as_slice(), bytes, "raw blob bytes must round-trip");
}

/// Unknown hash — no `attachment_blobs` row for it at all → 404
/// `attachment_not_found`. §11.4 collapses unknown / evicted /
/// edit-removed into the same wire shape.
#[tokio::test]
async fn attachment_fetch_returns_404_for_unknown_hash() {
    let harness = harness_with_peering().await;

    let hash = seeded_hash(0xAA);
    let path = format!("/federation/v1/attachments/{}", hex_lower(&hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

/// Malformed hex (not 64 lowercase hex chars) — handler shortcuts to 404
/// without touching the DB. The §11.4 not-here collapse applies to bad
/// inputs too.
#[tokio::test]
async fn attachment_fetch_returns_404_for_malformed_hex() {
    let harness = harness_with_peering().await;

    let path = "/federation/v1/attachments/not-a-valid-hex-string";
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

/// §11.5 forwarding-cache rule: the blob bytes are resident (we may have
/// fetched them while gossip-forwarding for another author) but no
/// `post_attachments` row binds the hash to a locally-authored post.
/// Serving would violate the spec; the handler must 404.
#[tokio::test]
async fn attachment_fetch_returns_404_when_resident_but_no_local_binding() {
    let harness = harness_with_peering().await;
    let a = harness.instance("a");
    let db = &a.state.db;

    // Blob bytes resident, but no binding row for any local post — exactly
    // the forwarding-cache state §11.5 calls out: bytes on disk, no §11
    // origin authority.
    let hash = seeded_hash(0x02);
    insert_attachment_blob(db, &hash, Some(b"opaque"), "image/jpeg", None).await;

    let path = format!("/federation/v1/attachments/{}", hex_lower(&hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

/// §11.5 fetch-pending / evicted state: a binding row exists for the hash
/// but `attachment_blobs.blob IS NULL` (the row carries metadata only).
/// 404 per §11.4.
#[tokio::test]
async fn attachment_fetch_returns_404_when_blob_bytes_null() {
    let harness = harness_with_peering().await;
    let a = harness.instance("a");
    let db = &a.state.db;

    let author_id = "user_bob";
    insert_local_user(db, author_id, "bob").await;
    ensure_general_room(db, author_id).await;
    let thread_id = Uuid::new_v4();
    insert_thread(db, &thread_id, author_id).await;
    let post_id = Uuid::new_v4();
    insert_post(db, &post_id, author_id, &thread_id, 1, false, None).await;
    insert_post_revision(db, &post_id, 0).await;

    let hash = seeded_hash(0x03);
    // Metadata row only — `blob` column intentionally NULL.
    insert_attachment_blob(db, &hash, None, "image/png", Some(author_id)).await;
    insert_post_attachment(db, &post_id, 0, 0, &hash, "fixture.png").await;

    let path = format!("/federation/v1/attachments/{}", hex_lower(&hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

/// §11.5 retracted-post case: bytes resident, binding present, but
/// `posts.retracted_at IS NOT NULL`. The handler collapses this to 404 —
/// the retraction reaches federation receivers via the §10.1 erase
/// pipeline; this serve gate is the local backstop for the receive-side
/// delete-handler having NOT yet run.
#[tokio::test]
async fn attachment_fetch_returns_404_when_post_retracted() {
    let harness = harness_with_peering().await;
    let a = harness.instance("a");
    let db = &a.state.db;

    let author_id = "user_carol";
    insert_local_user(db, author_id, "carol").await;
    ensure_general_room(db, author_id).await;
    let thread_id = Uuid::new_v4();
    insert_thread(db, &thread_id, author_id).await;
    let post_id = Uuid::new_v4();
    insert_post(db, &post_id, author_id, &thread_id, 1, true, None).await;
    insert_post_revision(db, &post_id, 0).await;

    let hash = seeded_hash(0x04);
    insert_attachment_blob(db, &hash, Some(b"bytes"), "image/png", Some(author_id)).await;
    insert_post_attachment(db, &post_id, 0, 0, &hash, "doomed.png").await;

    let path = format!("/federation/v1/attachments/{}", hex_lower(&hash));
    let (status, _resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// §11.5 prior-revision case: the post has been edited (revision_count =
/// 2, current revision = 1). The attachment row binds revision 0 — i.e.
/// the author removed it during the edit. The §11.5 check requires the
/// binding to be on the *current* revision. 404.
#[tokio::test]
async fn attachment_fetch_returns_404_when_binding_is_prior_revision() {
    let harness = harness_with_peering().await;
    let a = harness.instance("a");
    let db = &a.state.db;

    let author_id = "user_dave";
    insert_local_user(db, author_id, "dave").await;
    ensure_general_room(db, author_id).await;
    let thread_id = Uuid::new_v4();
    insert_thread(db, &thread_id, author_id).await;
    let post_id = Uuid::new_v4();
    // revision_count = 2 ⇒ current revision = 1. We only seed a binding on
    // revision 0, which is the prior (removed) one.
    insert_post(db, &post_id, author_id, &thread_id, 2, false, None).await;
    insert_post_revision(db, &post_id, 0).await;
    insert_post_revision(db, &post_id, 1).await;

    let hash = seeded_hash(0x05);
    insert_attachment_blob(db, &hash, Some(b"bytes"), "image/png", Some(author_id)).await;
    insert_post_attachment(db, &post_id, 0, 0, &hash, "removed.png").await;

    let path = format!("/federation/v1/attachments/{}", hex_lower(&hash));
    let (status, _resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Defence-in-depth: even with a current-revision binding in place, if the
/// post's author has been deleted (`users.deleted_at IS NOT NULL`) the
/// handler must 404 immediately — once a remote `deactivate` lands as a
/// `users.deleted_at` stamp, the attachment serve stops on the next
/// request rather than waiting for the orphan-GC sweep to reap the
/// binding.
#[tokio::test]
async fn attachment_fetch_returns_404_when_author_deleted() {
    let harness = harness_with_peering().await;
    let a = harness.instance("a");
    let db = &a.state.db;

    let author_id = "user_erin";
    insert_local_user(db, author_id, "erin").await;
    ensure_general_room(db, author_id).await;
    let thread_id = Uuid::new_v4();
    insert_thread(db, &thread_id, author_id).await;
    let post_id = Uuid::new_v4();
    insert_post(db, &post_id, author_id, &thread_id, 1, false, None).await;
    insert_post_revision(db, &post_id, 0).await;

    let hash = seeded_hash(0x06);
    insert_attachment_blob(db, &hash, Some(b"bytes"), "image/png", Some(author_id)).await;
    insert_post_attachment(db, &post_id, 0, 0, &hash, "fixture.png").await;

    // Sanity: pre-deletion the serve succeeds.
    let path = format!("/federation/v1/attachments/{}", hex_lower(&hash));
    let (status, _resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "pre-deletion control case must serve 200",
    );

    // Tombstone the author. The bindings stay in place — that's the point:
    // we're proving the `users.deleted_at IS NULL` gate is the thing
    // keeping the serve from succeeding, not a downstream refcount change.
    mark_user_deleted(db, author_id).await;

    let (status, _resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "post-deletion the `users.deleted_at IS NULL` gate must fire",
    );
}

/// §11.5 origin authority: a post stamped with a remote `home_instance`
/// (received via gossip-forwarding from the author's home instance) must
/// NOT serve its attachment from here even if the bytes are resident and
/// the author is a cross-instance-registered local `users` row. The §11
/// origin authority lives at the recorded `home_instance`, not at every
/// peer that ever cached the blob bytes.
///
/// Pins the `p.home_instance IS NULL` clause of the `EXISTS` subquery
/// against regression — without it, a cross-instance-registered local
/// user (§13) authoring on their remote home would pass an `author IN
/// users` check despite our not being origin.
#[tokio::test]
async fn attachment_fetch_returns_404_when_post_has_remote_home_instance() {
    let harness = harness_with_peering().await;
    let a = harness.instance("a");
    let db = &a.state.db;

    // A §13 cross-instance-registered identity that lives here but authors
    // elsewhere: the local row exists; the post itself was received via
    // gossip and carries the remote home's pubkey on the row.
    let author_id = "user_frank";
    insert_local_user(db, author_id, "frank").await;
    ensure_general_room(db, author_id).await;
    let thread_id = Uuid::new_v4();
    insert_thread(db, &thread_id, author_id).await;
    let post_id = Uuid::new_v4();

    // Arbitrary 32-byte pubkey standing in for the remote home instance's
    // identity. Any non-NULL value flips the gate.
    let remote_home_pubkey = [0xABu8; 32];
    insert_post(
        db,
        &post_id,
        author_id,
        &thread_id,
        1,
        false,
        Some(remote_home_pubkey.as_slice()),
    )
    .await;
    insert_post_revision(db, &post_id, 0).await;

    let hash = seeded_hash(0x07);
    insert_attachment_blob(db, &hash, Some(b"remote-origin bytes"), "image/png", None).await;
    insert_post_attachment(db, &post_id, 0, 0, &hash, "remote.png").await;

    let path = format!("/federation/v1/attachments/{}", hex_lower(&hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "post with `home_instance` set must not serve — we are not §11 origin",
    );
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

// ---------------------------------------------------------------------------
// §11.3 / §11.4 receiver fetch-on-demand — try_fetch_for_serve
//
// The synchronous serve trigger drives the failure-table state machine
// the local serve path (`/api/attachments/{hash}`) runs on a NULL blob.
// It wraps `fetch_attachment`, so the origin-resolution, hash-verify, and
// store steps of §11.3 are exercised end-to-end through this surface.
// ---------------------------------------------------------------------------

/// Happy path: B's trigger resolves A as origin, fetches, hash-verifies,
/// and stores the bytes — leaving no failure row.
#[tokio::test]
async fn serve_trigger_fetches_and_clears_failure_state() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, a_pub) = peered_pair(&harness).await;
    let a = harness.instance("a");

    let blob = b"servable federated bytes \x09\x08\x07".to_vec();
    let hash = sha256(&blob);

    seed_origin(&a.state.db, &hash, &blob, "image/png").await;
    seed_pending_receiver(&b_state.db, &hash, "image/png", blob.len() as i64, &a_pub).await;

    assert!(
        try_fetch_for_serve(&b_state, hash).await,
        "trigger must report the bytes are now resident",
    );
    assert_eq!(
        stored_blob(&b_state.db, &hash).await.as_deref(),
        Some(blob.as_slice()),
        "trigger must leave the verified bytes in the receiver blob",
    );
    assert!(
        failure_row(&b_state.db, &hash).await.is_none(),
        "a successful fetch must leave no failure row",
    );
}

/// A hash mismatch (A serves corrupt bytes under the requested key) is
/// discarded, bumps the §20 mismatch counter exactly once, persists a
/// terminal `mismatch` failure row, and short-circuits a second trigger
/// without a re-fetch (proven by the counter staying at 1).
#[tokio::test]
async fn serve_trigger_records_mismatch_and_is_terminal() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, a_pub) = peered_pair(&harness).await;
    let a = harness.instance("a");

    // The hash B requests is the SHA-256 of the *declared* bytes, but A is
    // seeded with a corrupt blob under that key — its bytes do not hash to
    // the key. A's content-addressed serve returns the corrupt bytes; B's
    // §11.3 check must catch the mismatch.
    let declared = b"what the reference claims".to_vec();
    let hash = sha256(&declared);
    let corrupt = b"totally different bytes".to_vec();
    assert_ne!(sha256(&corrupt), hash, "corrupt bytes must mismatch");

    seed_origin(&a.state.db, &hash, &corrupt, "image/png").await;
    seed_pending_receiver(
        &b_state.db,
        &hash,
        "image/png",
        declared.len() as i64,
        &a_pub,
    )
    .await;

    assert!(
        !try_fetch_for_serve(&b_state, hash).await,
        "a mismatch must not produce servable bytes",
    );
    assert!(
        stored_blob(&b_state.db, &hash).await.is_none(),
        "mismatched bytes must not be stored — row stays fetch-pending",
    );
    let (kind, _) = failure_row(&b_state.db, &hash)
        .await
        .expect("mismatch must persist a failure row");
    assert_eq!(kind, "mismatch", "integrity failure must be terminal");
    assert_eq!(
        b_state
            .metrics
            .attachment_hash_mismatch
            .load(Ordering::Relaxed),
        1,
        "the first attempt bumps the §20 counter once",
    );

    // A second trigger must short-circuit on the terminal row WITHOUT a
    // transport attempt — proven by the mismatch counter staying at 1 (a
    // re-fetch would re-bump it).
    assert!(!try_fetch_for_serve(&b_state, hash).await);
    assert_eq!(
        b_state
            .metrics
            .attachment_hash_mismatch
            .load(Ordering::Relaxed),
        1,
        "a terminal mismatch row must suppress further fetches",
    );
}

/// An unavailable origin (A holds no blob, so its content-addressed serve
/// 404s) records a `transient` failure that honours the retry backoff: an
/// immediate re-trigger does not re-attempt (proven by `last_attempt_at`
/// staying identical).
#[tokio::test]
async fn serve_trigger_records_transient_and_backs_off() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, a_pub) = peered_pair(&harness).await;

    // The receiver binds the hash (origin resolves to A) but A was never
    // seeded with the blob, so A's content-addressed serve 404s → every
    // candidate is Unavailable → §11.4 transient.
    let blob = b"bytes the origin does not hold".to_vec();
    let hash = sha256(&blob);
    seed_pending_receiver(&b_state.db, &hash, "image/png", blob.len() as i64, &a_pub).await;

    assert!(
        !try_fetch_for_serve(&b_state, hash).await,
        "an unavailable origin must not produce bytes",
    );
    let (kind, first_attempt) = failure_row(&b_state.db, &hash)
        .await
        .expect("a transient miss must persist a failure row");
    assert_eq!(kind, "transient");
    assert!(
        stored_blob(&b_state.db, &hash).await.is_none(),
        "transient miss leaves the row fetch-pending",
    );

    // An immediate re-trigger is inside ATTACHMENT_RETRY_BACKOFF, so it
    // must 404 WITHOUT re-attempting — proven by `last_attempt_at` staying
    // byte-for-byte identical (a re-attempt would refresh it).
    assert!(!try_fetch_for_serve(&b_state, hash).await);
    let (_, second_attempt) = failure_row(&b_state.db, &hash)
        .await
        .expect("failure row must persist across the backoff");
    assert_eq!(
        first_attempt, second_attempt,
        "within-backoff re-trigger must not refresh last_attempt_at",
    );
}

/// A hash with no remote binding resolves to no §11 origin: the trigger
/// reports false but writes no failure row (nothing to back off from, and
/// a binding may arrive later).
#[tokio::test]
async fn serve_trigger_no_origin_returns_false_without_row() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, _a_pub) = peered_pair(&harness).await;

    let unknown = sha256(b"never bound - serve trigger");

    assert!(!try_fetch_for_serve(&b_state, unknown).await);
    assert!(
        failure_row(&b_state.db, &unknown).await.is_none(),
        "a no-origin miss must not write a failure row",
    );
}

// ---------------------------------------------------------------------------
// §11.6 serve-side rate limiting on GET /federation/v1/attachments/{hash}
//
// The limiter keys on the envelope sender (the requesting peer's instance
// pubkey); we drive it into the rejecting state via its own public surface
// (cheap, in-memory) and assert the real handler returns 429 instead of
// serving the origin bytes it otherwise would.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn serve_route_429s_when_peer_exceeds_request_budget() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "b", "a").await;
    let a = harness.instance("a");
    let b_pub = *harness.instance("b").state.instance_key.public_bytes();

    let blob = b"servable bytes behind the rpm gate".to_vec();
    let hash = sha256(&blob);
    seed_origin(&a.state.db, &hash, &blob, "image/png").await;
    let path = format!("/federation/v1/attachments/{}", hex_lower(&hash));

    // Control: under budget, A is the origin and holds the bytes → 200.
    let (status, body) = send_envelope_signed(&harness, "b", "a", Method::GET, &path, b"").await;
    assert_eq!(status, StatusCode::OK, "origin must serve under budget");
    assert_eq!(body, blob, "served bytes must be the origin blob");

    // Saturate B's per-peer request window on A, then the same request that
    // just succeeded must shed.
    for _ in 0..ATTACHMENT_RPM_PER_PEER {
        a.state.attachment_serve_rate_limiter.try_admit(b_pub);
    }
    let (status, _) = send_envelope_signed(&harness, "b", "a", Method::GET, &path, b"").await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "request over the per-peer RPM budget must 429",
    );
}

#[tokio::test]
async fn serve_route_429s_when_peer_exceeds_byte_budget() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "b", "a").await;
    let a = harness.instance("a");
    let b_pub = *harness.instance("b").state.instance_key.public_bytes();

    let blob = b"servable bytes behind the byte gate".to_vec();
    let hash = sha256(&blob);
    seed_origin(&a.state.db, &hash, &blob, "image/png").await;
    let path = format!("/federation/v1/attachments/{}", hex_lower(&hash));

    // Burn B's whole per-minute byte budget on A in one charge; the
    // request-count budget is untouched, so the 429 is attributable to the
    // byte budget alone.
    a.state
        .attachment_serve_rate_limiter
        .charge_bytes(b_pub, ATTACHMENT_BYTES_PER_MIN_PER_PEER);

    let (status, _) = send_envelope_signed(&harness, "b", "a", Method::GET, &path, b"").await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "request over the per-peer byte budget must 429",
    );
}
