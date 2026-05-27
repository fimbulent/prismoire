//! Phase-9 Layer-1 integration tests: §11 attachment fetch-on-demand.
//!
//! Pins the Phase-9 done-when criteria from
//! `docs/federation-impl-plan.md`:
//!
//! - `GET /federation/v1/attachments/{hash}` returns `200 OK` with the
//!   raw blob bytes and the stored `Content-Type` when the requested
//!   hash maps to a locally-resident blob currently bound to a
//!   locally-authored, non-retracted, non-deleted-author post.
//! - The §11.5 origin-only check 404s when bytes are resident but no
//!   current locally-authored binding exists (forwarding-cache rule),
//!   when the binding's post is retracted, when the binding points at
//!   a prior (non-current) revision, or when the binding's author has
//!   been deleted (`users.deleted_at IS NOT NULL`). §11.4 collapses
//!   every "we don't authoritatively have this" sub-case into the
//!   same 404 shape.
//! - 404 for malformed hex (anything that isn't 64 lowercase hex
//!   chars), 404 for unknown hashes, 404 for hashes whose blob row
//!   exists but `blob IS NULL` (fetch-pending / cache-evicted).
//!
//! The §10.5.6 `410 Gone`-with-authority shape used by signed-object
//! routes is intentionally NOT tested here: attachment blobs are not
//! signed objects, they have no erasure authority of their own, and
//! §11.4 directs that edit-removal / admin-rm cases collapse to 404.
//! See the module docstring on `src/federation/attachments.rs` for
//! the full rationale.

#![cfg(feature = "test-auth")]

mod common;

use ciborium::value::Value;
use http::{Method, StatusCode};
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};

// ---------------------------------------------------------------------------
// Hex helper — keep this crate self-contained without a `hex` dep.
// ---------------------------------------------------------------------------

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("hi nibble"));
        s.push(char::from_digit((b & 0x0F) as u32, 16).expect("lo nibble"));
    }
    s
}

// ---------------------------------------------------------------------------
// Fixture seeding
//
// Phase 9 doesn't need a remote-author scenario — the §11.5 origin-only
// check only fires for *local* authorship. Every scenario here seeds a
// local user + thread + post + post_revision + attachment binding via
// direct SQL on the serving instance, then has a *peer* instance issue
// the envelope-signed GET. The peer is a known peer (active peering
// established) so `verify_known_peer` admits the request.
// ---------------------------------------------------------------------------

/// Minimum `users` row. `signup_method='admin'` matches the existing
/// fixture style elsewhere in the test suite. Returns the inserted id.
async fn insert_local_user(db: &SqlitePool, id: &str, display_name: &str) {
    let skeleton = display_name.to_lowercase();
    // public_key is required NOT NULL in some schemas — seed a stable
    // 32-byte value derived from the id so duplicate-user collisions
    // surface as a UNIQUE violation rather than silent reuse.
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
/// Used by the Phase 9 (c) defence-in-depth test that asserts the
/// `users.deleted_at IS NULL` gate fires.
async fn mark_user_deleted(db: &SqlitePool, id: &str) {
    sqlx::query!(
        "UPDATE users SET deleted_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?",
        id,
    )
    .execute(db)
    .await
    .expect("mark user deleted");
}

/// Ensure the `general` room exists. Idempotent: every test in this
/// file targets the same room so the helper can be called freely.
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
         VALUES (?, 'phase 9 fixture thread', ?, 'general')",
        thread_id_text,
        author_id,
    )
    .execute(db)
    .await
    .expect("insert thread");
}

/// Insert a `posts` row with caller-controlled `revision_count`,
/// `retracted_at`, and `home_instance`. The §11.5 check joins
/// `post_attachments.revision` against `posts.revision_count - 1`, so
/// the current revision is `revision_count - 1`. `home_instance =
/// None` means locally-authored; passing `Some(pubkey)` simulates a
/// post that arrived via gossip-forwarding with the remote home
/// stamped on the row.
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

/// Insert a `post_revisions` row. Caller decides which revision number
/// to write; `post_attachments` FKs into `(post_id, revision)` so each
/// binding needs its own revision row.
async fn insert_post_revision(db: &SqlitePool, post_id: &Uuid, revision: i64) {
    let post_id_text = post_id.to_string();
    // Stand-in canonical_hash and signature — these are required NOT
    // NULL but never inspected by the attachment-fetch handler.
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

/// Insert a `post_attachments` binding row. The AFTER INSERT trigger
/// bumps `attachment_blobs.refcount` so the binding semantics match
/// what the production bind path produces.
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

/// Build a fixed-content 32-byte hash from a test-local seed byte.
/// Avoids any dependency on the `sha2` crate just to mint distinct
/// hashes between scenarios — every test only needs hashes that don't
/// collide with each other.
fn seeded_hash(seed: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = seed;
    // Sprinkle a few non-zero bytes so the hex form isn't all-zeros
    // (purely cosmetic — the handler doesn't care).
    h[31] = seed.wrapping_add(0x5a);
    h
}

/// Convenience: seed a 4-instance harness with active peering between
/// "a" (the serving instance) and "d" (the requesting peer). Returns
/// the harness so each test can drop bytes / rows directly into
/// `harness.instance("a").state.db`.
async fn harness_with_peering() -> MultiInstanceHarness {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;
    harness
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
// Done-when scenarios
// ---------------------------------------------------------------------------

/// Happy path: locally-authored, non-retracted post with a current-
/// revision binding whose blob bytes are resident on the serving
/// instance → 200 OK with the raw bytes and the stored Content-Type.
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

    let path = format!("/federation/v1/attachments/{}", to_hex(&hash));
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
    let path = format!("/federation/v1/attachments/{}", to_hex(&hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

/// Malformed hex (not 64 lowercase hex chars) — handler shortcuts to
/// 404 without touching the DB. The §11.4 not-here collapse applies to
/// bad inputs too.
#[tokio::test]
async fn attachment_fetch_returns_404_for_malformed_hex() {
    let harness = harness_with_peering().await;

    let path = "/federation/v1/attachments/not-a-valid-hex-string";
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

/// §11.5 forwarding-cache rule: the blob bytes are resident (we may
/// have fetched them while gossip-forwarding for another author) but
/// no `post_attachments` row binds the hash to a locally-authored
/// post. Serving would violate the spec; the handler must 404.
#[tokio::test]
async fn attachment_fetch_returns_404_when_resident_but_no_local_binding() {
    let harness = harness_with_peering().await;
    let a = harness.instance("a");
    let db = &a.state.db;

    // Blob bytes resident, but we never wrote a binding row for any
    // local post. This is exactly the forwarding-cache state §11.5
    // calls out: bytes on disk, no §11 origin authority.
    let hash = seeded_hash(0x02);
    insert_attachment_blob(db, &hash, Some(b"opaque"), "image/jpeg", None).await;

    let path = format!("/federation/v1/attachments/{}", to_hex(&hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

/// §11.5 fetch-pending / evicted state: a binding row exists for the
/// hash but `attachment_blobs.blob IS NULL` (the row carries metadata
/// only). 404 per §11.4.
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

    let path = format!("/federation/v1/attachments/{}", to_hex(&hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

/// §11.5 retracted-post case: bytes resident, binding present, but
/// `posts.retracted_at IS NOT NULL`. The handler must collapse this to
/// 404 — the retraction reaches federation receivers via the §10.1
/// erase pipeline; this serve gate is the local backstop for the
/// receive-side delete-handler having NOT yet run.
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

    let path = format!("/federation/v1/attachments/{}", to_hex(&hash));
    let (status, _resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// §11.5 prior-revision case: the post has been edited (revision_count
/// = 2, current revision = 1). The attachment row binds revision 0 —
/// i.e. the author removed it during the edit. The §11.5 check
/// requires the binding to be on the *current* revision. 404.
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
    // revision_count = 2 ⇒ current revision = 1. We only seed a
    // binding on revision 0, which is the prior (removed) one.
    insert_post(db, &post_id, author_id, &thread_id, 2, false, None).await;
    insert_post_revision(db, &post_id, 0).await;
    insert_post_revision(db, &post_id, 1).await;

    let hash = seeded_hash(0x05);
    insert_attachment_blob(db, &hash, Some(b"bytes"), "image/png", Some(author_id)).await;
    insert_post_attachment(db, &post_id, 0, 0, &hash, "removed.png").await;

    let path = format!("/federation/v1/attachments/{}", to_hex(&hash));
    let (status, _resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Phase 9 (c) defence-in-depth: even with a current-revision binding
/// in place, if the post's author has been deleted
/// (`users.deleted_at IS NOT NULL`) the handler must 404 immediately.
/// Pairs with the Phase 9.5 remote-author hydration plan: once a
/// remote `deactivate` lands as a `users.deleted_at` stamp, the
/// attachment serve must stop on the next request — we don't wait
/// for the orphan-GC sweep to reap the binding.
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
    let path = format!("/federation/v1/attachments/{}", to_hex(&hash));
    let (status, _resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "pre-deletion control case must serve 200",
    );

    // Tombstone the author. The bindings stay in place — that's the
    // point: we're proving the `users.deleted_at IS NULL` gate is the
    // thing keeping the serve from succeeding, not a downstream
    // refcount adjustment.
    mark_user_deleted(db, author_id).await;

    let (status, _resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "post-deletion the `users.deleted_at IS NULL` gate must fire",
    );
}

/// §11.5 origin authority: a post stamped with a remote
/// `home_instance` (i.e. we received it via gossip-forwarding from
/// the author's home instance) must NOT serve its attachment from
/// here even if the bytes are resident and the author happens to be
/// a cross-instance-registered local `users` row. The §11 origin
/// authority lives at the recorded `home_instance`, not at every
/// peer that ever cached the blob bytes.
///
/// Pins the `p.home_instance IS NULL` clause of the `EXISTS`
/// subquery against regression — without it, a cross-instance-
/// registered local user (§13) authoring on their remote home would
/// pass an `author IN users` check despite our not being origin.
#[tokio::test]
async fn attachment_fetch_returns_404_when_post_has_remote_home_instance() {
    let harness = harness_with_peering().await;
    let a = harness.instance("a");
    let db = &a.state.db;

    // Construct a `users` row representing a §13 cross-instance-
    // registered identity that lives here but authors elsewhere.
    // The local row exists; the post itself was received via gossip
    // and carries the remote home's pubkey on the row.
    let author_id = "user_frank";
    insert_local_user(db, author_id, "frank").await;
    ensure_general_room(db, author_id).await;
    let thread_id = Uuid::new_v4();
    insert_thread(db, &thread_id, author_id).await;
    let post_id = Uuid::new_v4();

    // Arbitrary 32-byte pubkey standing in for the remote home
    // instance's identity. Any non-NULL value flips the gate.
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

    let path = format!("/federation/v1/attachments/{}", to_hex(&hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "post with `home_instance` set must not serve — we are not §11 origin",
    );
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}
