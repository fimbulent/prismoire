//! Phase B integration tests for §11.3 receiver-side attachment fetch
//! ([`prismoire_server::federation::attachment_fetch`]).
//!
//! Two-instance harness throughout: **A** is the §11 origin (a
//! locally-authored post binds the attachment and A holds the bytes, so
//! A's §11.5 serve gate passes); **B** is the receiver, holding the
//! same content_hash as a fetch-pending `attachment_blobs` row
//! (`blob = NULL`) plus a remote post binding (the shape Phase A's
//! projection produces). `fetch_attachment(&B.state, hash)` resolves
//! the origin from `posts.home_instance`, signs a §11.2 envelope GET to
//! A, verifies the response per §11.3, and stores the bytes.
//!
//! Pins:
//!
//! - **Happy path.** B fetches → A serves → bytes land in B's
//!   `attachment_blobs.blob`, hash-verified.
//! - **Hash mismatch.** A serves bytes that do not hash to the
//!   requested content_hash (a deliberately-corrupt origin row). B
//!   discards them, the §20 `attachment_hash_mismatch` counter
//!   increments, the blob stays NULL, and the call returns
//!   `FetchError::HashMismatch`.
//! - **No origin.** A hash with no remote binding resolves to no §11
//!   origin → `FetchError::NoOrigin`, no transport call.

#![cfg(feature = "test-auth")]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use prismoire_server::AppState;
use prismoire_server::federation::attachment_fetch::{
    FetchError, fetch_attachment, try_fetch_for_serve,
};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering};

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Seed the full FK chain a serve-able §11 origin needs on `db`:
/// local user → general room → local thread → local post (rev 0,
/// `home_instance NULL`) → post_revision → `attachment_blobs` row
/// holding `blob` under key `content_hash` → current-revision binding.
///
/// With `home_instance NULL` on both post and (implicitly) the local
/// author, this satisfies the §11.5 serve gate so A returns 200.
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
/// federated user/thread/post homed at `origin_pub`, plus a
/// fetch-pending `attachment_blobs` row (`blob = NULL`) and its
/// current-revision binding. `resolve_origins` reads `origin_pub` back
/// off the post to find the §11 origin to fetch from.
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

#[tokio::test]
async fn fetches_and_stores_origin_bytes() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, a_pub) = peered_pair(&harness).await;
    let a = harness.instance("a");

    let blob = b"the real attachment bytes \x01\x02\x03".to_vec();
    let hash = sha256(&blob);

    seed_origin(&a.state.db, &hash, &blob, "image/png").await;
    seed_pending_receiver(&b_state.db, &hash, "image/png", blob.len() as i64, &a_pub).await;

    fetch_attachment(&b_state, hash)
        .await
        .expect("fetch should succeed");

    assert_eq!(
        stored_blob(&b_state.db, &hash).await.as_deref(),
        Some(blob.as_slice()),
        "receiver blob must hold the origin's verified bytes",
    );
    assert_eq!(
        b_state
            .metrics
            .attachment_hash_mismatch
            .load(Ordering::Relaxed),
        0,
        "happy path must not bump the mismatch counter",
    );
}

#[tokio::test]
async fn discards_bytes_that_fail_hash_verification() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, a_pub) = peered_pair(&harness).await;
    let a = harness.instance("a");

    // The hash B requests is the SHA-256 of the *declared* bytes, but A
    // is seeded with a corrupt blob under that key — its bytes do not
    // hash to the key. A's content-addressed serve returns the corrupt
    // bytes; B's §11.3 check must catch the mismatch.
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

    let err = fetch_attachment(&b_state, hash)
        .await
        .expect_err("mismatch must fail");
    assert!(matches!(err, FetchError::HashMismatch), "got {err:?}");

    assert!(
        stored_blob(&b_state.db, &hash).await.is_none(),
        "mismatched bytes must not be stored — row stays fetch-pending",
    );
    assert_eq!(
        b_state
            .metrics
            .attachment_hash_mismatch
            .load(Ordering::Relaxed),
        1,
        "mismatch must bump the §20 counter exactly once",
    );
}

#[tokio::test]
async fn no_remote_binding_resolves_no_origin() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, _a_pub) = peered_pair(&harness).await;

    // A hash B has never bound: no post references it, so there is no
    // `posts.home_instance` to resolve a §11 origin from.
    let unknown = sha256(b"never bound anywhere");

    let err = fetch_attachment(&b_state, unknown)
        .await
        .expect_err("no origin must fail");
    assert!(matches!(err, FetchError::NoOrigin), "got {err:?}");
}

// ---------------------------------------------------------------------
// §11.4 synchronous serve trigger (`try_fetch_for_serve`) — Phase C.
// These exercise the failure-table state machine that the local serve
// path (`/api/attachments/{hash}`) drives on a NULL blob.
// ---------------------------------------------------------------------

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

#[tokio::test]
async fn serve_trigger_records_mismatch_and_is_terminal() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, a_pub) = peered_pair(&harness).await;
    let a = harness.instance("a");

    // A serves corrupt bytes under the requested key (see the Phase B
    // mismatch test for the construction).
    let declared = b"what the reference claims (c)".to_vec();
    let hash = sha256(&declared);
    let corrupt = b"corrupt origin bytes (c)".to_vec();
    assert_ne!(sha256(&corrupt), hash);

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
    // transport attempt — proven by the mismatch counter staying at 1
    // (a re-fetch would re-bump it).
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
    // must 404 WITHOUT re-attempting — proven by `last_attempt_at`
    // staying byte-for-byte identical (a re-attempt would refresh it).
    assert!(!try_fetch_for_serve(&b_state, hash).await);
    let (_, second_attempt) = failure_row(&b_state.db, &hash)
        .await
        .expect("failure row must persist across the backoff");
    assert_eq!(
        first_attempt, second_attempt,
        "within-backoff re-trigger must not refresh last_attempt_at",
    );
}

#[tokio::test]
async fn serve_trigger_no_origin_returns_false_without_row() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, _a_pub) = peered_pair(&harness).await;

    // No binding → no origin to fetch from. The trigger reports false
    // but writes no failure row: there is nothing to back off from, and
    // a binding may arrive later.
    let unknown = sha256(b"never bound - serve trigger");

    assert!(!try_fetch_for_serve(&b_state, unknown).await);
    assert!(
        failure_row(&b_state.db, &unknown).await.is_none(),
        "a no-origin miss must not write a failure row",
    );
}
