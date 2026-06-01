//! §11 remote attachment projection.
//!
//! A federated `post-rev` carries its attachment set as references
//! (`content_hash` + `mime` + `size` + `filename`) inside the signed
//! canonical body; the blob bytes do not travel with it (§11
//! fetch-on-demand). On receive we project those references into the
//! same local `post_attachments` bindings a locally-authored post would
//! produce, so read paths, the §11.5 serve gate, and the eviction sweep
//! all see remote attachments the same shape as local ones.
//!
//! The blob bytes themselves stay absent: each referenced hash gets a
//! fetch-pending `attachment_blobs` row (`blob = NULL`) — the exact
//! state the cache-eviction sweep and the local serve handler already
//! treat as "bytes not resident yet". The §11.3 fetch client (Phase B)
//! is what later fills `blob` in.
//!
//! This is the receive-side mirror of
//! [`crate::attachments::bind::persist_attachment_bindings`]; the one
//! difference is that the local bind path can assume the
//! `attachment_blobs` row already exists (the uploader staged the bytes
//! first), whereas here we must create the row — with no bytes — before
//! the binding can FK to it.

use crate::signed::AttachmentRef;

/// Project a remote post-rev's signed `attachments[]` into local
/// `post_attachments` bindings, creating a fetch-pending
/// `attachment_blobs` row for any hash not already resident.
///
/// Must run inside the same transaction that just inserted the
/// `post_revisions` row for `(post_id, revision)`: `post_attachments`
/// FKs to `post_revisions(post_id, revision)`, and each binding FKs to
/// `attachment_blobs(content_hash)`, which is why the blob row is
/// inserted first.
///
/// Idempotent against an already-resident blob: the `ON CONFLICT DO
/// NOTHING` keeps existing bytes/size/mime untouched (the hash is
/// content-addressed, so a row that already holds the bytes — a local
/// upload, or a prior binding by another post — is authoritative). The
/// `post_attachments` insert is plain: it runs exactly once per
/// `(post_id, revision)` because its caller
/// ([`crate::federation::content`]'s `project_remote_post_revision`)
/// inserts the paired `post_revisions` row with a non-idempotent
/// `INSERT` immediately prior, so a duplicate projection cannot reach
/// this code.
///
/// The `AFTER INSERT` trigger on `post_attachments` bumps
/// `attachment_blobs.refcount`, so callers never touch the refcount.
pub async fn project_post_attachments(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    post_id: &str,
    revision: i64,
    refs: &[AttachmentRef],
) -> Result<(), sqlx::Error> {
    for (idx, r) in refs.iter().enumerate() {
        let position = idx as i64;
        let hash_vec: Vec<u8> = r.content_hash.to_vec();
        let size = r.size as i64;

        // Fetch-pending blob row (`blob = NULL`). `content_type` and
        // `size` are populated from the signed reference so the §4
        // placeholder UX can render "Image (200 KiB, JPEG) —
        // unavailable" before the bytes are fetched. ON CONFLICT keeps
        // an already-resident row's bytes intact.
        sqlx::query!(
            "INSERT INTO attachment_blobs (content_hash, blob, content_type, size, uploader) \
             VALUES (?, NULL, ?, ?, NULL) \
             ON CONFLICT(content_hash) DO NOTHING",
            hash_vec,
            r.mime,
            size,
        )
        .execute(&mut **tx)
        .await?;

        // Per-revision binding. Array index is the wire-canonical
        // position (the signed array carries no explicit position).
        sqlx::query!(
            "INSERT INTO post_attachments (post_id, revision, position, content_hash, filename) \
             VALUES (?, ?, ?, ?, ?)",
            post_id,
            revision,
            position,
            hash_vec,
            r.filename,
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn fresh_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("sqlite memory pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("apply migrations");
        pool
    }

    /// Insert the FK chain a `post_attachments` binding needs:
    /// user → room → thread → post (rev_count 1) → post_revision (rev 0).
    async fn seed_post(pool: &SqlitePool) {
        sqlx::query!(
            "INSERT INTO users (id, display_name, signup_method, public_key, display_name_skeleton) \
             VALUES ('user_a', 'alice', 'admin', X'00', 'alice')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO rooms (id, slug, created_by) VALUES ('general', 'general', 'user_a')"
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO threads (id, title, author, room) VALUES ('thread-1', 'fixture', 'user_a', 'general')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO posts (id, author, thread, revision_count, home_instance) \
             VALUES ('post-1', 'user_a', 'thread-1', 1, X'ABAB')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO post_revisions (post_id, revision, body, signature, canonical_hash, created_at) \
             VALUES ('post-1', 0, 'body', X'00', X'01', '2026-01-01T00:00:00Z')",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    fn aref(seed: u8, mime: &str, size: u64, filename: &str) -> AttachmentRef {
        let mut hash = [0u8; 32];
        hash[0] = seed;
        hash[31] = seed.wrapping_add(0x5a);
        AttachmentRef {
            content_hash: hash,
            mime: mime.to_string(),
            size,
            filename: filename.to_string(),
        }
    }

    #[tokio::test]
    async fn projects_bindings_and_pending_blobs() {
        let pool = fresh_pool().await;
        seed_post(&pool).await;
        let refs = vec![
            aref(0x01, "image/png", 2048, "a.png"),
            aref(0x02, "application/pdf", 4096, "b.pdf"),
        ];

        let mut tx = pool.begin().await.unwrap();
        project_post_attachments(&mut tx, "post-1", 0, &refs)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        // Two bindings, contiguous positions, correct filenames.
        let bindings = sqlx::query!(
            "SELECT position AS \"position!: i64\", \
                    content_hash AS \"content_hash!: Vec<u8>\", \
                    filename AS \"filename!: String\" \
               FROM post_attachments WHERE post_id = 'post-1' AND revision = 0 \
              ORDER BY position",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].position, 0);
        assert_eq!(bindings[0].filename, "a.png");
        assert_eq!(bindings[0].content_hash, refs[0].content_hash.to_vec());
        assert_eq!(bindings[1].position, 1);
        assert_eq!(bindings[1].filename, "b.pdf");

        // Two fetch-pending blob rows: NULL bytes, mime/size populated,
        // refcount bumped to 1 by the trigger.
        for r in &refs {
            let hash_vec: Vec<u8> = r.content_hash.to_vec();
            let row = sqlx::query!(
                "SELECT blob, content_type AS \"content_type!: String\", \
                        size AS \"size!: i64\", refcount AS \"refcount!: i64\" \
                   FROM attachment_blobs WHERE content_hash = ?",
                hash_vec,
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(row.blob.is_none(), "blob must be NULL (fetch-pending)");
            assert_eq!(row.content_type, r.mime);
            assert_eq!(row.size, r.size as i64);
            assert_eq!(row.refcount, 1);
        }
    }

    #[tokio::test]
    async fn does_not_clobber_an_already_resident_blob() {
        let pool = fresh_pool().await;
        seed_post(&pool).await;
        let r = aref(0x01, "image/png", 2048, "a.png");
        let hash_vec: Vec<u8> = r.content_hash.to_vec();

        // Bytes already resident (e.g. a local upload of identical
        // content), with the canonical size already set.
        let existing_bytes = vec![0xAB_u8; 2048];
        sqlx::query!(
            "INSERT INTO attachment_blobs (content_hash, blob, content_type, size, uploader) \
             VALUES (?, ?, 'image/png', 2048, NULL)",
            hash_vec,
            existing_bytes,
        )
        .execute(&pool)
        .await
        .unwrap();

        let mut tx = pool.begin().await.unwrap();
        project_post_attachments(&mut tx, "post-1", 0, std::slice::from_ref(&r))
            .await
            .unwrap();
        tx.commit().await.unwrap();

        // Bytes survive (ON CONFLICT DO NOTHING), and the binding was
        // added — refcount went 0 → 1.
        let row = sqlx::query!(
            "SELECT blob, refcount AS \"refcount!: i64\" \
               FROM attachment_blobs WHERE content_hash = ?",
            hash_vec,
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.blob.as_deref(), Some(existing_bytes.as_slice()));
        assert_eq!(row.refcount, 1);

        let binding_count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM post_attachments WHERE content_hash = ?",
            hash_vec,
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(binding_count, 1);
    }

    #[tokio::test]
    async fn empty_refs_is_a_noop() {
        let pool = fresh_pool().await;
        seed_post(&pool).await;

        let mut tx = pool.begin().await.unwrap();
        project_post_attachments(&mut tx, "post-1", 0, &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let n: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM post_attachments")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        let b: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM attachment_blobs")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(b, 0);
    }
}
