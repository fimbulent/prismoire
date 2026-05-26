use std::collections::HashSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::attachments::{
    AttachmentBindRef, gc_orphan_blobs, hex_encode, parse_hash_hex, persist_attachment_bindings,
    validate_attachments, validate_body_attachment_refs,
};
use crate::error::{AppError, ErrorCode};
use crate::session::AuthUser;
use crate::signed::SignedPayload;
use crate::signing;
use crate::state::AppState;
use crate::threads::{AttachmentResponse, PostResponse, validate_body};
use crate::trust::UserViewerInfo;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RevisionResponse {
    pub revision: i64,
    pub body: String,
    pub created_at: String,
    /// Attachments signed into this specific revision, decoded from the
    /// canonical CBOR payload in `signed_objects`. Empty for revisions
    /// whose payload has been erased (post retracted) and for replies.
    /// Each entry carries `available` indicating whether the binding +
    /// blob still exist on this post — `false` means the attachment was
    /// removed in a later revision (`docs/attachments.md` §6.1 set-diff
    /// drops bindings across all revisions) and the UI should render a
    /// "removed" placeholder instead of an image/download link.
    pub attachments: Vec<RevisionAttachmentEntry>,
}

/// Per-revision attachment entry returned by
/// `GET /api/posts/:id/revisions`. Mirrors `AttachmentResponse` plus an
/// `available` flag that distinguishes "still bound and servable" from
/// "removed in a later edit". See `RevisionResponse::attachments`.
#[derive(Serialize)]
pub struct RevisionAttachmentEntry {
    pub content_hash: String,
    pub filename: String,
    pub mime: String,
    pub size: i64,
    /// 0-based index in the signed `attachments[]` array.
    pub position: i64,
    /// `true` when a current `post_attachments` row + non-NULL blob
    /// exist for this hash on this post. `false` once the binding has
    /// been dropped by a §6.1 set-diff or the blob has been GC'd /
    /// not-yet-fetched.
    pub available: bool,
}

#[derive(Serialize)]
pub struct RevisionHistoryResponse {
    pub post_id: String,
    pub author_id: String,
    pub author_name: String,
    pub retracted_at: Option<String>,
    pub revisions: Vec<RevisionResponse>,
}

/// Request body for editing a post.
#[derive(Deserialize)]
pub struct EditPostRequest {
    pub body: String,
    /// Replacement attachment array for revision N+1
    /// (`docs/attachments.md` §6.1). Missing / empty means the edited
    /// revision drops any attachments the prior revision carried —
    /// the prior revision's `post_attachments` rows stay in place
    /// (each revision projects its own array independently). On
    /// retract every revision's binding rows are dropped together.
    #[serde(default)]
    pub attachments: Vec<AttachmentBindRef>,
}

// ---------------------------------------------------------------------------
// PATCH /api/posts/:id — edit a post (creates new revision)
// ---------------------------------------------------------------------------

/// Edit a post by creating a new revision.
///
/// Only the post author can edit. The new body is signed with the author's
/// Ed25519 key and stored as the next revision. Returns the updated post
/// with `children` always empty — mutation endpoints return flat posts;
/// only `get_thread` populates the nested tree.
pub async fn edit_post(
    State(state): State<Arc<AppState>>,
    Path(post_id): Path<String>,
    user: AuthUser,
    Json(req): Json<EditPostRequest>,
) -> Result<impl IntoResponse, AppError> {
    let post = sqlx::query!(
        "SELECT author, retracted_at, parent, thread FROM posts WHERE id = ?",
        post_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::PostNotFound))?;

    // Replies cannot carry attachments — those live on the thread OP
    // only per docs/attachments.md §3. `create_reply` rejects the same
    // shape at request-parse time; this is the mirror guard for the
    // edit path so a reply author can't smuggle bindings into a signed
    // revision by editing instead of creating.
    if post.parent.is_some() && !req.attachments.is_empty() {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "replies cannot carry attachments".to_string(),
        ));
    }

    let max_len = if post.parent.is_some() {
        10_000
    } else {
        50_000
    };
    let body = validate_body(&req.body, max_len)
        .map_err(|msg| AppError::with_message(ErrorCode::InvalidPostBody, msg))?;

    if post.author != user.user_id {
        return Err(AppError::code(ErrorCode::NotPostAuthor));
    }

    if post.retracted_at.is_some() {
        return Err(AppError::code(ErrorCode::PostRetracted));
    }

    let post_uuid = uuid::Uuid::parse_str(&post_id).map_err(|e| {
        tracing::error!(post_id = %post_id, error = %e, "invalid post UUID");
        AppError::code(ErrorCode::Internal)
    })?;
    let thread_uuid = uuid::Uuid::parse_str(&post.thread).map_err(|e| {
        tracing::error!(thread_id = %post.thread, error = %e, "invalid thread UUID in row");
        AppError::code(ErrorCode::Internal)
    })?;
    let parent_uuid = post
        .parent
        .as_deref()
        .map(uuid::Uuid::parse_str)
        .transpose()
        .map_err(|e| {
            tracing::error!(error = %e, "invalid parent UUID in row");
            AppError::code(ErrorCode::Internal)
        })?;

    // Producer-side timestamp, truncated to whole seconds so the
    // signed millisecond value is reconstructable from the ISO-second
    // value we persist. See create_thread.rs for the longer rationale.
    let now_dt = chrono::Utc::now();
    let revision_created_at = now_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let created_at_ms = (now_dt.timestamp() as u64) * 1000;

    let mut tx = state.db.begin().await?;

    let rc_row = sqlx::query!(
        r#"SELECT revision_count AS "revision_count!: i64" FROM posts WHERE id = ?"#,
        post_id,
    )
    .fetch_one(&mut *tx)
    .await?;

    // `revision_count` is INTEGER NOT NULL DEFAULT 1 and we only ever
    // increment it, but try_from guards against a corrupted negative
    // row rather than wrapping silently into a giant u64.
    let new_revision = rc_row.revision_count;
    let revision_u64 = u64::try_from(new_revision).map_err(|_| {
        tracing::error!(post_id = %post_id, revision_count = new_revision, "negative revision_count");
        AppError::code(ErrorCode::Internal)
    })?;

    // §6.1 set diff: removed = hashes(rev_N) \ hashes(rev_N+1).
    // Pull the prior revision's hash set (rev N = revision_count - 1).
    let prior_revision = new_revision - 1;
    let prior_rows = sqlx::query!(
        r#"SELECT content_hash AS "content_hash!: Vec<u8>"
             FROM post_attachments
            WHERE post_id = ? AND revision = ?"#,
        post_id,
        prior_revision,
    )
    .fetch_all(&mut *tx)
    .await?;
    let prior_hashes: std::collections::HashSet<Vec<u8>> =
        prior_rows.into_iter().map(|r| r.content_hash).collect();
    // Drop malformed entries silently here: the canonical decode +
    // wire-error mapping happens inside `validate_attachments` a few
    // lines below, so a bad `content_hash` here just means it can't
    // possibly match a prior-revision hash (set-diff misses it) and
    // the validator surfaces the proper `AttachmentNotFound` /
    // `BadRequest` to the caller.
    let new_hashes: std::collections::HashSet<Vec<u8>> = req
        .attachments
        .iter()
        .filter_map(|a| parse_hash_hex(&a.content_hash).map(|h| h.to_vec()))
        .collect();

    // For each removed hash, drop its bindings across *all* prior
    // revisions of this post (§6.1 step 3). The AFTER DELETE trigger
    // decrements `attachment_blobs.refcount`; orphan blobs get GC'd
    // below after all deletes are done.
    for hash in prior_hashes.difference(&new_hashes) {
        sqlx::query!(
            "DELETE FROM post_attachments WHERE post_id = ? AND content_hash = ?",
            post_id,
            hash,
        )
        .execute(&mut *tx)
        .await?;
    }

    // §6.1 step 2+4: resolve the new array (read-only validation).
    // Carried-over hashes are re-bound as new revision N+1 rows; the
    // blob persists via content addressing.
    let signed_attachments = validate_attachments(&mut tx, &user.user_id, &req.attachments).await?;

    // Cross-check `![](filename)` references in the edited body
    // against the new array (same predicate as create — each ref must
    // hit an image MIME and may appear at most once).
    validate_body_attachment_refs(&body, &signed_attachments)?;

    // Load the user's signing key via the same tx connection — see
    // the matching note in `create_thread.rs` for why this matters
    // under a single-connection pool.
    let signing_key = signing::load_active_signing_key(&mut *tx, &user.user_id).await?;
    let signed = signing::sign_post_revision_with_key(
        &signing_key,
        &post_uuid,
        &thread_uuid,
        parent_uuid.as_ref(),
        revision_u64,
        &body,
        created_at_ms,
        signed_attachments.clone(),
    );
    let signature = signed.signature.clone();
    let canonical_hash_db: Vec<u8> = signed.canonical_hash.to_vec();

    sqlx::query!(
        "INSERT INTO post_revisions (post_id, revision, body, signature, canonical_hash, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
        post_id,
        new_revision,
        body,
        signature,
        canonical_hash_db,
        revision_created_at,
    )
    .execute(&mut *tx)
    .await?;

    // Now that revision N+1 exists, insert its `post_attachments`
    // projection rows and drop any staging rows for the new bindings.
    persist_attachment_bindings(&mut tx, &post_id, new_revision, &signed_attachments).await?;

    // After both the §6.1-step-3 removals and the new-revision inserts:
    // GC any blob whose refcount dropped to zero and which is not
    // held by a staging row. Order matters within the transaction —
    // running GC after `persist_attachment_bindings` ensures the
    // refcount snapshot the predicate sees reflects the post-edit
    // state (new revision rows already inserted), not an intermediate
    // mid-edit state. The same `gc_orphan_blobs` predicate is reused
    // by the retract path.
    gc_orphan_blobs(&mut tx).await?;

    // Dual-write the canonical bytes into `signed_objects`.
    signing::store_signed_object(
        &mut *tx,
        "post-rev",
        &signed.payload,
        &signed.signature,
        &signed.canonical_hash,
    )
    .await?;

    let new_count = new_revision + 1;
    sqlx::query!(
        "UPDATE posts SET revision_count = ? WHERE id = ?",
        new_count,
        post_id,
    )
    .execute(&mut *tx)
    .await?;

    let meta = sqlx::query!(
        r#"SELECT
           (SELECT pr0.created_at FROM post_revisions pr0 WHERE pr0.post_id = ? AND pr0.revision = 0) AS "original_at!: String",
           (SELECT pr1.created_at FROM post_revisions pr1 WHERE pr1.post_id = ? AND pr1.revision = ?) AS "edited_at!: String",
           (p.parent IS NULL) AS "is_op!: bool",
           p.parent AS "parent_id?: String"
           FROM posts p WHERE p.id = ?"#,
        post_id,
        post_id,
        new_revision,
        post_id,
    )
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    // §7.5 originator-side fanout. Locally-originated post-rev →
    // ForwardingClass::Authored, routing key = author pubkey.
    // `arrived_from = None` because we're the origin, not a relay.
    // Phase 6.4.1: awaited inline so the enqueue is observable by the
    // time the response returns — the enqueue itself is `Mutex` +
    // `Notify` and never blocks on egress.
    let wire =
        crate::federation::envelope::encode_signed_object(&signed.payload, &signed.signature);
    crate::federation::forwarder::forward_signed_object(
        state.clone(),
        signed.canonical_hash,
        crate::federation::routing::ForwardingClass::Authored,
        signed.public_key.to_vec(),
        wire,
        None,
    )
    .await;

    // Project the just-signed array into the response shape. Only OP
    // posts can carry attachments, but reflecting the signed
    // `signed_attachments` here either way keeps the edit response
    // shape consistent with `create_thread` — replies will have an
    // empty array.
    let response_attachments: Vec<AttachmentResponse> = signed_attachments
        .iter()
        .enumerate()
        .map(|(idx, r)| AttachmentResponse {
            content_hash: hex_encode(&r.content_hash),
            filename: r.filename.clone(),
            mime: r.mime.clone(),
            size: r.size as i64,
            position: idx as i64,
        })
        .collect();

    Ok(Json(PostResponse {
        id: post_id,
        parent_id: meta.parent_id,
        author_id: user.user_id,
        author_name: user.display_name,
        body,
        created_at: meta.original_at,
        edited_at: Some(meta.edited_at),
        revision: new_revision,
        is_op: meta.is_op,
        retracted_at: None,
        children: vec![],
        viewer: UserViewerInfo::self_view(),
        has_more_children: false,
        distrust_scaffold: false,
        attachments: response_attachments,
    }))
}

// ---------------------------------------------------------------------------
// DELETE /api/posts/:id — retract a post (author only, signed)
// ---------------------------------------------------------------------------

/// Retract a post.
///
/// Sets `retracted_at` on the post, nulls out all revision bodies, and stores
/// the retraction signature. The post row remains to preserve reply tree
/// structure. Only the post author can retract.
pub async fn retract_post(
    State(state): State<Arc<AppState>>,
    Path(post_id): Path<String>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let post = sqlx::query!(
        "SELECT author, retracted_at FROM posts WHERE id = ?",
        post_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::PostNotFound))?;

    if post.author != user.user_id {
        return Err(AppError::code(ErrorCode::NotPostAuthor));
    }

    if post.retracted_at.is_some() {
        return Err(AppError::code(ErrorCode::PostAlreadyRetracted));
    }

    let post_uuid = uuid::Uuid::parse_str(&post_id).map_err(|e| {
        tracing::error!(post_id = %post_id, error = %e, "invalid post UUID");
        AppError::code(ErrorCode::Internal)
    })?;

    // Producer-side timestamp, truncated to whole seconds so the
    // signed millisecond value is reconstructable from the ISO-second
    // value we persist. See create_thread.rs for the longer rationale.
    let now_dt = chrono::Utc::now();
    let retracted_at = now_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let created_at_ms = (now_dt.timestamp() as u64) * 1000;

    let signed =
        signing::sign_retraction(&state.db, &user.user_id, &post_uuid, created_at_ms).await?;
    let retraction_signature = signed.signature.clone();

    // Wrap the two UPDATEs in a transaction. Without it, a crash
    // between them leaves a post marked retracted but with revision
    // bodies still populated — a visible-content / signed-retraction
    // inconsistency.
    let mut tx = state.db.begin().await?;
    sqlx::query!(
        "UPDATE posts SET retracted_at = ?, retraction_signature = ? WHERE id = ?",
        retracted_at,
        retraction_signature,
        post_id,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "UPDATE post_revisions SET body = '' WHERE post_id = ?",
        post_id,
    )
    .execute(&mut *tx)
    .await?;

    // §5 attachment retraction: drop every binding row for this post
    // across *all* revisions. The AFTER DELETE trigger on
    // `post_attachments` decrements refcount on the corresponding
    // `attachment_blobs` row; any blob that now has refcount=0 and is
    // not held by a staging row is GC'd inline below. This is the
    // §6.1 step-3 GC predicate reused for the retract path.
    sqlx::query!("DELETE FROM post_attachments WHERE post_id = ?", post_id,)
        .execute(&mut *tx)
        .await?;
    gc_orphan_blobs(&mut tx).await?;

    // Dual-write the canonical retraction bytes into `signed_objects`
    // alongside the projection updates.
    signing::store_signed_object(
        &mut *tx,
        "retract",
        &signed.payload,
        &signed.signature,
        &signed.canonical_hash,
    )
    .await?;

    // Erasure: a retract is an erasure authority over the post's
    // signed `post-rev` history. NULL the canonical payload bytes of
    // every prior revision so the body text only survives in places
    // that a backfill is expected to return `410 Gone` for. The
    // retract object itself is retained verbatim above; chain
    // continuity is preserved via the canonical_hash that stays in
    // place.
    signing::erase_post_rev_payloads(&mut *tx, &post_id).await?;

    tx.commit().await?;

    // §7.5 originator-side fanout for the retract. ForwardingClass::Authored,
    // routing key = author pubkey. Awaited inline after commit so a
    // tx rollback can't leak a retract that never landed locally.
    let wire =
        crate::federation::envelope::encode_signed_object(&signed.payload, &signed.signature);
    crate::federation::forwarder::forward_signed_object(
        state.clone(),
        signed.canonical_hash,
        crate::federation::routing::ForwardingClass::Authored,
        signed.public_key.to_vec(),
        wire,
        None,
    )
    .await;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /api/posts/:id/revisions — view edit history
// ---------------------------------------------------------------------------

/// Return all revisions for a post in chronological order.
///
/// If the post has been retracted, revisions are returned with empty bodies
/// (they were already nulled on retraction).
pub async fn list_revisions(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(post_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let post = sqlx::query!(
        "SELECT p.author, u.display_name, p.retracted_at \
         FROM posts p \
         JOIN users u ON u.id = p.author \
         WHERE p.id = ?",
        post_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::PostNotFound))?;

    // Pull rows for every revision plus the corresponding signed
    // payload. The LEFT JOIN tolerates erased payloads: after retract,
    // `signed_objects.payload` is NULL while `signed_objects.canonical_hash`
    // is retained for chain continuity, so we still need a row but the
    // bytes are gone (`docs/federation-protocol.md` §11.4). For those
    // revisions we surface the body/timestamps from `post_revisions`
    // and emit an empty `attachments[]` — we cannot reconstruct what
    // *was* bound without the signed bytes, but that's the same
    // information loss the retraction was meant to enforce.
    let rows = sqlx::query!(
        r#"SELECT pr.revision AS "revision!: i64",
                  pr.body AS "body!: String",
                  pr.created_at AS "created_at!: String",
                  so.payload AS "payload?: Vec<u8>"
             FROM post_revisions pr
             LEFT JOIN signed_objects so ON so.canonical_hash = pr.canonical_hash
            WHERE pr.post_id = ?
            ORDER BY pr.revision ASC"#,
        post_id,
    )
    .fetch_all(&state.db)
    .await?;

    // Build the "still available" hash set in a single query. A binding
    // is available iff a `post_attachments` row exists for (post_id,
    // content_hash) — §6.1 set-diff drops these across all revisions
    // when an attachment is removed in a later edit — AND the blob
    // bytes are present (NULL `blob` is the fetch-pending / GC'd state,
    // mirroring the 404 the serve path returns for that case).
    let available_rows = sqlx::query!(
        r#"SELECT DISTINCT pa.content_hash AS "content_hash!: Vec<u8>"
             FROM post_attachments pa
             JOIN attachment_blobs ab ON ab.content_hash = pa.content_hash
            WHERE pa.post_id = ?
              AND ab.blob IS NOT NULL"#,
        post_id,
    )
    .fetch_all(&state.db)
    .await?;
    let available: HashSet<Vec<u8>> = available_rows.into_iter().map(|r| r.content_hash).collect();

    let mut revisions = Vec::with_capacity(rows.len());
    for r in rows {
        let mut atts: Vec<RevisionAttachmentEntry> = Vec::new();
        if let Some(bytes) = r.payload.as_deref()
            && let Ok(SignedPayload::PostRevision(pr)) = SignedPayload::parse(bytes)
        {
            for (idx, a) in pr.attachments.iter().enumerate() {
                let hash_vec = a.content_hash.to_vec();
                atts.push(RevisionAttachmentEntry {
                    content_hash: hex_encode(&a.content_hash),
                    filename: a.filename.clone(),
                    mime: a.mime.clone(),
                    size: a.size as i64,
                    position: idx as i64,
                    available: available.contains(&hash_vec),
                });
            }
        }
        revisions.push(RevisionResponse {
            revision: r.revision,
            body: r.body,
            created_at: r.created_at,
            attachments: atts,
        });
    }

    Ok(Json(RevisionHistoryResponse {
        post_id,
        author_id: post.author,
        author_name: post.display_name,
        retracted_at: post.retracted_at,
        revisions,
    }))
}
