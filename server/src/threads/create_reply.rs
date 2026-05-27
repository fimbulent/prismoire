use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;

use crate::error::{AppError, ErrorCode};
use crate::session::AuthUser;
use crate::signing;
use crate::state::AppState;
use crate::trust::UserViewerInfo;

use super::common::{
    CreateReplyRequest, MAX_REPLY_BODY_LEN, PostResponse, RECENT_REPLIERS_BUFFER, validate_body,
};

/// Create a reply to a post within a thread.
///
/// The `parent_id` is required — every reply must have a parent. The OP
/// is the only post with parent=NULL, created at thread creation time.
/// Rejects replies to retracted posts and replies in locked threads.
///
/// Returns the new post with `children` always empty — mutation endpoints
/// return flat posts; only `get_thread` populates the nested tree.
pub async fn create_reply(
    State(state): State<Arc<AppState>>,
    Path(thread_id): Path<String>,
    user: AuthUser,
    Json(req): Json<CreateReplyRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Replies cannot carry attachments — those live on the thread OP
    // only per docs/attachments.md §3. Rejecting at request-parse time
    // gives the client a clear error instead of dropping the array
    // silently inside the signed payload.
    if !req.attachments.is_empty() {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "replies cannot carry attachments".to_string(),
        ));
    }

    let body = validate_body(&req.body, MAX_REPLY_BODY_LEN)
        .map_err(|msg| AppError::with_message(ErrorCode::InvalidPostBody, msg))?;

    let thread = sqlx::query!(
        r#"SELECT locked AS "locked: bool", author FROM threads WHERE id = ?"#,
        thread_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::ThreadNotFound))?;

    if thread.locked {
        return Err(AppError::code(ErrorCode::ThreadLocked));
    }
    let thread_author = thread.author;

    let parent = sqlx::query!(
        "SELECT id, thread, retracted_at FROM posts WHERE id = ?",
        req.parent_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::PostNotFound))?;

    if parent.thread != thread_id {
        return Err(AppError::code(ErrorCode::ParentThreadMismatch));
    }
    if parent.retracted_at.is_some() {
        return Err(AppError::code(ErrorCode::ParentRetracted));
    }
    let parent_id = parent.id;

    // Parse incoming UUID strings so the canonical CBOR payload can
    // bind them as 16-byte values. Both come from rows we just read,
    // so a parse failure is a corruption signal — treat as Internal.
    let thread_uuid = uuid::Uuid::parse_str(&thread_id).map_err(|e| {
        tracing::error!(thread_id = %thread_id, error = %e, "invalid thread UUID in row");
        AppError::code(ErrorCode::Internal)
    })?;
    let parent_uuid = uuid::Uuid::parse_str(&parent_id).map_err(|e| {
        tracing::error!(parent_id = %parent_id, error = %e, "invalid parent UUID in row");
        AppError::code(ErrorCode::Internal)
    })?;

    // Producer-side timestamp, truncated to whole seconds so the
    // signed millisecond value is reconstructable from the ISO-second
    // value we persist. See create_thread.rs for the longer rationale.
    let now_dt = chrono::Utc::now();
    let post_created_at = now_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let created_at_ms = (now_dt.timestamp() as u64) * 1000;

    let post_uuid = uuid::Uuid::new_v4();
    let post_id = post_uuid.to_string();

    let signed = signing::sign_post_revision(
        &state.db,
        &user.user_id,
        &post_uuid,
        &thread_uuid,
        Some(&parent_uuid),
        0,
        &body,
        created_at_ms,
        // Replies don't carry attachments per docs/attachments.md
        // §3 — attachments live on the thread OP only. Phase 6 will
        // reject any `attachments[]` field on the reply route at
        // request-parse time, but the signed call always gets an
        // empty vec here.
        Vec::new(),
    )
    .await?;
    let signature = signed.signature.clone();
    let canonical_hash_db: Vec<u8> = signed.canonical_hash.to_vec();

    // Wrap the entire reply creation in a single transaction. Covers:
    // posts INSERT, post_revisions INSERT, signed_objects INSERT (canonical
    // bytes), threads UPDATE (reply_count + last_activity), and the
    // recent-repliers rank rewrite below.
    let mut tx = state.db.begin().await?;

    sqlx::query!(
        "INSERT INTO posts (id, author, thread, parent, created_at) VALUES (?, ?, ?, ?, ?)",
        post_id,
        user.user_id,
        thread_id,
        parent_id,
        post_created_at,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO post_revisions (post_id, revision, body, signature, canonical_hash, created_at) \
         VALUES (?, 0, ?, ?, ?, ?)",
        post_id,
        body,
        signature,
        canonical_hash_db,
        post_created_at,
    )
    .execute(&mut *tx)
    .await?;

    // Dual-write the canonical bytes into `signed_objects`.
    signing::store_signed_object(
        &mut *tx,
        "post-rev",
        &signed.payload,
        &signed.signature,
        &signed.canonical_hash,
    )
    .await?;

    sqlx::query!(
        "UPDATE threads SET reply_count = reply_count + 1, last_activity = ? WHERE id = ?",
        post_created_at,
        thread_id,
    )
    .execute(&mut *tx)
    .await?;

    // Shift recent-repliers ranks up by 1 and insert the new reply at rank 0.
    //
    // A naive UPDATE ... SET reply_rank = reply_rank + 1 fails because SQLite
    // processes rows in arbitrary order — bumping rank 0→1 can collide with
    // the existing rank 1 row (PK violation). The fix: use negative
    // intermediate values so no two rows ever share a rank during the UPDATE.

    // 1. Trim the tail to make room after the shift.
    sqlx::query!(
        "DELETE FROM thread_recent_repliers \
         WHERE thread_id = ? AND reply_rank >= ? - 1",
        thread_id,
        RECENT_REPLIERS_BUFFER,
    )
    .execute(&mut *tx)
    .await?;

    // 2. Shift to negative intermediates: rank 0 → -1, 1 → -2, etc.
    //    All values are unique and don't collide with each other.
    sqlx::query!(
        "UPDATE thread_recent_repliers \
         SET reply_rank = -(reply_rank + 1) \
         WHERE thread_id = ?",
        thread_id,
    )
    .execute(&mut *tx)
    .await?;

    // 3. Flip back to positive: -1 → 1, -2 → 2, etc. (shifted +1).
    sqlx::query!(
        "UPDATE thread_recent_repliers \
         SET reply_rank = -reply_rank \
         WHERE thread_id = ? AND reply_rank < 0",
        thread_id,
    )
    .execute(&mut *tx)
    .await?;

    // 4. Insert new reply at rank 0.
    sqlx::query!(
        "INSERT INTO thread_recent_repliers (thread_id, reply_rank, replier_id, replied_at) \
         VALUES (?, 0, ?, ?)",
        thread_id,
        user.user_id,
        post_created_at,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // §7.5 originator-side fanout for the locally-originated reply
    // post-rev. ForwardingClass::Authored, routing key = author pubkey.
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

    Ok((
        axum::http::StatusCode::CREATED,
        Json(PostResponse {
            id: post_id,
            parent_id: Some(parent_id),
            author_id: user.user_id.clone(),
            author_name: user.display_name.clone(),
            author_public_key_hex: crate::users::hex_lower(&signed.public_key),
            body,
            created_at: post_created_at,
            edited_at: None,
            revision: 0,
            is_op: user.user_id == thread_author,
            retracted_at: None,
            children: vec![],
            viewer: UserViewerInfo::self_view(),
            has_more_children: false,
            distrust_scaffold: false,
            // Replies never carry attachments (rejected upstream by
            // the `req.attachments.is_empty()` check), so the field
            // is always empty here.
            attachments: vec![],
        }),
    ))
}
