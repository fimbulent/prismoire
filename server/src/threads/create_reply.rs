use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;

use crate::error::{AppError, ErrorCode};
use crate::session::AuthUser;
use crate::signing;
use crate::state::AppState;
use crate::trust::TrustInfo;

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

    let signature = signing::sign_message(&state.db, &user.user_id, body.as_bytes()).await?;

    let post_id = uuid::Uuid::new_v4().to_string();

    sqlx::query!(
        "INSERT INTO posts (id, author, thread, parent) VALUES (?, ?, ?, ?)",
        post_id,
        user.user_id,
        thread_id,
        parent_id,
    )
    .execute(&state.db)
    .await?;

    sqlx::query!(
        "INSERT INTO post_revisions (post_id, revision, body, signature) VALUES (?, 0, ?, ?)",
        post_id,
        body,
        signature,
    )
    .execute(&state.db)
    .await?;

    let post_created_at = sqlx::query!(
        "SELECT created_at FROM post_revisions WHERE post_id = ? AND revision = 0",
        post_id,
    )
    .fetch_one(&state.db)
    .await?
    .created_at;

    sqlx::query!(
        "UPDATE threads SET reply_count = reply_count + 1, last_activity = ? WHERE id = ?",
        post_created_at,
        thread_id,
    )
    .execute(&state.db)
    .await?;

    // Shift recent-repliers ranks up by 1 and insert the new reply at rank 0.
    //
    // A naive UPDATE ... SET reply_rank = reply_rank + 1 fails because SQLite
    // processes rows in arbitrary order — bumping rank 0→1 can collide with
    // the existing rank 1 row (PK violation). The fix: use negative
    // intermediate values so no two rows ever share a rank during the UPDATE.
    //
    // All within a transaction to prevent concurrent interleaving.
    let mut tx = state.db.begin().await?;

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

    Ok((
        axum::http::StatusCode::CREATED,
        Json(PostResponse {
            id: post_id,
            parent_id: Some(parent_id),
            author_id: user.user_id.clone(),
            author_name: user.display_name.clone(),
            body,
            created_at: post_created_at,
            edited_at: None,
            revision: 0,
            is_op: user.user_id == thread_author,
            retracted_at: None,
            children: vec![],
            trust: TrustInfo::self_trust(),
            has_more_children: false,
            distrust_scaffold: false,
        }),
    ))
}
