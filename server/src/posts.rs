use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, ErrorCode};
use crate::session::AuthUser;
use crate::signing;
use crate::state::AppState;
use crate::threads::{PostResponse, validate_body};
use crate::trust::TrustInfo;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RevisionResponse {
    pub revision: i64,
    pub body: String,
    pub created_at: String,
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
        "SELECT author, retracted_at, parent FROM posts WHERE id = ?",
        post_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::PostNotFound))?;

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

    let signature = signing::sign_message(&state.db, &user.user_id, body.as_bytes()).await?;

    let mut tx = state.db.begin().await?;

    let rc_row = sqlx::query!(
        r#"SELECT revision_count AS "revision_count!: i64" FROM posts WHERE id = ?"#,
        post_id,
    )
    .fetch_one(&mut *tx)
    .await?;

    let new_revision = rc_row.revision_count;

    sqlx::query!(
        "INSERT INTO post_revisions (post_id, revision, body, signature) VALUES (?, ?, ?, ?)",
        post_id,
        new_revision,
        body,
        signature,
    )
    .execute(&mut *tx)
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
        trust: TrustInfo::self_trust(),
        has_more_children: false,
        distrust_scaffold: false,
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

    let retraction_message = format!("retract:{post_id}");
    let retraction_signature =
        signing::sign_message(&state.db, &user.user_id, retraction_message.as_bytes()).await?;

    sqlx::query!(
        "UPDATE posts SET retracted_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
         retraction_signature = ? WHERE id = ?",
        retraction_signature,
        post_id,
    )
    .execute(&state.db)
    .await?;

    sqlx::query!(
        "UPDATE post_revisions SET body = '' WHERE post_id = ?",
        post_id,
    )
    .execute(&state.db)
    .await?;

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

    let rows = sqlx::query!(
        "SELECT revision, body, created_at \
         FROM post_revisions \
         WHERE post_id = ? \
         ORDER BY revision ASC",
        post_id,
    )
    .fetch_all(&state.db)
    .await?;

    let revisions = rows
        .into_iter()
        .map(|r| RevisionResponse {
            revision: r.revision,
            body: r.body,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(RevisionHistoryResponse {
        post_id,
        author_id: post.author,
        author_name: post.display_name,
        retracted_at: post.retracted_at,
        revisions,
    }))
}
