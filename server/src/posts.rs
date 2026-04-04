use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::session::AuthUser;
use crate::signing;
use crate::state::AppState;
use crate::threads::{PostResponse, validate_body};

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
    let post = sqlx::query_as::<_, (String, Option<String>, Option<String>)>(
        "SELECT author, retracted_at, parent FROM posts WHERE id = ?",
    )
    .bind(&post_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("post not found".into()))?;

    let (author, retracted_at, parent) = post;

    let max_len = if parent.is_some() { 10_000 } else { 50_000 };
    let body = validate_body(&req.body, max_len).map_err(AppError::BadRequest)?;

    if author != user.user_id {
        return Err(AppError::Unauthorized(
            "you can only edit your own posts".into(),
        ));
    }

    if retracted_at.is_some() {
        return Err(AppError::BadRequest("cannot edit a retracted post".into()));
    }

    let signature = signing::sign_message(&state.db, &user.user_id, body.as_bytes()).await?;

    let mut tx = state.db.begin().await?;

    let (revision_count,): (i64,) = sqlx::query_as("SELECT revision_count FROM posts WHERE id = ?")
        .bind(&post_id)
        .fetch_one(&mut *tx)
        .await?;

    let new_revision = revision_count;

    sqlx::query(
        "INSERT INTO post_revisions (post_id, revision, body, signature) VALUES (?, ?, ?, ?)",
    )
    .bind(&post_id)
    .bind(new_revision)
    .bind(&body)
    .bind(&signature)
    .execute(&mut *tx)
    .await?;

    sqlx::query("UPDATE posts SET revision_count = ? WHERE id = ?")
        .bind(new_revision + 1)
        .bind(&post_id)
        .execute(&mut *tx)
        .await?;

    let (original_at, edited_at, is_op, parent_id): (String, String, bool, Option<String>) =
        sqlx::query_as(
            "SELECT \
             (SELECT pr0.created_at FROM post_revisions pr0 WHERE pr0.post_id = ? AND pr0.revision = 0), \
             (SELECT pr1.created_at FROM post_revisions pr1 WHERE pr1.post_id = ? AND pr1.revision = ?), \
             (p.parent IS NULL), \
             p.parent \
             FROM posts p WHERE p.id = ?",
        )
        .bind(&post_id)
        .bind(&post_id)
        .bind(new_revision)
        .bind(&post_id)
        .fetch_one(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(Json(PostResponse {
        id: post_id,
        parent_id,
        author_id: user.user_id,
        author_name: user.display_name,
        body,
        created_at: original_at,
        edited_at: Some(edited_at),
        revision: new_revision,
        is_op,
        retracted_at: None,
        children: vec![],
        trust_distance: None,
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
    let post = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT author, retracted_at FROM posts WHERE id = ?",
    )
    .bind(&post_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("post not found".into()))?;

    let (author, retracted_at) = post;

    if author != user.user_id {
        return Err(AppError::Unauthorized(
            "you can only retract your own posts".into(),
        ));
    }

    if retracted_at.is_some() {
        return Err(AppError::BadRequest("post is already retracted".into()));
    }

    let retraction_message = format!("retract:{post_id}");
    let retraction_signature =
        signing::sign_message(&state.db, &user.user_id, retraction_message.as_bytes()).await?;

    sqlx::query(
        "UPDATE posts SET retracted_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
         retraction_signature = ? WHERE id = ?",
    )
    .bind(&retraction_signature)
    .bind(&post_id)
    .execute(&state.db)
    .await?;

    sqlx::query("UPDATE post_revisions SET body = '' WHERE post_id = ?")
        .bind(&post_id)
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
    Path(post_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let post = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT p.author, u.display_name, p.retracted_at \
         FROM posts p \
         JOIN users u ON u.id = p.author \
         WHERE p.id = ?",
    )
    .bind(&post_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("post not found".into()))?;

    let (author_id, author_name, retracted_at) = post;

    let rows = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT revision, body, created_at \
         FROM post_revisions \
         WHERE post_id = ? \
         ORDER BY revision ASC",
    )
    .bind(&post_id)
    .fetch_all(&state.db)
    .await?;

    let revisions = rows
        .into_iter()
        .map(|(revision, body, created_at)| RevisionResponse {
            revision,
            body,
            created_at,
        })
        .collect();

    Ok(Json(RevisionHistoryResponse {
        post_id,
        author_id,
        author_name,
        retracted_at,
        revisions,
    }))
}
