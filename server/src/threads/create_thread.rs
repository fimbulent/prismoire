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
    CreateThreadRequest, MAX_BODY_LEN, PostResponse, ThreadDetailResponse, validate_body,
    validate_title,
};

/// Create a new thread in a room.
///
/// Inserts a `threads` row, a `posts` row (the OP with parent=NULL), and a
/// `post_revisions` row (revision 0) with the body signed by the author's
/// Ed25519 signing key.
pub async fn create_thread(
    State(state): State<Arc<AppState>>,
    Path(room_id_or_slug): Path<String>,
    user: AuthUser,
    Json(req): Json<CreateThreadRequest>,
) -> Result<impl IntoResponse, AppError> {
    let title = validate_title(&req.title)
        .map_err(|msg| AppError::with_message(ErrorCode::InvalidThreadTitle, msg))?;
    let body = validate_body(&req.body, MAX_BODY_LEN)
        .map_err(|msg| AppError::with_message(ErrorCode::InvalidPostBody, msg))?;

    let room: Option<(String, bool)> = sqlx::query_as(
        "SELECT id, public FROM rooms WHERE (id = ? OR slug = ?) AND merged_into IS NULL",
    )
    .bind(&room_id_or_slug)
    .bind(&room_id_or_slug)
    .fetch_optional(&state.db)
    .await?;

    let (room_id, room_public) = room.ok_or_else(|| AppError::code(ErrorCode::RoomNotFound))?;

    if room_public && !user.is_admin() {
        return Err(AppError::code(ErrorCode::PublicRoomAdminOnly));
    }

    let signature = signing::sign_message(&state.db, &user.user_id, body.as_bytes()).await?;

    let thread_id = uuid::Uuid::new_v4().to_string();
    let post_id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO threads (id, title, author, room, last_activity) \
         VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
    )
    .bind(&thread_id)
    .bind(&title)
    .bind(&user.user_id)
    .bind(&room_id)
    .execute(&state.db)
    .await?;

    sqlx::query("INSERT INTO posts (id, author, thread) VALUES (?, ?, ?)")
        .bind(&post_id)
        .bind(&user.user_id)
        .bind(&thread_id)
        .execute(&state.db)
        .await?;

    sqlx::query(
        "INSERT INTO post_revisions (post_id, revision, body, signature) VALUES (?, 0, ?, ?)",
    )
    .bind(&post_id)
    .bind(&body)
    .bind(&signature)
    .execute(&state.db)
    .await?;

    let (created_at, fetched_room_name): (String, String) = sqlx::query_as(
        "SELECT t.created_at, r.name FROM threads t JOIN rooms r ON r.id = t.room WHERE t.id = ?",
    )
    .bind(&thread_id)
    .fetch_one(&state.db)
    .await?;

    let (post_created_at,): (String,) =
        sqlx::query_as("SELECT created_at FROM post_revisions WHERE post_id = ? AND revision = 0")
            .bind(&post_id)
            .fetch_one(&state.db)
            .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(ThreadDetailResponse {
            id: thread_id,
            title,
            author_id: user.user_id.clone(),
            author_name: user.display_name.clone(),
            room_id,
            room_name: fetched_room_name,
            room_slug: room_id_or_slug,
            created_at,
            locked: false,
            room_public,
            post: PostResponse {
                id: post_id,
                parent_id: None,
                author_id: user.user_id,
                author_name: user.display_name,
                body,
                created_at: post_created_at,
                revision: 0,
                edited_at: None,
                is_op: true,
                retracted_at: None,
                children: vec![],
                trust: TrustInfo::self_trust(),
                has_more_children: false,
            },
            reply_count: 0,
            total_reply_count: 0,
            has_more_replies: false,
            focused_post_id: None,
        }),
    ))
}
