use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::error::{AppError, ErrorCode};
use crate::room_name::{is_announcements, validate_room_slug};
use crate::session::AuthUser;
use crate::signing;
use crate::state::AppState;
use crate::trust::UserViewerInfo;

use super::common::{
    MAX_BODY_LEN, PostResponse, ThreadDetailResponse, validate_body, validate_link, validate_title,
};

/// Wire request for `POST /api/threads`.
///
/// `link` and `body` together determine the thread kind:
/// - `link` is `Some` and `body` is empty/missing → link post (root post body
///   is stored as empty, the URL is what the thread is "about").
/// - `link` is `None` and `body` is non-empty → text post.
/// - Both present → link post with the body acting as framing/context.
/// - Neither present → rejected.
#[derive(Deserialize)]
pub struct CreateThreadWithRoomRequest {
    pub room: String,
    pub title: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub link: Option<String>,
}

/// Create a new thread, implicitly creating the room if it doesn't exist.
///
/// The room is identified by slug in the request body. If no room with
/// that slug exists, one is created on the fly.
pub async fn create_thread(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateThreadWithRoomRequest>,
) -> Result<impl IntoResponse, AppError> {
    let slug = validate_room_slug(&req.room)
        .map_err(|msg| AppError::with_message(ErrorCode::InvalidRoomSlug, msg))?;
    let title = validate_title(&req.title)
        .map_err(|msg| AppError::with_message(ErrorCode::InvalidThreadTitle, msg))?;

    // Link posts may have an empty body (the URL is what the thread is about).
    // Text posts must have a non-empty body. Either way, an oversized body is
    // rejected.
    let link_url = match req.link.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(
            validate_link(s)
                .map_err(|msg| AppError::with_message(ErrorCode::InvalidPostLink, msg))?,
        ),
        _ => None,
    };
    let body = if link_url.is_some() {
        let trimmed = req.body.trim().to_string();
        if trimmed.len() > MAX_BODY_LEN {
            return Err(AppError::with_message(
                ErrorCode::InvalidPostBody,
                format!("body must be at most {MAX_BODY_LEN} characters"),
            ));
        }
        trimmed
    } else {
        validate_body(&req.body, MAX_BODY_LEN)
            .map_err(|msg| AppError::with_message(ErrorCode::InvalidPostBody, msg))?
    };

    if is_announcements(&slug) && !user.is_admin() {
        return Err(AppError::code(ErrorCode::AnnouncementsAdminOnly));
    }

    let room_id = get_or_create_room(&state, &slug, &user.user_id).await?;

    let signature = signing::sign_message(&state.db, &user.user_id, body.as_bytes()).await?;

    let thread_id = uuid::Uuid::new_v4().to_string();
    let post_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    sqlx::query!(
        "INSERT INTO threads (id, title, author, room, created_at, last_activity, link_url) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        thread_id,
        title,
        user.user_id,
        room_id,
        now,
        now,
        link_url,
    )
    .execute(&state.db)
    .await?;

    sqlx::query!(
        "INSERT INTO posts (id, author, thread, created_at) VALUES (?, ?, ?, ?)",
        post_id,
        user.user_id,
        thread_id,
        now,
    )
    .execute(&state.db)
    .await?;

    sqlx::query!(
        "INSERT INTO post_revisions (post_id, revision, body, signature, created_at) VALUES (?, 0, ?, ?, ?)",
        post_id,
        body,
        signature,
        now,
    )
    .execute(&state.db)
    .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(ThreadDetailResponse {
            id: thread_id,
            title,
            author_id: user.user_id.clone(),
            author_name: user.display_name.clone(),
            room_id,
            room_slug: slug,
            created_at: now.clone(),
            locked: false,
            is_announcement: is_announcements(&req.room),
            post: PostResponse {
                id: post_id,
                parent_id: None,
                author_id: user.user_id,
                author_name: user.display_name,
                body,
                created_at: now,
                revision: 0,
                edited_at: None,
                is_op: true,
                retracted_at: None,
                children: vec![],
                viewer: UserViewerInfo::self_view(),
                has_more_children: false,
                distrust_scaffold: false,
            },
            reply_count: 0,
            total_reply_count: 0,
            has_more_replies: false,
            focused_post_id: None,
            top_level_loaded: None,
            link_url,
        }),
    ))
}

/// Look up a room by slug, creating it if it doesn't exist.
async fn get_or_create_room(
    state: &AppState,
    slug: &str,
    created_by: &str,
) -> Result<String, AppError> {
    let existing = sqlx::query!(
        "SELECT id FROM rooms WHERE slug = ? AND merged_into IS NULL",
        slug,
    )
    .fetch_optional(&state.db)
    .await?;

    if let Some(row) = existing {
        return Ok(row.id);
    }

    let id = uuid::Uuid::new_v4().to_string();
    let result = sqlx::query!(
        "INSERT INTO rooms (id, slug, created_by) VALUES (?, ?, ?)",
        id,
        slug,
        created_by,
    )
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => Ok(id),
        Err(sqlx::Error::Database(ref e)) if e.message().contains("UNIQUE") => {
            let row = sqlx::query!(
                "SELECT id FROM rooms WHERE slug = ? AND merged_into IS NULL",
                slug,
            )
            .fetch_one(&state.db)
            .await?;
            Ok(row.id)
        }
        Err(e) => Err(e.into()),
    }
}
