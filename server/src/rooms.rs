use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use serde::Serialize;

use crate::error::{AppError, ErrorCode};
use crate::room_name::is_announcements;
use crate::state::AppState;

#[derive(Serialize)]
pub struct RoomResponse {
    pub id: String,
    pub slug: String,
    pub is_announcement: bool,
    pub created_by: String,
    pub created_by_name: String,
    pub created_at: String,
    pub thread_count: i64,
    pub post_count: i64,
    pub last_activity: Option<String>,
}

#[derive(Serialize)]
pub struct RoomListResponse {
    pub rooms: Vec<RoomResponse>,
}

/// Lightweight room summary for tab bars and navigation.
#[derive(Serialize)]
pub struct RoomSummary {
    pub slug: String,
    pub is_announcement: bool,
}

#[derive(Serialize)]
pub struct RoomSummaryListResponse {
    pub rooms: Vec<RoomSummary>,
}

/// GET /api/rooms/top — return the most active rooms (lightweight, for tab bar).
pub async fn top_rooms(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, (String,)>(
        "SELECT r.slug \
         FROM rooms r \
         WHERE r.merged_into IS NULL \
         ORDER BY \
           (SELECT MAX(p.created_at) FROM posts p JOIN threads t ON p.thread = t.id WHERE t.room = r.id) DESC NULLS LAST, \
           r.created_at DESC \
         LIMIT 6",
    )
    .fetch_all(&state.db)
    .await?;

    let rooms = rows
        .into_iter()
        .map(|(slug,)| {
            let is_announcement = is_announcements(&slug);
            RoomSummary {
                slug,
                is_announcement,
            }
        })
        .collect();

    Ok(Json(RoomSummaryListResponse { rooms }))
}

/// GET /api/rooms — list all non-merged rooms with thread/post counts.
pub async fn list_rooms(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, i64, i64, Option<String>)>(
        "SELECT t.id, t.slug, t.created_by, u.display_name, t.created_at, \
         (SELECT COUNT(*) FROM threads th WHERE th.room = t.id) AS thread_count, \
         (SELECT COUNT(*) FROM posts p JOIN threads th2 ON p.thread = th2.id WHERE th2.room = t.id) AS post_count, \
         (SELECT MAX(p2.created_at) FROM posts p2 JOIN threads th3 ON p2.thread = th3.id WHERE th3.room = t.id) AS last_activity \
         FROM rooms t \
         JOIN users u ON u.id = t.created_by \
         WHERE t.merged_into IS NULL \
         ORDER BY last_activity DESC NULLS LAST, t.created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;

    let rooms = rows
        .into_iter()
        .map(
            |(
                id,
                slug,
                created_by,
                created_by_name,
                created_at,
                thread_count,
                post_count,
                last_activity,
            )| {
                let is_announcement = is_announcements(&slug);
                RoomResponse {
                    id,
                    slug,
                    is_announcement,
                    created_by,
                    created_by_name,
                    created_at,
                    thread_count,
                    post_count,
                    last_activity,
                }
            },
        )
        .collect();

    Ok(Json(RoomListResponse { rooms }))
}

/// GET /api/rooms/:id — get room detail by ID or slug.
pub async fn get_room(
    State(state): State<Arc<AppState>>,
    Path(id_or_slug): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query_as::<_, (String, String, String, String, String, i64, i64, Option<String>)>(
        "SELECT t.id, t.slug, t.created_by, u.display_name, t.created_at, \
         (SELECT COUNT(*) FROM threads th WHERE th.room = t.id) AS thread_count, \
         (SELECT COUNT(*) FROM posts p JOIN threads th2 ON p.thread = th2.id WHERE th2.room = t.id) AS post_count, \
         (SELECT MAX(p2.created_at) FROM posts p2 JOIN threads th3 ON p2.thread = th3.id WHERE th3.room = t.id) AS last_activity \
         FROM rooms t \
         JOIN users u ON u.id = t.created_by \
         WHERE (t.id = ? OR t.slug = ?) AND t.merged_into IS NULL",
    )
    .bind(&id_or_slug)
    .bind(&id_or_slug)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::RoomNotFound))?;

    let (
        id,
        slug,
        created_by,
        created_by_name,
        created_at,
        thread_count,
        post_count,
        last_activity,
    ) = row;
    let is_announcement = is_announcements(&slug);

    Ok(Json(RoomResponse {
        id,
        slug,
        is_announcement,
        created_by,
        created_by_name,
        created_at,
        thread_count,
        post_count,
        last_activity,
    }))
}
