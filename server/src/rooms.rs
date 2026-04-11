use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, ErrorCode};
use crate::room_name::{room_slug, validate_room_name};
use crate::session::AuthUser;
use crate::state::AppState;

const MAX_ROOM_DESCRIPTION_LEN: usize = 300;

#[derive(Serialize)]
pub struct RoomResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub description: String,
    pub public: bool,
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

#[derive(Deserialize)]
pub struct CreateRoomRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub public: Option<bool>,
}

/// Lightweight room summary for tab bars and navigation.
#[derive(Serialize)]
pub struct RoomSummary {
    pub slug: String,
    pub name: String,
    pub public: bool,
}

#[derive(Serialize)]
pub struct RoomSummaryListResponse {
    pub rooms: Vec<RoomSummary>,
}

/// GET /api/rooms/top — return the most active rooms (lightweight, for tab bar).
pub async fn top_rooms(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, (String, String, bool)>(
        "SELECT r.slug, r.name, r.public \
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
        .map(|(slug, name, public)| RoomSummary { slug, name, public })
        .collect();

    Ok(Json(RoomSummaryListResponse { rooms }))
}

/// GET /api/rooms — list all non-merged rooms with thread/post counts.
pub async fn list_rooms(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, (String, String, String, String, bool, String, String, String, i64, i64, Option<String>)>(
        "SELECT t.id, t.name, t.slug, t.description, t.public, t.created_by, u.display_name, t.created_at, \
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
                name,
                slug,
                description,
                public,
                created_by,
                created_by_name,
                created_at,
                thread_count,
                post_count,
                last_activity,
            )| {
                RoomResponse {
                    id,
                    name,
                    slug,
                    description,
                    public,
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
    let row = sqlx::query_as::<_, (String, String, String, String, bool, String, String, String, i64, i64, Option<String>)>(
        "SELECT t.id, t.name, t.slug, t.description, t.public, t.created_by, u.display_name, t.created_at, \
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
        name,
        slug,
        description,
        public,
        created_by,
        created_by_name,
        created_at,
        thread_count,
        post_count,
        last_activity,
    ) = row;

    Ok(Json(RoomResponse {
        id,
        name,
        slug,
        description,
        public,
        created_by,
        created_by_name,
        created_at,
        thread_count,
        post_count,
        last_activity,
    }))
}

/// POST /api/rooms — create a new room (requires auth).
pub async fn create_room(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateRoomRequest>,
) -> Result<impl IntoResponse, AppError> {
    let name = validate_room_name(&req.name)
        .map_err(|msg| AppError::with_message(ErrorCode::InvalidRoomName, msg))?;
    let slug = room_slug(&name);
    let description = req.description.as_deref().unwrap_or("").trim().to_string();
    let public = req.public.unwrap_or(false) && user.is_admin();

    if description.len() > MAX_ROOM_DESCRIPTION_LEN {
        return Err(AppError::code(ErrorCode::RoomDescriptionTooLong));
    }

    let existing: Option<(String,)> =
        sqlx::query_as("SELECT id FROM rooms WHERE slug = ? AND merged_into IS NULL")
            .bind(&slug)
            .fetch_optional(&state.db)
            .await?;

    if existing.is_some() {
        return Err(AppError::code(ErrorCode::RoomAlreadyExists));
    }

    let id = Uuid::new_v4().to_string();

    let (created_at,): (String,) = sqlx::query_as(
        "INSERT INTO rooms (id, name, slug, description, public, created_by) VALUES (?, ?, ?, ?, ?, ?) RETURNING created_at",
    )
    .bind(&id)
    .bind(&name)
    .bind(&slug)
    .bind(&description)
    .bind(public)
    .bind(&user.user_id)
    .fetch_one(&state.db)
    .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(RoomResponse {
            id,
            name,
            slug,
            description,
            public,
            created_by: user.user_id,
            created_by_name: user.display_name,
            created_at,
            thread_count: 0,
            post_count: 0,
            last_activity: None,
        }),
    ))
}
