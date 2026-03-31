use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::area_name::{area_slug, validate_area_name};
use crate::error::AppError;
use crate::session::AuthUser;
use crate::state::AppState;

const MAX_AREA_DESCRIPTION_LEN: usize = 300;

#[derive(Serialize)]
pub struct AreaResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub description: String,
    pub created_by: String,
    pub created_by_name: String,
    pub created_at: String,
    pub thread_count: i64,
    pub post_count: i64,
    pub last_activity: Option<String>,
}

#[derive(Serialize)]
pub struct AreaListResponse {
    pub areas: Vec<AreaResponse>,
}

#[derive(Deserialize)]
pub struct CreateAreaRequest {
    pub name: String,
    pub description: Option<String>,
}

/// GET /api/areas — list all non-merged areas with thread/post counts.
pub async fn list_areas(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, String, String, i64, i64, Option<String>)>(
        "SELECT t.id, t.name, t.slug, t.description, t.created_by, u.display_name, t.created_at, \
         (SELECT COUNT(*) FROM threads th WHERE th.area = t.id) AS thread_count, \
         (SELECT COUNT(*) FROM posts p JOIN threads th2 ON p.thread = th2.id WHERE th2.area = t.id) AS post_count, \
         (SELECT MAX(p2.created_at) FROM posts p2 JOIN threads th3 ON p2.thread = th3.id WHERE th3.area = t.id) AS last_activity \
         FROM areas t \
         JOIN users u ON u.id = t.created_by \
         WHERE t.merged_into IS NULL \
         ORDER BY last_activity DESC NULLS LAST, t.created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;

    let areas = rows
        .into_iter()
        .map(
            |(
                id,
                name,
                slug,
                description,
                created_by,
                created_by_name,
                created_at,
                thread_count,
                post_count,
                last_activity,
            )| {
                AreaResponse {
                    id,
                    name,
                    slug,
                    description,
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

    Ok(Json(AreaListResponse { areas }))
}

/// GET /api/areas/:id — get area detail by ID or slug.
pub async fn get_area(
    State(state): State<Arc<AppState>>,
    Path(id_or_slug): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query_as::<_, (String, String, String, String, String, String, String, i64, i64, Option<String>)>(
        "SELECT t.id, t.name, t.slug, t.description, t.created_by, u.display_name, t.created_at, \
         (SELECT COUNT(*) FROM threads th WHERE th.area = t.id) AS thread_count, \
         (SELECT COUNT(*) FROM posts p JOIN threads th2 ON p.thread = th2.id WHERE th2.area = t.id) AS post_count, \
         (SELECT MAX(p2.created_at) FROM posts p2 JOIN threads th3 ON p2.thread = th3.id WHERE th3.area = t.id) AS last_activity \
         FROM areas t \
         JOIN users u ON u.id = t.created_by \
         WHERE (t.id = ? OR t.slug = ?) AND t.merged_into IS NULL",
    )
    .bind(&id_or_slug)
    .bind(&id_or_slug)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("area not found".into()))?;

    let (
        id,
        name,
        slug,
        description,
        created_by,
        created_by_name,
        created_at,
        thread_count,
        post_count,
        last_activity,
    ) = row;

    Ok(Json(AreaResponse {
        id,
        name,
        slug,
        description,
        created_by,
        created_by_name,
        created_at,
        thread_count,
        post_count,
        last_activity,
    }))
}

/// POST /api/areas — create a new area (requires auth).
pub async fn create_area(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateAreaRequest>,
) -> Result<impl IntoResponse, AppError> {
    let name = validate_area_name(&req.name).map_err(AppError::BadRequest)?;
    let slug = area_slug(&name);
    let description = req.description.as_deref().unwrap_or("").trim().to_string();

    if description.len() > MAX_AREA_DESCRIPTION_LEN {
        return Err(AppError::BadRequest("description is too long".into()));
    }

    let existing: Option<(String,)> =
        sqlx::query_as("SELECT id FROM areas WHERE slug = ? AND merged_into IS NULL")
            .bind(&slug)
            .fetch_optional(&state.db)
            .await?;

    if existing.is_some() {
        return Err(AppError::Conflict(
            "an area with that name already exists".into(),
        ));
    }

    let id = Uuid::new_v4().to_string();

    let (created_at,): (String,) = sqlx::query_as(
        "INSERT INTO areas (id, name, slug, description, created_by) VALUES (?, ?, ?, ?, ?) RETURNING created_at",
    )
    .bind(&id)
    .bind(&name)
    .bind(&slug)
    .bind(&description)
    .bind(&user.user_id)
    .fetch_one(&state.db)
    .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(AreaResponse {
            id,
            name,
            slug,
            description,
            created_by: user.user_id,
            created_by_name: user.display_name,
            created_at,
            thread_count: 0,
            post_count: 0,
            last_activity: None,
        }),
    ))
}
