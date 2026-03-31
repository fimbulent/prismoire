use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::session::AuthUser;
use crate::state::AppState;
use crate::topic_name::{topic_slug, validate_topic_name};

const MAX_TOPIC_DESCRIPTION_LEN: usize = 300;

#[derive(Serialize)]
pub struct TopicResponse {
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
pub struct TopicListResponse {
    pub topics: Vec<TopicResponse>,
}

#[derive(Deserialize)]
pub struct CreateTopicRequest {
    pub name: String,
    pub description: Option<String>,
}

/// GET /api/topics — list all non-merged topics with thread/post counts.
pub async fn list_topics(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, String, String, i64, i64, Option<String>)>(
        "SELECT t.id, t.name, t.slug, t.description, t.created_by, u.display_name, t.created_at, \
         (SELECT COUNT(*) FROM threads th WHERE th.topic = t.id) AS thread_count, \
         (SELECT COUNT(*) FROM posts p JOIN threads th2 ON p.thread = th2.id WHERE th2.topic = t.id) AS post_count, \
         (SELECT MAX(p2.created_at) FROM posts p2 JOIN threads th3 ON p2.thread = th3.id WHERE th3.topic = t.id) AS last_activity \
         FROM topics t \
         JOIN users u ON u.id = t.created_by \
         WHERE t.merged_into IS NULL \
         ORDER BY last_activity DESC NULLS LAST, t.created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;

    let topics = rows
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
                TopicResponse {
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

    Ok(Json(TopicListResponse { topics }))
}

/// GET /api/topics/:id — get topic detail by ID or slug.
pub async fn get_topic(
    State(state): State<Arc<AppState>>,
    Path(id_or_slug): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query_as::<_, (String, String, String, String, String, String, String, i64, i64, Option<String>)>(
        "SELECT t.id, t.name, t.slug, t.description, t.created_by, u.display_name, t.created_at, \
         (SELECT COUNT(*) FROM threads th WHERE th.topic = t.id) AS thread_count, \
         (SELECT COUNT(*) FROM posts p JOIN threads th2 ON p.thread = th2.id WHERE th2.topic = t.id) AS post_count, \
         (SELECT MAX(p2.created_at) FROM posts p2 JOIN threads th3 ON p2.thread = th3.id WHERE th3.topic = t.id) AS last_activity \
         FROM topics t \
         JOIN users u ON u.id = t.created_by \
         WHERE (t.id = ? OR t.slug = ?) AND t.merged_into IS NULL",
    )
    .bind(&id_or_slug)
    .bind(&id_or_slug)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("topic not found".into()))?;

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

    Ok(Json(TopicResponse {
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

/// POST /api/topics — create a new topic (requires auth).
pub async fn create_topic(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateTopicRequest>,
) -> Result<impl IntoResponse, AppError> {
    let name = validate_topic_name(&req.name).map_err(AppError::BadRequest)?;
    let slug = topic_slug(&name);
    let description = req.description.as_deref().unwrap_or("").trim().to_string();

    if description.len() > MAX_TOPIC_DESCRIPTION_LEN {
        return Err(AppError::BadRequest("description is too long".into()));
    }

    let existing: Option<(String,)> =
        sqlx::query_as("SELECT id FROM topics WHERE slug = ? AND merged_into IS NULL")
            .bind(&slug)
            .fetch_optional(&state.db)
            .await?;

    if existing.is_some() {
        return Err(AppError::Conflict(
            "a topic with that name already exists".into(),
        ));
    }

    let id = Uuid::new_v4().to_string();

    let (created_at,): (String,) = sqlx::query_as(
        "INSERT INTO topics (id, name, slug, description, created_by) VALUES (?, ?, ?, ?, ?) RETURNING created_at",
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
        Json(TopicResponse {
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
