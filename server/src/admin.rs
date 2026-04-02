use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::session::AuthUser;
use crate::state::AppState;
use crate::threads::parse_cursor;

const LOG_PAGE_SIZE: usize = 50;

// ---------------------------------------------------------------------------
// Response / request types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct AdminLogEntry {
    pub id: String,
    pub admin_id: String,
    pub admin_name: String,
    pub action: String,
    pub thread_id: Option<String>,
    pub thread_title: Option<String>,
    pub post_id: Option<String>,
    pub room_id: Option<String>,
    pub room_name: Option<String>,
    pub reason: Option<String>,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct AdminLogResponse {
    pub entries: Vec<AdminLogEntry>,
    pub next_cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct LogPaginationParams {
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct LockThreadRequest {
    pub reason: String,
}

#[derive(Deserialize)]
pub struct RemovePostRequest {
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_admin(user: &AuthUser) -> Result<(), AppError> {
    if !user.is_admin() {
        return Err(AppError::Unauthorized("admin access required".into()));
    }
    Ok(())
}

async fn insert_admin_log(
    db: &sqlx::SqlitePool,
    admin_id: &str,
    action: &str,
    thread_id: Option<&str>,
    post_id: Option<&str>,
    room_id: Option<&str>,
    reason: Option<&str>,
) -> Result<(), AppError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO admin_log (id, admin, action, thread_id, post_id, room_id, reason) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(admin_id)
    .bind(action)
    .bind(thread_id)
    .bind(post_id)
    .bind(room_id)
    .bind(reason)
    .execute(db)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /api/admin/threads/:id/lock — lock a thread (requires reason)
// ---------------------------------------------------------------------------

pub async fn lock_thread(
    State(state): State<Arc<AppState>>,
    Path(thread_id): Path<String>,
    user: AuthUser,
    Json(req): Json<LockThreadRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let reason = req.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::BadRequest("reason is required".into()));
    }

    let thread = sqlx::query_as::<_, (String, bool)>("SELECT id, locked FROM threads WHERE id = ?")
        .bind(&thread_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".into()))?;

    let (tid, already_locked) = thread;
    if already_locked {
        return Err(AppError::BadRequest("thread is already locked".into()));
    }

    sqlx::query("UPDATE threads SET locked = 1 WHERE id = ?")
        .bind(&tid)
        .execute(&state.db)
        .await?;

    insert_admin_log(
        &state.db,
        &user.user_id,
        "lock_thread",
        Some(&tid),
        None,
        None,
        Some(&reason),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/threads/:id/lock — unlock a thread
// ---------------------------------------------------------------------------

pub async fn unlock_thread(
    State(state): State<Arc<AppState>>,
    Path(thread_id): Path<String>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let thread = sqlx::query_as::<_, (String, bool)>("SELECT id, locked FROM threads WHERE id = ?")
        .bind(&thread_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("thread not found".into()))?;

    let (tid, locked) = thread;
    if !locked {
        return Err(AppError::BadRequest("thread is not locked".into()));
    }

    sqlx::query("UPDATE threads SET locked = 0 WHERE id = ?")
        .bind(&tid)
        .execute(&state.db)
        .await?;

    insert_admin_log(
        &state.db,
        &user.user_id,
        "unlock_thread",
        Some(&tid),
        None,
        None,
        None,
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/posts/:id — remove a post (requires reason)
// ---------------------------------------------------------------------------

pub async fn remove_post(
    State(state): State<Arc<AppState>>,
    Path(post_id): Path<String>,
    user: AuthUser,
    Json(req): Json<RemovePostRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let reason = req.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::BadRequest("reason is required".into()));
    }

    let post = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT id, thread, retracted_at FROM posts WHERE id = ?",
    )
    .bind(&post_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("post not found".into()))?;

    let (pid, thread_id, retracted_at) = post;
    if retracted_at.is_some() {
        return Err(AppError::BadRequest("post is already retracted".into()));
    }

    sqlx::query(
        "UPDATE posts SET retracted_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?",
    )
    .bind(&pid)
    .execute(&state.db)
    .await?;

    sqlx::query("UPDATE post_revisions SET body = '[removed by admin]' WHERE post_id = ?")
        .bind(&pid)
        .execute(&state.db)
        .await?;

    insert_admin_log(
        &state.db,
        &user.user_id,
        "remove_post",
        Some(&thread_id),
        Some(&pid),
        None,
        Some(&reason),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /api/admin/log — public admin log (any authenticated user)
// ---------------------------------------------------------------------------

pub async fn get_admin_log(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Query(params): Query<LogPaginationParams>,
) -> Result<impl IntoResponse, AppError> {
    let rows = if let Some(ref cursor) = params.cursor {
        let (cursor_ts, cursor_id) = parse_cursor(cursor)?;

        sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            ),
        >(
            "SELECT al.id, al.admin, u.display_name, al.action, \
             al.thread_id, t.title, al.post_id, al.room_id, r.name, al.reason, al.created_at \
             FROM admin_log al \
             JOIN users u ON u.id = al.admin \
             LEFT JOIN threads t ON t.id = al.thread_id \
             LEFT JOIN rooms r ON r.id = al.room_id \
             WHERE (al.created_at < ? OR (al.created_at = ? AND al.id < ?)) \
             ORDER BY al.created_at DESC, al.id DESC \
             LIMIT ?",
        )
        .bind(&cursor_ts)
        .bind(&cursor_ts)
        .bind(&cursor_id)
        .bind(LOG_PAGE_SIZE as i64 + 1)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            ),
        >(
            "SELECT al.id, al.admin, u.display_name, al.action, \
             al.thread_id, t.title, al.post_id, al.room_id, r.name, al.reason, al.created_at \
             FROM admin_log al \
             JOIN users u ON u.id = al.admin \
             LEFT JOIN threads t ON t.id = al.thread_id \
             LEFT JOIN rooms r ON r.id = al.room_id \
             ORDER BY al.created_at DESC, al.id DESC \
             LIMIT ?",
        )
        .bind(LOG_PAGE_SIZE as i64 + 1)
        .fetch_all(&state.db)
        .await?
    };

    let has_more = rows.len() > LOG_PAGE_SIZE;
    let entries: Vec<AdminLogEntry> = rows
        .into_iter()
        .take(LOG_PAGE_SIZE)
        .map(
            |(
                id,
                admin_id,
                admin_name,
                action,
                thread_id,
                thread_title,
                post_id,
                room_id,
                room_name,
                reason,
                created_at,
            )| {
                AdminLogEntry {
                    id,
                    admin_id,
                    admin_name,
                    action,
                    thread_id,
                    thread_title,
                    post_id,
                    room_id,
                    room_name,
                    reason,
                    created_at,
                }
            },
        )
        .collect();

    let next_cursor = if has_more {
        entries.last().map(|e| format!("{}|{}", e.created_at, e.id))
    } else {
        None
    };

    Ok(Json(AdminLogResponse {
        entries,
        next_cursor,
    }))
}
