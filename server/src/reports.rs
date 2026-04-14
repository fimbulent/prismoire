use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::admin::require_admin;
use crate::error::{AppError, ErrorCode};
use crate::session::AuthUser;
use crate::state::AppState;

const REPORTS_PAGE_SIZE: usize = 50;
const VALID_REASONS: &[&str] = &["spam", "rules_violation", "illegal_content", "other"];

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateReportRequest {
    pub reason: String,
    pub detail: Option<String>,
}

#[derive(Serialize)]
pub struct ReportResponse {
    pub id: String,
    pub post_id: String,
    pub post_body: String,
    pub post_author_id: String,
    pub post_author_name: String,
    pub post_created_at: String,
    pub thread_id: String,
    pub thread_title: String,
    pub room_slug: String,
    pub reporter_id: String,
    pub reporter_name: String,
    pub reason: String,
    pub detail: Option<String>,
    pub status: String,
    pub created_at: String,
    pub resolved_by_name: Option<String>,
    pub resolved_at: Option<String>,
    pub report_count: i64,
}

#[derive(Serialize)]
pub struct ReportListResponse {
    pub reports: Vec<ReportResponse>,
    pub next_cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct ReportListParams {
    pub status: Option<String>,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
pub struct DashboardResponse {
    pub pending_reports: i64,
}

// ---------------------------------------------------------------------------
// POST /api/posts/:id/report — report a post
// ---------------------------------------------------------------------------

/// Create a report against a post.
///
/// Validates the reason against [`VALID_REASONS`], rejects reports on
/// retracted posts, self-reports, and duplicate reports by the same user.
pub async fn create_report(
    State(state): State<Arc<AppState>>,
    Path(post_id): Path<String>,
    user: AuthUser,
    Json(req): Json<CreateReportRequest>,
) -> Result<impl IntoResponse, AppError> {
    let reason = req.reason.trim().to_lowercase();
    if !VALID_REASONS.contains(&reason.as_str()) {
        return Err(AppError::code(ErrorCode::ReportReasonInvalid));
    }

    let detail = req
        .detail
        .as_deref()
        .map(|d| d.trim())
        .filter(|d| !d.is_empty());

    let post = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT id, author, retracted_at FROM posts WHERE id = ?",
    )
    .bind(&post_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::PostNotFound))?;

    let (pid, post_author, retracted_at) = post;

    if retracted_at.is_some() {
        return Err(AppError::code(ErrorCode::PostAlreadyRetracted));
    }

    if post_author == user.user_id {
        return Err(AppError::code(ErrorCode::SelfReport));
    }

    let already_reported =
        sqlx::query_as::<_, (String,)>("SELECT id FROM reports WHERE post_id = ? AND reporter = ?")
            .bind(&pid)
            .bind(&user.user_id)
            .fetch_optional(&state.db)
            .await?
            .is_some();

    if already_reported {
        return Err(AppError::code(ErrorCode::AlreadyReported));
    }

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO reports (id, post_id, reporter, reason, detail) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&pid)
    .bind(&user.user_id)
    .bind(&reason)
    .bind(detail)
    .execute(&state.db)
    .await?;

    Ok(axum::http::StatusCode::CREATED)
}

// ---------------------------------------------------------------------------
// GET /api/admin/reports — list reports (admin only)
// ---------------------------------------------------------------------------

/// Build and execute the report list query.
///
/// Reports are grouped by post_id so the admin sees one entry per reported
/// post with the aggregate report count. The newest report per post drives
/// the sort order. Cursor pagination uses `(created_at, id)`.
pub async fn list_reports(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<ReportListParams>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let status_filter = params.status.as_deref().unwrap_or("pending").to_lowercase();

    // Query fetches grouped reports: one row per post, with the most recent
    // report's data and the total report count for that post.
    //
    // Two literal query strings instead of format!() so no dynamic SQL
    // construction is involved — all variable parts go through bind params.
    let rows = if let Some(ref cursor) = params.cursor {
        let (cursor_ts, cursor_id) = crate::threads::parse_cursor(cursor)?;
        sqlx::query(
            "SELECT r.id AS report_id, r.post_id, \
                    COALESCE(pr.body, '') AS post_body, \
                    p.author AS post_author_id, \
                    pu.display_name AS post_author_name, \
                    p.created_at AS post_created_at, \
                    p.thread AS thread_id, \
                    t.title AS thread_title, \
                    rm.slug AS room_slug, \
                    r.reporter, \
                    ru.display_name AS reporter_name, \
                    r.reason, r.detail, r.status, r.created_at AS report_created_at, \
                    res.display_name AS resolved_by_name, \
                    r.resolved_at, \
                    (SELECT COUNT(*) FROM reports r2 WHERE r2.post_id = r.post_id AND r2.status = ?) AS report_count \
             FROM reports r \
             JOIN posts p ON p.id = r.post_id \
             LEFT JOIN post_revisions pr ON pr.post_id = p.id \
                  AND pr.revision = (SELECT MAX(revision) FROM post_revisions WHERE post_id = p.id) \
             JOIN threads t ON t.id = p.thread \
             JOIN rooms rm ON rm.id = t.room \
             JOIN users pu ON pu.id = p.author \
             JOIN users ru ON ru.id = r.reporter \
             LEFT JOIN users res ON res.id = r.resolved_by \
             WHERE r.status = ? \
               AND r.id = ( \
                   SELECT r3.id FROM reports r3 \
                   WHERE r3.post_id = r.post_id AND r3.status = ? \
                   ORDER BY r3.created_at DESC LIMIT 1 \
               ) \
               AND (r.created_at < ? OR (r.created_at = ? AND r.id < ?)) \
             ORDER BY r.created_at DESC, r.id DESC LIMIT ?",
        )
        .bind(&status_filter)
        .bind(&status_filter)
        .bind(&status_filter)
        .bind(&cursor_ts)
        .bind(&cursor_ts)
        .bind(&cursor_id)
        .bind(REPORTS_PAGE_SIZE as i64 + 1)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query(
            "SELECT r.id AS report_id, r.post_id, \
                    COALESCE(pr.body, '') AS post_body, \
                    p.author AS post_author_id, \
                    pu.display_name AS post_author_name, \
                    p.created_at AS post_created_at, \
                    p.thread AS thread_id, \
                    t.title AS thread_title, \
                    rm.slug AS room_slug, \
                    r.reporter, \
                    ru.display_name AS reporter_name, \
                    r.reason, r.detail, r.status, r.created_at AS report_created_at, \
                    res.display_name AS resolved_by_name, \
                    r.resolved_at, \
                    (SELECT COUNT(*) FROM reports r2 WHERE r2.post_id = r.post_id AND r2.status = ?) AS report_count \
             FROM reports r \
             JOIN posts p ON p.id = r.post_id \
             LEFT JOIN post_revisions pr ON pr.post_id = p.id \
                  AND pr.revision = (SELECT MAX(revision) FROM post_revisions WHERE post_id = p.id) \
             JOIN threads t ON t.id = p.thread \
             JOIN rooms rm ON rm.id = t.room \
             JOIN users pu ON pu.id = p.author \
             JOIN users ru ON ru.id = r.reporter \
             LEFT JOIN users res ON res.id = r.resolved_by \
             WHERE r.status = ? \
               AND r.id = ( \
                   SELECT r3.id FROM reports r3 \
                   WHERE r3.post_id = r.post_id AND r3.status = ? \
                   ORDER BY r3.created_at DESC LIMIT 1 \
               ) \
             ORDER BY r.created_at DESC, r.id DESC LIMIT ?",
        )
        .bind(&status_filter)
        .bind(&status_filter)
        .bind(&status_filter)
        .bind(REPORTS_PAGE_SIZE as i64 + 1)
        .fetch_all(&state.db)
        .await?
    };

    let has_more = rows.len() > REPORTS_PAGE_SIZE;
    let reports: Vec<ReportResponse> = rows
        .into_iter()
        .take(REPORTS_PAGE_SIZE)
        .map(|row| ReportResponse {
            id: row.get("report_id"),
            post_id: row.get("post_id"),
            post_body: row.get("post_body"),
            post_author_id: row.get("post_author_id"),
            post_author_name: row.get("post_author_name"),
            post_created_at: row.get("post_created_at"),
            thread_id: row.get("thread_id"),
            thread_title: row.get("thread_title"),
            room_slug: row.get("room_slug"),
            reporter_id: row.get("reporter"),
            reporter_name: row.get("reporter_name"),
            reason: row.get("reason"),
            detail: row.get("detail"),
            status: row.get("status"),
            created_at: row.get("report_created_at"),
            resolved_by_name: row.get("resolved_by_name"),
            resolved_at: row.get("resolved_at"),
            report_count: row.get("report_count"),
        })
        .collect();

    let next_cursor = if has_more {
        reports.last().map(|r| format!("{}|{}", r.created_at, r.id))
    } else {
        None
    };

    Ok(Json(ReportListResponse {
        reports,
        next_cursor,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/admin/reports/:id/dismiss — dismiss a report
// ---------------------------------------------------------------------------

/// Dismiss all pending reports for the post identified by `report_id`.
///
/// Marks every pending report on the same post as `dismissed` so the
/// admin doesn't have to dismiss each reporter individually.
pub async fn dismiss_report(
    State(state): State<Arc<AppState>>,
    Path(report_id): Path<String>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let (_, post_id) =
        sqlx::query_as::<_, (String, String)>("SELECT id, post_id FROM reports WHERE id = ?")
            .bind(&report_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::code(ErrorCode::ReportNotFound))?;

    // Dismiss all reports for the same post, not just this one.
    sqlx::query(
        "UPDATE reports SET status = 'dismissed', resolved_by = ?, \
         resolved_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE post_id = ? AND status = 'pending'",
    )
    .bind(&user.user_id)
    .bind(&post_id)
    .execute(&state.db)
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /api/admin/reports/:id/action — mark report as actioned
// ---------------------------------------------------------------------------

/// Mark all pending reports for the post identified by `report_id` as actioned.
///
/// Typically called after an admin has already taken a moderation action
/// (e.g. removing the post) to close out the remaining reports.
pub async fn action_report(
    State(state): State<Arc<AppState>>,
    Path(report_id): Path<String>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let (_, post_id) =
        sqlx::query_as::<_, (String, String)>("SELECT id, post_id FROM reports WHERE id = ?")
            .bind(&report_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::code(ErrorCode::ReportNotFound))?;

    sqlx::query(
        "UPDATE reports SET status = 'actioned', resolved_by = ?, \
         resolved_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE post_id = ? AND status = 'pending'",
    )
    .bind(&user.user_id)
    .bind(&post_id)
    .execute(&state.db)
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /api/admin/dashboard — dashboard overview stats (admin only)
// ---------------------------------------------------------------------------

/// Return high-level dashboard statistics for the admin overview.
///
/// Currently returns only the count of pending reports.
pub async fn get_dashboard(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let (pending_reports,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM reports WHERE status = 'pending'")
            .fetch_one(&state.db)
            .await?;

    Ok(Json(DashboardResponse { pending_reports }))
}
