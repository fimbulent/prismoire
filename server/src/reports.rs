use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::admin::require_admin;
use crate::error::{AppError, ErrorCode};
use crate::session::AuthUser;
use crate::signed::ReportReason;
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
    /// Lowercase-hex pubkey of the reported post's author.
    pub post_author_public_key_hex: String,
    pub post_created_at: String,
    pub thread_id: String,
    pub thread_title: String,
    pub room_slug: String,
    pub reporter_id: String,
    pub reporter_name: String,
    /// Lowercase-hex pubkey of the user who filed the report.
    pub reporter_public_key_hex: String,
    pub reason: String,
    pub detail: Option<String>,
    pub status: String,
    pub created_at: String,
    pub resolved_by_name: Option<String>,
    /// Lowercase-hex pubkey of the admin who resolved the report.
    pub resolved_by_public_key_hex: Option<String>,
    pub resolved_at: Option<String>,
    pub report_count: i64,
    /// Attachments bound to the reported post's latest revision. Lets
    /// the moderator see inline images referenced in the body (often
    /// the very reason a post was reported). Empty for posts with no
    /// attachments; omitted from JSON in that case.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<crate::threads::AttachmentResponse>,
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
/// Validates the reason against [`VALID_REASONS`] and bounds `detail` by
/// [`MAX_REPORT_DETAIL_LEN`](crate::signed::MAX_REPORT_DETAIL_LEN);
/// rejects reports on retracted posts and self-reports.
///
/// Persistence is split by where the post is hosted. A report against a
/// **locally-authored** post is stored in the local `reports` table (the
/// local moderation queue), and a duplicate by the same reporter is
/// rejected. A report against a **remote-authored** post is *not* stored
/// here — it is relayed to the author's home instance (§18), which owns
/// that post's moderation queue.
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

    // Bound `detail` before any persistence or signing — the §18
    // receiver enforces this same ceiling in `parse_report`, so an
    // oversized detail would only be rejected after we spent the
    // Ed25519 sign + CBOR + queue bytes relaying it.
    if let Some(d) = detail
        && d.len() > crate::signed::MAX_REPORT_DETAIL_LEN
    {
        return Err(AppError::code(ErrorCode::ReportDetailTooLong));
    }

    let post = sqlx::query!(
        r#"SELECT p.id, p.author, p.retracted_at,
                  u.public_key AS "author_public_key!: Vec<u8>",
                  u.home_instance AS "author_home_instance: Vec<u8>"
           FROM posts p JOIN users u ON u.id = p.author
           WHERE p.id = ?"#,
        post_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::PostNotFound))?;

    if post.retracted_at.is_some() {
        return Err(AppError::code(ErrorCode::PostAlreadyRetracted));
    }

    if post.author == user.user_id {
        return Err(AppError::code(ErrorCode::SelfReport));
    }

    // The `reports` table is the *local* moderation queue: it stores
    // only reports against locally-authored posts (`home_instance IS
    // NULL`). A report against a remote-authored post is not persisted
    // here — it is relayed to the author's home instance (§18), which
    // owns that post's moderation queue.
    if post.author_home_instance.is_none() {
        let already_reported = sqlx::query!(
            "SELECT id FROM reports WHERE post_id = ? AND reporter = ?",
            post.id,
            user.user_id,
        )
        .fetch_optional(&state.db)
        .await?
        .is_some();

        if already_reported {
            return Err(AppError::code(ErrorCode::AlreadyReported));
        }

        let id = Uuid::new_v4().to_string();
        sqlx::query!(
            "INSERT INTO reports (id, post_id, reporter, reason, detail) VALUES (?, ?, ?, ?, ?)",
            id,
            post.id,
            user.user_id,
            reason,
            detail,
        )
        .execute(&state.db)
        .await?;

        return Ok(axum::http::StatusCode::CREATED);
    }

    // §18 federation: the reported post is hosted on another instance,
    // so relay the report to that author's home (single-recipient,
    // best-effort). Nothing is written to the local `reports` table. A
    // dispatch failure must not fail the user's report, so we log and
    // return success.
    let (Ok(post_uuid), Ok(author_key), Some(report_reason)) = (
        Uuid::parse_str(&post.id),
        <[u8; 32]>::try_from(post.author_public_key.as_slice()),
        ReportReason::parse(&reason),
    ) else {
        // All three are infallible given DB invariants (stored UUID,
        // 32-byte key, reason pre-validated above). Reaching here means
        // schema/validation drift has silently dropped the relay — loud
        // enough to catch in logs rather than vanish behind a 201.
        tracing::warn!(
            post_id = %post.id,
            "skipped federated report dispatch: post/author/reason failed to parse"
        );
        return Ok(axum::http::StatusCode::CREATED);
    };

    if let Err(e) = crate::federation::reports::dispatch_local_report(
        &state,
        &user.user_id,
        &post_uuid,
        &author_key,
        report_reason,
        detail,
    )
    .await
    {
        tracing::error!(error = ?e, post_id = %post.id, "failed to dispatch federated report");
    }

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
    let page_limit = REPORTS_PAGE_SIZE as i64 + 1;
    let reports: Vec<ReportResponse> = if let Some(ref cursor) = params.cursor {
        let (cursor_ts, cursor_id) = crate::threads::parse_cursor(cursor)?;
        sqlx::query!(
            r#"SELECT r.id AS report_id, r.post_id,
                    COALESCE(pr.body, '') AS "post_body!: String",
                    p.author AS post_author_id,
                    pu.display_name AS post_author_name,
                    pu.public_key AS "post_author_public_key!: Vec<u8>",
                    p.created_at AS post_created_at,
                    p.thread AS thread_id,
                    t.title AS thread_title,
                    rm.slug AS room_slug,
                    r.reporter,
                    ru.display_name AS reporter_name,
                    ru.public_key AS "reporter_public_key!: Vec<u8>",
                    r.reason, r.detail, r.status, r.created_at AS report_created_at,
                    res.display_name AS "resolved_by_name?: String",
                    res.public_key AS "resolved_by_public_key?: Vec<u8>",
                    r.resolved_at,
                    (SELECT COUNT(*) FROM reports r2 WHERE r2.post_id = r.post_id AND r2.status = ?) AS "report_count!: i64"
             FROM reports r
             JOIN posts p ON p.id = r.post_id
             LEFT JOIN post_revisions pr ON pr.post_id = p.id
                  AND pr.revision = (SELECT MAX(revision) FROM post_revisions WHERE post_id = p.id)
             JOIN threads t ON t.id = p.thread
             JOIN rooms rm ON rm.id = t.room
             JOIN users pu ON pu.id = p.author
             JOIN users ru ON ru.id = r.reporter
             LEFT JOIN users res ON res.id = r.resolved_by
             WHERE r.status = ?
               AND r.id = (
                   SELECT r3.id FROM reports r3
                   WHERE r3.post_id = r.post_id AND r3.status = ?
                   ORDER BY r3.created_at DESC LIMIT 1
               )
               AND (r.created_at < ? OR (r.created_at = ? AND r.id < ?))
             ORDER BY r.created_at DESC, r.id DESC LIMIT ?"#,
            status_filter,
            status_filter,
            status_filter,
            cursor_ts,
            cursor_ts,
            cursor_id,
            page_limit,
        )
        .fetch_all(&state.db)
        .await?
        .into_iter()
        .map(|r| ReportResponse {
            id: r.report_id,
            post_id: r.post_id,
            post_body: r.post_body,
            post_author_id: r.post_author_id,
            post_author_name: r.post_author_name,
            post_author_public_key_hex: crate::users::hex_lower(&r.post_author_public_key),
            post_created_at: r.post_created_at,
            thread_id: r.thread_id,
            thread_title: r.thread_title,
            room_slug: r.room_slug,
            reporter_id: r.reporter,
            reporter_name: r.reporter_name,
            reporter_public_key_hex: crate::users::hex_lower(&r.reporter_public_key),
            reason: r.reason,
            detail: r.detail,
            status: r.status,
            created_at: r.report_created_at,
            resolved_by_name: r.resolved_by_name,
            resolved_by_public_key_hex: r
                .resolved_by_public_key
                .as_deref()
                .map(crate::users::hex_lower),
            resolved_at: r.resolved_at,
            report_count: r.report_count,
            attachments: Vec::new(),
        })
        .collect()
    } else {
        sqlx::query!(
            r#"SELECT r.id AS report_id, r.post_id,
                    COALESCE(pr.body, '') AS "post_body!: String",
                    p.author AS post_author_id,
                    pu.display_name AS post_author_name,
                    pu.public_key AS "post_author_public_key!: Vec<u8>",
                    p.created_at AS post_created_at,
                    p.thread AS thread_id,
                    t.title AS thread_title,
                    rm.slug AS room_slug,
                    r.reporter,
                    ru.display_name AS reporter_name,
                    ru.public_key AS "reporter_public_key!: Vec<u8>",
                    r.reason, r.detail, r.status, r.created_at AS report_created_at,
                    res.display_name AS "resolved_by_name?: String",
                    res.public_key AS "resolved_by_public_key?: Vec<u8>",
                    r.resolved_at,
                    (SELECT COUNT(*) FROM reports r2 WHERE r2.post_id = r.post_id AND r2.status = ?) AS "report_count!: i64"
             FROM reports r
             JOIN posts p ON p.id = r.post_id
             LEFT JOIN post_revisions pr ON pr.post_id = p.id
                  AND pr.revision = (SELECT MAX(revision) FROM post_revisions WHERE post_id = p.id)
             JOIN threads t ON t.id = p.thread
             JOIN rooms rm ON rm.id = t.room
             JOIN users pu ON pu.id = p.author
             JOIN users ru ON ru.id = r.reporter
             LEFT JOIN users res ON res.id = r.resolved_by
             WHERE r.status = ?
               AND r.id = (
                   SELECT r3.id FROM reports r3
                   WHERE r3.post_id = r.post_id AND r3.status = ?
                   ORDER BY r3.created_at DESC LIMIT 1
               )
             ORDER BY r.created_at DESC, r.id DESC LIMIT ?"#,
            status_filter,
            status_filter,
            status_filter,
            page_limit,
        )
        .fetch_all(&state.db)
        .await?
        .into_iter()
        .map(|r| ReportResponse {
            id: r.report_id,
            post_id: r.post_id,
            post_body: r.post_body,
            post_author_id: r.post_author_id,
            post_author_name: r.post_author_name,
            post_author_public_key_hex: crate::users::hex_lower(&r.post_author_public_key),
            post_created_at: r.post_created_at,
            thread_id: r.thread_id,
            thread_title: r.thread_title,
            room_slug: r.room_slug,
            reporter_id: r.reporter,
            reporter_name: r.reporter_name,
            reporter_public_key_hex: crate::users::hex_lower(&r.reporter_public_key),
            reason: r.reason,
            detail: r.detail,
            status: r.status,
            created_at: r.report_created_at,
            resolved_by_name: r.resolved_by_name,
            resolved_by_public_key_hex: r
                .resolved_by_public_key
                .as_deref()
                .map(crate::users::hex_lower),
            resolved_at: r.resolved_at,
            report_count: r.report_count,
            attachments: Vec::new(),
        })
        .collect()
    };

    let has_more = reports.len() > REPORTS_PAGE_SIZE;
    let mut reports: Vec<ReportResponse> = reports.into_iter().take(REPORTS_PAGE_SIZE).collect();

    // Second pass: resolve attachments for every reported post on this
    // page. Mirrors `users::get_activity` — moderators reviewing a
    // reported post see the inline images the body references, which
    // is often the very content under review.
    let post_ids: Vec<String> = reports.iter().map(|r| r.post_id.clone()).collect();
    let mut attachments_map =
        crate::threads::fetch_latest_attachments(&state.db, &post_ids).await?;
    for r in &mut reports {
        if let Some(atts) = attachments_map.remove(&r.post_id) {
            r.attachments = atts;
        }
    }

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

    let post_id = sqlx::query!("SELECT post_id FROM reports WHERE id = ?", report_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::code(ErrorCode::ReportNotFound))?
        .post_id;

    // Dismiss all reports for the same post, not just this one.
    sqlx::query!(
        "UPDATE reports SET status = 'dismissed', resolved_by = ?, \
         resolved_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE post_id = ? AND status = 'pending'",
        user.user_id,
        post_id,
    )
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

    let post_id = sqlx::query!("SELECT post_id FROM reports WHERE id = ?", report_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::code(ErrorCode::ReportNotFound))?
        .post_id;

    sqlx::query!(
        "UPDATE reports SET status = 'actioned', resolved_by = ?, \
         resolved_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE post_id = ? AND status = 'pending'",
        user.user_id,
        post_id,
    )
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

    let pending_reports =
        sqlx::query!(r#"SELECT COUNT(*) AS "n!: i64" FROM reports WHERE status = 'pending'"#,)
            .fetch_one(&state.db)
            .await?
            .n;

    Ok(Json(DashboardResponse { pending_reports }))
}
