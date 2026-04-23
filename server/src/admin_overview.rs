//! Admin dashboard overview endpoint.
//!
//! Aggregates instance-wide statistics for the admin overview page:
//! user counts, activity, trust graph health, sessions, and time-series
//! data for posts-per-day and new-users-per-week charts.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use chrono::{Datelike, Duration, NaiveDate, Utc};
use serde::Serialize;

use crate::admin::require_admin;
use crate::error::AppError;
use crate::session::AuthUser;
use crate::state::AppState;

const POSTS_PER_DAY_WINDOW: i64 = 14;
const NEW_USERS_PER_WEEK_WINDOW: i64 = 8;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// A single (date, count) bucket for the posts-per-day chart.
#[derive(Serialize)]
pub struct DayCount {
    /// ISO date, e.g. `"2026-04-22"`.
    pub date: String,
    pub count: i64,
}

/// A single (week, count) bucket for the new-users-per-week chart.
///
/// `week_start` is the ISO date of the Monday that begins the week.
#[derive(Serialize)]
pub struct WeekCount {
    pub week_start: String,
    pub count: i64,
}

#[derive(Serialize)]
pub struct TrustGraphStats {
    pub trust_edges: i64,
    pub distrust_edges: i64,
    pub avg_trusts_per_user: f64,
    pub avg_distrusts_per_user: f64,

    /// ISO timestamp of the last successful in-memory trust graph
    /// rebuild, or `None` if the first build has not yet succeeded.
    pub last_rebuild_at: Option<String>,
    /// Combined BFS cache hit rate (`hits / (hits + misses)`) across
    /// forward and reverse caches, in `[0, 1]`. `None` if no BFS
    /// lookups have happened since the last rebuild.
    pub bfs_cache_hit_rate: Option<f64>,
    /// Total BFS lookups recorded since the last rebuild.
    pub bfs_total_lookups: u64,
    /// p50 graph-build duration (ms) over the recent sample window,
    /// or `None` if no builds have completed yet.
    pub graph_load_ms_p50: Option<f64>,
    pub graph_load_ms_p95: Option<f64>,
    pub graph_load_ms_p99: Option<f64>,
}

#[derive(Serialize)]
pub struct SessionStats {
    pub active_sessions: i64,
    pub logins_today: i64,
    pub failed_auth_24h: i64,
}

#[derive(Serialize)]
pub struct AdminOverviewResponse {
    // Stat cards
    pub total_users: i64,
    pub new_users_7d: i64,
    pub active_users_7d: i64,
    pub active_users_prev_7d: i64,
    pub posts_today: i64,
    pub posts_7d: i64,
    pub threads_today: i64,
    pub threads_7d: i64,
    pub total_rooms: i64,
    pub empty_rooms: i64,
    pub pending_reports: i64,
    pub oldest_pending_report_at: Option<String>,

    pub trust: TrustGraphStats,
    pub sessions: SessionStats,

    /// Posts per day for the last 14 days, oldest first. Always contains
    /// exactly 14 entries (missing days are filled with `count: 0`).
    pub posts_per_day: Vec<DayCount>,
    /// New users per ISO week for the last 8 weeks, oldest first. Always
    /// contains exactly 8 entries (missing weeks are filled with `count: 0`).
    pub new_users_per_week: Vec<WeekCount>,
}

// ---------------------------------------------------------------------------
// GET /api/admin/overview — comprehensive overview for the dashboard
// ---------------------------------------------------------------------------

/// Return aggregated statistics for the admin overview page.
///
/// All counts are global (instance-wide) and cheap to compute: each query is
/// a single aggregate scan over indexed columns.
pub async fn get_overview(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let db = &state.db;

    // --- Users -----------------------------------------------------------
    let total_users = sqlx::query!(r#"SELECT COUNT(*) AS "n!: i64" FROM users"#)
        .fetch_one(db)
        .await?
        .n;

    let new_users_7d = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM users WHERE created_at > datetime('now', '-7 days')"#,
    )
    .fetch_one(db)
    .await?
    .n;

    // "Active" = posted or created a thread within the window. Using posts
    // + threads rather than sessions gives a more honest signal of
    // participation (a long-lived session doesn't imply activity).
    let active_users_7d = sqlx::query!(
        r#"SELECT COUNT(DISTINCT author) AS "n!: i64" FROM (
             SELECT author FROM posts WHERE created_at > datetime('now', '-7 days')
             UNION
             SELECT author FROM threads WHERE created_at > datetime('now', '-7 days')
         )"#,
    )
    .fetch_one(db)
    .await?
    .n;

    let active_users_prev_7d = sqlx::query!(
        r#"SELECT COUNT(DISTINCT author) AS "n!: i64" FROM (
             SELECT author FROM posts
               WHERE created_at > datetime('now', '-14 days')
                 AND created_at <= datetime('now', '-7 days')
             UNION
             SELECT author FROM threads
               WHERE created_at > datetime('now', '-14 days')
                 AND created_at <= datetime('now', '-7 days')
         )"#,
    )
    .fetch_one(db)
    .await?
    .n;

    // --- Content ---------------------------------------------------------
    let posts_today = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM posts WHERE DATE(created_at) = DATE('now')"#,
    )
    .fetch_one(db)
    .await?
    .n;

    let posts_7d = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM posts WHERE created_at > datetime('now', '-7 days')"#,
    )
    .fetch_one(db)
    .await?
    .n;

    let threads_today = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM threads WHERE DATE(created_at) = DATE('now')"#,
    )
    .fetch_one(db)
    .await?
    .n;

    let threads_7d = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM threads WHERE created_at > datetime('now', '-7 days')"#,
    )
    .fetch_one(db)
    .await?
    .n;

    // Exclude merged rooms (they redirect to their target and aren't
    // independently visible).
    let total_rooms =
        sqlx::query!(r#"SELECT COUNT(*) AS "n!: i64" FROM rooms WHERE merged_into IS NULL"#)
            .fetch_one(db)
            .await?
            .n;

    let empty_rooms = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM rooms r
         WHERE r.merged_into IS NULL
           AND NOT EXISTS (SELECT 1 FROM threads t WHERE t.room = r.id)"#,
    )
    .fetch_one(db)
    .await?
    .n;

    // --- Reports ---------------------------------------------------------
    let pending_reports =
        sqlx::query!(r#"SELECT COUNT(*) AS "n!: i64" FROM reports WHERE status = 'pending'"#,)
            .fetch_one(db)
            .await?
            .n;

    let oldest_pending_report_at = sqlx::query!(
        r#"SELECT MIN(created_at) AS "min_at?: String" FROM reports WHERE status = 'pending'"#,
    )
    .fetch_one(db)
    .await?
    .min_at;

    // --- Trust graph -----------------------------------------------------
    let trust_edges = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM trust_edges WHERE trust_type = 'trust'"#,
    )
    .fetch_one(db)
    .await?
    .n;

    let distrust_edges = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM trust_edges WHERE trust_type = 'distrust'"#,
    )
    .fetch_one(db)
    .await?
    .n;

    let (avg_trusts_per_user, avg_distrusts_per_user) = if total_users > 0 {
        let divisor = total_users as f64;
        (
            (trust_edges as f64) / divisor,
            (distrust_edges as f64) / divisor,
        )
    } else {
        (0.0, 0.0)
    };

    // --- Sessions & auth -------------------------------------------------
    let active_sessions = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM sessions
         WHERE expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')"#,
    )
    .fetch_one(db)
    .await?
    .n;

    let logins_today = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM sessions WHERE DATE(created_at) = DATE('now')"#,
    )
    .fetch_one(db)
    .await?
    .n;

    // Failed WebAuthn verifications from the last 24 hours. Incremented
    // by `auth::login_complete` / `auth::discover_complete` whenever a
    // ceremony fails to verify; see `crate::metrics::Metrics::failed_auth_count_24h`.
    let failed_auth_24h = state.metrics.failed_auth_count_24h() as i64;

    // --- Time series -----------------------------------------------------
    let posts_per_day = fetch_posts_per_day(db).await?;
    let new_users_per_week = fetch_new_users_per_week(db).await?;

    // --- In-process metrics ---------------------------------------------
    let m = state.metrics.snapshot();

    Ok(Json(AdminOverviewResponse {
        total_users,
        new_users_7d,
        active_users_7d,
        active_users_prev_7d,
        posts_today,
        posts_7d,
        threads_today,
        threads_7d,
        total_rooms,
        empty_rooms,
        pending_reports,
        oldest_pending_report_at,
        trust: TrustGraphStats {
            trust_edges,
            distrust_edges,
            avg_trusts_per_user,
            avg_distrusts_per_user,
            last_rebuild_at: m.last_rebuild_at.map(|t| t.to_rfc3339()),
            bfs_cache_hit_rate: m.bfs_hit_rate,
            bfs_total_lookups: m.bfs_total_lookups,
            graph_load_ms_p50: m.graph_load_ms_p50,
            graph_load_ms_p95: m.graph_load_ms_p95,
            graph_load_ms_p99: m.graph_load_ms_p99,
        },
        sessions: SessionStats {
            active_sessions,
            logins_today,
            failed_auth_24h,
        },
        posts_per_day,
        new_users_per_week,
    }))
}

/// Fetch a 14-day window of post counts, filling empty days with zero so the
/// chart always renders the same number of bars.
async fn fetch_posts_per_day(db: &sqlx::SqlitePool) -> Result<Vec<DayCount>, AppError> {
    let since = (Utc::now() - Duration::days(POSTS_PER_DAY_WINDOW - 1))
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let rows = sqlx::query!(
        r#"SELECT DATE(created_at) AS "day!: String", COUNT(*) AS "count!: i64"
         FROM posts
         WHERE DATE(created_at) >= ?
         GROUP BY DATE(created_at)"#,
        since,
    )
    .fetch_all(db)
    .await?;

    let today = Utc::now().date_naive();
    let mut out = Vec::with_capacity(POSTS_PER_DAY_WINDOW as usize);
    for i in (0..POSTS_PER_DAY_WINDOW).rev() {
        let date = today - Duration::days(i);
        let iso = date.format("%Y-%m-%d").to_string();
        let count = rows
            .iter()
            .find(|r| r.day == iso)
            .map(|r| r.count)
            .unwrap_or(0);
        out.push(DayCount { date: iso, count });
    }
    Ok(out)
}

/// Fetch an 8-week window of new-user counts keyed by ISO-week Monday.
async fn fetch_new_users_per_week(db: &sqlx::SqlitePool) -> Result<Vec<WeekCount>, AppError> {
    // Anchor the window to the Monday of the current ISO week, then walk back
    // 7 more weeks. Using Monday keeps buckets aligned regardless of which
    // day the query fires.
    let today = Utc::now().date_naive();
    let monday = today - Duration::days(today.weekday().num_days_from_monday() as i64);
    let window_start = monday - Duration::weeks(NEW_USERS_PER_WEEK_WINDOW - 1);

    let window_start_str = window_start.format("%Y-%m-%d").to_string();
    let rows = sqlx::query!(
        r#"SELECT DATE(created_at) AS "day!: String"
         FROM users
         WHERE DATE(created_at) >= ?"#,
        window_start_str,
    )
    .fetch_all(db)
    .await?;

    // Bucket in Rust — SQLite's strftime('%W') uses Sunday-start weeks in
    // some builds and is awkward to reconcile with a Monday anchor.
    let mut counts = vec![0i64; NEW_USERS_PER_WEEK_WINDOW as usize];
    for r in &rows {
        if let Ok(day) = NaiveDate::parse_from_str(&r.day, "%Y-%m-%d") {
            let days_from_start = (day - window_start).num_days();
            if days_from_start < 0 {
                continue;
            }
            let bucket = (days_from_start / 7) as usize;
            if bucket < counts.len() {
                counts[bucket] += 1;
            }
        }
    }

    let out = counts
        .into_iter()
        .enumerate()
        .map(|(i, count)| WeekCount {
            week_start: (window_start + Duration::weeks(i as i64))
                .format("%Y-%m-%d")
                .to_string(),
            count,
        })
        .collect();
    Ok(out)
}
