//! Instance-level runtime configuration loaded from the `instance_config`
//! table and exposed to admins via the Config tab in the admin dashboard.
//!
//! This module is the single point of contact between the DB row and the
//! in-memory handles on [`crate::AppState`] that handlers and background
//! tasks read at runtime. Values that need to be applied immediately
//! (the trust-graph rebuild schedule) live in their own
//! [`std::sync::RwLock`] so the rebuild loop can pick up changes on its
//! next scheduling iteration without a server restart.
//!
//! The `instance_config` table is seeded with the compile-time defaults
//! by the migration, so [`load_from_db`] is guaranteed to find exactly
//! one row in every operational deployment.

use std::time::Duration;

use sqlx::SqlitePool;

use crate::error::{AppError, ErrorCode};
use crate::trust::RebuildSchedule;

/// In-memory mirror of the single row in the `instance_config` table.
///
/// Read once at startup, then split: the rebuild schedule is stored in
/// an [`std::sync::RwLock`] on [`crate::AppState`] so the rebuild loop
/// picks up admin edits live; the source repo URL is stored in another
/// [`std::sync::RwLock`] so the public `/api/setup/status` endpoint
/// reflects edits without a DB roundtrip per request.
#[derive(Debug, Clone)]
pub struct InstanceConfig {
    pub rebuild_schedule: RebuildSchedule,
    pub source_repo_url: Option<String>,
}

/// Load the singleton `instance_config` row.
///
/// The migration seeds the row at install time, so this call always
/// succeeds against a properly migrated database. If the row is somehow
/// missing — manual DB tampering or a partial restore — the underlying
/// `sqlx::Error::RowNotFound` propagates rather than silently falling
/// back to defaults, so the misconfiguration surfaces loudly (callers
/// typically map this to `AppError::Internal` and log it at startup).
pub async fn load_from_db(db: &SqlitePool) -> Result<InstanceConfig, sqlx::Error> {
    let row = sqlx::query!(
        r#"SELECT
               rebuild_debounce_ms AS "rebuild_debounce_ms!: i64",
               rebuild_min_interval_ms AS "rebuild_min_interval_ms!: i64",
               rebuild_max_interval_ms AS "rebuild_max_interval_ms!: i64",
               rebuild_bfs_cache_bytes AS "rebuild_bfs_cache_bytes!: i64",
               source_repo_url
           FROM instance_config
           WHERE id = 1"#
    )
    .fetch_one(db)
    .await?;

    Ok(InstanceConfig {
        rebuild_schedule: RebuildSchedule {
            debounce: Duration::from_millis(row.rebuild_debounce_ms as u64),
            min_interval: Duration::from_millis(row.rebuild_min_interval_ms as u64),
            max_interval: Duration::from_millis(row.rebuild_max_interval_ms as u64),
            bfs_cache_bytes: row.rebuild_bfs_cache_bytes as u64,
        },
        source_repo_url: row.source_repo_url,
    })
}

/// Persist a new rebuild schedule to the `instance_config` row.
///
/// The DB-level `CHECK` constraints enforce the same range / ordering
/// invariants the API handler validates; a constraint failure here
/// surfaces as a `sqlx::Error` and is logged with a correlation id.
///
/// Generic over the executor so callers can run this inside a
/// transaction alongside the matching `admin_log` insert — the existing
/// admin handlers in `admin.rs` follow the same pattern.
pub async fn save_rebuild_schedule<'e, E>(
    db: E,
    schedule: &RebuildSchedule,
) -> Result<(), sqlx::Error>
where
    E: sqlx::sqlite::SqliteExecutor<'e>,
{
    let debounce_ms = schedule.debounce.as_millis() as i64;
    let min_ms = schedule.min_interval.as_millis() as i64;
    let max_ms = schedule.max_interval.as_millis() as i64;
    let bytes = schedule.bfs_cache_bytes as i64;

    sqlx::query!(
        "UPDATE instance_config
            SET rebuild_debounce_ms = ?,
                rebuild_min_interval_ms = ?,
                rebuild_max_interval_ms = ?,
                rebuild_bfs_cache_bytes = ?
          WHERE id = 1",
        debounce_ms,
        min_ms,
        max_ms,
        bytes,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Persist a new source repo URL to the `instance_config` row.
///
/// The URL is required at setup and `validate_source_repo_url` rejects
/// empty / whitespace-only values, so there is no API path that ever
/// clears the column back to NULL — the parameter is non-optional to
/// reflect that. If we ever add a "clear the URL" affordance the
/// signature can grow back to `Option<&str>`.
///
/// Generic over the executor so callers can run this inside a
/// transaction alongside the matching `admin_log` insert.
pub async fn save_source_repo_url<'e, E>(db: E, url: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::sqlite::SqliteExecutor<'e>,
{
    sqlx::query!(
        "UPDATE instance_config SET source_repo_url = ? WHERE id = 1",
        url,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Maximum accepted length of a source repo URL.
///
/// 2048 chars is a generous cap that still keeps the value comfortably
/// indexable and renderable. Anything longer is almost certainly junk.
const MAX_SOURCE_REPO_URL_LEN: usize = 2048;

/// Validate a source-code repository URL submitted by an admin or setup
/// flow.
///
/// Requirements:
///   - parses as an absolute URL
///   - scheme is `http` or `https`
///   - has a host component
///   - within [`MAX_SOURCE_REPO_URL_LEN`]
///
/// Returns the trimmed URL on success or an `AppError` with a specific
/// message on failure. The caller is responsible for translating the
/// trimmed value into storage / state.
pub fn validate_source_repo_url(raw: &str) -> Result<String, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "source repo URL is required",
        ));
    }
    if trimmed.len() > MAX_SOURCE_REPO_URL_LEN {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "source repo URL is too long",
        ));
    }
    let parsed = url::Url::parse(trimmed)
        .map_err(|_| AppError::with_message(ErrorCode::BadRequest, "source repo URL is invalid"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "source repo URL must use http or https",
        ));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "source repo URL must include a host",
        ));
    }
    Ok(trimmed.to_string())
}

/// Validate a candidate [`RebuildSchedule`] against the admin-config
/// invariants. Mirrors the DB-level CHECK constraints so the API
/// returns a clear human-readable message rather than a generic
/// constraint-violation error.
pub fn validate_rebuild_schedule(schedule: &RebuildSchedule) -> Result<(), AppError> {
    let debounce_ms = schedule.debounce.as_millis();
    let min_ms = schedule.min_interval.as_millis();
    let max_ms = schedule.max_interval.as_millis();

    if !(1_000..=60_000).contains(&debounce_ms) {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "rebuild debounce must be between 1s and 60s",
        ));
    }
    if !(1_000..=3_600_000).contains(&min_ms) {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "rebuild min interval must be between 1s and 1h",
        ));
    }
    if !(1_000..=3_600_000).contains(&max_ms) {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "rebuild max interval must be between 1s and 1h",
        ));
    }
    if debounce_ms > min_ms {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "rebuild debounce must be <= min interval",
        ));
    }
    if min_ms > max_ms {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "rebuild min interval must be <= max interval",
        ));
    }
    if !(1_048_576..=4_294_967_296).contains(&schedule.bfs_cache_bytes) {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "BFS cache bytes must be between 1 MiB and 4 GiB",
        ));
    }
    Ok(())
}
