//! Admin Config tab handlers.
//!
//! Exposes the singleton `instance_config` row to the admin dashboard:
//!
//! - `GET /api/admin/config` — returns the current runtime config
//!   values (rebuild schedule + source repo URL).
//! - `PATCH /api/admin/config` — partially updates one or more fields,
//!   validates against the same invariants the DB CHECK constraints
//!   enforce, persists the change, updates the in-memory mirrors on
//!   [`AppState`] (so the trust-graph rebuild loop and the
//!   `/api/setup/status` handler pick the change up without a server
//!   restart), and writes an admin-log entry with `action = 'edit_config'`.
//!
//! Why a PATCH with all fields optional rather than a PUT: the admin
//! UI surfaces each field as a small "edit + save" affordance, so the
//! common case is updating one value at a time. A full-replace PUT
//! would force the client to round-trip every field on each edit.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::admin::require_admin;
use crate::error::AppError;
use crate::instance_config::{
    save_rebuild_schedule, save_source_repo_url, validate_rebuild_schedule,
    validate_source_repo_url,
};
use crate::session::AuthUser;
use crate::state::AppState;
use crate::trust::RebuildSchedule;

// ---------------------------------------------------------------------------
// Response / request types
// ---------------------------------------------------------------------------

/// Wire-format view of the singleton `instance_config` row.
///
/// Durations and byte counts are exposed as plain integers (ms / bytes)
/// rather than as ISO-8601 / human-readable strings so the admin form
/// can round-trip them through `<input type="number">` without
/// client-side parsing.
#[derive(Serialize)]
pub struct AdminConfigResponse {
    pub rebuild_debounce_ms: u64,
    pub rebuild_min_interval_ms: u64,
    pub rebuild_max_interval_ms: u64,
    pub rebuild_bfs_cache_bytes: u64,
    pub source_repo_url: Option<String>,
}

/// Partial-update payload for `PATCH /api/admin/config`.
///
/// Every field is optional; only the ones present in the request body
/// are applied. The rebuild-schedule fields are validated together (as
/// a candidate `RebuildSchedule`) so cross-field invariants like
/// `debounce <= min <= max` are enforced even when the client only
/// supplies one of the three.
#[derive(Deserialize, Default)]
pub struct AdminConfigUpdateRequest {
    pub rebuild_debounce_ms: Option<u64>,
    pub rebuild_min_interval_ms: Option<u64>,
    pub rebuild_max_interval_ms: Option<u64>,
    pub rebuild_bfs_cache_bytes: Option<u64>,
    pub source_repo_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read the current rebuild-schedule snapshot from `AppState`.
///
/// On poisoning, falls back to the last good value and logs. Same
/// recovery strategy as the rebuild loop: serving stale-but-sane
/// values is better than 500-ing the admin dashboard.
fn snapshot_schedule(state: &AppState) -> RebuildSchedule {
    match state.rebuild_schedule.read() {
        Ok(guard) => *guard,
        Err(poisoned) => {
            tracing::error!("admin_config: rebuild_schedule RwLock poisoned");
            *poisoned.into_inner()
        }
    }
}

/// Read the current source-repo-URL snapshot from `AppState`.
fn snapshot_source_repo_url(state: &AppState) -> Option<String> {
    match state.source_repo_url.read() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => {
            tracing::error!("admin_config: source_repo_url RwLock poisoned");
            poisoned.into_inner().clone()
        }
    }
}

fn schedule_to_response(
    schedule: &RebuildSchedule,
    source_repo_url: Option<String>,
) -> AdminConfigResponse {
    AdminConfigResponse {
        rebuild_debounce_ms: schedule.debounce.as_millis() as u64,
        rebuild_min_interval_ms: schedule.min_interval.as_millis() as u64,
        rebuild_max_interval_ms: schedule.max_interval.as_millis() as u64,
        rebuild_bfs_cache_bytes: schedule.bfs_cache_bytes,
        source_repo_url,
    }
}

/// Insert an `edit_config` admin log entry. Generic over the executor so
/// it can run inside the same transaction as the config UPDATE.
async fn log_edit_config<'e, E>(db: E, admin_id: &str, reason: &str) -> Result<(), AppError>
where
    E: sqlx::sqlite::SqliteExecutor<'e>,
{
    let id = Uuid::new_v4().to_string();
    sqlx::query!(
        "INSERT INTO admin_log (id, admin, action, reason) VALUES (?, ?, 'edit_config', ?)",
        id,
        admin_id,
        reason,
    )
    .execute(db)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/admin/config
// ---------------------------------------------------------------------------

/// Return the current runtime config.
///
/// Served from the in-memory mirrors on `AppState` rather than the DB
/// — both are kept in sync by the PATCH handler and the setup flow, so
/// the mirror is authoritative for read traffic.
pub async fn get_config(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;
    let schedule = snapshot_schedule(&state);
    let source_repo_url = snapshot_source_repo_url(&state);
    Ok(Json(schedule_to_response(&schedule, source_repo_url)))
}

// ---------------------------------------------------------------------------
// PATCH /api/admin/config
// ---------------------------------------------------------------------------

/// Apply a partial update to the runtime config.
///
/// Schedule fields are applied together as a single candidate
/// `RebuildSchedule` and validated as a unit so cross-field invariants
/// (debounce <= min <= max, byte range) surface as a single
/// human-readable error rather than a CHECK-constraint violation.
///
/// The source-repo URL is validated separately because its failure
/// modes (scheme, host, length) are independent of the schedule.
///
/// On success: persists to the DB, updates the in-memory mirrors on
/// `AppState`, and writes a single `edit_config` admin-log entry
/// summarising what changed.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<AdminConfigUpdateRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let current = snapshot_schedule(&state);
    let current_url = snapshot_source_repo_url(&state);

    // Build the candidate schedule by overlaying any provided fields
    // on the current snapshot. We always validate the whole thing,
    // even when only one field changed, because validation is
    // cross-field and cheap.
    let candidate = RebuildSchedule {
        debounce: req
            .rebuild_debounce_ms
            .map_or(current.debounce, Duration::from_millis),
        min_interval: req
            .rebuild_min_interval_ms
            .map_or(current.min_interval, Duration::from_millis),
        max_interval: req
            .rebuild_max_interval_ms
            .map_or(current.max_interval, Duration::from_millis),
        bfs_cache_bytes: req
            .rebuild_bfs_cache_bytes
            .unwrap_or(current.bfs_cache_bytes),
    };

    let schedule_changed = candidate.debounce != current.debounce
        || candidate.min_interval != current.min_interval
        || candidate.max_interval != current.max_interval
        || candidate.bfs_cache_bytes != current.bfs_cache_bytes;

    if schedule_changed {
        validate_rebuild_schedule(&candidate)?;
    }

    // Validate (and trim) the URL if the field was supplied. The
    // validator rejects empty / whitespace-only values, so an admin
    // can't accidentally NULL out the AGPL §13 link from the Config
    // tab after setup has completed.
    let new_url = match &req.source_repo_url {
        Some(raw) => Some(validate_source_repo_url(raw)?),
        None => None,
    };
    let url_changed = req.source_repo_url.is_some() && new_url != current_url;

    if !schedule_changed && !url_changed {
        // Nothing actually changed; return the current view without
        // hitting the DB or writing an audit-log entry. Covers the
        // no-op PATCH-of-current-value case the UI produces if the
        // user clicks "save" without editing anything.
        return Ok(Json(schedule_to_response(&current, current_url)));
    }

    // Compact summary of what changed for the audit log. Old values
    // aren't included to keep the row short; a sequence of entries
    // reconstructs the history.
    let reason = build_change_summary(&current, &candidate, &new_url, url_changed);

    // Atomically persist the config UPDATE(s) and the audit-log INSERT
    // so a crash between them can't leave the table changed without a
    // record (or vice versa). Same pattern as the user-action handlers
    // in `admin.rs` (ban/unban/suspend/unsuspend).
    let mut tx = state.db.begin().await?;
    if schedule_changed {
        save_rebuild_schedule(&mut *tx, &candidate).await?;
    }
    if url_changed {
        // `url_changed` implies the client supplied a value and
        // `validate_source_repo_url` produced a Some — that is a
        // structural invariant of how `new_url` is built above, so
        // the unwrap can't fire.
        let url = new_url
            .as_deref()
            .expect("url_changed implies new_url is Some");
        save_source_repo_url(&mut *tx, url).await?;
    }
    log_edit_config(&mut *tx, &user.user_id, &reason).await?;
    tx.commit().await?;

    // In-memory mirrors are updated only after the commit succeeds so
    // a rollback can't leave them ahead of the DB.
    if schedule_changed {
        match state.rebuild_schedule.write() {
            Ok(mut guard) => *guard = candidate,
            Err(_) => {
                tracing::error!("update_config: rebuild_schedule RwLock poisoned");
            }
        }
    }
    if url_changed {
        match state.source_repo_url.write() {
            Ok(mut guard) => guard.clone_from(&new_url),
            Err(_) => {
                tracing::error!("update_config: source_repo_url RwLock poisoned");
            }
        }
    }

    // Return the updated view from the mirrors we just wrote.
    Ok(Json(schedule_to_response(
        &snapshot_schedule(&state),
        snapshot_source_repo_url(&state),
    )))
}

/// Build a single-line summary of changed fields for `admin_log.reason`.
fn build_change_summary(
    old: &RebuildSchedule,
    new: &RebuildSchedule,
    new_url: &Option<String>,
    url_changed: bool,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if old.debounce != new.debounce {
        parts.push(format!("debounce_ms={}", new.debounce.as_millis()));
    }
    if old.min_interval != new.min_interval {
        parts.push(format!("min_interval_ms={}", new.min_interval.as_millis()));
    }
    if old.max_interval != new.max_interval {
        parts.push(format!("max_interval_ms={}", new.max_interval.as_millis()));
    }
    if old.bfs_cache_bytes != new.bfs_cache_bytes {
        parts.push(format!("bfs_cache_bytes={}", new.bfs_cache_bytes));
    }
    if url_changed {
        parts.push(format!(
            "source_repo_url={}",
            new_url.as_deref().unwrap_or("")
        ));
    }
    if parts.is_empty() {
        "edit_config".to_string()
    } else {
        parts.join(", ")
    }
}
