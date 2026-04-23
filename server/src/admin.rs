use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, ErrorCode};
use crate::session::AuthUser;
use crate::state::AppState;
use crate::threads::parse_cursor;
use crate::trust::UserStatus;

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
    pub target_user_id: Option<String>,
    pub target_user_name: Option<String>,
    pub thread_id: Option<String>,
    pub thread_title: Option<String>,
    pub post_id: Option<String>,
    pub room_id: Option<String>,
    pub room_slug: Option<String>,
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

#[derive(Deserialize)]
pub struct BanUserRequest {
    pub reason: String,
    #[serde(default)]
    pub ban_tree: bool,
}

#[derive(Deserialize)]
pub struct SuspendUserRequest {
    pub reason: String,
    pub duration: String,
}

#[derive(Deserialize)]
pub struct ReasonRequest {
    pub reason: String,
}

#[derive(Deserialize)]
pub struct DeleteRoomRequest {
    pub reason: String,
    /// Typed back by the admin to confirm the deletion — must match the
    /// target room's current slug. Guards against a mis-clicked
    /// dropdown wiping the wrong room.
    pub confirm_slug: String,
}

#[derive(Deserialize)]
pub struct DeleteUserRequest {
    pub reason: String,
    /// Typed back by the admin to confirm the deletion — must match the
    /// target user's current display name. Guards against a mis-typed
    /// lookup deleting the wrong account.
    pub confirm_display_name: String,
}

#[derive(Serialize)]
pub struct BannedUserEntry {
    pub id: String,
    pub display_name: String,
}

#[derive(Serialize)]
pub struct BanResponse {
    pub banned_users: Vec<BannedUserEntry>,
    pub snapshot_edges: i64,
}

#[derive(Serialize)]
pub struct InviteTreeEntry {
    pub id: String,
    pub display_name: String,
    pub status: String,
    pub depth: i64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Verify that the authenticated user has the `admin` role.
///
/// Returns `AdminRequired` if the user is not an admin.
pub fn require_admin(user: &AuthUser) -> Result<(), AppError> {
    if !user.is_admin() {
        return Err(AppError::code(ErrorCode::AdminRequired));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_admin_log(
    db: &sqlx::SqlitePool,
    admin_id: &str,
    action: &str,
    target_user: Option<&str>,
    thread_id: Option<&str>,
    post_id: Option<&str>,
    room_id: Option<&str>,
    reason: Option<&str>,
) -> Result<(), AppError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO admin_log (id, admin, action, target_user, thread_id, post_id, room_id, reason) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(admin_id)
    .bind(action)
    .bind(target_user)
    .bind(thread_id)
    .bind(post_id)
    .bind(room_id)
    .bind(reason)
    .execute(db)
    .await?;
    Ok(())
}

/// Insert an admin log entry for a user-targeted action, returning the log entry ID.
///
/// Used by ban/suspend handlers that need the log ID for the trust snapshot FK.
async fn insert_user_action_log<'e, E: sqlx::sqlite::SqliteExecutor<'e>>(
    db: E,
    admin_id: &str,
    action: &str,
    target_user: &str,
    reason: &str,
) -> Result<String, AppError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO admin_log (id, admin, action, target_user, reason) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(admin_id)
    .bind(action)
    .bind(target_user)
    .bind(reason)
    .execute(db)
    .await?;
    Ok(id)
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
        return Err(AppError::code(ErrorCode::ReasonRequired));
    }

    let thread = sqlx::query_as::<_, (String, bool)>("SELECT id, locked FROM threads WHERE id = ?")
        .bind(&thread_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::code(ErrorCode::ThreadNotFound))?;

    let (tid, already_locked) = thread;
    if already_locked {
        return Err(AppError::code(ErrorCode::ThreadAlreadyLocked));
    }

    sqlx::query("UPDATE threads SET locked = 1 WHERE id = ?")
        .bind(&tid)
        .execute(&state.db)
        .await?;

    insert_admin_log(
        &state.db,
        &user.user_id,
        "lock_thread",
        None,
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
        .ok_or_else(|| AppError::code(ErrorCode::ThreadNotFound))?;

    let (tid, locked) = thread;
    if !locked {
        return Err(AppError::code(ErrorCode::ThreadNotLocked));
    }

    sqlx::query("UPDATE threads SET locked = 0 WHERE id = ?")
        .bind(&tid)
        .execute(&state.db)
        .await?;

    insert_admin_log(
        &state.db,
        &user.user_id,
        "unlock_thread",
        None,
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
        return Err(AppError::code(ErrorCode::ReasonRequired));
    }

    let post = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT id, thread, retracted_at FROM posts WHERE id = ?",
    )
    .bind(&post_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::PostNotFound))?;

    let (pid, thread_id, retracted_at) = post;
    if retracted_at.is_some() {
        return Err(AppError::code(ErrorCode::PostAlreadyRetracted));
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
        None,
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
    type LogRow = (
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
        Option<String>,
        Option<String>,
        String,
    );

    // Some actions (lock_thread, unlock_thread, remove_post) record a thread
    // but not a room, so join rooms via the thread as a fallback and coalesce
    // the two. This means historical entries surface a room_slug without
    // needing a backfill migration.
    let base_select = "SELECT al.id, al.admin, u.display_name, al.action, \
             al.target_user, tu.display_name, \
             al.thread_id, t.title, al.post_id, \
             COALESCE(al.room_id, t.room), COALESCE(r.slug, rt.slug), \
             al.reason, al.created_at \
             FROM admin_log al \
             JOIN users u ON u.id = al.admin \
             LEFT JOIN users tu ON tu.id = al.target_user \
             LEFT JOIN threads t ON t.id = al.thread_id \
             LEFT JOIN rooms r ON r.id = al.room_id \
             LEFT JOIN rooms rt ON rt.id = t.room";

    let rows: Vec<LogRow> = if let Some(ref cursor) = params.cursor {
        let (cursor_ts, cursor_id) = parse_cursor(cursor)?;

        sqlx::query_as::<_, LogRow>(&format!(
            "{base_select} \
                 WHERE (al.created_at < ? OR (al.created_at = ? AND al.id < ?)) \
                 ORDER BY al.created_at DESC, al.id DESC \
                 LIMIT ?"
        ))
        .bind(&cursor_ts)
        .bind(&cursor_ts)
        .bind(&cursor_id)
        .bind(LOG_PAGE_SIZE as i64 + 1)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, LogRow>(&format!(
            "{base_select} ORDER BY al.created_at DESC, al.id DESC LIMIT ?"
        ))
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
                target_user_id,
                target_user_name,
                thread_id,
                thread_title,
                post_id,
                room_id,
                room_slug,
                reason,
                created_at,
            )| {
                AdminLogEntry {
                    id,
                    admin_id,
                    admin_name,
                    action,
                    target_user_id,
                    target_user_name,
                    thread_id,
                    thread_title,
                    post_id,
                    room_id,
                    room_slug,
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

// ---------------------------------------------------------------------------
// Shared helpers for ban/suspend
// ---------------------------------------------------------------------------

/// Snapshot all inbound trust edges for a user into `ban_trust_snapshots`.
///
/// Records who trusted the target at the moment of the admin action,
/// enabling sybil clique analysis on the admin dashboard.
async fn snapshot_trust_edges(
    db: &sqlx::SqlitePool,
    tx: &mut sqlx::sqlite::SqliteConnection,
    admin_log_id: &str,
    target_user_id: &str,
    action_type: &str,
) -> Result<i64, AppError> {
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let edges = sqlx::query_as::<_, (String, String)>(
        "SELECT source_user, created_at FROM trust_edges \
         WHERE target_user = ? AND trust_type = 'trust'",
    )
    .bind(target_user_id)
    .fetch_all(db)
    .await?;

    let count = edges.len() as i64;
    for (trusting_user, edge_created_at) in &edges {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO ban_trust_snapshots \
             (id, admin_log_id, target_user, trusting_user, edge_created_at, snapshot_at, action_type) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(admin_log_id)
        .bind(target_user_id)
        .bind(trusting_user)
        .bind(edge_created_at)
        .bind(&now)
        .bind(action_type)
        .execute(&mut *tx)
        .await?;
    }

    Ok(count)
}

/// Kill all active sessions for a user so they are immediately logged out.
async fn kill_sessions<'e, E: sqlx::sqlite::SqliteExecutor<'e>>(
    db: E,
    user_id: &str,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Revoke all active (non-revoked) invite links for a user.
async fn revoke_all_invites<'e, E: sqlx::sqlite::SqliteExecutor<'e>>(
    db: E,
    user_id: &str,
) -> Result<(), AppError> {
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    sqlx::query("UPDATE invites SET revoked_at = ? WHERE created_by = ? AND revoked_at IS NULL")
        .bind(&now)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Look up a user by ID, returning (id, display_name, status, role).
///
/// Returns `UserNotFound` if no row matches.
async fn fetch_target_user(
    db: &sqlx::SqlitePool,
    user_id: &str,
) -> Result<(String, String, UserStatus, String), AppError> {
    let (id, display_name, status_str, role) =
        sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT id, display_name, status, role FROM users WHERE id = ?",
        )
        .bind(user_id)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| AppError::code(ErrorCode::UserNotFound))?;
    let status = UserStatus::try_from(status_str.as_str()).map_err(|e| {
        eprintln!("{e}");
        AppError::code(ErrorCode::Internal)
    })?;
    Ok((id, display_name, status, role))
}

/// Parse a duration string ("1d", "3d", "1w", "2w", "1m") into a chrono Duration.
fn parse_duration(s: &str) -> Result<Duration, AppError> {
    match s {
        "1d" => Ok(Duration::days(1)),
        "3d" => Ok(Duration::days(3)),
        "1w" => Ok(Duration::weeks(1)),
        "2w" => Ok(Duration::weeks(2)),
        "1m" => Ok(Duration::days(30)),
        _ => Err(AppError::code(ErrorCode::InvalidDuration)),
    }
}

// ---------------------------------------------------------------------------
// POST /api/admin/users/:id/ban — ban a user (optionally ban invite tree)
// ---------------------------------------------------------------------------

/// Ban a user, kill their sessions, revoke their invites, snapshot trust edges,
/// and notify the trust graph to rebuild.
///
/// When `ban_tree` is true, recursively bans all users in the target's invite
/// subtree. Admins in the tree are skipped. Each banned user gets an individual
/// admin log entry and trust snapshot.
pub async fn ban_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    user: AuthUser,
    Json(req): Json<BanUserRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let reason = req.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::code(ErrorCode::ReasonRequired));
    }

    let (target_id, target_name, status, role) = fetch_target_user(&state.db, &user_id).await?;

    if role == "admin" {
        return Err(AppError::code(ErrorCode::CannotModerateAdmin));
    }
    if status == UserStatus::Banned {
        return Err(AppError::code(ErrorCode::AlreadyBanned));
    }

    let mut users_to_ban = vec![(target_id.clone(), target_name.clone())];

    if req.ban_tree {
        let tree_users = sqlx::query_as::<_, (String, String, String)>(
            "WITH RECURSIVE invite_tree(user_id) AS ( \
                 SELECT u.id FROM users u \
                 JOIN invites i ON i.id = u.invite_id \
                 WHERE i.created_by = ? \
               UNION ALL \
                 SELECT u.id FROM users u \
                 JOIN invites i ON i.id = u.invite_id \
                 JOIN invite_tree it ON i.created_by = it.user_id \
             ) \
             SELECT u.id, u.display_name, u.role FROM users u \
             JOIN invite_tree it ON u.id = it.user_id \
             WHERE u.status != 'banned'",
        )
        .bind(&target_id)
        .fetch_all(&state.db)
        .await?;

        for (uid, name, r) in tree_users {
            if r != "admin" {
                users_to_ban.push((uid, name));
            }
        }
    }

    let mut tx = state.db.begin().await?;
    let mut total_snapshot_edges: i64 = 0;
    let mut banned_entries = Vec::new();

    for (uid, name) in &users_to_ban {
        sqlx::query("UPDATE users SET status = 'banned' WHERE id = ?")
            .bind(uid)
            .execute(&mut *tx)
            .await?;

        kill_sessions(&mut *tx, uid).await?;
        revoke_all_invites(&mut *tx, uid).await?;

        let log_id =
            insert_user_action_log(&mut *tx, &user.user_id, "ban_user", uid, &reason).await?;

        let edges = snapshot_trust_edges(&state.db, &mut tx, &log_id, uid, "ban").await?;
        total_snapshot_edges += edges;

        banned_entries.push(BannedUserEntry {
            id: uid.clone(),
            display_name: name.clone(),
        });
    }

    tx.commit().await?;
    state.trust_graph_notify.notify_one();

    Ok(Json(BanResponse {
        banned_users: banned_entries,
        snapshot_edges: total_snapshot_edges,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/admin/users/:id/unban — unban a user
// ---------------------------------------------------------------------------

/// Restore a banned user to active status.
pub async fn unban_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    user: AuthUser,
    Json(req): Json<ReasonRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let reason = req.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::code(ErrorCode::ReasonRequired));
    }

    let (target_id, _, status, _) = fetch_target_user(&state.db, &user_id).await?;

    if status != UserStatus::Banned {
        return Err(AppError::code(ErrorCode::NotBanned));
    }

    sqlx::query("UPDATE users SET status = 'active' WHERE id = ?")
        .bind(&target_id)
        .execute(&state.db)
        .await?;

    insert_user_action_log(&state.db, &user.user_id, "unban_user", &target_id, &reason).await?;

    state.trust_graph_notify.notify_one();

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /api/admin/users/:id/suspend — suspend a user for a duration
// ---------------------------------------------------------------------------

/// Suspend a user for a specified duration (1d, 1w, 1m).
///
/// Sets status to suspended, records suspended_until, kills sessions,
/// revokes invite links, snapshots trust edges, and notifies the trust graph.
pub async fn suspend_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    user: AuthUser,
    Json(req): Json<SuspendUserRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let reason = req.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::code(ErrorCode::ReasonRequired));
    }

    let duration = parse_duration(&req.duration)?;
    let (target_id, _, status, role) = fetch_target_user(&state.db, &user_id).await?;

    if role == "admin" {
        return Err(AppError::code(ErrorCode::CannotModerateAdmin));
    }
    if status == UserStatus::Suspended {
        return Err(AppError::code(ErrorCode::AlreadySuspended));
    }
    if status == UserStatus::Banned {
        return Err(AppError::code(ErrorCode::AlreadyBanned));
    }

    let suspended_until = (Utc::now() + duration)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let mut tx = state.db.begin().await?;

    sqlx::query("UPDATE users SET status = 'suspended', suspended_until = ? WHERE id = ?")
        .bind(&suspended_until)
        .bind(&target_id)
        .execute(&mut *tx)
        .await?;

    kill_sessions(&mut *tx, &target_id).await?;
    revoke_all_invites(&mut *tx, &target_id).await?;

    let log_id =
        insert_user_action_log(&mut *tx, &user.user_id, "suspend_user", &target_id, &reason)
            .await?;

    snapshot_trust_edges(&state.db, &mut tx, &log_id, &target_id, "suspend").await?;

    tx.commit().await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /api/admin/users/:id/unsuspend — unsuspend a user
// ---------------------------------------------------------------------------

/// Immediately lift a suspension, restoring the user to active status.
pub async fn unsuspend_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let (target_id, _, status, _) = fetch_target_user(&state.db, &user_id).await?;

    if status != UserStatus::Suspended {
        return Err(AppError::code(ErrorCode::NotSuspended));
    }

    sqlx::query("UPDATE users SET status = 'active', suspended_until = NULL WHERE id = ?")
        .bind(&target_id)
        .execute(&state.db)
        .await?;

    insert_user_action_log(
        &state.db,
        &user.user_id,
        "unsuspend_user",
        &target_id,
        "manual unsuspend",
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /api/admin/users/:id/revoke-invites — revoke invite privileges
// ---------------------------------------------------------------------------

/// Revoke a user's ability to create new invite links.
pub async fn admin_revoke_invites(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    user: AuthUser,
    Json(req): Json<ReasonRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let reason = req.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::code(ErrorCode::ReasonRequired));
    }

    let (target_id, _, _, _) = fetch_target_user(&state.db, &user_id).await?;

    let (can_invite,): (bool,) = sqlx::query_as("SELECT can_invite FROM users WHERE id = ?")
        .bind(&target_id)
        .fetch_one(&state.db)
        .await?;

    if !can_invite {
        return Err(AppError::code(ErrorCode::InvitePrivilegeUnchanged));
    }

    sqlx::query("UPDATE users SET can_invite = 0 WHERE id = ?")
        .bind(&target_id)
        .execute(&state.db)
        .await?;

    insert_user_action_log(
        &state.db,
        &user.user_id,
        "revoke_invites",
        &target_id,
        &reason,
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /api/admin/users/:id/grant-invites — grant invite privileges
// ---------------------------------------------------------------------------

/// Restore a user's ability to create new invite links.
pub async fn admin_grant_invites(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    user: AuthUser,
    Json(req): Json<ReasonRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let reason = req.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::code(ErrorCode::ReasonRequired));
    }

    let (target_id, _, _, _) = fetch_target_user(&state.db, &user_id).await?;

    let (can_invite,): (bool,) = sqlx::query_as("SELECT can_invite FROM users WHERE id = ?")
        .bind(&target_id)
        .fetch_one(&state.db)
        .await?;

    if can_invite {
        return Err(AppError::code(ErrorCode::InvitePrivilegeUnchanged));
    }

    sqlx::query("UPDATE users SET can_invite = 1 WHERE id = ?")
        .bind(&target_id)
        .execute(&state.db)
        .await?;

    insert_user_action_log(
        &state.db,
        &user.user_id,
        "grant_invites",
        &target_id,
        &reason,
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/users/:id/bio — clear a user's bio
// ---------------------------------------------------------------------------

/// Clear a user's bio. Used to take down inappropriate bio content without
/// suspending or banning the user.
pub async fn admin_remove_bio(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    user: AuthUser,
    Json(req): Json<ReasonRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let reason = req.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::code(ErrorCode::ReasonRequired));
    }

    let (target_id, _, _, _) = fetch_target_user(&state.db, &user_id).await?;

    // Atomic read-check-update-log: clearing the bio and writing the audit
    // entry must either both happen or neither. Without the tx, a log-insert
    // failure after the UPDATE would leave the bio cleared with no record.
    let mut tx = state.db.begin().await?;

    let (bio,): (Option<String>,) = sqlx::query_as("SELECT bio FROM users WHERE id = ?")
        .bind(&target_id)
        .fetch_one(&mut *tx)
        .await?;

    if bio.is_none() {
        return Err(AppError::code(ErrorCode::BioAlreadyEmpty));
    }

    sqlx::query("UPDATE users SET bio = NULL WHERE id = ?")
        .bind(&target_id)
        .execute(&mut *tx)
        .await?;

    insert_user_action_log(&mut *tx, &user.user_id, "remove_bio", &target_id, &reason).await?;

    tx.commit().await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /api/admin/users/:id/invite-tree — preview invite tree
// ---------------------------------------------------------------------------

/// Return the recursive invite tree rooted at a user.
///
/// Used by admins to preview the scope of a tree ban before executing it.
pub async fn get_invite_tree(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let _ = fetch_target_user(&state.db, &user_id).await?;

    let rows = sqlx::query_as::<_, (String, String, String, i64)>(
        "WITH RECURSIVE invite_tree(user_id, depth) AS ( \
             SELECT u.id, 1 FROM users u \
             JOIN invites i ON i.id = u.invite_id \
             WHERE i.created_by = ? \
           UNION ALL \
             SELECT u.id, it.depth + 1 FROM users u \
             JOIN invites i ON i.id = u.invite_id \
             JOIN invite_tree it ON i.created_by = it.user_id \
         ) \
         SELECT u.id, u.display_name, u.status, it.depth \
         FROM users u \
         JOIN invite_tree it ON u.id = it.user_id \
         ORDER BY it.depth ASC, u.created_at ASC",
    )
    .bind(&user_id)
    .fetch_all(&state.db)
    .await?;

    let tree: Vec<InviteTreeEntry> = rows
        .into_iter()
        .map(|(id, display_name, status, depth)| InviteTreeEntry {
            id,
            display_name,
            status,
            depth,
        })
        .collect();

    Ok(Json(tree))
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/rooms/:id — delete a room, all its threads, and all
// posts in those threads.
// ---------------------------------------------------------------------------

/// Permanently delete a room's content and tombstone the room itself.
///
/// Admin-initiated counterpart to user self-deletion, reached via the
/// "Actions" tab on the admin dashboard. Requires a non-empty `reason`
/// and a `confirm_slug` that matches the target room's current slug.
///
/// The room row is soft-deleted (`deleted_at` set) rather than hard
/// dropped so `admin_log` entries referencing it — including the
/// `delete_room` entry this handler emits — stay FK-valid and
/// renderable in the log UI. The threads, posts, post revisions,
/// recent-replier rows, and reports against posts in the room are all
/// hard-deleted: the whole point of the action is to make the content
/// disappear for every viewer, not just hide it.
///
/// `admin_log.thread_id` and `admin_log.post_id` for any historical
/// entries that pointed at the deleted content are nulled out, because
/// the content they referenced no longer exists and a dangling FK
/// would fail the CHECK on read.
pub async fn delete_room(
    State(state): State<Arc<AppState>>,
    Path(room_id): Path<String>,
    user: AuthUser,
    Json(req): Json<DeleteRoomRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let reason = req.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::code(ErrorCode::ReasonRequired));
    }

    let room = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT id, slug, deleted_at FROM rooms WHERE id = ?",
    )
    .bind(&room_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::RoomNotFound))?;

    let (rid, slug, deleted_at) = room;
    if deleted_at.is_some() {
        return Err(AppError::code(ErrorCode::RoomAlreadyDeleted));
    }
    if req.confirm_slug.trim() != slug {
        return Err(AppError::code(ErrorCode::ConfirmationMismatch));
    }

    let mut tx = state.db.begin().await?;

    // 1. Null out admin_log FKs that point at posts / threads we are
    //    about to hard-delete. The columns are nullable, so there's no
    //    data integrity loss — the log entry's `action`, `reason`, and
    //    `room_id` (which we keep) still tell the story.
    sqlx::query(
        "UPDATE admin_log SET post_id = NULL \
         WHERE post_id IN (SELECT p.id FROM posts p JOIN threads t ON t.id = p.thread WHERE t.room = ?)",
    )
    .bind(&rid)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "UPDATE admin_log SET thread_id = NULL \
         WHERE thread_id IN (SELECT id FROM threads WHERE room = ?)",
    )
    .bind(&rid)
    .execute(&mut *tx)
    .await?;

    // 2. Hard-delete content, leaves-to-root to satisfy FKs.
    sqlx::query(
        "DELETE FROM reports \
         WHERE post_id IN (SELECT p.id FROM posts p JOIN threads t ON t.id = p.thread WHERE t.room = ?)",
    )
    .bind(&rid)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "DELETE FROM post_revisions \
         WHERE post_id IN (SELECT p.id FROM posts p JOIN threads t ON t.id = p.thread WHERE t.room = ?)",
    )
    .bind(&rid)
    .execute(&mut *tx)
    .await?;

    // Posts carry `parent REFERENCES posts(id)` — delete leaves first
    // and loop until no rows remain, peeling parent chains one layer
    // at a time. Bounded by the thread depth of the room, which is
    // small in practice.
    loop {
        let res = sqlx::query(
            "DELETE FROM posts \
             WHERE thread IN (SELECT id FROM threads WHERE room = ?) \
               AND id NOT IN (SELECT parent FROM posts WHERE parent IS NOT NULL \
                              AND thread IN (SELECT id FROM threads WHERE room = ?))",
        )
        .bind(&rid)
        .bind(&rid)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            break;
        }
    }

    sqlx::query(
        "DELETE FROM thread_recent_repliers \
         WHERE thread_id IN (SELECT id FROM threads WHERE room = ?)",
    )
    .bind(&rid)
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM threads WHERE room = ?")
        .bind(&rid)
        .execute(&mut *tx)
        .await?;

    // 3. Tombstone the room.
    sqlx::query("UPDATE rooms SET deleted_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?")
        .bind(&rid)
        .execute(&mut *tx)
        .await?;

    // 4. Emit the admin log entry. Inserted inside the same
    //    transaction so a rollback on any earlier step also rolls back
    //    the log row.
    let log_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO admin_log (id, admin, action, room_id, reason) \
         VALUES (?, ?, 'delete_room', ?, ?)",
    )
    .bind(&log_id)
    .bind(&user.user_id)
    .bind(&rid)
    .bind(&reason)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/users/:id — delete a user account (admin-initiated).
// ---------------------------------------------------------------------------

/// Admin-initiated account deletion.
///
/// Applies the same soft-delete as the user self-service endpoint
/// (`privacy::soft_delete_user`): retract every post, drop credentials
/// / sessions / settings / trust-edges, revoke open invites, deactivate
/// signing keys, and anonymise the `users` row. Admins and
/// already-deleted users are rejected before any mutation happens.
/// Refuses to delete the caller's own account — self-delete has its
/// own endpoint (`DELETE /api/me`) which also clears the session
/// cookie, which this handler cannot do for someone else's session.
///
/// The deletion and the `admin_log` entry share a single transaction,
/// so a crash mid-way through either rolls both back or records both.
pub async fn delete_user_by_admin(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    user: AuthUser,
    Json(req): Json<DeleteUserRequest>,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let reason = req.reason.trim().to_string();
    if reason.is_empty() {
        return Err(AppError::code(ErrorCode::ReasonRequired));
    }

    // Load the target, including `deleted_at`, because the shared
    // helper (`fetch_target_user`) only returns the moderation status
    // and we need the tombstone + current display name here.
    let row = sqlx::query_as::<_, (String, String, String, Option<String>)>(
        "SELECT id, display_name, role, deleted_at FROM users WHERE id = ?",
    )
    .bind(&user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::UserNotFound))?;

    let (target_id, display_name, role, deleted_at) = row;
    if deleted_at.is_some() {
        return Err(AppError::code(ErrorCode::UserAlreadyDeleted));
    }
    if role == "admin" {
        return Err(AppError::code(ErrorCode::CannotModerateAdmin));
    }
    if target_id == user.user_id {
        // Admins self-deleting should go through the GDPR self-service
        // endpoint; that path also clears their session cookie.
        return Err(AppError::code(ErrorCode::Forbidden));
    }
    if req.confirm_display_name.trim() != display_name {
        return Err(AppError::code(ErrorCode::ConfirmationMismatch));
    }

    // Run the shared soft-delete and emit the admin log entry inside a
    // single transaction. Doing both together closes the audit-trail
    // gap where a crash between the two could leave a deleted user
    // with no corresponding log row.
    let mut tx = state.db.begin().await?;

    crate::privacy::soft_delete_user(&mut tx, &target_id).await?;

    let log_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO admin_log (id, admin, action, target_user, reason) \
         VALUES (?, ?, 'delete_user', ?, ?)",
    )
    .bind(&log_id)
    .bind(&user.user_id)
    .bind(&target_id)
    .bind(&reason)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    state.trust_graph_notify.notify_one();

    Ok(axum::http::StatusCode::NO_CONTENT)
}
