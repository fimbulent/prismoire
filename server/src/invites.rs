use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, ErrorCode};
use crate::session::AuthUser;
use crate::state::AppState;

const INVITE_CODE_BYTES: usize = 16;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateInviteRequest {
    pub max_uses: Option<i64>,
    pub expires_in_seconds: Option<i64>,
}

#[derive(Serialize)]
pub struct InviteResponse {
    pub id: String,
    pub code: String,
    pub max_uses: Option<i64>,
    pub use_count: i64,
    pub expires_at: Option<String>,
    pub revoked: bool,
    pub created_at: String,
    pub users: Vec<InviteUserResponse>,
}

#[derive(Serialize)]
pub struct InviteUserResponse {
    pub display_name: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct InviteListResponse {
    pub invites: Vec<InviteResponse>,
}

#[derive(Serialize)]
pub struct InviteValidationResponse {
    pub valid: bool,
    pub inviter_display_name: Option<String>,
}

#[derive(Serialize)]
pub struct InvitedUserResponse {
    pub display_name: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct InvitedUsersListResponse {
    pub users: Vec<InvitedUserResponse>,
}

// ---------------------------------------------------------------------------
// POST /api/invites — create a new invite link
// ---------------------------------------------------------------------------

/// Generate a new invite link with optional use limits and expiry.
///
/// The invite code is 128 bits of entropy, base64url-encoded (22 characters).
/// Accepts `max_uses` (null = unlimited) and `expires_in_seconds` (null = never
/// expires). Defaults: 1 use, expires in 30 days.
pub async fn create_invite(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateInviteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let max_uses = req.max_uses;

    if let Some(n) = max_uses
        && n < 1
    {
        return Err(AppError::code(ErrorCode::InviteMaxUsesInvalid));
    }

    // Cap expiry to 1 year to avoid nonsensical far-future dates.
    const MAX_EXPIRY_SECONDS: i64 = 365 * 24 * 60 * 60;

    let expires_at = match req.expires_in_seconds {
        Some(seconds) => {
            if seconds < 60 {
                return Err(AppError::with_message(
                    ErrorCode::InviteExpiryInvalid,
                    "expiry must be at least 60 seconds",
                ));
            }
            if seconds > MAX_EXPIRY_SECONDS {
                return Err(AppError::with_message(
                    ErrorCode::InviteExpiryInvalid,
                    "expiry must be at most 1 year",
                ));
            }
            Some(
                (chrono::Utc::now() + chrono::Duration::seconds(seconds))
                    .format("%Y-%m-%dT%H:%M:%SZ")
                    .to_string(),
            )
        }
        None => None,
    };

    let code = generate_invite_code();
    let id = Uuid::new_v4().to_string();

    let (created_at,): (String,) = sqlx::query_as(
        "INSERT INTO invites (id, code, created_by, max_uses, expires_at) \
         VALUES (?, ?, ?, ?, ?) RETURNING created_at",
    )
    .bind(&id)
    .bind(&code)
    .bind(&user.user_id)
    .bind(max_uses)
    .bind(&expires_at)
    .fetch_one(&state.db)
    .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(InviteResponse {
            id,
            code,
            max_uses,
            use_count: 0,
            expires_at,
            revoked: false,
            created_at,
            users: vec![],
        }),
    ))
}

// ---------------------------------------------------------------------------
// GET /api/invites — list current user's invites
// ---------------------------------------------------------------------------

/// List all invite links created by the authenticated user, newest first.
pub async fn list_invites(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    // Hide invites that have been inactive (revoked, expired, or exhausted) for >30 days.
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(30))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<i64>,
            i64,
            Option<String>,
            Option<String>,
            String,
        ),
    >(
        "SELECT i.id, i.code, i.max_uses, \
         (SELECT COUNT(*) FROM users u WHERE u.invite_id = i.id) AS use_count, \
         i.expires_at, i.revoked_at, i.created_at \
         FROM invites i WHERE i.created_by = ? \
         AND (i.revoked_at IS NULL OR i.revoked_at > ?) \
         AND (i.expires_at IS NULL OR i.expires_at > ?) \
         AND (i.max_uses IS NULL \
              OR (SELECT COUNT(*) FROM users u WHERE u.invite_id = i.id) < i.max_uses \
              OR (SELECT MAX(u.created_at) FROM users u WHERE u.invite_id = i.id) > ?) \
         ORDER BY i.created_at DESC",
    )
    .bind(&user.user_id)
    .bind(&cutoff)
    .bind(&cutoff)
    .bind(&cutoff)
    .fetch_all(&state.db)
    .await?;

    let mut invites = Vec::with_capacity(rows.len());
    for (id, code, max_uses, use_count, expires_at, revoked_at, created_at) in rows {
        let users = fetch_invite_users(&state.db, &id).await?;
        invites.push(InviteResponse {
            id,
            code,
            max_uses,
            use_count,
            expires_at,
            revoked: revoked_at.is_some(),
            created_at,
            users,
        });
    }

    Ok(Json(InviteListResponse { invites }))
}

// ---------------------------------------------------------------------------
// GET /api/invites/:code — validate invite code (public, no auth)
// ---------------------------------------------------------------------------

/// Validate an invite code and return the inviter's display name if valid.
///
/// If the code is expired, fully used, or revoked, returns `valid: false` with
/// no inviter info (to avoid leaking usernames on dead links).
pub async fn validate_invite(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query_as::<_, (Option<i64>, i64, Option<String>, Option<String>, String)>(
        "SELECT i.max_uses, \
         (SELECT COUNT(*) FROM users u2 WHERE u2.invite_id = i.id) AS use_count, \
         i.expires_at, i.revoked_at, u.display_name \
         FROM invites i \
         JOIN users u ON u.id = i.created_by \
         WHERE i.code = ?",
    )
    .bind(&code)
    .fetch_optional(&state.db)
    .await?;

    let Some((max_uses, use_count, expires_at, revoked_at, inviter_name)) = row else {
        return Ok(Json(InviteValidationResponse {
            valid: false,
            inviter_display_name: None,
        }));
    };

    let valid =
        revoked_at.is_none() && !is_exhausted(max_uses, use_count) && !is_expired(&expires_at);

    Ok(Json(InviteValidationResponse {
        valid,
        inviter_display_name: if valid { Some(inviter_name) } else { None },
    }))
}

// ---------------------------------------------------------------------------
// GET /api/invites/users — list users invited by the current user
// ---------------------------------------------------------------------------

/// List all users who signed up via one of the authenticated user's invites.
pub async fn list_invited_users(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT u.display_name, u.created_at FROM users u \
         JOIN invites i ON i.id = u.invite_id \
         WHERE i.created_by = ? ORDER BY u.created_at DESC",
    )
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;

    let users = rows
        .into_iter()
        .map(|(display_name, created_at)| InvitedUserResponse {
            display_name,
            created_at,
        })
        .collect();

    Ok(Json(InvitedUsersListResponse { users }))
}

// ---------------------------------------------------------------------------
// DELETE /api/invites/:id — revoke an invite
// ---------------------------------------------------------------------------

/// Revoke an invite link. Only the creator can revoke their own invites.
pub async fn revoke_invite(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let row: Option<(String,)> = sqlx::query_as("SELECT created_by FROM invites WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?;

    let (created_by,) = row.ok_or_else(|| AppError::code(ErrorCode::InviteNotFound))?;

    if created_by != user.user_id {
        return Err(AppError::code(ErrorCode::Forbidden));
    }

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    sqlx::query("UPDATE invites SET revoked_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&id)
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a 128-bit random invite code, base64url-encoded (22 characters).
fn generate_invite_code() -> String {
    let mut bytes = [0u8; INVITE_CODE_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Check whether an invite has been fully used.
fn is_exhausted(max_uses: Option<i64>, use_count: i64) -> bool {
    max_uses.is_some_and(|max| use_count >= max)
}

/// Check whether an invite has expired.
fn is_expired(expires_at: &Option<String>) -> bool {
    expires_at.as_ref().is_some_and(|exp| {
        chrono::NaiveDateTime::parse_from_str(exp, "%Y-%m-%dT%H:%M:%SZ")
            .map(|dt| dt < chrono::Utc::now().naive_utc())
            .unwrap_or(false)
    })
}

/// Validate an invite code for use during signup.
///
/// Looks up the code directly via indexed query. With 128 bits of entropy in
/// the invite code, timing side-channels are not exploitable.
/// Returns the invite ID and inviter user ID if valid.
pub async fn validate_invite_for_signup(
    db: &sqlx::SqlitePool,
    code: &str,
) -> Result<(String, String), AppError> {
    let row = sqlx::query_as::<_, (String, String, Option<i64>, i64, Option<String>)>(
        "SELECT i.id, i.created_by, i.max_uses, \
         (SELECT COUNT(*) FROM users u WHERE u.invite_id = i.id) AS use_count, \
         i.expires_at \
         FROM invites i WHERE i.code = ? AND i.revoked_at IS NULL",
    )
    .bind(code)
    .fetch_optional(db)
    .await?;

    let Some((invite_id, inviter_id, max_uses, use_count, expires_at)) = row else {
        return Err(AppError::code(ErrorCode::InviteInvalid));
    };

    if is_exhausted(max_uses, use_count) {
        return Err(AppError::code(ErrorCode::InviteExhausted));
    }

    if is_expired(&expires_at) {
        return Err(AppError::code(ErrorCode::InviteExpired));
    }

    Ok((invite_id, inviter_id))
}

/// Fetch the list of users who signed up with a given invite.
async fn fetch_invite_users(
    db: &sqlx::SqlitePool,
    invite_id: &str,
) -> Result<Vec<InviteUserResponse>, AppError> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT display_name, created_at FROM users \
         WHERE invite_id = ? ORDER BY created_at ASC",
    )
    .bind(invite_id)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(display_name, created_at)| InviteUserResponse {
            display_name,
            created_at,
        })
        .collect())
}
