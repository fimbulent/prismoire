use std::sync::Arc;

use axum::extract::{FromRequestParts, State};
use axum::http::Request;
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{Duration, Utc};
use rand::RngCore;
use sqlx::SqlitePool;

use crate::error::{AppError, ErrorCode};
use crate::state::AppState;
use crate::trust::UserStatus;

/// Maximum age of an auth challenge before it is considered stale.
///
/// WebAuthn ceremonies should complete within seconds. Challenges older
/// than this are abandoned browser tabs or failed flows and safe to purge.
const AUTH_CHALLENGE_MAX_AGE_MINUTES: i64 = 10;

/// How often the cleanup job runs.
const CLEANUP_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

pub const SESSION_COOKIE_NAME: &str = "prismoire_session";
const SESSION_DURATION_DAYS: i64 = 30;
const TOKEN_BYTES: usize = 32;

/// Renewal threshold: renew the session when more than half its lifetime has elapsed.
const RENEWAL_THRESHOLD_DAYS: i64 = SESSION_DURATION_DAYS / 2;

/// Authenticated user info, populated by [`session_middleware`] and read by handlers
/// via the [`AuthUser`] / [`RestrictedAuthUser`] extractors.
///
/// `status` is carried alongside the user so extractors can decide whether to
/// accept the session. Banned and suspended users get a populated [`AuthSession`]
/// so they can still reach a restricted subset of endpoints (profile, settings,
/// logout); the standard [`AuthUser`] extractor rejects them with 403.
#[derive(Clone)]
struct AuthSession {
    user_id: String,
    display_name: String,
    role: String,
    status: UserStatus,
    suspended_until: Option<String>,
}

/// Authenticated user extracted from request extensions.
///
/// The [`session_middleware`] validates the session cookie and stores the
/// authenticated user in request extensions. This extractor reads it back,
/// returning 401 if no valid session was found, or 403 if the user is banned
/// or suspended — most endpoints are off-limits to restricted users, who
/// should use [`RestrictedAuthUser`] instead.
pub struct AuthUser {
    pub user_id: String,
    pub display_name: String,
    pub role: String,
}

impl AuthUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let session = parts
            .extensions
            .get::<AuthSession>()
            .ok_or_else(|| AppError::code(ErrorCode::Unauthenticated).into_response())?;
        if !session.status.is_active() {
            return Err(AppError::code(ErrorCode::Forbidden).into_response());
        }
        Ok(AuthUser {
            user_id: session.user_id.clone(),
            display_name: session.display_name.clone(),
            role: session.role.clone(),
        })
    }
}

/// Authenticated user that can be banned or suspended.
///
/// Used by the small set of endpoints a restricted user must still reach:
/// `/api/auth/session`, their own profile + activity + trust + settings.
/// Handlers read [`status`](Self::status) to decide whether to surface
/// reduced functionality or deny requests targeting other users.
pub struct RestrictedAuthUser {
    pub user_id: String,
    pub display_name: String,
    pub role: String,
    pub status: UserStatus,
    pub suspended_until: Option<String>,
}

impl FromRequestParts<Arc<AppState>> for RestrictedAuthUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let session = parts
            .extensions
            .get::<AuthSession>()
            .ok_or_else(|| AppError::code(ErrorCode::Unauthenticated).into_response())?;
        Ok(RestrictedAuthUser {
            user_id: session.user_id.clone(),
            display_name: session.display_name.clone(),
            role: session.role.clone(),
            status: session.status,
            suspended_until: session.suspended_until.clone(),
        })
    }
}

/// Optional authenticated user — succeeds with `None` if no valid session.
///
/// Use this for endpoints that behave differently for logged-in vs. anonymous
/// users (e.g. public thread view with optional trust badges). Banned and
/// suspended users are treated as anonymous here: they should not get a
/// trust-gated view of content reserved for active users.
pub struct OptionalAuthUser(pub Option<AuthUser>);

impl FromRequestParts<Arc<AppState>> for OptionalAuthUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let user = parts
            .extensions
            .get::<AuthSession>()
            .filter(|session| session.status.is_active())
            .map(|session| AuthUser {
                user_id: session.user_id.clone(),
                display_name: session.display_name.clone(),
                role: session.role.clone(),
            });
        Ok(OptionalAuthUser(user))
    }
}

/// Generate a cryptographically random session token.
pub fn generate_token() -> String {
    let mut bytes = vec![0u8; TOKEN_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
}

/// Create a new session in the database and return the token.
pub async fn create_session(db: &SqlitePool, user_id: &str) -> Result<String, sqlx::Error> {
    let token = generate_token();
    let expires_at = (Utc::now() + Duration::days(SESSION_DURATION_DAYS))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    sqlx::query("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&token)
        .bind(user_id)
        .bind(&expires_at)
        .execute(db)
        .await?;

    Ok(token)
}

/// Delete a session from the database.
pub async fn delete_session(db: &SqlitePool, token: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE token = ?")
        .bind(token)
        .execute(db)
        .await?;
    Ok(())
}

/// Build a Set-Cookie header value for the session cookie.
pub fn session_cookie(token: &str) -> String {
    format!(
        "{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        SESSION_DURATION_DAYS * 24 * 60 * 60
    )
}

/// Build a Set-Cookie header value that clears the session cookie.
pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

/// Extract the session token from a Cookie header value.
///
/// Shared helper used by both the session middleware and the rate-limiting
/// session key extractor. Parses the standard `name=value; name=value` cookie
/// header format, returning the value of the session cookie if present and
/// non-empty.
pub fn parse_session_cookie(cookie_header: &str) -> Option<&str> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{SESSION_COOKIE_NAME}="))
            && !value.is_empty()
        {
            return Some(value);
        }
    }
    None
}

/// Extract the session token from the Cookie header.
fn extract_session_token<B>(request: &Request<B>) -> Option<String> {
    let cookie_header = request.headers().get(COOKIE)?.to_str().ok()?;
    parse_session_cookie(cookie_header).map(|s| s.to_string())
}

/// Session authentication and renewal middleware.
///
/// Validates the session cookie against the database, stores the authenticated
/// user in request extensions for downstream extractors, and handles sliding
/// session renewal. When a session is past its renewal threshold (half its
/// lifetime), the database expiry is extended and a fresh `Set-Cookie` header
/// is added to the response.
///
/// Requests without a session cookie pass through unauthenticated — handlers
/// that require auth use the [`AuthUser`] extractor which returns 401.
pub async fn session_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let mut renewal_cookie: Option<String> = None;

    if let Some(token) = extract_session_token(&request) {
        // Deleted users (`deleted_at IS NOT NULL`) are filtered here so a
        // stale session cookie for a self-deleted account can't hydrate an
        // AuthSession. Sessions are dropped as part of the delete
        // transaction, so this is belt-and-suspenders.
        let row = sqlx::query_as::<_, (String, String, String, String, String, Option<String>)>(
            "SELECT s.user_id, u.display_name, s.expires_at, u.status, u.role, u.suspended_until \
             FROM sessions s \
             JOIN users u ON u.id = s.user_id \
             WHERE s.token = ? AND u.deleted_at IS NULL",
        )
        .bind(&token)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        if let Some((user_id, display_name, expires_at, status_str, role, mut suspended_until)) =
            row
            && let Ok(expires) =
                chrono::NaiveDateTime::parse_from_str(&expires_at, "%Y-%m-%dT%H:%M:%SZ")
        {
            let mut status = match UserStatus::try_from(status_str.as_str()) {
                Ok(s) => s,
                Err(msg) => {
                    // `users.status` has a CHECK constraint, so seeing
                    // this would mean DB corruption or a migration bug.
                    // Log and fall back to Active so the user's session
                    // is still usable; operator can sort it out.
                    eprintln!(
                        "session_middleware: unrecognised users.status for {user_id}: {msg}; defaulting to active"
                    );
                    UserStatus::Active
                }
            };
            // Lazy suspension expiry: if the user is suspended and the
            // suspension period has elapsed, atomically restore to active.
            if status == UserStatus::Suspended {
                let expired = suspended_until
                    .as_deref()
                    .and_then(|s| {
                        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ").ok()
                    })
                    .is_some_and(|until| until < Utc::now().naive_utc());
                if expired {
                    let _ = sqlx::query(
                        "UPDATE users SET status = 'active', suspended_until = NULL WHERE id = ?",
                    )
                    .bind(&user_id)
                    .execute(&state.db)
                    .await;
                    status = UserStatus::Active;
                    suspended_until = None;
                }
            }

            let now = Utc::now().naive_utc();
            if expires >= now {
                // Banned and suspended users still get an AuthSession so that
                // restricted endpoints (session info, own profile, settings)
                // work. The `AuthUser` extractor rejects them with 403; only
                // `RestrictedAuthUser` accepts non-active statuses.
                request.extensions_mut().insert(AuthSession {
                    user_id,
                    display_name,
                    role,
                    status,
                    suspended_until,
                });

                // Sliding session: renew when past the halfway point.
                let remaining = expires - now;
                if remaining < Duration::days(RENEWAL_THRESHOLD_DAYS) {
                    let new_expires = (Utc::now() + Duration::days(SESSION_DURATION_DAYS))
                        .format("%Y-%m-%dT%H:%M:%SZ")
                        .to_string();
                    let _ = sqlx::query("UPDATE sessions SET expires_at = ? WHERE token = ?")
                        .bind(&new_expires)
                        .bind(&token)
                        .execute(&state.db)
                        .await;
                    renewal_cookie = Some(session_cookie(&token));
                }
            }
        }
    }

    let mut response = next.run(request).await;

    if let Some(cookie) = renewal_cookie
        && let Ok(val) = cookie.parse()
    {
        response.headers_mut().insert(SET_COOKIE, val);
    }

    response
}

/// Background task: once per hour, delete expired sessions and stale
/// auth challenges. Runs for the lifetime of the process.
///
/// Sessions are deleted when `expires_at` is in the past. Auth challenges
/// are deleted when `created_at` is older than [`AUTH_CHALLENGE_MAX_AGE_MINUTES`]
/// — WebAuthn ceremonies should complete within seconds, so anything older
/// is an abandoned flow.
///
/// Errors are logged but never propagated — a transient DB failure
/// should not take the server down, and the next sweep will catch up.
pub async fn cleanup_loop(pool: SqlitePool) {
    let mut ticker = tokio::time::interval(CLEANUP_SWEEP_INTERVAL);
    ticker.tick().await;

    let challenge_modifier = format!("-{AUTH_CHALLENGE_MAX_AGE_MINUTES} minutes");
    loop {
        ticker.tick().await;

        if let Err(e) = sqlx::query("DELETE FROM sessions WHERE expires_at < datetime('now')")
            .execute(&pool)
            .await
        {
            eprintln!("session cleanup sweep failed: {e}");
        }

        if let Err(e) =
            sqlx::query("DELETE FROM auth_challenges WHERE created_at < datetime('now', ?)")
                .bind(&challenge_modifier)
                .execute(&pool)
                .await
        {
            eprintln!("auth challenge cleanup sweep failed: {e}");
        }
    }
}
