use std::sync::Arc;

use axum::extract::{FromRequestParts, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{Duration, Utc};
use rand::RngCore;
use sqlx::SqlitePool;

use crate::state::AppState;

pub const SESSION_COOKIE_NAME: &str = "prismoire_session";
const SESSION_DURATION_DAYS: i64 = 30;
const TOKEN_BYTES: usize = 32;

/// Renewal threshold: renew the session when more than half its lifetime has elapsed.
const RENEWAL_THRESHOLD_DAYS: i64 = SESSION_DURATION_DAYS / 2;

/// Authenticated user info, populated by [`session_middleware`] and read by handlers
/// via the [`AuthUser`] extractor.
#[derive(Clone)]
struct AuthSession {
    user_id: String,
    display_name: String,
    role: String,
}

/// Authenticated user extracted from request extensions.
///
/// The [`session_middleware`] validates the session cookie and stores the
/// authenticated user in request extensions. This extractor reads it back,
/// returning 401 if no valid session was found.
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
            .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;
        Ok(AuthUser {
            user_id: session.user_id.clone(),
            display_name: session.display_name.clone(),
            role: session.role.clone(),
        })
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

/// Extract the session token from the Cookie header.
fn extract_session_token<B>(request: &Request<B>) -> Option<String> {
    let cookie_header = request.headers().get(COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{SESSION_COOKIE_NAME}="))
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    None
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
        let row = sqlx::query_as::<_, (String, String, String, String, String)>(
            "SELECT s.user_id, u.display_name, s.expires_at, u.status, u.role \
             FROM sessions s \
             JOIN users u ON u.id = s.user_id \
             WHERE s.token = ?",
        )
        .bind(&token)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        if let Some((user_id, display_name, expires_at, status, role)) = row
            && status == "active"
            && let Ok(expires) =
                chrono::NaiveDateTime::parse_from_str(&expires_at, "%Y-%m-%dT%H:%M:%SZ")
        {
            let now = Utc::now().naive_utc();
            if expires >= now {
                request.extensions_mut().insert(AuthSession {
                    user_id,
                    display_name,
                    role,
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
