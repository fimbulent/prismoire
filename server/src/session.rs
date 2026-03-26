use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::header::COOKIE;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{Duration, Utc};
use rand::RngCore;
use sqlx::SqlitePool;

use crate::state::AppState;

pub const SESSION_COOKIE_NAME: &str = "prismoire_session";
const SESSION_DURATION_DAYS: i64 = 30;
const TOKEN_BYTES: usize = 32;

/// Authenticated user extracted from the session cookie.
pub struct AuthUser {
    pub user_id: String,
    pub display_name: String,
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
fn extract_session_token(parts: &Parts) -> Option<String> {
    let cookie_header = parts.headers.get(COOKIE)?.to_str().ok()?;
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

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = Response;

    /// Extract the authenticated user from the session cookie.
    ///
    /// Looks up the session token in the database, checks expiry, and returns
    /// the associated user. Returns 401 if the session is missing, expired, or
    /// the user account is not active.
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token =
            extract_session_token(parts).ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;

        let row = sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT s.user_id, u.display_name, s.expires_at, u.status \
             FROM sessions s \
             JOIN users u ON u.id = s.user_id \
             WHERE s.token = ?",
        )
        .bind(&token)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;

        let (user_id, display_name, expires_at, status) = row;

        if status != "active" {
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }

        let expires = chrono::NaiveDateTime::parse_from_str(&expires_at, "%Y-%m-%dT%H:%M:%SZ")
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        if expires < Utc::now().naive_utc() {
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }

        Ok(AuthUser {
            user_id,
            display_name,
        })
    }
}
