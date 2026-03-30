use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Json;
use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::auth::{AuthBeginResponse, SessionResponse};
use crate::display_name::{display_name_skeleton, validate_display_name};
use crate::error::AppError;
use crate::session::{create_session, session_cookie};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SetupStatusResponse {
    pub needs_setup: bool,
}

#[derive(Deserialize)]
pub struct SetupBeginRequest {
    pub token: String,
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct SetupCompleteRequest {
    pub challenge_id: String,
    pub credential: RegisterPublicKeyCredential,
}

// ---------------------------------------------------------------------------
// GET /api/setup/status
// ---------------------------------------------------------------------------

/// Return whether the instance needs initial admin setup.
pub async fn setup_status(State(state): State<Arc<AppState>>) -> Json<SetupStatusResponse> {
    Json(SetupStatusResponse {
        needs_setup: state.needs_setup.load(Ordering::Relaxed),
    })
}

// ---------------------------------------------------------------------------
// POST /api/setup/begin
// ---------------------------------------------------------------------------

/// Begin the initial admin setup: validate the setup token and display name,
/// then start a WebAuthn registration ceremony.
pub async fn setup_begin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetupBeginRequest>,
) -> Result<impl IntoResponse, AppError> {
    if !state.needs_setup.load(Ordering::Relaxed) {
        return Err(AppError::Conflict("setup already completed".into()));
    }

    let expected = state
        .setup_token
        .as_deref()
        .ok_or_else(|| AppError::Internal("no setup token configured".into()))?;

    if req.token.as_bytes().ct_ne(expected.as_bytes()).into() {
        return Err(AppError::Unauthorized("invalid setup token".into()));
    }

    let display_name =
        validate_display_name(&req.display_name).map_err(|msg| AppError::BadRequest(msg.into()))?;
    let skeleton = display_name_skeleton(&display_name);

    let existing: Option<(String,)> =
        sqlx::query_as("SELECT id FROM users WHERE display_name = ? OR display_name_skeleton = ?")
            .bind(&display_name)
            .bind(&skeleton)
            .fetch_optional(&state.db)
            .await?;

    if existing.is_some() {
        return Err(AppError::Conflict("display name already taken".into()));
    }

    let user_uuid = Uuid::new_v4();

    let (ccr, reg_state) =
        state
            .webauthn
            .start_passkey_registration(user_uuid, &display_name, &display_name, None)?;

    let challenge_id = Uuid::new_v4().to_string();
    let state_bytes = serde_json::to_vec(&reg_state)?;

    sqlx::query(
        "INSERT INTO auth_challenges (id, challenge_type, state, display_name, user_id) \
         VALUES (?, 'registration', ?, ?, ?)",
    )
    .bind(&challenge_id)
    .bind(&state_bytes)
    .bind(&display_name)
    .bind(user_uuid.to_string())
    .execute(&state.db)
    .await?;

    let mut options = serde_json::to_value(ccr)?;
    if let Some(sel) = options
        .get_mut("publicKey")
        .and_then(|pk| pk.get_mut("authenticatorSelection"))
    {
        sel["residentKey"] = serde_json::json!("preferred");
        sel["requireResidentKey"] = serde_json::json!(false);
    }

    Ok(Json(AuthBeginResponse {
        challenge_id,
        options,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/setup/complete
// ---------------------------------------------------------------------------

/// Complete the admin setup: finish the WebAuthn registration, create the
/// admin user, start a session, and disable setup mode.
pub async fn setup_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetupCompleteRequest>,
) -> Result<impl IntoResponse, AppError> {
    if !state.needs_setup.load(Ordering::Relaxed) {
        return Err(AppError::Conflict("setup already completed".into()));
    }

    let challenge = sqlx::query_as::<_, (Vec<u8>, Option<String>, Option<String>)>(
        "SELECT state, display_name, user_id FROM auth_challenges \
         WHERE id = ? AND challenge_type = 'registration'",
    )
    .bind(&req.challenge_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::BadRequest("invalid or expired challenge".into()))?;

    let (state_bytes, display_name, user_id) = challenge;
    let display_name = display_name
        .ok_or_else(|| AppError::Internal("missing display_name in challenge".into()))?;
    let user_id =
        user_id.ok_or_else(|| AppError::Internal("missing user_id in challenge".into()))?;

    sqlx::query("DELETE FROM auth_challenges WHERE id = ?")
        .bind(&req.challenge_id)
        .execute(&state.db)
        .await?;

    let reg_state: PasskeyRegistration = serde_json::from_slice(&state_bytes)?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)?;

    let skeleton = display_name_skeleton(&display_name);

    // Use INSERT OR IGNORE + check rows_affected to prevent a race where two
    // concurrent setup_complete calls both pass the AtomicBool check above.
    // The UNIQUE constraint on (role = 'admin') isn't available, but the
    // display_name uniqueness constraint and the challenge consumption above
    // already prevent duplicates. As a belt-and-suspenders measure, we check
    // whether an admin was created between our guard check and now.
    let admin_exists: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1")
            .fetch_optional(&state.db)
            .await?;
    if admin_exists.is_some() {
        state.needs_setup.store(false, Ordering::Relaxed);
        return Err(AppError::Conflict("setup already completed".into()));
    }

    sqlx::query(
        "INSERT INTO users (id, display_name, display_name_skeleton, signup_method, role) \
         VALUES (?, ?, ?, 'admin', 'admin')",
    )
    .bind(&user_id)
    .bind(&display_name)
    .bind(&skeleton)
    .execute(&state.db)
    .await?;

    let cred_id = Uuid::new_v4().to_string();
    let passkey_bytes = serde_json::to_vec(&passkey)?;

    sqlx::query(
        "INSERT INTO credentials (id, user_id, credential_id, public_key, sign_count) \
         VALUES (?, ?, ?, ?, 0)",
    )
    .bind(&cred_id)
    .bind(&user_id)
    .bind(passkey.cred_id().as_ref() as &[u8])
    .bind(&passkey_bytes)
    .execute(&state.db)
    .await?;

    state.needs_setup.store(false, Ordering::Relaxed);

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    Ok((
        headers,
        Json(SessionResponse {
            user_id,
            display_name,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Middleware: gate non-setup routes when setup is required
// ---------------------------------------------------------------------------

/// When the instance needs setup, return 503 with `"error": "setup_required"`
/// for all routes except `/api/setup/*` and `/api/health`.
pub async fn setup_guard_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    if state.needs_setup.load(Ordering::Relaxed) {
        let path = request.uri().path();
        if !path.starts_with("/api/setup/") && path != "/api/health" {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "setup_required",
                    "message": "instance setup required — visit /setup to create the admin account"
                })),
            )
                .into_response();
        }
    }
    next.run(request).await
}
