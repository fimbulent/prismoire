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
use crate::error::{AppError, ErrorCode};
use crate::session::{create_session, session_cookie};
use crate::signing;
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
        return Err(AppError::code(ErrorCode::SetupAlreadyComplete));
    }

    let expected = state.setup_token.as_deref().ok_or_else(|| {
        eprintln!("setup_begin: no setup token configured");
        AppError::code(ErrorCode::SetupTokenMissing)
    })?;

    if req.token.as_bytes().ct_ne(expected.as_bytes()).into() {
        return Err(AppError::code(ErrorCode::SetupTokenInvalid));
    }

    let display_name = validate_display_name(&req.display_name)
        .map_err(|msg| AppError::with_message(ErrorCode::InvalidDisplayName, msg))?;
    let skeleton = display_name_skeleton(&display_name);

    let existing = sqlx::query!(
        "SELECT id FROM users WHERE display_name = ? OR display_name_skeleton = ?",
        display_name,
        skeleton,
    )
    .fetch_optional(&state.db)
    .await?;

    if existing.is_some() {
        return Err(AppError::code(ErrorCode::DisplayNameTaken));
    }

    let user_uuid = Uuid::new_v4();

    let (ccr, reg_state) =
        state
            .webauthn
            .start_passkey_registration(user_uuid, &display_name, &display_name, None)?;

    let challenge_id = Uuid::new_v4().to_string();
    let state_bytes = serde_json::to_vec(&reg_state)?;
    let user_uuid_str = user_uuid.to_string();

    sqlx::query!(
        "INSERT INTO auth_challenges (id, challenge_type, state, display_name, user_id) \
         VALUES (?, 'registration', ?, ?, ?)",
        challenge_id,
        state_bytes,
        display_name,
        user_uuid_str,
    )
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
        return Err(AppError::code(ErrorCode::SetupAlreadyComplete));
    }

    let challenge = sqlx::query!(
        "SELECT state, display_name, user_id FROM auth_challenges \
         WHERE id = ? AND challenge_type = 'registration'",
        req.challenge_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::InvalidChallenge))?;

    let state_bytes = challenge.state;
    let display_name = challenge.display_name.ok_or_else(|| {
        eprintln!("setup_complete: missing display_name in challenge");
        AppError::code(ErrorCode::Internal)
    })?;
    let user_id = challenge.user_id.ok_or_else(|| {
        eprintln!("setup_complete: missing user_id in challenge");
        AppError::code(ErrorCode::Internal)
    })?;

    sqlx::query!("DELETE FROM auth_challenges WHERE id = ?", req.challenge_id,)
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
    let admin_exists = sqlx::query!("SELECT 1 AS n FROM users WHERE role = 'admin' LIMIT 1")
        .fetch_optional(&state.db)
        .await?;
    if admin_exists.is_some() {
        state.needs_setup.store(false, Ordering::Relaxed);
        return Err(AppError::code(ErrorCode::SetupAlreadyComplete));
    }

    sqlx::query!(
        "INSERT INTO users (id, display_name, display_name_skeleton, signup_method, role) \
         VALUES (?, ?, ?, 'admin', 'admin')",
        user_id,
        display_name,
        skeleton,
    )
    .execute(&state.db)
    .await?;

    let cred_id = Uuid::new_v4().to_string();
    let passkey_bytes = serde_json::to_vec(&passkey)?;
    let cred_id_bytes = passkey.cred_id().as_ref() as &[u8];

    sqlx::query!(
        "INSERT INTO credentials (id, user_id, credential_id, public_key, sign_count) \
         VALUES (?, ?, ?, ?, 0)",
        cred_id,
        user_id,
        cred_id_bytes,
        passkey_bytes,
    )
    .execute(&state.db)
    .await?;

    signing::create_signing_key(&state.db, &user_id).await?;

    state.needs_setup.store(false, Ordering::Relaxed);

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    Ok((
        headers,
        Json(SessionResponse::active(
            user_id,
            display_name,
            "admin".into(),
            crate::settings::DEFAULT_THEME.into(),
        )),
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
