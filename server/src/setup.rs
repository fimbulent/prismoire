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
use crate::instance_config::{save_source_repo_url, validate_source_repo_url};
use crate::session::{create_session, session_cookie};
use crate::signing;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SetupStatusResponse {
    pub needs_setup: bool,
    /// Public URL to this instance's source code (AGPL §13). The
    /// SvelteKit root layout renders this as a footer link visible to
    /// all users. `None` only between fresh-install and the moment
    /// `setup_complete` succeeds — every other path in the admin
    /// config requires a non-empty value.
    pub source_repo_url: Option<String>,
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
    /// Admin-supplied source code URL captured by the initial setup
    /// page. Required at setup time so a freshly installed instance
    /// never serves the app without AGPL §13 source-availability
    /// being satisfied.
    pub source_repo_url: String,
}

// ---------------------------------------------------------------------------
// GET /api/setup/status
// ---------------------------------------------------------------------------

/// Return whether the instance needs initial admin setup, plus the
/// configured source-code URL (for the AGPL footer link).
///
/// Read from the in-memory mirror on `AppState` rather than the DB so
/// this endpoint stays cheap: the SvelteKit root layout hits it on
/// every SSR. The mirror is updated whenever an admin edits the URL
/// from the Config tab. A poisoned RwLock falls back to `None` and
/// logs — losing the footer link is preferable to 500-ing every page
/// load.
pub async fn setup_status(State(state): State<Arc<AppState>>) -> Json<SetupStatusResponse> {
    let source_repo_url = match state.source_repo_url.read() {
        Ok(guard) => guard.clone(),
        Err(_) => {
            tracing::error!("setup_status: source_repo_url RwLock poisoned");
            None
        }
    };
    Json(SetupStatusResponse {
        needs_setup: state.needs_setup.load(Ordering::Relaxed),
        source_repo_url,
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
        tracing::error!("setup_begin: no setup token configured");
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

    // Validate the source URL before doing any WebAuthn / DB work. A
    // malformed URL here means we'd start the instance without a
    // valid AGPL §13 link, which is exactly what this field exists to
    // prevent.
    let source_repo_url = validate_source_repo_url(&req.source_repo_url)?;

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
        tracing::error!("setup_complete: missing display_name in challenge");
        AppError::code(ErrorCode::Internal)
    })?;
    let user_id = challenge.user_id.ok_or_else(|| {
        tracing::error!("setup_complete: missing user_id in challenge");
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

    let signing_key = signing::generate_signing_key();
    let verifying_bytes = signing_key.verifying_key().to_bytes();
    let public_key: &[u8] = verifying_bytes.as_slice();

    let cred_id = Uuid::new_v4().to_string();
    let passkey_bytes = serde_json::to_vec(&passkey)?;
    let cred_id_bytes = passkey.cred_id().as_ref() as &[u8];

    // The admin is a locally-born identity like any other: it needs the
    // full §11.9.5 / §12.8 birth write-set (genesis profile-rev + genesis
    // move), not just a bare `users` row. See `complete_local_user_birth`.
    let created_at_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).map_err(|_| {
        tracing::error!("setup_complete: system clock is pre-1970; cannot sign genesis objects");
        AppError::code(ErrorCode::Internal)
    })?;

    let mut tx = state.db.begin().await?;
    let birth = crate::auth::complete_local_user_birth(
        &mut tx,
        &state.instance_key,
        &state.instance_domain,
        created_at_ms,
        &crate::auth::LocalUserBirth {
            user_id: &user_id,
            display_name: &display_name,
            display_name_skeleton: &skeleton,
            signup_method: "admin",
            role: "admin",
            public_key,
            signing_key: &signing_key,
            credential: Some(crate::auth::BirthCredential {
                credential_id: &cred_id,
                passkey_credential_id: cred_id_bytes,
                passkey_bytes: &passkey_bytes,
            }),
        },
    )
    .await?;
    tx.commit().await?;

    // §7.5 / §12.2 originator-side fanout for the genesis profile
    // revision (Authored) and genesis move (Move). Routing key = the
    // admin's pubkey for both. Fire-and-forget.
    let profile_wire = crate::federation::envelope::encode_signed_object(
        &birth.genesis_profile.payload,
        &birth.genesis_profile.signature,
    );
    crate::federation::forwarder::forward_signed_object(
        state.clone(),
        birth.genesis_profile.canonical_hash,
        crate::federation::routing::ForwardingClass::Authored,
        birth.genesis_profile.public_key.to_vec(),
        profile_wire,
        None,
    )
    .await;
    crate::federation::forwarder::forward_signed_object(
        state.clone(),
        birth.genesis_move_hash,
        crate::federation::routing::ForwardingClass::Move,
        verifying_bytes.to_vec(),
        birth.genesis_move_wire,
        None,
    )
    .await;

    // Persist the source URL to `instance_config` and update the
    // in-memory mirror so `/api/setup/status` and the SvelteKit footer
    // pick it up without a roundtrip. A failure here is logged via
    // `AppError`'s `From<sqlx::Error>` impl; the row update is an
    // ordinary UPDATE on a known-existing single row.
    save_source_repo_url(&state.db, &source_repo_url).await?;
    match state.source_repo_url.write() {
        Ok(mut guard) => *guard = Some(source_repo_url),
        Err(_) => tracing::error!("setup_complete: source_repo_url RwLock poisoned"),
    }

    state.needs_setup.store(false, Ordering::Relaxed);

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    Ok((
        headers,
        Json(SessionResponse::active(
            user_id,
            display_name,
            crate::users::hex_lower(public_key),
            "admin".into(),
            crate::settings::DEFAULT_THEME.into(),
            crate::settings::DEFAULT_FONT.into(),
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
        let is_exempt = path.starts_with("/api/setup/") || path == "/api/health";
        // Under the `test-auth` feature, the test-only bypass router lives
        // under `/test/*` and must be reachable before setup completes —
        // `POST /test/setup-admin` is the *equivalent* of the real setup
        // flow for integration tests. See `server/src/test_support.rs`.
        #[cfg(any(test, feature = "test-auth"))]
        let is_exempt = is_exempt || path.starts_with("/test/");
        if !is_exempt {
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
