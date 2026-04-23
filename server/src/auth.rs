use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::display_name::{display_name_skeleton, validate_display_name};
use crate::error::{AppError, ErrorCode};
use crate::invites;
use crate::session::{
    RestrictedAuthUser, clear_session_cookie, create_session, delete_session, session_cookie,
};
use crate::signing;
use crate::state::AppState;
use crate::trust::UserStatus;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignupBeginRequest {
    pub display_name: String,
    pub invite_code: Option<String>,
}

#[derive(Deserialize)]
pub struct SignupCompleteRequest {
    pub challenge_id: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
pub struct LoginBeginRequest {
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct LoginCompleteRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredential,
}

#[derive(Serialize)]
pub struct AuthBeginResponse {
    pub challenge_id: String,
    #[serde(flatten)]
    pub options: serde_json::Value,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub user_id: String,
    pub display_name: String,
    pub role: String,
    pub theme: String,
    /// Account status (`active`, `suspended`, or `banned`). The frontend
    /// branches on this to lock the UI into a restricted profile-only view
    /// for suspended/banned users.
    pub status: UserStatus,
    /// ISO-8601 timestamp at which a suspension lifts. Present only for
    /// suspended users so the UI can render remaining time in the restriction
    /// notice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended_until: Option<String>,
}

impl SessionResponse {
    /// Build a [`SessionResponse`] for a user newly authenticated or signing up.
    /// Freshly created accounts are always active; callers that may be handling
    /// a restricted login should use [`SessionResponse::new`] instead.
    pub fn active(user_id: String, display_name: String, role: String, theme: String) -> Self {
        Self {
            user_id,
            display_name,
            role,
            theme,
            status: UserStatus::Active,
            suspended_until: None,
        }
    }

    /// Build a [`SessionResponse`] for any status. Drops `suspended_until`
    /// for non-suspended users so the wire payload never carries a stale
    /// timestamp after a suspension has lifted or a ban has been applied.
    pub fn new(
        user_id: String,
        display_name: String,
        role: String,
        theme: String,
        status: UserStatus,
        suspended_until: Option<String>,
    ) -> Self {
        Self {
            user_id,
            display_name,
            role,
            theme,
            status,
            suspended_until: if status == UserStatus::Suspended {
                suspended_until
            } else {
                None
            },
        }
    }
}

/// Parse a user status string from the DB, logging and falling back to
/// `Active` on malformed data.
///
/// Malformed statuses mean the `users.status` CHECK constraint has been
/// violated (a migration bug, or manual DB mutation). Falling back to
/// `Active` keeps the site reachable for the affected user; the log line
/// surfaces the corruption so an operator can fix it.
fn parse_status_or_log(raw: &str, user_id: &str) -> UserStatus {
    match UserStatus::try_from(raw) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!(
                "auth: unrecognised users.status for user {user_id}: {msg}; defaulting to active"
            );
            UserStatus::Active
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/auth/signup/begin
// ---------------------------------------------------------------------------

/// Begin a WebAuthn registration ceremony for a new user.
///
/// Validates the display name (Unicode normalization, character rules, mixed-
/// script detection), checks uniqueness against both the exact name and the
/// UTS #39 confusable skeleton, generates a WebAuthn registration challenge,
/// and stores the challenge state in the database for retrieval during the
/// completion step.
pub async fn signup_begin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignupBeginRequest>,
) -> Result<impl IntoResponse, AppError> {
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

    let invite_code = req
        .invite_code
        .as_deref()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| AppError::code(ErrorCode::InviteRequired))?;

    invites::validate_invite_for_signup(&state.db, invite_code).await?;

    let user_uuid = Uuid::new_v4();

    let (ccr, reg_state) =
        state
            .webauthn
            .start_passkey_registration(user_uuid, &display_name, &display_name, None)?;

    let challenge_id = Uuid::new_v4().to_string();
    let state_bytes = serde_json::to_vec(&reg_state)?;
    let user_uuid_str = user_uuid.to_string();

    sqlx::query!(
        "INSERT INTO auth_challenges (id, challenge_type, state, display_name, invite_code, user_id) \
         VALUES (?, 'registration', ?, ?, ?, ?)",
        challenge_id,
        state_bytes,
        display_name,
        invite_code,
        user_uuid_str,
    )
    .execute(&state.db)
    .await?;

    // FIXME
    // webauthn-rs hardcodes residentKey: "discouraged" in start_passkey_registration
    // and doesn't expose a way to override it. Patch the JSON to request discoverable
    // credentials so conditional UI works on the login page. Can be removed if
    // webauthn-rs adds a configurable resident key option to start_passkey_registration.
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
// POST /api/auth/signup/complete
// ---------------------------------------------------------------------------

/// Complete the WebAuthn registration ceremony and create the user account.
///
/// Looks up the stored challenge state, verifies the browser's credential
/// response, creates the user and credential rows (including the confusable
/// skeleton for future uniqueness checks), optionally consumes the invite
/// code (creating a mutual trust), and starts a session.
pub async fn signup_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignupCompleteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let challenge = sqlx::query!(
        "SELECT state, display_name, invite_code, user_id FROM auth_challenges \
         WHERE id = ? AND challenge_type = 'registration'",
        req.challenge_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::InvalidChallenge))?;

    let state_bytes = challenge.state;
    let invite_code = challenge.invite_code;
    let display_name = challenge.display_name.ok_or_else(|| {
        eprintln!("signup_complete: missing display_name in challenge");
        AppError::code(ErrorCode::Internal)
    })?;
    let user_id = challenge.user_id.ok_or_else(|| {
        eprintln!("signup_complete: missing user_id in challenge");
        AppError::code(ErrorCode::Internal)
    })?;

    sqlx::query!("DELETE FROM auth_challenges WHERE id = ?", req.challenge_id)
        .execute(&state.db)
        .await?;

    let reg_state: PasskeyRegistration = serde_json::from_slice(&state_bytes)?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)?;

    let invite_code = invite_code.ok_or_else(|| {
        eprintln!("signup_complete: missing invite_code in challenge");
        AppError::code(ErrorCode::Internal)
    })?;

    let (invite_id, inviter_id) =
        invites::validate_invite_for_signup(&state.db, &invite_code).await?;

    let skeleton = display_name_skeleton(&display_name);

    if let Err(err) = sqlx::query!(
        "INSERT INTO users (id, display_name, display_name_skeleton, signup_method) \
         VALUES (?, ?, ?, 'invite')",
        user_id,
        display_name,
        skeleton,
    )
    .execute(&state.db)
    .await
    {
        eprintln!("user creation constraint failure for display_name={display_name}: {err}");
        return Err(err.into());
    }

    let cred_id = Uuid::new_v4().to_string();
    let passkey_bytes = serde_json::to_vec(&passkey)?;
    let cred_id_bytes: &[u8] = passkey.cred_id().as_ref();

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

    sqlx::query!(
        "UPDATE users SET invite_id = ? WHERE id = ?",
        invite_id,
        user_id,
    )
    .execute(&state.db)
    .await?;

    let trust1_id = Uuid::new_v4().to_string();
    let trust2_id = Uuid::new_v4().to_string();

    sqlx::query!(
        "INSERT INTO trust_edges (id, source_user, target_user, trust_type) \
         VALUES (?, ?, ?, 'trust')",
        trust1_id,
        inviter_id,
        user_id,
    )
    .execute(&state.db)
    .await?;

    sqlx::query!(
        "INSERT INTO trust_edges (id, source_user, target_user, trust_type) \
         VALUES (?, ?, ?, 'trust')",
        trust2_id,
        user_id,
        inviter_id,
    )
    .execute(&state.db)
    .await?;

    state.trust_graph_notify.notify_one();

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    Ok((
        headers,
        Json(SessionResponse::active(
            user_id,
            display_name,
            "user".into(),
            crate::settings::DEFAULT_THEME.into(),
        )),
    ))
}

// ---------------------------------------------------------------------------
// POST /api/auth/login/begin
// ---------------------------------------------------------------------------

/// Begin a WebAuthn authentication ceremony for an existing user.
///
/// Looks up the user's passkey credentials, generates an authentication
/// challenge, and stores the challenge state in the database.
pub async fn login_begin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginBeginRequest>,
) -> Result<impl IntoResponse, AppError> {
    let display_name = req.display_name.trim();

    // Suspended and banned users are still allowed to begin a login — they
    // need a valid session to reach their own profile + settings after they
    // authenticate. The restriction is enforced downstream by the `AuthUser`
    // extractor rejecting non-active sessions with 403. Self-deleted users
    // (`deleted_at IS NOT NULL`) are filtered out here — their credentials
    // have already been purged, so this is belt-and-suspenders.
    let user = sqlx::query!(
        "SELECT id FROM users WHERE display_name = ? AND deleted_at IS NULL",
        display_name,
    )
    .fetch_optional(&state.db)
    .await?;

    let user_id = user
        .ok_or_else(|| AppError::code(ErrorCode::UserNotFound))?
        .id;

    let cred_rows = sqlx::query!(
        "SELECT public_key FROM credentials WHERE user_id = ?",
        user_id,
    )
    .fetch_all(&state.db)
    .await?;

    if cred_rows.is_empty() {
        return Err(AppError::code(ErrorCode::NoCredentials));
    }

    let passkeys: Vec<Passkey> = cred_rows
        .iter()
        .map(|r| serde_json::from_slice(&r.public_key))
        .collect::<Result<_, _>>()?;

    let (rcr, auth_state) = state.webauthn.start_passkey_authentication(&passkeys)?;

    let challenge_id = Uuid::new_v4().to_string();
    let state_bytes = serde_json::to_vec(&auth_state)?;

    sqlx::query!(
        "INSERT INTO auth_challenges (id, challenge_type, state, display_name) \
         VALUES (?, 'authentication', ?, ?)",
        challenge_id,
        state_bytes,
        display_name,
    )
    .execute(&state.db)
    .await?;

    let options = serde_json::to_value(rcr)?;
    Ok(Json(AuthBeginResponse {
        challenge_id,
        options,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/auth/login/complete
// ---------------------------------------------------------------------------

/// Complete the WebAuthn authentication ceremony and start a session.
///
/// Looks up the stored challenge state, verifies the browser's credential
/// response, updates the passkey's sign counter, and creates a session.
pub async fn login_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginCompleteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let challenge = sqlx::query!(
        "SELECT state, display_name FROM auth_challenges \
         WHERE id = ? AND challenge_type = 'authentication'",
        req.challenge_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        state.metrics.record_failed_auth();
        AppError::code(ErrorCode::InvalidChallenge)
    })?;

    let state_bytes = challenge.state;
    let display_name = challenge.display_name.ok_or_else(|| {
        eprintln!("login_complete: missing display_name in challenge");
        AppError::code(ErrorCode::Internal)
    })?;

    sqlx::query!("DELETE FROM auth_challenges WHERE id = ?", req.challenge_id)
        .execute(&state.db)
        .await?;

    let auth_state: PasskeyAuthentication = serde_json::from_slice(&state_bytes)?;

    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .inspect_err(|_| {
            state.metrics.record_failed_auth();
        })?;

    // Banned and suspended users may complete login — their session lets
    // them reach a restricted UI surface (profile + settings). The `status`
    // and `suspended_until` fields travel back to the client in the session
    // payload so the frontend knows to lock the UI down. Self-deleted users
    // are filtered out: their credentials are purged, but this closes the
    // path defensively if one somehow survived.
    let user = sqlx::query!(
        "SELECT id, role, status, suspended_until FROM users \
         WHERE display_name = ? AND deleted_at IS NULL",
        display_name,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        state.metrics.record_failed_auth();
        AppError::code(ErrorCode::UserNotFound)
    })?;
    let user_id = user.id;
    let role = user.role;
    let suspended_until = user.suspended_until;
    let status = parse_status_or_log(&user.status, &user_id);

    update_credential_counter(&state.db, &user_id, &auth_result).await?;

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    let theme = crate::settings::get_user_theme(&state.db, &user_id).await?;

    Ok((
        headers,
        Json(SessionResponse::new(
            user_id,
            display_name,
            role,
            theme,
            status,
            suspended_until,
        )),
    ))
}

// ---------------------------------------------------------------------------
// GET /api/auth/discover/begin
// ---------------------------------------------------------------------------

/// Begin a discoverable (conditional UI) WebAuthn authentication.
///
/// Returns a challenge with empty `allowCredentials` so the browser can offer
/// passkeys from its autofill UI. No display name is needed — the browser
/// discovers which credential to use.
pub async fn discover_begin(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    let (rcr, disc_state) = state.webauthn.start_discoverable_authentication()?;

    let challenge_id = Uuid::new_v4().to_string();
    let state_bytes = serde_json::to_vec(&disc_state)?;

    sqlx::query!(
        "INSERT INTO auth_challenges (id, challenge_type, state) \
         VALUES (?, 'discoverable', ?)",
        challenge_id,
        state_bytes,
    )
    .execute(&state.db)
    .await?;

    let options = serde_json::to_value(rcr)?;
    Ok(Json(AuthBeginResponse {
        challenge_id,
        options,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/auth/discover/complete
// ---------------------------------------------------------------------------

/// Complete a discoverable (conditional UI) WebAuthn authentication.
///
/// The browser response contains the user handle, which lets us identify the
/// user without them ever typing a display name.
pub async fn discover_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginCompleteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let challenge = sqlx::query!(
        "SELECT state FROM auth_challenges \
         WHERE id = ? AND challenge_type = 'discoverable'",
        req.challenge_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        state.metrics.record_failed_auth();
        AppError::code(ErrorCode::InvalidChallenge)
    })?;

    let state_bytes = challenge.state;

    sqlx::query!("DELETE FROM auth_challenges WHERE id = ?", req.challenge_id)
        .execute(&state.db)
        .await?;

    let disc_state: DiscoverableAuthentication = serde_json::from_slice(&state_bytes)?;

    let (user_uuid, _cred_id) = state
        .webauthn
        .identify_discoverable_authentication(&req.credential)
        .inspect_err(|_| {
            state.metrics.record_failed_auth();
        })?;

    // Banned and suspended users may still complete discoverable login; the
    // `status` / `suspended_until` fields flow to the client so the frontend
    // renders the restricted UI surface. Self-deleted users are filtered
    // defensively (their credentials have been purged).
    let user_uuid_str = user_uuid.to_string();
    let user = sqlx::query!(
        "SELECT id, display_name, role, status, suspended_until FROM users \
         WHERE id = ? AND deleted_at IS NULL",
        user_uuid_str,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| {
        state.metrics.record_failed_auth();
        AppError::code(ErrorCode::UserNotFound)
    })?;

    let user_id = user.id;
    let display_name = user.display_name;
    let role = user.role;
    let suspended_until = user.suspended_until;
    let status = parse_status_or_log(&user.status, &user_id);

    let cred_rows = sqlx::query!(
        "SELECT public_key FROM credentials WHERE user_id = ?",
        user_id,
    )
    .fetch_all(&state.db)
    .await?;

    let discoverable_keys: Vec<DiscoverableKey> = cred_rows
        .iter()
        .map(|r| {
            let passkey: Passkey = serde_json::from_slice(&r.public_key)?;
            Ok(DiscoverableKey::from(passkey))
        })
        .collect::<Result<_, serde_json::Error>>()?;

    let auth_result = state.webauthn.finish_discoverable_authentication(
        &req.credential,
        disc_state,
        &discoverable_keys,
    )?;

    update_credential_counter(&state.db, &user_id, &auth_result).await?;

    let theme = crate::settings::get_user_theme(&state.db, &user_id).await?;

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    Ok((
        headers,
        Json(SessionResponse::new(
            user_id,
            display_name,
            role,
            theme,
            status,
            suspended_until,
        )),
    ))
}

/// Update the credential sign counter after successful authentication.
async fn update_credential_counter(
    db: &sqlx::SqlitePool,
    user_id: &str,
    auth_result: &AuthenticationResult,
) -> Result<(), AppError> {
    let cred_rows = sqlx::query!(
        "SELECT id, public_key FROM credentials WHERE user_id = ?",
        user_id,
    )
    .fetch_all(db)
    .await?;

    for row in &cred_rows {
        let mut passkey: Passkey = serde_json::from_slice(&row.public_key)?;
        if passkey.update_credential(auth_result).is_some() {
            let updated_bytes = serde_json::to_vec(&passkey)?;
            let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            let counter = auth_result.counter() as i64;
            sqlx::query!(
                "UPDATE credentials SET public_key = ?, sign_count = ?, last_used = ? WHERE id = ?",
                updated_bytes,
                counter,
                now,
                row.id,
            )
            .execute(db)
            .await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/auth/session
// ---------------------------------------------------------------------------

/// Return the current authenticated user's info, or 401 if not logged in.
///
/// Uses [`RestrictedAuthUser`] so banned and suspended users can still query
/// their own session state — the `status` / `suspended_until` fields are what
/// drives the frontend's restricted UI.
pub async fn session_info(
    State(state): State<Arc<AppState>>,
    user: RestrictedAuthUser,
) -> Result<Json<SessionResponse>, AppError> {
    let theme = crate::settings::get_user_theme(&state.db, &user.user_id).await?;
    Ok(Json(SessionResponse::new(
        user.user_id,
        user.display_name,
        user.role,
        theme,
        user.status,
        user.suspended_until,
    )))
}

// ---------------------------------------------------------------------------
// POST /api/auth/logout
// ---------------------------------------------------------------------------

/// End the current session and clear the session cookie.
pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(cookie) = headers.get(COOKIE)
        && let Ok(cookie_str) = cookie.to_str()
    {
        for pair in cookie_str.split(';') {
            let pair = pair.trim();
            if let Some(token) =
                pair.strip_prefix(&format!("{}=", crate::session::SESSION_COOKIE_NAME))
            {
                let _ = delete_session(&state.db, token).await;
            }
        }
    }

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(SET_COOKIE, clear_session_cookie().parse().unwrap());
    (resp_headers, Json(serde_json::json!({"ok": true})))
}
