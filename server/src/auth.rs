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
use crate::error::AppError;
use crate::session::{
    AuthUser, clear_session_cookie, create_session, delete_session, session_cookie,
};
use crate::signing;
use crate::state::AppState;

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

    let invite_code = req
        .invite_code
        .as_deref()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| AppError::BadRequest("invite code required".into()))?;

    let invite: Option<(String,)> =
        sqlx::query_as("SELECT id FROM invites WHERE code = ? AND used_by IS NULL AND revoked = 0")
            .bind(invite_code)
            .fetch_optional(&state.db)
            .await?;

    if invite.is_none() {
        return Err(AppError::BadRequest("invalid or used invite code".into()));
    }

    let user_uuid = Uuid::new_v4();

    let (ccr, reg_state) =
        state
            .webauthn
            .start_passkey_registration(user_uuid, &display_name, &display_name, None)?;

    let challenge_id = Uuid::new_v4().to_string();
    let state_bytes = serde_json::to_vec(&reg_state)?;

    sqlx::query(
        "INSERT INTO auth_challenges (id, challenge_type, state, display_name, invite_code, user_id) \
         VALUES (?, 'registration', ?, ?, ?, ?)",
    )
    .bind(&challenge_id)
    .bind(&state_bytes)
    .bind(&display_name)
    .bind(invite_code)
    .bind(user_uuid.to_string())
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
/// code (creating a mutual vouch), and starts a session.
pub async fn signup_complete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignupCompleteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let challenge = sqlx::query_as::<_, (Vec<u8>, Option<String>, Option<String>, Option<String>)>(
        "SELECT state, display_name, invite_code, user_id FROM auth_challenges \
         WHERE id = ? AND challenge_type = 'registration'",
    )
    .bind(&req.challenge_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::BadRequest("invalid or expired challenge".into()))?;

    let (state_bytes, display_name, invite_code, user_id) = challenge;
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

    let invite_code =
        invite_code.ok_or_else(|| AppError::Internal("missing invite_code in challenge".into()))?;

    let skeleton = display_name_skeleton(&display_name);

    if let Err(err) = sqlx::query(
        "INSERT INTO users (id, display_name, display_name_skeleton, signup_method) \
         VALUES (?, ?, ?, 'invite')",
    )
    .bind(&user_id)
    .bind(&display_name)
    .bind(&skeleton)
    .execute(&state.db)
    .await
    {
        eprintln!("user creation constraint failure for display_name={display_name}: {err}");
        return Err(err.into());
    }

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

    signing::create_signing_key(&state.db, &user_id).await?;

    let inviter_id: Option<(String,)> = sqlx::query_as(
        "SELECT i.created_by FROM invites i WHERE i.code = ? AND i.used_by IS NULL AND i.revoked = 0",
    )
    .bind(&invite_code)
    .fetch_optional(&state.db)
    .await?;

    if let Some((inviter_id,)) = inviter_id {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        sqlx::query("UPDATE invites SET used_by = ?, used_at = ? WHERE code = ?")
            .bind(&user_id)
            .bind(&now)
            .bind(&invite_code)
            .execute(&state.db)
            .await?;

        sqlx::query("UPDATE users SET invited_by = ? WHERE id = ?")
            .bind(&inviter_id)
            .bind(&user_id)
            .execute(&state.db)
            .await?;

        let vouch1_id = Uuid::new_v4().to_string();
        let vouch2_id = Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO trust_edges (id, source_user, target_user, trust_type, weight) \
             VALUES (?, ?, ?, 'vouch', 1.0)",
        )
        .bind(&vouch1_id)
        .bind(&inviter_id)
        .bind(&user_id)
        .execute(&state.db)
        .await?;

        sqlx::query(
            "INSERT INTO trust_edges (id, source_user, target_user, trust_type, weight) \
             VALUES (?, ?, ?, 'vouch', 1.0)",
        )
        .bind(&vouch2_id)
        .bind(&user_id)
        .bind(&inviter_id)
        .execute(&state.db)
        .await?;
    }

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = HeaderMap::new();
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

    let user: Option<(String,)> =
        sqlx::query_as("SELECT id FROM users WHERE display_name = ? AND status = 'active'")
            .bind(display_name)
            .fetch_optional(&state.db)
            .await?;

    let (user_id,) = user.ok_or_else(|| AppError::NotFound("user not found".into()))?;

    let cred_rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT public_key FROM credentials WHERE user_id = ?")
            .bind(&user_id)
            .fetch_all(&state.db)
            .await?;

    if cred_rows.is_empty() {
        return Err(AppError::NotFound("no credentials registered".into()));
    }

    let passkeys: Vec<Passkey> = cred_rows
        .iter()
        .map(|(bytes,)| serde_json::from_slice(bytes))
        .collect::<Result<_, _>>()?;

    let (rcr, auth_state) = state.webauthn.start_passkey_authentication(&passkeys)?;

    let challenge_id = Uuid::new_v4().to_string();
    let state_bytes = serde_json::to_vec(&auth_state)?;

    sqlx::query(
        "INSERT INTO auth_challenges (id, challenge_type, state, display_name) \
         VALUES (?, 'authentication', ?, ?)",
    )
    .bind(&challenge_id)
    .bind(&state_bytes)
    .bind(display_name)
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
    let challenge = sqlx::query_as::<_, (Vec<u8>, Option<String>)>(
        "SELECT state, display_name FROM auth_challenges \
         WHERE id = ? AND challenge_type = 'authentication'",
    )
    .bind(&req.challenge_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::BadRequest("invalid or expired challenge".into()))?;

    let (state_bytes, display_name) = challenge;
    let display_name = display_name
        .ok_or_else(|| AppError::Internal("missing display_name in challenge".into()))?;

    sqlx::query("DELETE FROM auth_challenges WHERE id = ?")
        .bind(&req.challenge_id)
        .execute(&state.db)
        .await?;

    let auth_state: PasskeyAuthentication = serde_json::from_slice(&state_bytes)?;

    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)?;

    let user: (String,) =
        sqlx::query_as("SELECT id FROM users WHERE display_name = ? AND status = 'active'")
            .bind(&display_name)
            .fetch_one(&state.db)
            .await?;
    let user_id = user.0;

    update_credential_counter(&state.db, &user_id, &auth_result).await?;

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = HeaderMap::new();
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

    sqlx::query(
        "INSERT INTO auth_challenges (id, challenge_type, state) \
         VALUES (?, 'discoverable', ?)",
    )
    .bind(&challenge_id)
    .bind(&state_bytes)
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
    let challenge = sqlx::query_as::<_, (Vec<u8>,)>(
        "SELECT state FROM auth_challenges \
         WHERE id = ? AND challenge_type = 'discoverable'",
    )
    .bind(&req.challenge_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::BadRequest("invalid or expired challenge".into()))?;

    let (state_bytes,) = challenge;

    sqlx::query("DELETE FROM auth_challenges WHERE id = ?")
        .bind(&req.challenge_id)
        .execute(&state.db)
        .await?;

    let disc_state: DiscoverableAuthentication = serde_json::from_slice(&state_bytes)?;

    let (user_uuid, _cred_id) = state
        .webauthn
        .identify_discoverable_authentication(&req.credential)?;

    let user = sqlx::query_as::<_, (String, String)>(
        "SELECT id, display_name FROM users WHERE id = ? AND status = 'active'",
    )
    .bind(user_uuid.to_string())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    let (user_id, display_name) = user;

    let cred_rows: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT public_key FROM credentials WHERE user_id = ?")
            .bind(&user_id)
            .fetch_all(&state.db)
            .await?;

    let discoverable_keys: Vec<DiscoverableKey> = cred_rows
        .iter()
        .map(|(bytes,)| {
            let passkey: Passkey = serde_json::from_slice(bytes)?;
            Ok(DiscoverableKey::from(passkey))
        })
        .collect::<Result<_, serde_json::Error>>()?;

    let auth_result = state.webauthn.finish_discoverable_authentication(
        &req.credential,
        disc_state,
        &discoverable_keys,
    )?;

    update_credential_counter(&state.db, &user_id, &auth_result).await?;

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    Ok((
        headers,
        Json(SessionResponse {
            user_id,
            display_name,
        }),
    ))
}

/// Update the credential sign counter after successful authentication.
async fn update_credential_counter(
    db: &sqlx::SqlitePool,
    user_id: &str,
    auth_result: &AuthenticationResult,
) -> Result<(), AppError> {
    let cred_rows: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT id, public_key FROM credentials WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(db)
            .await?;

    for (cred_db_id, passkey_bytes) in &cred_rows {
        let mut passkey: Passkey = serde_json::from_slice(passkey_bytes)?;
        if passkey.update_credential(auth_result).is_some() {
            let updated_bytes = serde_json::to_vec(&passkey)?;
            let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            sqlx::query(
                "UPDATE credentials SET public_key = ?, sign_count = ?, last_used = ? WHERE id = ?",
            )
            .bind(&updated_bytes)
            .bind(auth_result.counter() as i64)
            .bind(&now)
            .bind(cred_db_id)
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
pub async fn session_info(user: AuthUser) -> Json<SessionResponse> {
    Json(SessionResponse {
        user_id: user.user_id,
        display_name: user.display_name,
    })
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
