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
    /// Lowercase-hex of the session user's 32-byte Ed25519 public key.
    /// Lets the frontend build canonical `/@username.{8hex}` profile
    /// URLs without a separate resolve roundtrip — see
    /// `web/src/lib/user-url.ts::canonicalProfilePath`.
    pub public_key_hex: String,
    pub role: String,
    pub theme: String,
    pub font: String,
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
    pub fn active(
        user_id: String,
        display_name: String,
        public_key_hex: String,
        role: String,
        theme: String,
        font: String,
    ) -> Self {
        Self {
            user_id,
            display_name,
            public_key_hex,
            role,
            theme,
            font,
            status: UserStatus::Active,
            suspended_until: None,
        }
    }

    /// Build a [`SessionResponse`] for any status. Drops `suspended_until`
    /// for non-suspended users so the wire payload never carries a stale
    /// timestamp after a suspension has lifted or a ban has been applied.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_id: String,
        display_name: String,
        public_key_hex: String,
        role: String,
        theme: String,
        font: String,
        status: UserStatus,
        suspended_until: Option<String>,
    ) -> Self {
        Self {
            user_id,
            display_name,
            public_key_hex,
            role,
            theme,
            font,
            status,
            suspended_until: if status == UserStatus::Suspended {
                suspended_until
            } else {
                None
            },
        }
    }
}

/// Inputs to [`bootstrap_local_user`].
///
/// Shared across the invited-signup path (`POST /api/auth/signup/complete`)
/// and the cross-instance registration path
/// (`POST /api/auth/cross-instance/complete`, §13 of
/// `docs/federation-protocol.md`). The two paths diverge in *how* they
/// arrive at a credential + signing key (WebAuthn-generated vs.
/// user-supplied) and in what mutual-trust / move-publication
/// bookkeeping they do *afterwards*, but the core write-set of "create
/// the user row, store the credential, persist the signing key" is
/// identical and is what this struct describes.
pub struct LocalUserBootstrap<'a> {
    /// Pre-allocated UUID for the new `users.id` row.
    pub user_id: &'a str,
    /// Display name as already validated by
    /// [`crate::display_name::validate_display_name`].
    pub display_name: &'a str,
    /// Confusable skeleton from
    /// [`crate::display_name::display_name_skeleton`].
    pub display_name_skeleton: &'a str,
    /// One of the values allowed by the `users.signup_method` CHECK
    /// constraint (`'invite'`, `'cross_instance_register'`, …).
    pub signup_method: &'a str,
    /// Raw 32-byte Ed25519 verifying key — the per-user federation
    /// identity. Must agree with `signing_key.verifying_key()`;
    /// [`crate::signing::store_signing_key`] re-asserts this
    /// invariant.
    pub public_key: &'a [u8],
    /// Per-user Ed25519 private key. Generated locally for the
    /// invited-signup path; supplied by the moving user for the
    /// cross-instance path.
    pub signing_key: &'a ed25519_dalek::SigningKey,
    /// Pre-allocated UUID for the new `credentials.id` row.
    pub credential_id: &'a str,
    /// WebAuthn `credential_id` blob (the authenticator-issued
    /// credential handle, not our internal `credentials.id`).
    pub passkey_credential_id: &'a [u8],
    /// Serialised [`webauthn_rs::prelude::Passkey`] bytes for the
    /// `credentials.public_key` column.
    pub passkey_bytes: &'a [u8],
}

/// Insert a new local user, their credential, and their signing key in
/// one transactional sweep.
///
/// The three writes are tightly coupled: a user without a credential
/// can never log in, and a user without a signing key cannot author
/// signed objects (trust edges, posts, profile revisions). Bundling
/// them lets every caller hold a single `BEGIN IMMEDIATE` open and
/// commit-or-rollback the whole bootstrap atomically.
///
/// Callers retain responsibility for the *path-specific* follow-up:
///   * invited signups append a mutual trust edge with the inviter and
///     dual-write it into `signed_objects`,
///   * cross-instance registrations optionally sign + enqueue a §12
///     `Move` declaration.
///
/// `conn` is taken as `&mut SqliteConnection` (not a `&mut Transaction`)
/// so the helper composes with `&mut *tx` from any caller already
/// holding a transaction.
pub async fn bootstrap_local_user(
    conn: &mut sqlx::SqliteConnection,
    input: &LocalUserBootstrap<'_>,
) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT INTO users (id, display_name, display_name_skeleton, signup_method, public_key) \
         VALUES (?, ?, ?, ?, ?)",
        input.user_id,
        input.display_name,
        input.display_name_skeleton,
        input.signup_method,
        input.public_key,
    )
    .execute(&mut *conn)
    .await
    .map_err(|err| {
        tracing::error!(
            display_name = %input.display_name,
            error = %err,
            "bootstrap_local_user: user creation constraint failure",
        );
        AppError::from(err)
    })?;

    sqlx::query!(
        "INSERT INTO credentials (id, user_id, credential_id, public_key, sign_count) \
         VALUES (?, ?, ?, ?, 0)",
        input.credential_id,
        input.user_id,
        input.passkey_credential_id,
        input.passkey_bytes,
    )
    .execute(&mut *conn)
    .await?;

    signing::store_signing_key(conn, input.user_id, input.signing_key).await?;

    Ok(())
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
            tracing::warn!(
                user_id = %user_id,
                error = %msg,
                "auth: unrecognised users.status; defaulting to active"
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
        tracing::error!("signup_complete: missing display_name in challenge");
        AppError::code(ErrorCode::Internal)
    })?;
    let user_id = challenge.user_id.ok_or_else(|| {
        tracing::error!("signup_complete: missing user_id in challenge");
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
        tracing::error!("signup_complete: missing invite_code in challenge");
        AppError::code(ErrorCode::Internal)
    })?;

    let (invite_id, inviter_id) =
        invites::validate_invite_for_signup(&state.db, &invite_code).await?;

    let skeleton = display_name_skeleton(&display_name);

    let signing_key = signing::generate_signing_key();
    let verifying_bytes = signing_key.verifying_key().to_bytes();
    let public_key: &[u8] = verifying_bytes.as_slice();

    let cred_id = Uuid::new_v4().to_string();
    let passkey_bytes = serde_json::to_vec(&passkey)?;
    let cred_id_bytes: &[u8] = passkey.cred_id().as_ref();

    let trust1_id = Uuid::new_v4().to_string();
    let trust2_id = Uuid::new_v4().to_string();

    // Sign both reciprocal trust edges per docs/signed-payload-format.md §4.3.
    // Producer-side timestamp truncated to whole seconds so the signed
    // millisecond value is reconstructable from the persisted ISO-second
    // value. See create_thread.rs for the longer rationale.
    let now_dt = chrono::Utc::now();
    let now_iso = now_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let created_at_ms = u64::try_from(now_dt.timestamp()).map_err(|_| {
        tracing::error!(
            ts = now_dt.timestamp(),
            "system clock is pre-1970; cannot sign signup trust edges"
        );
        AppError::code(ErrorCode::Internal)
    })? * 1000;

    // BEGIN IMMEDIATE: wrap the entire signup write-set in a single
    // transaction so a partial-failure scenario can't leave a half-
    // built account.
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    bootstrap_local_user(
        &mut tx,
        &LocalUserBootstrap {
            user_id: &user_id,
            display_name: &display_name,
            display_name_skeleton: &skeleton,
            signup_method: "invite",
            public_key,
            signing_key: &signing_key,
            credential_id: &cred_id,
            passkey_credential_id: cred_id_bytes,
            passkey_bytes: &passkey_bytes,
        },
    )
    .await?;

    sqlx::query!(
        "UPDATE users SET invite_id = ? WHERE id = ?",
        invite_id,
        user_id,
    )
    .execute(&mut *tx)
    .await?;

    let signed_inviter_to_user = signing::sign_trust_edge(
        &mut tx,
        &inviter_id,
        &user_id,
        crate::signed::TrustStance::Trust,
        created_at_ms,
        None,
    )
    .await?;
    let signed_user_to_inviter = signing::sign_trust_edge(
        &mut tx,
        &user_id,
        &inviter_id,
        crate::signed::TrustStance::Trust,
        created_at_ms,
        None,
    )
    .await?;
    let inviter_to_user_payload = signed_inviter_to_user.payload;
    let user_to_inviter_payload = signed_user_to_inviter.payload;
    let inviter_to_user_sig = signed_inviter_to_user.signature;
    let user_to_inviter_sig = signed_user_to_inviter.signature;
    let inviter_to_user_canonical = signed_inviter_to_user.canonical_hash;
    let user_to_inviter_canonical = signed_user_to_inviter.canonical_hash;
    let inviter_to_user_hash: Vec<u8> = inviter_to_user_canonical.to_vec();
    let user_to_inviter_hash: Vec<u8> = user_to_inviter_canonical.to_vec();

    sqlx::query!(
        "INSERT INTO trust_edges (id, source_user, target_user, trust_type, created_at, signature, canonical_hash) \
         VALUES (?, ?, ?, 'trust', ?, ?, ?)",
        trust1_id,
        inviter_id,
        user_id,
        now_iso,
        inviter_to_user_sig,
        inviter_to_user_hash,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO trust_edges (id, source_user, target_user, trust_type, created_at, signature, canonical_hash) \
         VALUES (?, ?, ?, 'trust', ?, ?, ?)",
        trust2_id,
        user_id,
        inviter_id,
        now_iso,
        user_to_inviter_sig,
        user_to_inviter_hash,
    )
    .execute(&mut *tx)
    .await?;

    // Dual-write the canonical bytes for both reciprocal edges into
    // `signed_objects`.
    signing::store_signed_object(
        &mut *tx,
        "trust-edge",
        &inviter_to_user_payload,
        &inviter_to_user_sig,
        &inviter_to_user_canonical,
    )
    .await?;
    signing::store_signed_object(
        &mut *tx,
        "trust-edge",
        &user_to_inviter_payload,
        &user_to_inviter_sig,
        &user_to_inviter_canonical,
    )
    .await?;

    tx.commit().await?;

    state.trust_graph_notify.notify_one();

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    Ok((
        headers,
        Json(SessionResponse::active(
            user_id,
            display_name,
            crate::users::hex_lower(public_key),
            "user".into(),
            crate::settings::DEFAULT_THEME.into(),
            crate::settings::DEFAULT_FONT.into(),
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
        tracing::error!("login_complete: missing display_name in challenge");
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
        "SELECT id, role, status, suspended_until, public_key FROM users \
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
    let public_key_hex = crate::users::hex_lower(&user.public_key);

    update_credential_counter(&state.db, &user_id, &auth_result).await?;

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    let (theme, font) = crate::settings::get_user_settings(&state.db, &user_id).await?;

    Ok((
        headers,
        Json(SessionResponse::new(
            user_id,
            display_name,
            public_key_hex,
            role,
            theme,
            font,
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
        "SELECT id, display_name, role, status, suspended_until, public_key FROM users \
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
    let public_key_hex = crate::users::hex_lower(&user.public_key);

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

    let (theme, font) = crate::settings::get_user_settings(&state.db, &user_id).await?;

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    Ok((
        headers,
        Json(SessionResponse::new(
            user_id,
            display_name,
            public_key_hex,
            role,
            theme,
            font,
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
    let (theme, font) = crate::settings::get_user_settings(&state.db, &user.user_id).await?;
    Ok(Json(SessionResponse::new(
        user.user_id,
        user.display_name,
        user.public_key_hex,
        user.role,
        theme,
        font,
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
