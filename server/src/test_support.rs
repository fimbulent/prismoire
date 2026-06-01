//! Test-only auth bypass routes for integration tests.
//!
//! Gated behind `#[cfg(any(test, feature = "test-auth"))]` so they're
//! never compiled into production builds. CI builds the integration test
//! pass with `--features test-auth` and the release build without.
//!
//! WebAuthn ceremony cannot be invoked from a Rust test runner, so these
//! two handlers mirror the two real user-creation paths
//! (`setup_complete` and `signup_complete`) with the passkey step
//! removed. They must keep every other step intact — signing keys,
//! trust edges, session creation, the `needs_setup` flip — so fixtures
//! match the shape of real data and trust-visibility tests start from a
//! realistic graph.
//!
//! See `docs/handler_tests.md` for the rationale and the test plan.
//!
//! Routes:
//! - `POST /test/setup-admin` — equivalent to `setup_complete` minus WebAuthn.
//! - `POST /test/signup-as` — equivalent to `signup_complete` minus
//!   WebAuthn and invite-code ceremony.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::SET_COOKIE;
use axum::response::IntoResponse;
use axum::routing::post;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::display_name::display_name_skeleton;
use crate::error::{AppError, ErrorCode};
use crate::session::{create_session, session_cookie};
use crate::signing;
use crate::state::AppState;

/// Build the test-only bypass router.
///
/// Merged into the main `api` router under `cfg(any(test, feature =
/// "test-auth"))`. The routes live at `/test/*` so they're easy to
/// spot in logs and easy to exempt from middleware that's not relevant
/// to fixture setup (`setup_guard_middleware` is the only one that
/// matters today; CSRF still applies and tests are expected to send a
/// matching `Origin` header).
pub fn test_router() -> Router<Arc<AppState>> {
    // Defense-in-depth: scream at startup whenever the bypass router is
    // mounted, so an accidental release build with `test-auth` enabled
    // shows up immediately in operator logs rather than silently
    // exposing two un-authenticated user-creation endpoints. The Cargo
    // feature gate is the primary defense; this is just a tripwire.
    tracing::warn!(
        "mounting test-only auth bypass routes (/test/setup-admin, /test/signup-as) — \
         the `test-auth` feature MUST NOT be enabled in production builds"
    );
    Router::new()
        .route("/test/setup-admin", post(test_setup_admin))
        .route("/test/signup-as", post(test_signup_as))
}

#[derive(Deserialize)]
pub struct TestSetupAdminRequest {
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct TestSignupAsRequest {
    pub inviter_id: String,
    pub display_name: String,
}

/// Response body for both bypass handlers.
///
/// `session_token` is the raw token (also set via `Set-Cookie`). Tests
/// can either re-use the cookie header verbatim or build their own
/// `Cookie:` header from the token; both work.
#[derive(Serialize)]
pub struct TestSessionResponse {
    pub user_id: String,
    pub display_name: String,
    /// Lowercase-hex of the new user's 32-byte signing pubkey. Tests use
    /// this to build pubkey-keyed user-route URLs.
    pub public_key_hex: String,
    pub session_token: String,
}

/// Insert an admin user, signing key, flip `needs_setup`, mint a session.
///
/// Mirrors `setup::setup_complete` minus the WebAuthn passkey step.
async fn test_setup_admin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestSetupAdminRequest>,
) -> Result<impl IntoResponse, AppError> {
    let display_name = req.display_name.trim().to_string();
    if display_name.is_empty() {
        return Err(AppError::with_message(
            ErrorCode::InvalidDisplayName,
            "display_name must not be empty".to_string(),
        ));
    }

    // Mirror real signup's `display_name_skeleton` normalization so
    // fixture users don't drift wider than prod's case-folded /
    // confusable-collapsed uniqueness rules. Tests that intentionally
    // exercise the skeleton-collision path then exercise the *same*
    // collision logic as production.
    let user_id = Uuid::new_v4().to_string();
    let skeleton = display_name_skeleton(&display_name);

    let signing_key = signing::generate_signing_key();
    let verifying_bytes = signing_key.verifying_key().to_bytes();
    let public_key: &[u8] = verifying_bytes.as_slice();
    let public_key_hex = crate::users::hex_lower(public_key);

    // Same birth write-set as `setup_complete` (minus the WebAuthn
    // credential, which tests have no passkey material for): user row,
    // signing key, genesis profile-rev, genesis move. Routing both
    // through `complete_local_user_birth` is what keeps fixtures from
    // drifting away from prod — the drift that masked the §11.9.5
    // bootstrap bug. Birth output is discarded: tests drive federation
    // by hand rather than relying on originator-side flood.
    let created_at_ms = u64::try_from(chrono::Utc::now().timestamp_millis())
        .map_err(|_| AppError::code(ErrorCode::Internal))?;
    let mut tx = state.db.begin().await?;
    crate::auth::complete_local_user_birth(
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
            credential: None,
        },
    )
    .await?;
    tx.commit().await?;

    state.needs_setup.store(false, Ordering::Relaxed);

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    Ok((
        headers,
        Json(TestSessionResponse {
            user_id,
            display_name,
            public_key_hex,
            session_token: token,
        }),
    ))
}

/// Insert an invited user, signing key, two trust edges, mint a session.
///
/// Mirrors `auth::signup_complete` minus the WebAuthn passkey step and
/// the invite-code ceremony. The two `trust_edges` inserts are
/// load-bearing: fixtures created via this handler match the shape of
/// real prod data (every signed-up user has a bidirectional trust edge
/// with their inviter), which is exactly what makes Tier-2 trust
/// visibility tests realistic.
async fn test_signup_as(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestSignupAsRequest>,
) -> Result<impl IntoResponse, AppError> {
    let display_name = req.display_name.trim().to_string();
    if display_name.is_empty() {
        return Err(AppError::with_message(
            ErrorCode::InvalidDisplayName,
            "display_name must not be empty".to_string(),
        ));
    }
    let inviter_id = req.inviter_id;

    // See `test_setup_admin` — mirror the real skeleton normalization
    // so fixtures match prod's uniqueness rules.
    let user_id = Uuid::new_v4().to_string();
    let skeleton = display_name_skeleton(&display_name);

    let signing_key = signing::generate_signing_key();
    let verifying_bytes = signing_key.verifying_key().to_bytes();
    let public_key: &[u8] = verifying_bytes.as_slice();
    let public_key_hex = crate::users::hex_lower(public_key);

    // Mirror `signup_complete` exactly: two `trust` edges, inviter→invitee
    // and invitee→inviter. Signed under V1 server-side keys so fixtures
    // match the shape of production-signed trust edges.
    let trust1_id = Uuid::new_v4().to_string();
    let trust2_id = Uuid::new_v4().to_string();

    let now_dt = chrono::Utc::now();
    let now_iso = now_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let created_at_ms = u64::try_from(now_dt.timestamp()).map_err(|_| {
        tracing::error!(
            ts = now_dt.timestamp(),
            "system clock is pre-1970; cannot sign test-signup trust edges"
        );
        AppError::code(ErrorCode::Internal)
    })? * 1000;

    // Mirror prod's transactional shape — see `signup_complete`.
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    // Same birth write-set as `signup_complete` (minus the WebAuthn
    // credential): user row, signing key, genesis profile-rev, genesis
    // move — via the shared `complete_local_user_birth` so fixtures
    // can't drift from prod. Output discarded (tests flood by hand).
    // Must precede the trust-edge signing below, which needs the
    // invitee's signing key stored.
    crate::auth::complete_local_user_birth(
        &mut tx,
        &state.instance_key,
        &state.instance_domain,
        created_at_ms,
        &crate::auth::LocalUserBirth {
            user_id: &user_id,
            display_name: &display_name,
            display_name_skeleton: &skeleton,
            signup_method: "invite",
            role: "user",
            public_key,
            signing_key: &signing_key,
            credential: None,
        },
    )
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

    // Dual-write canonical bytes for both edges so fixtures match the
    // shape of production-signed rows in `signed_objects` as well as
    // `trust_edges`.
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
        Json(TestSessionResponse {
            user_id,
            display_name,
            public_key_hex,
            session_token: token,
        }),
    ))
}
