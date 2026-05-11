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

    sqlx::query!(
        "INSERT INTO users (id, display_name, display_name_skeleton, signup_method, role) \
         VALUES (?, ?, ?, 'admin', 'admin')",
        user_id,
        display_name,
        skeleton,
    )
    .execute(&state.db)
    .await?;

    signing::create_signing_key(&state.db, &user_id).await?;

    state.needs_setup.store(false, Ordering::Relaxed);

    let token = create_session(&state.db, &user_id).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session_cookie(&token).parse().unwrap());

    Ok((
        headers,
        Json(TestSessionResponse {
            user_id,
            display_name,
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

    sqlx::query!(
        "INSERT INTO users (id, display_name, display_name_skeleton, signup_method) \
         VALUES (?, ?, ?, 'invite')",
        user_id,
        display_name,
        skeleton,
    )
    .execute(&state.db)
    .await?;

    signing::create_signing_key(&state.db, &user_id).await?;

    // Mirror `signup_complete` exactly: two `trust` edges, inviter→invitee
    // and invitee→inviter. This is the critical step that lets every
    // fixture user start with a realistic trust graph.
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
        Json(TestSessionResponse {
            user_id,
            display_name,
            session_token: token,
        }),
    ))
}
