//! Shared helpers for integration tests.
//!
//! Each integration test binary under `server/tests/` does `mod common;`
//! at the top to pick this up. The patterns here are documented in
//! `docs/handler_tests.md`.
//!
//! Key invariants:
//!
//! - `test_app()` constructs an `AppState` and Router without spawning
//!   the trust-graph `rebuild_loop`. Tests are expected to call
//!   `refresh_trust_graph` synchronously after fixture setup or any
//!   mutation that affects trust visibility.
//! - The bypass routes `/test/setup-admin` and `/test/signup-as` are
//!   merged into the live router via the `test-auth` Cargo feature.
//!   See `server/src/test_support.rs`.
//! - Requests are dispatched via `tower::ServiceExt::oneshot`. Each
//!   request carries a fake `ConnectInfo<SocketAddr>` extension so the
//!   rate limiter's `PeerIpKeyExtractor` can extract a peer IP, and an
//!   `Origin` header matching the test `AllowedOrigin` so the CSRF
//!   check passes on non-safe methods.

// Functions here aren't all used by every test binary; suppress the
// per-binary dead-code warnings that result.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::AtomicBool;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use prismoire_config::RateLimitConfig;
use prismoire_server::middleware::csrf::AllowedOrigin;
use prismoire_server::middleware::security_headers::HttpsEnabled;
use prismoire_server::trust::{self, RebuildSchedule, TrustGraph};
use prismoire_server::{AppState, build_app, metrics, rate_limit};
use serde_json::Value;
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::Notify;
use tower::ServiceExt;
use url::Url;
use webauthn_rs::WebauthnBuilder;
use webauthn_rs::prelude::Webauthn;

/// The origin tests send in the `Origin` header so the real CSRF
/// middleware accepts non-safe requests. Tests build their
/// [`AllowedOrigin`] from this same value via [`test_allowed_origin`].
pub const TEST_ORIGIN: &str = "http://test.local";

/// A captured session: the raw token, the full `Set-Cookie` value, and
/// the user id. Tests usually only care about `cookie` (passed verbatim
/// as the `Cookie:` header on subsequent requests) and `user_id`.
#[derive(Clone, Debug)]
pub struct Session {
    pub user_id: String,
    pub display_name: String,
    pub cookie: String,
}

/// Build a Webauthn instance for tests.
///
/// `test_setup_admin` and `test_signup_as` don't touch this — they skip
/// the passkey ceremony entirely — but the field is non-optional on
/// `AppState`, so we still need a value. The configuration mirrors the
/// dev-mode setup in `main::build_webauthn` (localhost relying party,
/// `allow_any_port`).
fn test_webauthn() -> Arc<Webauthn> {
    let rp_origin = Url::parse("http://localhost").expect("static URL parses");
    let builder = WebauthnBuilder::new("localhost", &rp_origin)
        .expect("WebauthnBuilder accepts localhost rp_id")
        .rp_name("Prismoire-Test")
        .allow_any_port(true);
    Arc::new(builder.build().expect("webauthn build"))
}

/// Build an [`AllowedOrigin`] matching [`TEST_ORIGIN`].
fn test_allowed_origin() -> AllowedOrigin {
    let url = Url::parse(TEST_ORIGIN).expect("static URL parses");
    AllowedOrigin::from_url(&url).expect("test origin has a host")
}

/// Build a permissive rate-limit config for tests.
///
/// The real burst sizes (`ip_burst_size: 50`, etc.) are tight enough
/// that a fixture-heavy test could plausibly trip them; bump everything
/// to a value that no realistic test will reach. The replenish
/// intervals stay at sane defaults so the limiter still exists
/// structurally — tests exercise the full middleware stack the same
/// way prod does.
fn test_rate_limit_config() -> RateLimitConfig {
    RateLimitConfig {
        ip_replenish_seconds: 1,
        ip_burst_size: 100_000,
        auth_replenish_seconds: 1,
        auth_burst_size: 100_000,
        user_replenish_seconds: 1,
        user_burst_size: 100_000,
    }
}

/// Spin up a fresh in-memory database, run migrations, apply prod-
/// equivalent connection pragmas.
///
/// Single connection avoids the `:memory:` pool-isolation issue
/// (separate connections see separate databases). `foreign_keys = ON`
/// is connection-scoped, so we set it here exactly as
/// `main::configure_pool` does.
pub async fn fresh_db() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("open in-memory sqlite");
    sqlx::query("PRAGMA journal_mode = WAL")
        .execute(&pool)
        .await
        .expect("set journal_mode");
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await
        .expect("enable foreign_keys");
    sqlx::query("PRAGMA busy_timeout = 5000")
        .execute(&pool)
        .await
        .expect("set busy_timeout");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    pool
}

/// Build a complete test app: fresh DB, AppState, Router, no
/// `rebuild_loop` spawned.
///
/// Returns `(Router, Arc<AppState>)`. The state handle is what tests
/// pass to [`refresh_trust_graph`] when they need the cached graph to
/// reflect newly-inserted edges.
pub async fn test_app() -> (Router, Arc<AppState>) {
    let pool = fresh_db().await;
    let trust_graph_notify = Arc::new(Notify::new());
    let trust_graph = Arc::new(RwLock::new(Arc::new(TrustGraph::empty())));
    let app_metrics = Arc::new(metrics::Metrics::new());
    let pending_deltas = Arc::new(trust::PendingDeltas::new(Some(app_metrics.clone())));

    let state = Arc::new(AppState {
        db: pool,
        webauthn: test_webauthn(),
        // Starts true so `POST /test/setup-admin` flips it, matching the
        // real `setup_complete` lifecycle. Tests that need to bypass
        // setup entirely can call `setup_admin` once at the top of the
        // fixture.
        needs_setup: AtomicBool::new(true),
        setup_token: None,
        trust_graph_notify,
        trust_graph,
        metrics: app_metrics,
        pending_deltas,
    });

    let layers = rate_limit::build_layers(&test_rate_limit_config(), false);
    let app = build_app(
        state.clone(),
        test_allowed_origin(),
        HttpsEnabled(false),
        layers,
    );
    (app, state)
}

/// Force a synchronous rebuild of the trust graph cache.
///
/// Always call this after any fixture step or handler call that
/// mutates trust edges. `test_app()` does not spawn `rebuild_loop`, so
/// the `trust_graph_notify.notify_one()` calls inside `signup_as` and
/// `set_trust_edge` never trigger a rebuild on their own.
///
/// Note that `set_trust_edge` *does* apply its mutation to
/// `pending_deltas` synchronously, so the mutating user sees their own
/// edge change reflected via `get_trust_graph()` immediately even
/// without this call — but other readers see the cached graph alone
/// and need a refresh to observe the change. Always refreshing after a
/// trust mutation keeps test reasoning simple.
pub async fn refresh_trust_graph(state: &AppState) {
    trust::rebuild_trust_graph(
        &state.db,
        &state.trust_graph,
        RebuildSchedule::default().bfs_cache_bytes,
        None,
    )
    .await
    .expect("trust graph rebuild");
}

/// Send a request through the router and return the response.
///
/// Adds the fake `ConnectInfo<SocketAddr>` extension so the rate
/// limiter's `PeerIpKeyExtractor` doesn't fail, and sets the `Origin`
/// header on non-safe methods so the CSRF middleware accepts the
/// request.
pub async fn send(app: &Router, mut req: Request<Body>) -> Response<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS)
        && !req.headers().contains_key(header::ORIGIN)
    {
        req.headers_mut()
            .insert(header::ORIGIN, TEST_ORIGIN.parse().unwrap());
    }
    app.clone().oneshot(req).await.expect("router dispatch")
}

/// Build a JSON-bodied request with an optional session cookie.
pub fn json_request(
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    body: &Value,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder
        .body(Body::from(serde_json::to_vec(body).expect("serialize")))
        .expect("build request")
}

/// Build a body-less GET request with an optional session cookie.
pub fn get_request(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::empty()).expect("build request")
}

/// Materialise a response body into bytes (then UTF-8 string for
/// debug-friendly assertion messages).
pub async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec()
}

/// Parse a response body as JSON. Panics with the raw body on parse
/// failure so test output points at the actual server response.
pub async fn body_json(response: Response<Body>) -> Value {
    let bytes = body_bytes(response).await;
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "response body was not valid JSON: {e}; body: {}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

/// `POST /test/setup-admin` — equivalent to the real setup flow minus
/// WebAuthn. Returns the new admin's [`Session`].
pub async fn setup_admin(app: &Router, display_name: &str) -> Session {
    let req = json_request(
        Method::POST,
        "/test/setup-admin",
        None,
        &serde_json::json!({ "display_name": display_name }),
    );
    let response = send(app, req).await;
    let status = response.status();
    // Capture the cookie (if any) and the raw body before any
    // status-conditional logic. If the bypass route 404s or 500s, the
    // body is probably HTML or a JSON error payload — assert on the
    // status first with the body included for diagnostics, rather than
    // panicking inside `body_json` on a parse failure.
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().expect("cookie is ASCII").to_string());
    let bytes = body_bytes(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "setup-admin failed: status={status} body={:?}",
        String::from_utf8_lossy(&bytes)
    );
    let cookie = cookie.expect("setup-admin (200 OK) should set a session cookie");
    let body: Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "setup-admin response not JSON: {e}; body={:?}",
            String::from_utf8_lossy(&bytes)
        )
    });
    Session {
        user_id: body["user_id"].as_str().expect("user_id").to_string(),
        display_name: body["display_name"]
            .as_str()
            .expect("display_name")
            .to_string(),
        cookie,
    }
}

/// `POST /test/signup-as` — equivalent to invited signup minus
/// WebAuthn / invite-code ceremony. Inserts the user, signing key, and
/// the two trust edges with the inviter. Returns the new user's
/// [`Session`].
pub async fn signup_as(app: &Router, inviter: &Session, display_name: &str) -> Session {
    let req = json_request(
        Method::POST,
        "/test/signup-as",
        None,
        &serde_json::json!({
            "inviter_id": inviter.user_id,
            "display_name": display_name,
        }),
    );
    let response = send(app, req).await;
    let status = response.status();
    // See `setup_admin` for why we capture the body before asserting
    // status.
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().expect("cookie is ASCII").to_string());
    let bytes = body_bytes(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "signup-as failed: status={status} body={:?}",
        String::from_utf8_lossy(&bytes)
    );
    let cookie = cookie.expect("signup-as (200 OK) should set a session cookie");
    let body: Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "signup-as response not JSON: {e}; body={:?}",
            String::from_utf8_lossy(&bytes)
        )
    });
    Session {
        user_id: body["user_id"].as_str().expect("user_id").to_string(),
        display_name: body["display_name"]
            .as_str()
            .expect("display_name")
            .to_string(),
        cookie,
    }
}
