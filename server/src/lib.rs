//! Prismoire server library.
//!
//! The HTTP router, handlers, application state, and helpers all live in
//! this library crate. The actual `main` (`src/main.rs`) is a thin
//! wrapper that parses config, opens the database, runs migrations,
//! constructs the [`AppState`], spawns background tasks, and calls
//! [`build_app`] to assemble the Axum router.
//!
//! Splitting `main.rs` from `lib.rs` is what makes integration tests in
//! `server/tests/` possible — they link against this library crate
//! directly and call [`build_app`] with a test [`AppState`] of their own
//! construction.

use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get, post, put};

pub mod admin;
pub mod admin_config;
pub mod admin_overview;
pub mod admin_routes;
pub mod admin_watchlists;
pub mod attachments;
pub mod auth;
pub mod csp_report;
pub mod display_name;
pub mod error;
pub mod favorites;
pub mod federation;
pub mod instance_config;
pub mod invites;
pub mod metrics;
pub mod middleware;
pub mod posts;
pub mod privacy;
pub mod rate_limit;
pub mod reports;
pub mod room_name;
pub mod rooms;
pub mod search;
pub mod session;
pub mod settings;
pub mod setup;
pub mod signed;
pub mod signing;
pub mod state;
pub mod threads;
pub mod trust;
pub mod users;
pub mod validation;

#[cfg(any(test, feature = "test-auth"))]
pub mod test_support;

pub use state::AppState;

use middleware::csrf::AllowedOrigin;
use middleware::security_headers::HttpsEnabled;
use rate_limit::RateLimitLayers;

/// Build the full Axum application router.
///
/// Assembles every route group, applies the middleware stack (session,
/// CSRF, setup-guard, cache-control, security-headers, route-metrics)
/// and binds the rate-limit layers at their respective scopes:
///
/// - `auth_routes` (`/api/setup/*`, `/api/auth/{signup,login,discover}/*`)
///   carry the strict auth rate limit and bypass `session_middleware`.
/// - `session_route` (`/api/auth/session`) carries the session middleware
///   but skips the per-session user limiter (see comment inline).
/// - `report_route` (`POST /api/posts/{id}/report`) carries the session
///   middleware plus the tighter per-session report limiter.
/// - `authed` (everything else under `/api/*`) carries the session
///   middleware and the per-session user limiter.
/// - The merged `api` router carries the global IP limiter and the
///   setup-guard / CSRF / cache-control middleware.
/// - `health_router` (`/api/health`) and `csp_report_router`
///   (`/api/csp-report`) sit outside the main `api` router so they
///   bypass setup-guard, CSRF, and the general IP limit (the CSP report
///   path has its own tighter per-IP bucket).
///
/// When the `test-auth` feature is enabled, the bypass routes from
/// [`test_support::test_router`] are merged alongside `auth_routes` so
/// they share the same "no session middleware" exemption. The
/// `setup_guard_middleware` also exempts `/test/*` paths under that
/// feature so `test_setup_admin` can run before the instance is set up.
pub fn build_app(
    shared_state: Arc<AppState>,
    allowed_origin: AllowedOrigin,
    https_enabled: HttpsEnabled,
    layers: RateLimitLayers,
) -> Router {
    let RateLimitLayers {
        ip: ip_limiter,
        auth: auth_limiter,
        user: user_limiter,
        report: report_limiter,
        upload: upload_limiter,
        csp_report: csp_report_limiter,
    } = layers;

    let authed = Router::new()
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/rooms", get(rooms::list_rooms))
        .route("/api/rooms/more", post(rooms::load_more_rooms))
        .route("/api/rooms/tab-bar", get(rooms::tab_bar))
        .route("/api/rooms/search", get(rooms::search_rooms))
        .route("/api/search", get(search::search_dropdown))
        .route("/api/search/threads", get(search::search_threads_paginated))
        .route("/api/search/threads/more", post(search::load_more_threads))
        .route("/api/search/posts", get(search::search_posts))
        .route("/api/search/posts/more", post(search::load_more_posts))
        .route("/api/search/users", get(users::search_users_paginated))
        .route(
            "/api/search/users/more",
            post(users::load_more_search_users),
        )
        .route("/api/search/rooms", get(rooms::search_rooms_paginated))
        .route(
            "/api/search/rooms/more",
            post(rooms::load_more_search_rooms),
        )
        .route("/api/rooms/{id}", get(rooms::get_room))
        .route("/api/rooms/{id}/threads", get(threads::list_threads))
        .route(
            "/api/rooms/{id}/favorite",
            post(favorites::favorite_room).delete(favorites::unfavorite_room),
        )
        .route(
            "/api/me/favorites",
            get(favorites::list_favorites).put(favorites::reorder_favorites),
        )
        .route(
            "/api/threads",
            get(threads::list_all_threads).post(threads::create_thread),
        )
        .route("/api/threads/more", post(threads::load_more_all_threads))
        .route("/api/threads/by-link", get(threads::get_threads_by_link))
        .route(
            "/api/rooms/{id}/threads/more",
            post(threads::load_more_room_threads),
        )
        .route("/api/threads/{id}", get(threads::get_thread))
        .route("/api/threads/{id}/posts", post(threads::create_reply))
        .route(
            "/api/threads/{id}/replies",
            get(threads::get_thread_replies),
        )
        .route(
            "/api/threads/{id}/subtree/{post_id}",
            get(threads::get_thread_subtree),
        )
        .route(
            "/api/posts/{id}",
            axum::routing::patch(posts::edit_post).delete(posts::retract_post),
        )
        .route("/api/posts/{id}/revisions", get(posts::list_revisions))
        .route(
            "/api/invites",
            get(invites::list_invites).post(invites::create_invite),
        )
        .route("/api/invites/users", get(invites::list_invited_users))
        .route("/api/invites/{id}", delete(invites::revoke_invite))
        .route("/api/users/search", get(users::search_users))
        .route(
            "/api/users/{username}/resolve",
            get(users::resolve_username),
        )
        .route(
            "/api/users/{pubkey_hex}",
            get(users::get_profile).patch(users::update_bio),
        )
        .route(
            "/api/users/{pubkey_hex}/trust",
            get(users::get_trust_detail),
        )
        .route("/api/users/{pubkey_hex}/activity", get(users::get_activity))
        .route(
            "/api/users/{pubkey_hex}/trust/edges",
            get(users::get_trust_edges),
        )
        .route(
            "/api/users/{pubkey_hex}/trust-edge",
            put(users::set_trust_edge).delete(users::delete_trust_edge),
        )
        .route(
            "/api/users/{pubkey_hex}/tag",
            put(users::set_user_tag).delete(users::delete_user_tag),
        )
        .route(
            "/api/settings",
            get(settings::get_settings).patch(settings::update_settings),
        )
        .route("/api/me/export", get(privacy::export_my_data))
        .route(
            "/api/me/export/attachments",
            get(privacy::export_my_attachments),
        )
        .route("/api/me", delete(privacy::delete_my_account))
        .route(
            "/api/attachments/{hash}",
            get(attachments::serve_attachment),
        )
        .route("/api/admin/log", get(admin::get_admin_log))
        .route(
            "/api/admin/threads/{id}/lock",
            post(admin::lock_thread).delete(admin::unlock_thread),
        )
        .route("/api/admin/posts/{id}", delete(admin::remove_post))
        .route("/api/admin/reports", get(reports::list_reports))
        .route(
            "/api/admin/reports/{id}/dismiss",
            post(reports::dismiss_report),
        )
        .route(
            "/api/admin/reports/{id}/action",
            post(reports::action_report),
        )
        .route("/api/admin/dashboard", get(reports::get_dashboard))
        .route("/api/admin/overview", get(admin_overview::get_overview))
        .route(
            "/api/admin/config",
            get(admin_config::get_config).patch(admin_config::update_config),
        )
        .route("/api/admin/routes", get(admin_routes::list_routes))
        .route(
            "/api/admin/watchlists",
            get(admin_watchlists::get_watchlists),
        )
        .route(
            "/api/admin/users/{id}/ban",
            post(admin::ban_user).delete(admin::unban_user),
        )
        .route(
            "/api/admin/users/{id}/suspend",
            post(admin::suspend_user).delete(admin::unsuspend_user),
        )
        .route(
            "/api/admin/users/{id}/invites",
            post(admin::admin_grant_invites).delete(admin::admin_revoke_invites),
        )
        .route(
            "/api/admin/users/{id}/invite-tree",
            get(admin::get_invite_tree),
        )
        .route("/api/admin/users/{id}", delete(admin::delete_user_by_admin))
        .route("/api/admin/rooms/{id}", delete(admin::delete_room))
        .layer(axum::middleware::from_fn_with_state(
            shared_state.clone(),
            session::session_middleware,
        ))
        .layer(user_limiter);

    // Report creation gets the general session middleware plus a tighter
    // per-session rate limit so a single user cannot flood the admin
    // moderation queue. The route still inherits the outer `ip_limiter`
    // from the `api` router.
    let report_route = Router::new()
        .route("/api/posts/{id}/report", post(reports::create_report))
        .layer(axum::middleware::from_fn_with_state(
            shared_state.clone(),
            session::session_middleware,
        ))
        .layer(report_limiter);

    // Attachment uploads carry their own per-session rate limit because
    // `POST /api/attachments` is by far the most CPU-expensive
    // authenticated endpoint (multipart parse + image decode + downscale
    // + re-encode, all on the `spawn_blocking` pool). The general
    // `user_limiter` would let a single session spam the encode pool;
    // a dedicated bucket caps sustained throughput without affecting
    // other write endpoints. The body-size cap on the inner `.layer(...)`
    // is the wire-canonical `MAX_ATTACHMENT_SIZE` (500 KiB) plus the
    // configurable `attachments.request_body_overhead_bytes` slack for
    // multipart boundary headers and form fields (docs/attachments.md
    // §3 step 0). The route still inherits the outer `ip_limiter`.
    let upload_route = Router::new()
        .route(
            "/api/attachments",
            post(attachments::upload_attachment).layer(axum::extract::DefaultBodyLimit::max(
                signed::MAX_ATTACHMENT_SIZE
                    + shared_state.attachments_config.request_body_overhead_bytes,
            )),
        )
        .layer(axum::middleware::from_fn_with_state(
            shared_state.clone(),
            session::session_middleware,
        ))
        .layer(upload_limiter);

    // `/api/auth/session` is intentionally separated from the rest of
    // the authed routes so it does not carry the per-session
    // `user_limiter`. The endpoint is cheap, idempotent, and called by
    // the SvelteKit root layout load on every SSR — including tap
    // preloads — so a brief burst of navigations would otherwise
    // exhaust the per-session bucket and start returning 429s. A 429
    // here would surface to the user as a 503 error page (see the
    // `sessionError` handling in `web/src/routes/+layout.server.ts`),
    // which is correct as a safety net but a poor day-to-day
    // experience. The endpoint still gets the global `ip_limiter` from
    // the outer `api` router, so abuse from a single source is still
    // bounded; we just stop conflating "look up my session" with the
    // write-endpoint budget.
    let session_route = Router::new()
        .route("/api/auth/session", get(auth::session_info))
        .layer(axum::middleware::from_fn_with_state(
            shared_state.clone(),
            session::session_middleware,
        ));

    let auth_routes = Router::new()
        .route("/api/setup/begin", post(setup::setup_begin))
        .route("/api/setup/complete", post(setup::setup_complete))
        .route("/api/auth/signup/begin", post(auth::signup_begin))
        .route("/api/auth/signup/complete", post(auth::signup_complete))
        .route("/api/auth/login/begin", post(auth::login_begin))
        .route("/api/auth/login/complete", post(auth::login_complete))
        .route("/api/auth/discover/complete", post(auth::discover_complete))
        // §13 cross-instance registration (account-move ceremony).
        // Mounted alongside the rest of the unauthenticated auth
        // surface — no session required (the user has no local account
        // yet), and shares the auth_limiter bucket with signup/login
        // because the failure modes (passkey ceremony abuse, brute
        // force, etc.) are the same. The module lives under
        // `federation::registration` because the wire format is §5.5,
        // but per spec there is no `/federation/v1/...` route here.
        .route(
            "/api/auth/cross-instance/begin",
            post(federation::registration::begin),
        )
        .route(
            "/api/auth/cross-instance/complete",
            post(federation::registration::complete),
        )
        .layer(auth_limiter);

    // Test-only auth bypass routes. Mounted at the same scope as
    // `auth_routes` so they share the "no session middleware required"
    // property. `setup_guard_middleware` also exempts `/test/*` paths
    // under this feature so `POST /test/setup-admin` can run before the
    // instance is set up. See `server/src/test_support.rs` and
    // `docs/handler_tests.md`.
    #[cfg(any(test, feature = "test-auth"))]
    let test_routes = test_support::test_router();

    let api = Router::new()
        .route(
            "/api/threads/public",
            get(threads::list_public_announcement_threads),
        )
        .route("/api/setup/status", get(setup::setup_status))
        .route("/api/auth/discover/begin", get(auth::discover_begin))
        .route(
            "/api/invites/{code}/validate",
            get(invites::validate_invite),
        )
        .merge(auth_routes)
        .merge(session_route)
        .merge(report_route)
        .merge(upload_route)
        .merge(authed);

    #[cfg(any(test, feature = "test-auth"))]
    let api = api.merge(test_routes);

    let api = api
        .layer(axum::middleware::from_fn_with_state(
            allowed_origin,
            middleware::csrf::csrf_origin_check,
        ))
        .layer(ip_limiter)
        .layer(axum::middleware::from_fn_with_state(
            shared_state.clone(),
            setup::setup_guard_middleware,
        ))
        // Cache-Control wraps every response (handler output,
        // rate-limit 429s, CSRF 403s, setup 503s) with `no-store`.
        .layer(axum::middleware::from_fn(
            middleware::cache_control::cache_control,
        ))
        // Per-route metrics is the outermost layer on the API router
        // so the latency it records covers every inner layer
        // (rate-limiting, CSRF, setup-guard, cache-control). Placed
        // after `.merge(...)` calls so every merged route template is
        // measured under its real matched path.
        .layer(axum::middleware::from_fn_with_state(
            shared_state.metrics.clone(),
            middleware::route_metrics::route_metrics,
        ))
        .with_state(shared_state.clone());

    // Health check lives outside the rate-limited `api` router so that
    // monitoring probes (Prometheus, k8s liveness, etc.) cannot trip the
    // IP rate limiter. It also bypasses setup_guard and CSRF — the endpoint
    // is a safe GET with no side effects, and is already safelisted in
    // setup_guard anyway.
    let health_router = Router::new().route("/api/health", get(|| async { "ok" }));

    // CSP violation reports. Sits outside the main `api` router so it
    // bypasses:
    //   - CSRF origin check: browsers submit these as UA-initiated POSTs
    //     with no Origin header, which the standard check would reject.
    //   - setup_guard: reports from the SSR'd SvelteKit setup page would
    //     otherwise be rejected with a 503 `setup_required`, and we do
    //     want to see those too.
    //   - The general IP limiter: replaced here with a tighter CSP-specific
    //     bucket (see `rate_limit::build_layers`) so a report flood can
    //     be shed without crowding out the rest of the API.
    // The response is `204 No Content` with no body, so Cache-Control
    // semantics are moot — no outer cache_control layer is applied.
    let csp_report_router = Router::new()
        .route("/api/csp-report", post(csp_report::receive_csp_report))
        .layer(csp_report_limiter)
        .with_state(shared_state.clone());

    // Federation subrouter. Sits outside the `/api/*` middleware
    // stack: it has its own §6.5 envelope verification per-handler
    // (later: a router-wide middleware in Phase 3), its own CBOR
    // content-type discipline, and its own rate-limiting needs that
    // do not align with the user-session-scoped buckets the `/api`
    // surface uses. Setup-guard is also intentionally skipped — the
    // §5.2 `GET /identity` route must answer during the bootstrap
    // window so peer operators can fetch our pubkey while we still
    // have no admin account.
    let federation_router = federation::router::federation_router(shared_state.clone());

    api.merge(health_router)
        .merge(csp_report_router)
        .merge(federation_router)
        .layer(axum::middleware::from_fn_with_state(
            https_enabled,
            middleware::security_headers::security_headers,
        ))
}
