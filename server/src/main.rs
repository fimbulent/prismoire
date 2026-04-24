use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use tokio::sync::Notify;

use axum::Router;
use axum::routing::{delete, get, post, put};
use prismoire_config::Config;
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use url::Url;
use webauthn_rs::WebauthnBuilder;

mod admin;
mod admin_overview;
mod admin_routes;
mod admin_watchlists;
mod auth;
mod csp_report;
mod display_name;
mod error;
mod favorites;
mod invites;
mod metrics;
mod middleware;
mod posts;
mod privacy;
mod rate_limit;
mod reports;
mod room_name;
mod rooms;
mod session;
mod settings;
mod setup;
mod signing;
mod state;
mod threads;
mod trust;
mod users;
mod validation;

use state::AppState;

/// Configure SQLite connection pragmas for performance and correctness.
async fn configure_pool(pool: &SqlitePool) {
    sqlx::query("PRAGMA journal_mode = WAL")
        .execute(pool)
        .await
        .expect("failed to set journal_mode");
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(pool)
        .await
        .expect("failed to enable foreign_keys");
    sqlx::query("PRAGMA busy_timeout = 5000")
        .execute(pool)
        .await
        .expect("failed to set busy_timeout");
}

/// Build the WebAuthn relying party configuration from config values.
///
/// The rp_origin URL is already validated during config loading.
fn build_webauthn(config: &Config) -> Arc<webauthn_rs::Webauthn> {
    let rp_origin =
        Url::parse(&config.webauthn.rp_origin).expect("rp_origin validated during config load");

    let is_dev = rp_origin.host_str() == Some("localhost");

    let builder = WebauthnBuilder::new(&config.webauthn.rp_id, &rp_origin)
        .expect("failed to create WebauthnBuilder")
        .rp_name("Prismoire")
        .allow_any_port(is_dev);

    Arc::new(builder.build().expect("failed to build Webauthn"))
}

/// Check whether an admin account exists in the database.
async fn has_admin(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!("SELECT 1 AS n FROM users WHERE role = 'admin' LIMIT 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

/// Start the Prismoire API server and listen for connections.
///
/// Loads TOML config, connects to SQLite, runs migrations, configures
/// WebAuthn, checks for admin bootstrap state, then serves the JSON API.
/// The SvelteKit frontend runs as a separate `adapter-node` process;
/// a reverse proxy (Caddy / nginx) routes `/api/*` here and everything
/// else to the Node process.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_arg = prismoire_config::parse_config_arg()?;
    let config = prismoire_config::load_config(config_arg.as_deref())?;

    let db_url = format!("sqlite:{}?mode=rwc", config.server.database);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    configure_pool(&pool).await;
    sqlx::migrate!().run(&pool).await?;

    let admin_exists = has_admin(&pool).await?;

    let setup_token = match &config.server.setup_token_file {
        Some(path) => Some(prismoire_config::read_secret_file(path)?),
        None => None,
    };

    if !admin_exists && setup_token.is_none() {
        eprintln!(
            "error: no admin account exists and server.setup_token_file is not configured.\n\
             Set setup_token_file in the [server] section of your config file,\n\
             then visit /setup in the browser to create the initial admin account."
        );
        std::process::exit(1);
    }

    let webauthn = build_webauthn(&config);

    // Derive CSRF / security-header inputs from the validated rp_origin.
    // rp_origin is checked during config load so parsing here cannot fail.
    let rp_origin_url =
        Url::parse(&config.webauthn.rp_origin).expect("rp_origin validated during config load");
    let allowed_origin = middleware::csrf::AllowedOrigin::from_url(&rp_origin_url)
        .expect("rp_origin must have a host");
    let https_enabled =
        middleware::security_headers::HttpsEnabled(rp_origin_url.scheme() == "https");

    let trust_graph_notify = Arc::new(Notify::new());
    let trust_graph = Arc::new(RwLock::new(Arc::new(trust::TrustGraph::empty())));
    let app_metrics = Arc::new(metrics::Metrics::new());

    let shared_state = Arc::new(AppState {
        db: pool.clone(),
        webauthn,
        needs_setup: AtomicBool::new(!admin_exists),
        setup_token: if admin_exists { None } else { setup_token },
        trust_graph_notify: trust_graph_notify.clone(),
        trust_graph: trust_graph.clone(),
        metrics: app_metrics.clone(),
    });

    // Spawn the debounced trust graph rebuild background task.
    // Performs an initial build immediately, then waits for mutation
    // notifications and rebuilds subject to debounce / min / max timing.
    tokio::spawn(trust::rebuild_loop(
        pool,
        trust_graph,
        trust_graph_notify,
        trust::RebuildSchedule::default(),
        app_metrics,
    ));

    // Spawn the CSP report retention sweep. Runs once per hour and
    // deletes reports older than the retention window (see
    // `csp_report::retention_loop`).
    tokio::spawn(csp_report::retention_loop(shared_state.db.clone()));

    // Spawn the expired session and stale auth challenge cleanup sweep.
    // Runs once per hour (see `session::cleanup_loop`).
    tokio::spawn(session::cleanup_loop(shared_state.db.clone()));

    let (ip_limiter, auth_limiter, user_limiter, report_limiter, csp_report_limiter) =
        rate_limit::build_layers(&config.rate_limit, config.server.trust_proxy_headers);

    let authed = Router::new()
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/rooms", get(rooms::list_rooms))
        .route("/api/rooms/more", post(rooms::load_more_rooms))
        .route("/api/rooms/tab-bar", get(rooms::tab_bar))
        .route("/api/rooms/search", get(rooms::search_rooms))
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
            "/api/users/{username}",
            get(users::get_profile).patch(users::update_bio),
        )
        .route("/api/users/{username}/trust", get(users::get_trust_detail))
        .route("/api/users/{username}/activity", get(users::get_activity))
        .route(
            "/api/users/{username}/trust/edges",
            get(users::get_trust_edges),
        )
        .route(
            "/api/users/{username}/trust-edge",
            put(users::set_trust_edge).delete(users::delete_trust_edge),
        )
        .route(
            "/api/settings",
            get(settings::get_settings).patch(settings::update_settings),
        )
        .route("/api/me/export", get(privacy::export_my_data))
        .route("/api/me", delete(privacy::delete_my_account))
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
        .route("/api/admin/users/{id}/bio", delete(admin::admin_remove_bio))
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
        .layer(auth_limiter);

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
        .merge(authed)
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
        .with_state(shared_state);

    let app = api.merge(health_router).merge(csp_report_router).layer(
        axum::middleware::from_fn_with_state(
            https_enabled,
            middleware::security_headers::security_headers,
        ),
    );

    let addr = format!("127.0.0.1:{}", config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("listening on http://{addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
