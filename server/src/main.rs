use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use tokio::sync::Notify;

use axum::Router;
use axum::routing::{delete, get, post, put};
use prismoire_config::Config;
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use tower_http::services::{ServeDir, ServeFile};
use url::Url;
use webauthn_rs::WebauthnBuilder;

mod admin;
mod auth;
mod display_name;
mod error;
mod invites;
mod posts;
mod rate_limit;
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
    let row: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

/// Start the Prismoire API server and listen for connections.
///
/// Loads TOML config, connects to SQLite, runs migrations, configures
/// WebAuthn, checks for admin bootstrap state, then serves the SvelteKit
/// static build as a fallback behind the API routes.
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

    let trust_graph_notify = Arc::new(Notify::new());
    let trust_graph = Arc::new(RwLock::new(Arc::new(trust::TrustGraph::empty())));

    let shared_state = Arc::new(AppState {
        db: pool.clone(),
        webauthn,
        needs_setup: AtomicBool::new(!admin_exists),
        setup_token: if admin_exists { None } else { setup_token },
        trust_graph_notify: trust_graph_notify.clone(),
        trust_graph: trust_graph.clone(),
    });

    // Spawn the debounced trust graph rebuild background task.
    // Performs an initial build immediately, then waits for mutation
    // notifications and rebuilds subject to debounce / min / max timing.
    tokio::spawn(trust::rebuild_loop(
        pool,
        trust_graph,
        trust_graph_notify,
        trust::RebuildSchedule::default(),
    ));

    let (ip_limiter, auth_limiter, user_limiter) = rate_limit::build_layers(&config.rate_limit);

    let authed = Router::new()
        .route("/api/auth/session", get(auth::session_info))
        .route("/api/auth/logout", post(auth::logout))
        .route(
            "/api/rooms",
            get(rooms::list_rooms).post(rooms::create_room),
        )
        .route("/api/rooms/top", get(rooms::top_rooms))
        .route("/api/rooms/{id}", get(rooms::get_room))
        .route(
            "/api/rooms/{id}/threads",
            get(threads::list_threads).post(threads::create_thread),
        )
        .route("/api/threads", get(threads::list_all_threads))
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
        .route("/api/admin/log", get(admin::get_admin_log))
        .route(
            "/api/admin/threads/{id}/lock",
            post(admin::lock_thread).delete(admin::unlock_thread),
        )
        .route("/api/admin/posts/{id}", delete(admin::remove_post))
        .layer(user_limiter)
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
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/threads/public", get(threads::list_public_threads))
        .route("/api/setup/status", get(setup::setup_status))
        .route("/api/auth/discover/begin", get(auth::discover_begin))
        .route(
            "/api/invites/{code}/validate",
            get(invites::validate_invite),
        )
        .merge(auth_routes)
        .merge(authed)
        .layer(ip_limiter)
        .layer(axum::middleware::from_fn_with_state(
            shared_state.clone(),
            setup::setup_guard_middleware,
        ))
        .with_state(shared_state);

    let web_build: PathBuf = config.server.web_dir.map(PathBuf::from).unwrap_or_else(|| {
        [env!("CARGO_MANIFEST_DIR"), "..", "web", "build"]
            .iter()
            .collect()
    });

    if !web_build.exists() {
        eprintln!(
            "warning: web build directory not found at {}. Run `pnpm --dir web build` first.",
            web_build.display()
        );
    }

    let spa_fallback = ServeDir::new(&web_build)
        .append_index_html_on_directories(false)
        .fallback(ServeFile::new(web_build.join("index.html")));

    let app = api.fallback_service(spa_fallback);

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
