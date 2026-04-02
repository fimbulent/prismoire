use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use axum::Router;
use axum::routing::{delete, get, post};
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use tower_http::services::{ServeDir, ServeFile};
use url::Url;
use webauthn_rs::WebauthnBuilder;

mod admin;
mod auth;
mod display_name;
mod error;
mod posts;
mod room_name;
mod rooms;
mod session;
mod setup;
mod signing;
mod state;
mod threads;
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

/// Build the WebAuthn relying party configuration from environment variables.
///
/// Reads `PRISMOIRE_RP_ID` (defaults to "localhost") and `PRISMOIRE_RP_ORIGIN`
/// (defaults to "http://localhost:3000") to configure the WebAuthn ceremony
/// parameters.
fn build_webauthn() -> Arc<webauthn_rs::Webauthn> {
    let rp_id = std::env::var("PRISMOIRE_RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let rp_origin_str = std::env::var("PRISMOIRE_RP_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    let rp_origin = Url::parse(&rp_origin_str).expect("invalid PRISMOIRE_RP_ORIGIN URL");

    let is_dev = rp_origin.host_str() == Some("localhost");

    let builder = WebauthnBuilder::new(&rp_id, &rp_origin)
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

/// Read the setup token from the file path in `PRISMOIRE_SETUP_TOKEN_FILE`.
///
/// Returns `None` if the env var is not set. Returns an error if the file
/// cannot be read or contains an empty token (misconfiguration should fail
/// loud at startup).
fn load_setup_token() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let path = match std::env::var("PRISMOIRE_SETUP_TOKEN_FILE") {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read setup token file {path}: {e}"))?;
    let token = contents.trim().to_string();
    if token.is_empty() {
        return Err(format!("setup token file {path} is empty").into());
    }
    Ok(Some(token))
}

/// Start the Prismoire API server and listen for connections.
///
/// Connects to SQLite, runs migrations, configures WebAuthn, checks for
/// admin bootstrap state, then serves the SvelteKit static build from
/// `web/build/` as a fallback behind the API routes.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db_path = std::env::var("PRISMOIRE_DB").unwrap_or_else(|_| "prismoire.db".to_string());
    let db_url = format!("sqlite:{db_path}?mode=rwc");

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    configure_pool(&pool).await;
    sqlx::migrate!().run(&pool).await?;

    let admin_exists = has_admin(&pool).await?;
    let setup_token = load_setup_token()?;

    if !admin_exists && setup_token.is_none() {
        eprintln!(
            "error: no admin account exists and PRISMOIRE_SETUP_TOKEN_FILE is not configured.\n\
             Set PRISMOIRE_SETUP_TOKEN_FILE to a file containing a one-time setup token,\n\
             then visit /setup in the browser to create the initial admin account."
        );
        std::process::exit(1);
    }

    let webauthn = build_webauthn();

    let shared_state = Arc::new(AppState {
        db: pool,
        webauthn,
        needs_setup: AtomicBool::new(!admin_exists),
        setup_token: if admin_exists { None } else { setup_token },
    });

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
        .route("/api/threads/{id}", get(threads::get_thread))
        .route("/api/threads/{id}/posts", post(threads::create_reply))
        .route(
            "/api/posts/{id}",
            axum::routing::patch(posts::edit_post).delete(posts::retract_post),
        )
        .route("/api/posts/{id}/revisions", get(posts::list_revisions))
        .route("/api/admin/log", get(admin::get_admin_log))
        .route(
            "/api/admin/threads/{id}/lock",
            post(admin::lock_thread).delete(admin::unlock_thread),
        )
        .route("/api/admin/posts/{id}", delete(admin::remove_post))
        .layer(axum::middleware::from_fn_with_state(
            shared_state.clone(),
            session::session_middleware,
        ));

    let api = Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/threads/public", get(threads::list_public_threads))
        .route("/api/setup/status", get(setup::setup_status))
        .route("/api/setup/begin", post(setup::setup_begin))
        .route("/api/setup/complete", post(setup::setup_complete))
        .route("/api/auth/signup/begin", post(auth::signup_begin))
        .route("/api/auth/signup/complete", post(auth::signup_complete))
        .route("/api/auth/login/begin", post(auth::login_begin))
        .route("/api/auth/login/complete", post(auth::login_complete))
        .route("/api/auth/discover/begin", get(auth::discover_begin))
        .route("/api/auth/discover/complete", post(auth::discover_complete))
        .merge(authed)
        .layer(axum::middleware::from_fn_with_state(
            shared_state.clone(),
            setup::setup_guard_middleware,
        ))
        .with_state(shared_state);

    let web_build: PathBuf = std::env::var("PRISMOIRE_WEB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
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

    let port = std::env::var("PRISMOIRE_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);
    let addr = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("listening on http://{addr}");
    axum::serve(listener, app).await?;

    Ok(())
}
