use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use tower_http::services::{ServeDir, ServeFile};
use url::Url;
use webauthn_rs::WebauthnBuilder;

mod auth;
mod display_name;
mod error;
mod session;
mod state;

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

/// Start the Prismoire API server and listen for connections.
///
/// Connects to SQLite, runs migrations, configures WebAuthn, then serves
/// the SvelteKit static build from `web/build/` as a fallback behind the
/// API routes.
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

    let webauthn = build_webauthn();

    let shared_state = Arc::new(AppState { db: pool, webauthn });

    let api = Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/auth/signup/begin", post(auth::signup_begin))
        .route("/api/auth/signup/complete", post(auth::signup_complete))
        .route("/api/auth/login/begin", post(auth::login_begin))
        .route("/api/auth/login/complete", post(auth::login_complete))
        .route("/api/auth/session", get(auth::session_info))
        .route("/api/auth/logout", post(auth::logout))
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

    let addr = "127.0.0.1:3000";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("listening on http://{addr}");
    axum::serve(listener, app).await?;

    Ok(())
}
