use std::path::PathBuf;

use axum::{Router, routing::get};
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use tower_http::services::{ServeDir, ServeFile};

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

/// Start the Prismoire API server and listen for connections.
///
/// Connects to SQLite, runs migrations, then serves the SvelteKit static
/// build from `web/build/` as a fallback behind the API routes.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // PRISMOIRE_DB overrides the default database path. During local
    // development the database lives next to the server binary; in
    // production the NixOS module sets this to /var/lib/prismoire/prismoire.db.
    let db_path = std::env::var("PRISMOIRE_DB").unwrap_or_else(|_| "prismoire.db".to_string());
    let db_url = format!("sqlite:{db_path}?mode=rwc");

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    configure_pool(&pool).await;

    sqlx::migrate!().run(&pool).await?;

    let api = Router::new().route("/api/health", get(|| async { "ok" }));

    // PRISMOIRE_WEB_DIR overrides the default location (set by the Nix
    // package wrapper). During local development the compile-time
    // CARGO_MANIFEST_DIR is used as a fallback.
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
