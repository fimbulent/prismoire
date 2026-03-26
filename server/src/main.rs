use std::path::PathBuf;

use axum::{Router, routing::get};
use tower_http::services::{ServeDir, ServeFile};

/// Start the Prismoire API server and listen for connections.
///
/// Serves the SvelteKit static build from `web/build/` (relative to the
/// project root) as a fallback behind the API routes.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
