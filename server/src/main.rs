use axum::{Router, routing::get};

/// Start the Prismoire API server and listen for connections.
#[tokio::main]
async fn main() {
    let app = Router::new().route("/api/health", get(|| async { "ok" }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}
