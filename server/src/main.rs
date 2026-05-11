use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use tokio::sync::Notify;

use prismoire_config::Config;
use prismoire_server::middleware::csrf::AllowedOrigin;
use prismoire_server::middleware::security_headers::HttpsEnabled;
use prismoire_server::{AppState, build_app, csp_report, metrics, rate_limit, session, trust};
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use url::Url;
use webauthn_rs::WebauthnBuilder;

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
    // Initialize structured logging. Honours RUST_LOG; defaults to `info`
    // for prismoire crates and `warn` for everything else.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("warn,prismoire_server=info")
            }),
        )
        .init();

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
        tracing::error!(
            "no admin account exists and server.setup_token_file is not configured. \
             Set setup_token_file in the [server] section of your config file, \
             then visit /setup in the browser to create the initial admin account."
        );
        std::process::exit(1);
    }

    let webauthn = build_webauthn(&config);

    // Derive CSRF / security-header inputs from the validated rp_origin.
    // rp_origin is checked during config load so parsing here cannot fail.
    let rp_origin_url =
        Url::parse(&config.webauthn.rp_origin).expect("rp_origin validated during config load");
    let allowed_origin =
        AllowedOrigin::from_url(&rp_origin_url).expect("rp_origin must have a host");
    let https_enabled = HttpsEnabled(rp_origin_url.scheme() == "https");

    let trust_graph_notify = Arc::new(Notify::new());
    let trust_graph = Arc::new(RwLock::new(Arc::new(trust::TrustGraph::empty())));
    let app_metrics = Arc::new(metrics::Metrics::new());
    let pending_deltas = Arc::new(trust::PendingDeltas::new(Some(app_metrics.clone())));

    let shared_state = Arc::new(AppState {
        db: pool.clone(),
        webauthn,
        needs_setup: AtomicBool::new(!admin_exists),
        setup_token: if admin_exists { None } else { setup_token },
        trust_graph_notify: trust_graph_notify.clone(),
        trust_graph: trust_graph.clone(),
        metrics: app_metrics.clone(),
        pending_deltas: pending_deltas.clone(),
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
        pending_deltas,
    ));

    // Spawn the CSP report retention sweep. Runs once per hour and
    // deletes reports older than the retention window (see
    // `csp_report::retention_loop`).
    tokio::spawn(csp_report::retention_loop(shared_state.db.clone()));

    // Spawn the expired session and stale auth challenge cleanup sweep.
    // Runs once per hour (see `session::cleanup_loop`).
    tokio::spawn(session::cleanup_loop(shared_state.db.clone()));

    let layers = rate_limit::build_layers(&config.rate_limit, config.server.trust_proxy_headers);

    let app = build_app(shared_state, allowed_origin, https_enabled, layers);

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
