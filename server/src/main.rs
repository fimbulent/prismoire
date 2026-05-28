use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use tokio::sync::Notify;

use prismoire_config::Config;
use prismoire_server::federation::domain::allow_private_targets_from_env;
use prismoire_server::federation::envelope::NonceLru;
use prismoire_server::federation::instance_key;
use prismoire_server::federation::transport::{FederationTransport, ReqwestTransport};
use prismoire_server::middleware::csrf::AllowedOrigin;
use prismoire_server::middleware::security_headers::HttpsEnabled;
use prismoire_server::{
    AppState, attachments, build_app, csp_report, instance_config, metrics, rate_limit, session,
    trust,
};
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

    // Load the admin-editable runtime config (rebuild schedule, source
    // repo URL). The single-row `instance_config` table is seeded by
    // the migration, so this always succeeds against a properly
    // migrated DB. Both fields are wrapped in `Arc<RwLock<…>>` so the
    // rebuild loop and the `/api/setup/status` handler can pick up
    // admin edits without a server restart.
    let loaded_config = instance_config::load_from_db(&pool).await?;
    let rebuild_schedule = Arc::new(RwLock::new(loaded_config.rebuild_schedule));
    let source_repo_url = Arc::new(RwLock::new(loaded_config.source_repo_url));
    let attachment_budget = Arc::new(RwLock::new(loaded_config.attachment_budget));

    // Federation §6.2 signing key + per-instance replay LRU + outbound
    // transport. The key is loaded once at boot and held in memory for
    // the process lifetime; restart-required to rotate (§6.6 rotation
    // lifecycle is Phase 3+). The transport is the production
    // `reqwest`-backed impl: HTTPS over rustls with webpki roots, a
    // shared HTTP/2 connection pool, and `peers.instance_domain`
    // resolution per outbound request.
    let instance_key = instance_key::load_or_generate(&pool).await?;
    let federation_nonce_lru = Arc::new(NonceLru::default());
    // SSRF policy is read from `PRISMOIRE_FEDERATION_ALLOW_PRIVATE_TARGETS`
    // once at boot and held as a `bool` on the transport — restart-required
    // to flip. Tests construct their own transport with `true` directly,
    // never via the env var, to keep process-wide state out of the harness.
    let federation_transport: Arc<dyn FederationTransport> = Arc::new(ReqwestTransport::new(
        pool.clone(),
        ReqwestTransport::default_client()?,
        allow_private_targets_from_env(),
    ));
    // §7.3 per-peer outbound FIFO queues (Phase 6.4 / 6.4.1). One
    // process-wide collection of per-peer FIFOs + drain workers; the
    // §7.5 sizing caps and the drain-worker backoff schedule come from
    // the `[federation.outbound_queue]` TOML section. Defaults match
    // the spec when the section is omitted.
    let outbound_queues = prismoire_server::federation::outbound_queue::OutboundQueues::new(
        (&config.federation.outbound_queue).into(),
        federation_transport.clone(),
        instance_key.clone(),
    );
    // §5.2 `instance_domain` is the bare canonical domain this
    // instance serves on. The closest existing config we have is
    // `webauthn.rp_id`, which is the *same* concept by design (both
    // identify the host as a security principal). Reuse it rather
    // than adding a parallel `[federation].domain` knob that
    // operators would have to keep in sync.
    let instance_domain = config.webauthn.rp_id.clone();

    let shared_state = Arc::new(AppState {
        db: pool.clone(),
        webauthn,
        needs_setup: AtomicBool::new(!admin_exists),
        setup_token: if admin_exists { None } else { setup_token },
        trust_graph_notify: trust_graph_notify.clone(),
        trust_graph: trust_graph.clone(),
        metrics: app_metrics.clone(),
        pending_deltas: pending_deltas.clone(),
        rebuild_schedule: rebuild_schedule.clone(),
        source_repo_url: source_repo_url.clone(),
        attachment_budget: attachment_budget.clone(),
        attachments_config: config.attachments.clone(),
        federation_attachment_cache: config.federation.attachment_cache.clone(),
        instance_domain,
        instance_key,
        federation_nonce_lru,
        federation_transport,
        local_frontier: Arc::new(std::sync::RwLock::new(Arc::new(
            prismoire_server::federation::frontier::LocalFrontier::empty(),
        ))),
        forwarding_lru: Arc::new(prismoire_server::federation::forwarder::ForwardingLru::new()),
        outbound_queues,
        content_rate_limiter: Arc::new(
            prismoire_server::federation::content_rate_limit::ContentRateLimiter::default(),
        ),
        move_rate_limiter: Arc::new(
            prismoire_server::federation::content_rate_limit::ContentRateLimiter::new(
                prismoire_server::federation::moves::MAX_MOVE_OBJECTS_PER_HOUR,
            ),
        ),
        backfill_rate_limiter: Arc::new(
            prismoire_server::federation::backfill_rate_limit::BackfillRateLimiter::default(),
        ),
        prior_home_rate_limiter: Arc::new(
            prismoire_server::federation::prior_home_rate_limit::PriorHomeRateLimiter::default(),
        ),
        prior_home_challenge_rate_limiter: Arc::new(
            prismoire_server::federation::prior_home_challenge_rate_limit::PriorHomeChallengeRateLimiter::default(),
        ),
        user_status_rate_limiter: Arc::new(
            prismoire_server::federation::push_rate_limit::PushRateLimiter::for_user_status(),
        ),
        thread_status_rate_limiter: Arc::new(
            prismoire_server::federation::push_rate_limit::PushRateLimiter::for_thread_status(),
        ),
        reports_rate_limiter: Arc::new(
            prismoire_server::federation::push_rate_limit::PushRateLimiter::for_reports(),
        ),
    });

    // Spawn the debounced trust graph rebuild background task.
    // Performs an initial build immediately, then waits for mutation
    // notifications and rebuilds subject to debounce / min / max timing.
    // The schedule is shared (not owned) so admin edits via the Config
    // tab take effect on the next scheduling window without a restart.
    tokio::spawn(trust::rebuild_loop(
        pool,
        trust_graph,
        trust_graph_notify,
        rebuild_schedule,
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

    // Spawn the in-memory federation rate-limiter sweeps. The two
    // limiters are keyed on a `HashMap<peer_pubkey, _>`; without a
    // periodic prune the map would grow O(N_distinct_peers) without
    // bound as short-lived or departed peers churn through.
    tokio::spawn(
        prismoire_server::federation::content_rate_limit::cleanup_loop(
            shared_state.content_rate_limiter.clone(),
            "content",
        ),
    );
    tokio::spawn(
        prismoire_server::federation::content_rate_limit::cleanup_loop(
            shared_state.move_rate_limiter.clone(),
            "move",
        ),
    );
    tokio::spawn(
        prismoire_server::federation::backfill_rate_limit::cleanup_loop(
            shared_state.backfill_rate_limiter.clone(),
            "backfill",
        ),
    );
    tokio::spawn(
        prismoire_server::federation::prior_home_rate_limit::cleanup_loop(
            shared_state.prior_home_rate_limiter.clone(),
            "prior_home",
        ),
    );
    tokio::spawn(
        prismoire_server::federation::prior_home_challenge_rate_limit::cleanup_loop(
            shared_state.prior_home_challenge_rate_limiter.clone(),
            "prior_home_challenge",
        ),
    );
    tokio::spawn(prismoire_server::federation::push_rate_limit::cleanup_loop(
        shared_state.user_status_rate_limiter.clone(),
        "user_status",
    ));
    tokio::spawn(prismoire_server::federation::push_rate_limit::cleanup_loop(
        shared_state.thread_status_rate_limiter.clone(),
        "thread_status",
    ));
    tokio::spawn(prismoire_server::federation::push_rate_limit::cleanup_loop(
        shared_state.reports_rate_limiter.clone(),
        "reports",
    ));

    // Spawn the attachment staging-expiry + orphan-blob GC + §11.5
    // receiver-local cache-eviction sweep. Cadence is the server-static
    // `attachments.sweep_interval_seconds` from TOML
    // (docs/attachments.md §10.2). The cache budget is the §11.5
    // `[federation.attachment_cache] max_bytes` knob; eviction is
    // federation-only by construction (origin-authored bytes are
    // excluded from the eligibility predicate inside the eviction
    // step). See `attachments::sweep` and
    // `federation::attachment_cache`.
    tokio::spawn(attachments::sweep_loop(
        shared_state.db.clone(),
        config.attachments.sweep_interval_seconds,
        shared_state.federation_attachment_cache.max_bytes,
        shared_state.metrics.clone(),
    ));

    // Spawn the Phase 9.8 pending-orphan TTL sweep. Buffered
    // `pending_trust_edges` rows whose `received_at` is older than
    // `DEFERRED_ORPHAN_TTL` (1h per spec §9.6) are evicted: the
    // receiver has given up on autonomous §9.3 recovery and the
    // chain becomes the sender's problem on the next push. Cadence
    // is 5 min so an orphan ages out within ~1h+5min worst case
    // without paying a per-receive timer cost.
    tokio::spawn(
        prismoire_server::federation::edges::pending_orphan_ttl_loop(shared_state.db.clone()),
    );

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
