use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Top-level configuration for the Prismoire server.
///
/// Loaded from a TOML file. All sections are optional and use sensible
/// defaults for local development when omitted.
#[derive(Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub webauthn: WebauthnConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub attachments: AttachmentsConfig,
    #[serde(default)]
    pub federation: FederationConfig,
}

/// Server configuration (`[server]` section).
#[derive(Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub port: u16,
    pub database: String,
    pub setup_token_file: Option<String>,
    /// Whether to trust `X-Forwarded-For`, `X-Real-IP`, and `Forwarded`
    /// headers for client-IP-based rate limiting.
    ///
    /// Set to `true` **only** when the server is exclusively reachable via
    /// a trusted reverse proxy (e.g. Caddy / nginx) that strips these
    /// headers from inbound requests and inserts its own. If the server is
    /// directly reachable by clients, leaving this `false` prevents a
    /// trivial rate-limit bypass in which a malicious client forges the
    /// headers to appear as a different IP on every request.
    ///
    /// Default: `false` (peer IP only).
    pub trust_proxy_headers: bool,
}

/// WebAuthn relying party configuration (`[webauthn]` section).
#[derive(Deserialize)]
#[serde(default)]
pub struct WebauthnConfig {
    pub rp_id: String,
    pub rp_origin: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 3000,
            database: "prismoire.db".to_string(),
            setup_token_file: None,
            trust_proxy_headers: false,
        }
    }
}

impl Default for WebauthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_origin: "http://localhost:3000".to_string(),
        }
    }
}

/// Rate limiting configuration (`[rate_limit]` section).
///
/// Controls request rate limits at both the IP level and per-user level.
/// Uses a token bucket algorithm: `burst_size` requests are allowed
/// immediately, then one token is replenished every `replenish_seconds`.
#[derive(Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Seconds between token replenishment for general IP-based limits.
    pub ip_replenish_seconds: u64,
    /// Maximum burst size for general IP-based limits.
    pub ip_burst_size: u32,
    /// Seconds between token replenishment for auth endpoints (login/signup/setup).
    pub auth_replenish_seconds: u64,
    /// Maximum burst size for auth endpoints.
    pub auth_burst_size: u32,
    /// Seconds between token replenishment for per-user write limits.
    pub user_replenish_seconds: u64,
    /// Maximum burst size for per-user write limits.
    pub user_burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            ip_replenish_seconds: 1,
            ip_burst_size: 50,
            auth_replenish_seconds: 4,
            auth_burst_size: 5,
            user_replenish_seconds: 1,
            user_burst_size: 20,
        }
    }
}

/// Attachment processing configuration (`[attachments]` section).
///
/// These knobs (docs/attachments.md §10.2) are federation-inert: they
/// shape how the local origin handles an upload (decode safety,
/// re-encode target, sweep cadence), and once bytes are
/// hash-addressed and federated, peers serve cached bytes without
/// re-processing. Live alongside the other deployment-shaped knobs
/// rather than in `instance_config` because changing them requires no
/// audit log and applies on restart, not live.
///
/// Wire-canonical constants (`MAX_ATTACHMENT_SIZE`,
/// `ALLOWED_MIMES`, etc.) are §10.1 protocol invariants and live in
/// `server/src/signed.rs` as `const` — NOT here.
#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct AttachmentsConfig {
    /// Pixel-bomb guard. Maximum width or height (px) accepted before
    /// the decoder allocates a pixel buffer. Applied at the
    /// header-read step (`image::ImageReader::into_dimensions`),
    /// before any work proportional to pixel count. Local upload
    /// policy only — peers do not re-decode incoming blobs.
    pub max_image_px_decode: u32,
    /// Server-side re-encode cap. Maximum longest-side dimension (px)
    /// of the stored image. Sized to the inline-image rendering width
    /// (`--container-measure: 70ch` × 2-3× device-pixel density).
    /// Storage and bandwidth follow this cap, not the decode guard.
    pub max_image_px_output: u32,
    /// Time-to-live (seconds) for `attachment_staging` rows: an upload
    /// that never gets bound to a post is swept after this duration.
    /// Purely local table housekeeping; not on the wire.
    pub staging_ttl_seconds: u64,
    /// Cadence of the staging sweep / orphan-GC background task.
    /// Sized so swept rows are reaped within roughly one TTL window
    /// of their expiry.
    pub sweep_interval_seconds: u64,
    /// Body-size slack (bytes) allowed on the upload route above the
    /// wire-invariant `MAX_ATTACHMENT_SIZE`. Covers multipart
    /// boundary headers and small form fields so legitimate uploads
    /// of a single 500-KiB blob fit; tuned so the Axum body-limit
    /// rejects multi-gigabyte abuse before the §3 step 1 check would
    /// buffer it. Not a wire concern.
    pub request_body_overhead_bytes: usize,
}

impl Default for AttachmentsConfig {
    fn default() -> Self {
        Self {
            max_image_px_decode: 4096,
            max_image_px_output: 1600,
            staging_ttl_seconds: 24 * 60 * 60,
            sweep_interval_seconds: 60 * 60,
            request_body_overhead_bytes: 8 * 1024,
        }
    }
}

/// Federation configuration (`[federation]` section).
///
/// Parent for nested federation subsections. Empty when no
/// `[federation.*]` sections are present in the TOML, in which case
/// every nested struct picks up its `defaults()`.
#[derive(Default, Deserialize)]
pub struct FederationConfig {
    #[serde(default)]
    pub outbound_queue: OutboundQueueConfig,
    #[serde(default)]
    pub attachment_cache: AttachmentCacheConfig,
}

/// §11.5 receiver-local attachment-cache sizing
/// (`[federation.attachment_cache]` section).
///
/// Bounds the total bytes the local instance retains for federation-
/// fetched attachment blobs. The §11 wire contract is fetch-on-demand
/// against the origin; receivers cache fetched bytes so repeat reads
/// don't re-touch the origin, but the cache is sender-local — peers
/// neither know nor care about the cap.
///
/// Eviction policy and the actual cache mechanics live in the server
/// crate (a later phase wires the LRU sweep that honours this budget).
/// The knob lives here so it's set once in TOML and surfaced through
/// `AppState` to whichever subsystem ends up enforcing it.
///
/// Per §11.5: origin-authored blobs (those bound to a current, locally-
/// addressable post) are NOT counted against this budget — origin
/// retention is a §11 protocol obligation, not a cache. Only federation-
/// fetched bytes (blobs whose `uploader` is NULL and that we received
/// via §11.1) participate in eviction.
#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct AttachmentCacheConfig {
    /// Total byte budget for federation-fetched attachment blobs.
    /// Default: 1 GiB. Origin-authored blobs are exempt from this
    /// budget (see struct-level rationale).
    pub max_bytes: u64,
}

impl Default for AttachmentCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// §7.3 / §7.5 outbound-queue sizing + drain-worker backoff
/// (`[federation.outbound_queue]` section).
///
/// These knobs are federation-inert: they shape how the local instance
/// retains and retries pushes to its immediate peers (memory budget,
/// staleness cap, exponential-backoff schedule). They have no
/// federation-visible effect — peer instances do not know or care what
/// values are in effect locally — and there is no compliance audit need
/// for changes. A restart cleanly resets queue state, which is arguably
/// *cleaner* than a live-tune that would have to decide what to do with
/// already-queued bytes that newly violate a shrunken cap.
///
/// Live alongside the other deployment-shaped knobs rather than in
/// `instance_config` because changing them requires no audit log and
/// applies on restart, not live — same rationale as [`AttachmentsConfig`].
///
/// Wire-canonical constants (`MAX_CONTENT_BATCH = 64`,
/// `REDUNDANCY_K = 2`, etc.) are §10.6 / §7.4 protocol invariants and
/// live in `server/src/federation/...` as `const` — NOT here.
#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct OutboundQueueConfig {
    /// Process-wide outbound byte budget summed across every per-peer
    /// queue. Caps total resident memory so operators can size hosts
    /// predictably regardless of peer count. Default: 512 MiB.
    pub total_bytes: usize,
    /// Per-peer byte cap. Hard ceiling on any single peer's queue so
    /// one slow or dead peer cannot monopolize the global byte budget.
    /// Default: 32 MiB.
    pub bytes_per_peer: usize,
    /// Per-peer object-count cap. Default: 50,000.
    pub objects_per_peer: usize,
    /// Staleness cap (seconds). Queued objects older than this are
    /// dropped on drain before the egress write — matching the §7.5
    /// `T_propagate_max` guarantee that no object is ever delivered
    /// after this window from origination. Default: 3600 (1 hour).
    pub object_max_age_secs: u64,
    /// Drain-worker exponential-backoff schedule applied on transient
    /// failures (5xx, 429, transport error, UnknownPeer).
    pub backoff: BackoffConfig,
}

impl Default for OutboundQueueConfig {
    fn default() -> Self {
        Self {
            total_bytes: 512 * 1024 * 1024,
            bytes_per_peer: 32 * 1024 * 1024,
            objects_per_peer: 50_000,
            object_max_age_secs: 3600,
            backoff: BackoffConfig::default(),
        }
    }
}

/// Backoff schedule for the per-peer drain worker
/// (`[federation.outbound_queue.backoff]` section).
///
/// Full-jitter (AWS 2015 "Exponential Backoff And Jitter") with a
/// small absolute floor applied in the runtime to bound the worst-case
/// burst after consecutive transient failures. The jitter scheme is
/// not currently configurable: one strategy is implemented, so a knob
/// would be configurability without a choice.
#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct BackoffConfig {
    /// First retry delay (ms) after a transient failure. Default: 1000.
    pub initial_ms: u64,
    /// Cap on the exponentiated delay (ms). Default: 300000 (5 min).
    pub max_ms: u64,
    /// Multiplier applied per failed attempt. Default: 2.0.
    pub multiplier: f64,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_ms: 1000,
            max_ms: 300_000,
            multiplier: 2.0,
        }
    }
}

/// Resolve the config file path.
///
/// Priority: explicit `--config` argument > `PRISMOIRE_CONFIG` env var >
/// `prismoire.toml` in the working directory (only if it exists).
///
/// Returns `(path, required)` where `required` means the path was explicitly
/// specified and the file *must* exist.
fn resolve_config_path(explicit: Option<&str>) -> (Option<PathBuf>, bool) {
    if let Some(path) = explicit {
        return (Some(PathBuf::from(path)), true);
    }
    if let Ok(path) = std::env::var("PRISMOIRE_CONFIG") {
        return (Some(PathBuf::from(path)), true);
    }
    let default_path = PathBuf::from("prismoire.toml");
    if default_path.exists() {
        return (Some(default_path), false);
    }
    (None, false)
}

/// Load configuration from the resolved path, or return defaults.
fn load_from_path(path: Option<&Path>, required: bool) -> Result<Config, ConfigError> {
    let Some(path) = path else {
        return Ok(Config::default());
    };

    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => {
            return Ok(Config::default());
        }
        Err(e) => {
            return Err(ConfigError(format!(
                "failed to read config file {}: {e}",
                path.display()
            )));
        }
    };

    toml::from_str(&contents).map_err(|e| {
        ConfigError(format!(
            "failed to parse config file {}: {e}",
            path.display()
        ))
    })
}

/// Validate config values that would otherwise cause panics or confusing
/// errors later during server startup.
fn validate(config: &Config) -> Result<(), ConfigError> {
    url::Url::parse(&config.webauthn.rp_origin).map_err(|e| {
        ConfigError(format!(
            "invalid webauthn.rp_origin URL '{}': {e}",
            config.webauthn.rp_origin
        ))
    })?;
    validate_outbound_queue_config(&config.federation.outbound_queue)?;
    validate_attachment_cache_config(&config.federation.attachment_cache)?;
    Ok(())
}

/// `[federation.attachment_cache]` validation. The §11 wire contract
/// bounds an individual attachment at `MAX_ATTACHMENT_SIZE` (500 KiB);
/// a cache budget smaller than that cannot hold even one max-sized blob,
/// so federation-fetched attachments would be evicted faster than they
/// could be served. Reject at load time rather than discover the
/// thrashing under load.
///
/// `MAX_ATTACHMENT_SIZE` is duplicated here as a literal rather than
/// imported from the server crate so the config crate stays
/// dependency-free. If §11.6 ever raises the per-blob cap, this floor
/// must move in lockstep with it.
fn validate_attachment_cache_config(cfg: &AttachmentCacheConfig) -> Result<(), ConfigError> {
    /// §11.6 `MAX_ATTACHMENT_SIZE` (bytes). Lower bound on the cache
    /// budget — see function-level rationale.
    const MAX_ATTACHMENT_SIZE: u64 = 500 * 1024;

    if cfg.max_bytes < MAX_ATTACHMENT_SIZE {
        return Err(ConfigError(format!(
            "federation.attachment_cache.max_bytes ({}) must be ≥ MAX_ATTACHMENT_SIZE ({}B) — \
             a cache smaller than one max-sized blob can't retain any federated attachment",
            cfg.max_bytes, MAX_ATTACHMENT_SIZE,
        )));
    }
    Ok(())
}

/// `[federation.outbound_queue]` cross-field validation. Catches the
/// misconfigurations that would otherwise surface as either a panic
/// (zero values divide by) or a silent violation of the §7.5
/// `T_propagate_max` delivery guarantee.
///
/// The hard `T_propagate_max` value (3600s, §7.5) is duplicated here as
/// a literal rather than imported from the server crate so the config
/// crate can stay dependency-free. If §7.5 ever raises the bound, this
/// constant must move in lockstep with it; the runtime caps that
/// enforce it live in `server/src/federation/outbound_queue.rs`.
fn validate_outbound_queue_config(cfg: &OutboundQueueConfig) -> Result<(), ConfigError> {
    /// §7.5 `T_propagate_max` (seconds). Upper bound on
    /// `object_max_age_secs` — past this, the dedup-LRU at downstream
    /// peers has already expired the entry, and a late delivery could
    /// trigger a slow-loop. See `docs/federation-protocol.md` §7.5.
    const T_PROPAGATE_MAX_SECS: u64 = 3600;

    if cfg.total_bytes == 0 {
        return Err(ConfigError(
            "federation.outbound_queue.total_bytes must be > 0".into(),
        ));
    }
    if cfg.bytes_per_peer == 0 {
        return Err(ConfigError(
            "federation.outbound_queue.bytes_per_peer must be > 0".into(),
        ));
    }
    if cfg.objects_per_peer == 0 {
        return Err(ConfigError(
            "federation.outbound_queue.objects_per_peer must be > 0".into(),
        ));
    }
    if cfg.object_max_age_secs == 0 {
        return Err(ConfigError(
            "federation.outbound_queue.object_max_age_secs must be > 0".into(),
        ));
    }
    if cfg.bytes_per_peer > cfg.total_bytes {
        return Err(ConfigError(format!(
            "federation.outbound_queue.bytes_per_peer ({}) must be ≤ total_bytes ({})",
            cfg.bytes_per_peer, cfg.total_bytes,
        )));
    }
    if cfg.object_max_age_secs > T_PROPAGATE_MAX_SECS {
        return Err(ConfigError(format!(
            "federation.outbound_queue.object_max_age_secs ({}) must be ≤ T_propagate_max ({}s) — \
             past this, downstream dedup-LRU entries have expired and late deliveries \
             can trigger slow-loops (§7.5)",
            cfg.object_max_age_secs, T_PROPAGATE_MAX_SECS,
        )));
    }
    if cfg.backoff.initial_ms == 0 {
        return Err(ConfigError(
            "federation.outbound_queue.backoff.initial_ms must be > 0".into(),
        ));
    }
    if cfg.backoff.max_ms < cfg.backoff.initial_ms {
        return Err(ConfigError(format!(
            "federation.outbound_queue.backoff.max_ms ({}) must be ≥ initial_ms ({})",
            cfg.backoff.max_ms, cfg.backoff.initial_ms,
        )));
    }
    if !(cfg.backoff.multiplier > 1.0 && cfg.backoff.multiplier.is_finite()) {
        return Err(ConfigError(format!(
            "federation.outbound_queue.backoff.multiplier ({}) must be > 1.0 and finite",
            cfg.backoff.multiplier,
        )));
    }
    Ok(())
}

/// Load configuration.
///
/// Resolves the config file path from an explicit `--config` argument,
/// the `PRISMOIRE_CONFIG` env var, or `prismoire.toml` in the working
/// directory. Returns defaults if no config file is found.
pub fn load_config(explicit_path: Option<&str>) -> Result<Config, ConfigError> {
    let (path, required) = resolve_config_path(explicit_path);
    let config = load_from_path(path.as_deref(), required)?;
    validate(&config)?;
    Ok(config)
}

/// Parse `--config <path>` from command-line arguments.
///
/// Handles both `--config path` and `--config=path` forms. Intended for
/// binaries that don't use a full argument parser (the server). The CLI
/// uses clap and should pass its parsed value to [`load_config`] directly.
pub fn parse_config_arg() -> Result<Option<String>, ConfigError> {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" {
            return match args.get(i + 1) {
                Some(path) => Ok(Some(path.clone())),
                None => Err(ConfigError("--config requires a path argument".into())),
            };
        }
        if let Some(path) = args[i].strip_prefix("--config=") {
            return Ok(Some(path.to_string()));
        }
        i += 1;
    }
    Ok(None)
}

/// Read a secret value from a file, trimming surrounding whitespace.
///
/// Used for `*_file` config keys (e.g. `setup_token_file`) that point to
/// files containing secrets rather than embedding them in the config.
pub fn read_secret_file(path: &str) -> Result<String, ConfigError> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| ConfigError(format!("failed to read secret file {path}: {e}")))?;
    let value = contents.trim().to_string();
    if value.is_empty() {
        return Err(ConfigError(format!("secret file {path} is empty")));
    }
    Ok(value)
}

/// Configuration loading error.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_queue_defaults_validate() {
        validate_outbound_queue_config(&OutboundQueueConfig::default())
            .expect("documented defaults must validate");
    }

    #[test]
    fn outbound_queue_per_peer_must_fit_total() {
        let mut cfg = OutboundQueueConfig::default();
        cfg.bytes_per_peer = cfg.total_bytes + 1;
        let err = validate_outbound_queue_config(&cfg).expect_err("must reject");
        assert!(err.0.contains("bytes_per_peer"));
        assert!(err.0.contains("total_bytes"));
    }

    #[test]
    fn outbound_queue_rejects_zero_total_bytes() {
        let cfg = OutboundQueueConfig {
            total_bytes: 0,
            ..OutboundQueueConfig::default()
        };
        let err = validate_outbound_queue_config(&cfg).expect_err("must reject");
        assert!(err.0.contains("total_bytes"));
    }

    #[test]
    fn outbound_queue_rejects_zero_objects_per_peer() {
        let cfg = OutboundQueueConfig {
            objects_per_peer: 0,
            ..OutboundQueueConfig::default()
        };
        let err = validate_outbound_queue_config(&cfg).expect_err("must reject");
        assert!(err.0.contains("objects_per_peer"));
    }

    #[test]
    fn outbound_queue_rejects_object_max_age_past_t_propagate_max() {
        let cfg = OutboundQueueConfig {
            object_max_age_secs: 3601,
            ..OutboundQueueConfig::default()
        };
        let err = validate_outbound_queue_config(&cfg).expect_err("must reject");
        assert!(err.0.contains("T_propagate_max"));
    }

    #[test]
    fn outbound_queue_rejects_backoff_max_below_initial() {
        let cfg = OutboundQueueConfig {
            backoff: BackoffConfig {
                initial_ms: 1000,
                max_ms: 999,
                multiplier: 2.0,
            },
            ..OutboundQueueConfig::default()
        };
        let err = validate_outbound_queue_config(&cfg).expect_err("must reject");
        assert!(err.0.contains("max_ms"));
    }

    #[test]
    fn outbound_queue_rejects_multiplier_le_one() {
        let cfg = OutboundQueueConfig {
            backoff: BackoffConfig {
                initial_ms: 1000,
                max_ms: 2000,
                multiplier: 1.0,
            },
            ..OutboundQueueConfig::default()
        };
        let err = validate_outbound_queue_config(&cfg).expect_err("must reject");
        assert!(err.0.contains("multiplier"));
    }

    #[test]
    fn outbound_queue_round_trips_from_toml() {
        let toml = r#"
[federation.outbound_queue]
total_bytes = 16777216
bytes_per_peer = 8388608
objects_per_peer = 100
object_max_age_secs = 60

[federation.outbound_queue.backoff]
initial_ms = 50
max_ms = 5000
multiplier = 1.5
"#;
        let parsed: Config = toml::from_str(toml).expect("parses");
        let q = &parsed.federation.outbound_queue;
        assert_eq!(q.total_bytes, 16 * 1024 * 1024);
        assert_eq!(q.bytes_per_peer, 8 * 1024 * 1024);
        assert_eq!(q.objects_per_peer, 100);
        assert_eq!(q.object_max_age_secs, 60);
        assert_eq!(q.backoff.initial_ms, 50);
        assert_eq!(q.backoff.max_ms, 5000);
        assert_eq!(q.backoff.multiplier, 1.5);
        validate_outbound_queue_config(q).expect("round-trip values validate");
    }

    #[test]
    fn attachment_cache_defaults_validate() {
        validate_attachment_cache_config(&AttachmentCacheConfig::default())
            .expect("documented defaults must validate");
    }

    #[test]
    fn attachment_cache_rejects_below_max_attachment_size() {
        let cfg = AttachmentCacheConfig {
            max_bytes: 500 * 1024 - 1,
        };
        let err = validate_attachment_cache_config(&cfg).expect_err("must reject");
        assert!(err.0.contains("MAX_ATTACHMENT_SIZE"));
    }

    #[test]
    fn attachment_cache_round_trips_from_toml() {
        let toml = r#"
[federation.attachment_cache]
max_bytes = 2147483648
"#;
        let parsed: Config = toml::from_str(toml).expect("parses");
        assert_eq!(
            parsed.federation.attachment_cache.max_bytes,
            2 * 1024 * 1024 * 1024
        );
        validate_attachment_cache_config(&parsed.federation.attachment_cache)
            .expect("round-trip values validate");
    }

    #[test]
    fn missing_federation_section_uses_defaults() {
        let parsed: Config = toml::from_str("").expect("empty config parses");
        let q = &parsed.federation.outbound_queue;
        let d = OutboundQueueConfig::default();
        assert_eq!(q.total_bytes, d.total_bytes);
        assert_eq!(q.bytes_per_peer, d.bytes_per_peer);
        assert_eq!(q.objects_per_peer, d.objects_per_peer);
        assert_eq!(q.object_max_age_secs, d.object_max_age_secs);
        assert_eq!(q.backoff.initial_ms, d.backoff.initial_ms);
        assert_eq!(q.backoff.max_ms, d.backoff.max_ms);
        assert_eq!(q.backoff.multiplier, d.backoff.multiplier);
        let a = &parsed.federation.attachment_cache;
        assert_eq!(a.max_bytes, AttachmentCacheConfig::default().max_bytes);
    }
}
