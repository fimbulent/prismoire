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
