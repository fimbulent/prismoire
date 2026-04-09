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
}

/// Server configuration (`[server]` section).
#[derive(Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub port: u16,
    pub database: String,
    pub web_dir: Option<String>,
    pub setup_token_file: Option<String>,
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
            web_dir: None,
            setup_token_file: None,
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
