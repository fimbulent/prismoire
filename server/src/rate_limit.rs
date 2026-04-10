use std::sync::Arc;

use governor::clock::QuantaInstant;
use governor::middleware::NoOpMiddleware;
use http::request::Request;
use tower_governor::GovernorLayer;
use tower_governor::errors::GovernorError;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::{KeyExtractor, SmartIpKeyExtractor};

use crate::session::parse_session_cookie;

/// Extracts the session cookie value as a rate-limiting key.
///
/// Used for per-user rate limiting. Falls back to the client IP address
/// (using [`SmartIpKeyExtractor`] logic) for unauthenticated requests so
/// they are still rate-limited. The same `x-forwarded-for` / `x-real-ip` /
/// `forwarded` headers are honored, which is safe as long as the server is
/// only reachable via a trusted reverse proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeyExtractor;

impl KeyExtractor for SessionKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        if let Some(cookie) = req
            .headers()
            .get(http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            && let Some(token) = parse_session_cookie(cookie)
        {
            return Ok(format!("session:{token}"));
        }

        SmartIpKeyExtractor
            .extract(req)
            .map(|ip| format!("ip:{ip}"))
    }
}

type IpLayer = GovernorLayer<SmartIpKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;
type AuthLayer =
    GovernorLayer<SmartIpKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;
type UserLayer =
    GovernorLayer<SessionKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;

/// Build rate limiting layers from configuration.
///
/// Returns three governor layers:
/// - General IP rate limit (applied to all API routes)
/// - Strict auth rate limit (applied to login/signup/setup endpoints)
/// - Per-user rate limit (applied to authenticated endpoints)
///
/// The IP-based layers use [`SmartIpKeyExtractor`], which checks
/// `x-forwarded-for`, `x-real-ip`, and `forwarded` headers before falling
/// back to the peer IP. This is the correct default for deployments behind
/// a trusted reverse proxy (see the NixOS module for the recommended Caddy
/// configuration). **Do not expose the server directly to untrusted
/// clients without a reverse proxy** — a malicious client could forge
/// these headers to bypass the per-IP rate limit.
pub fn build_layers(config: &prismoire_config::RateLimitConfig) -> (IpLayer, AuthLayer, UserLayer) {
    let ip_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(config.ip_replenish_seconds)
            .burst_size(config.ip_burst_size)
            .finish()
            .expect("invalid IP rate limit config"),
    );

    let auth_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(config.auth_replenish_seconds)
            .burst_size(config.auth_burst_size)
            .finish()
            .expect("invalid auth rate limit config"),
    );

    let user_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SessionKeyExtractor)
            .per_second(config.user_replenish_seconds)
            .burst_size(config.user_burst_size)
            .finish()
            .expect("invalid user rate limit config"),
    );

    (
        GovernorLayer::new(ip_config),
        GovernorLayer::new(auth_config),
        GovernorLayer::new(user_config),
    )
}
