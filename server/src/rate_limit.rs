use std::net::IpAddr;
use std::sync::Arc;

use governor::clock::QuantaInstant;
use governor::middleware::NoOpMiddleware;
use http::request::Request;
use tower_governor::GovernorLayer;
use tower_governor::errors::GovernorError;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::{KeyExtractor, PeerIpKeyExtractor, SmartIpKeyExtractor};

use crate::session::parse_session_cookie;

/// Client-IP key extractor that dispatches between [`PeerIpKeyExtractor`]
/// and [`SmartIpKeyExtractor`] based on the `server.trust_proxy_headers`
/// configuration flag.
///
/// - `Peer` (default): the key is the TCP peer address only. Forwarded
///   headers are ignored entirely. This is the correct, safe choice when
///   the server is directly exposed to clients (no reverse proxy).
/// - `Smart`: the key is taken from `X-Forwarded-For`, `X-Real-IP`, or
///   `Forwarded` (in that order), falling back to the peer address. This
///   must only be enabled when the server is exclusively reachable via a
///   trusted reverse proxy that strips these headers from inbound requests
///   and sets its own — otherwise a malicious client can forge the
///   headers to appear as a different IP on every request and trivially
///   bypass the per-IP rate limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIpKeyExtractor {
    Peer,
    Smart,
}

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        match self {
            Self::Peer => PeerIpKeyExtractor.extract(req),
            Self::Smart => SmartIpKeyExtractor.extract(req),
        }
    }
}

impl ClientIpKeyExtractor {
    fn from_config(trust_proxy_headers: bool) -> Self {
        if trust_proxy_headers {
            Self::Smart
        } else {
            Self::Peer
        }
    }
}

/// Extracts the session cookie value as a rate-limiting key.
///
/// Used for per-user rate limiting. Falls back to the configured client
/// IP extractor for unauthenticated requests so they are still
/// rate-limited. The IP fallback honors `server.trust_proxy_headers`:
/// when that flag is unset, forwarded headers are ignored and the peer
/// IP is used.
///
/// This extractor deliberately keys on the **raw cookie string** without
/// validating the session against the database. That makes it cheap
/// enough to run as the outermost layer on authed routes (outside
/// `session_middleware`), so abusive traffic is rate-limited before any
/// DB query happens. A bogus or expired cookie still gets a stable
/// bucket — the bucket just won't correspond to a real user.
///
/// Implication for future session token rotation: the per-session bucket
/// is keyed on the exact token string, so if session renewal ever starts
/// rotating the token value (rather than extending the expiry of the
/// same token as it does today), each rotation will reset the bucket and
/// the per-user limit will effectively stop working for long-lived
/// sessions. Key on the user ID instead at that point, by moving the
/// extractor to run after `session_middleware` and reading from
/// request extensions — at the cost of reintroducing the DB-before-limit
/// ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeyExtractor {
    ip_fallback: ClientIpKeyExtractor,
}

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

        self.ip_fallback.extract(req).map(|ip| format!("ip:{ip}"))
    }
}

type IpLayer = GovernorLayer<ClientIpKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;
type AuthLayer =
    GovernorLayer<ClientIpKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;
type UserLayer =
    GovernorLayer<SessionKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;

/// Build rate limiting layers from configuration.
///
/// Returns three governor layers:
/// - General IP rate limit (applied to all API routes)
/// - Strict auth rate limit (applied to login/signup/setup endpoints)
/// - Per-user rate limit (applied to authenticated endpoints)
///
/// `trust_proxy_headers` selects between peer-IP-only extraction (the
/// safe default when the server is directly exposed) and
/// [`SmartIpKeyExtractor`]-style extraction from `X-Forwarded-For` /
/// `X-Real-IP` / `Forwarded` headers (correct only behind a trusted
/// reverse proxy that strips client-supplied copies of those headers).
pub fn build_layers(
    config: &prismoire_config::RateLimitConfig,
    trust_proxy_headers: bool,
) -> (IpLayer, AuthLayer, UserLayer) {
    let ip_extractor = ClientIpKeyExtractor::from_config(trust_proxy_headers);

    let ip_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(ip_extractor)
            .per_second(config.ip_replenish_seconds)
            .burst_size(config.ip_burst_size)
            .finish()
            .expect("invalid IP rate limit config"),
    );

    let auth_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(ip_extractor)
            .per_second(config.auth_replenish_seconds)
            .burst_size(config.auth_burst_size)
            .finish()
            .expect("invalid auth rate limit config"),
    );

    let user_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SessionKeyExtractor {
                ip_fallback: ip_extractor,
            })
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
