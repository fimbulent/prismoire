use std::net::IpAddr;
use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use governor::clock::QuantaInstant;
use governor::middleware::NoOpMiddleware;
use http::HeaderMap;
use http::request::Request;
use tower_governor::GovernorLayer;
use tower_governor::errors::GovernorError;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::{KeyExtractor, PeerIpKeyExtractor, SmartIpKeyExtractor};

use crate::error::{AppError, ErrorCode};
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

pub type IpLayer =
    GovernorLayer<ClientIpKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;
pub type AuthLayer =
    GovernorLayer<ClientIpKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;
pub type UserLayer =
    GovernorLayer<SessionKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;
pub type ReportLayer =
    GovernorLayer<SessionKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;
pub type UploadLayer =
    GovernorLayer<SessionKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;
pub type RedeemLayer =
    GovernorLayer<SessionKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;
pub type CspReportLayer =
    GovernorLayer<ClientIpKeyExtractor, NoOpMiddleware<QuantaInstant>, axum::body::Body>;

/// Bundle of rate-limit layers returned by [`build_layers`].
///
/// Grouped into a struct so the application router builder can receive
/// them as one parameter and apply each at its correct scope (auth-only
/// vs per-session vs global IP) without juggling a 5-tuple.
pub struct RateLimitLayers {
    pub ip: IpLayer,
    pub auth: AuthLayer,
    pub user: UserLayer,
    pub report: ReportLayer,
    pub upload: UploadLayer,
    pub redeem: RedeemLayer,
    pub csp_report: CspReportLayer,
}

/// Translate a [`GovernorError`] into the project's structured
/// [`AppError`] JSON envelope.
///
/// Without this, `tower_governor` writes a plain-text
/// `"Too Many Requests! Wait for Ns"` body on 429s, which breaks the
/// invariant that every non-2xx API response carries a stable
/// machine-readable `code` the frontend catalog can map. With the
/// handler installed, clients get the same `{ error, code: "rate_limited", ... }`
/// JSON shape as any other error, and the frontend's i18n catalog
/// entry for `rate_limited` actually fires.
///
/// - `TooManyRequests`: preserves the middleware's `Retry-After` /
///   `X-RateLimit-*` headers so clients that implement backoff still
///   get the timing signal, then overwrites the body with our JSON
///   envelope.
/// - `UnableToExtractKey`: a misconfiguration (bad proxy headers,
///   missing peer address); map to `Internal` so it's logged and
///   correlated like any other server bug.
/// - `Other`: custom key extractors in this codebase never produce
///   it, so treat it as a surprise and map to `Internal`.
fn govern_error_handler(err: GovernorError) -> Response {
    match err {
        GovernorError::TooManyRequests { headers, .. } => {
            let mut response = AppError::code(ErrorCode::RateLimited).into_response();
            if let Some(extra) = headers {
                merge_headers(response.headers_mut(), extra);
            }
            response
        }
        GovernorError::UnableToExtractKey | GovernorError::Other { .. } => {
            AppError::code(ErrorCode::Internal).into_response()
        }
    }
}

/// Copy governor-supplied headers (`Retry-After`, `X-RateLimit-*`)
/// onto the response without clobbering headers already set by
/// `AppError::into_response` (e.g. `content-type: application/json`).
fn merge_headers(dst: &mut HeaderMap, src: HeaderMap) {
    for (name, value) in src.iter() {
        dst.insert(name.clone(), value.clone());
    }
}

/// Replenish interval for the `/api/posts/:id/report` per-session bucket,
/// in seconds.
///
/// Reports require admin attention, so a tighter limit than the general
/// user bucket prevents a single user from flooding the moderation queue.
/// One token every ten seconds allows legitimate multi-post reports while
/// capping sustained throughput to ~6 per minute.
const REPORT_REPLENISH_SECONDS: u64 = 10;

/// Burst size for the `/api/posts/:id/report` per-session bucket.
///
/// A user encountering a spam wave may want to report several posts in
/// quick succession. Three tokens accommodate that without allowing
/// sustained abuse.
const REPORT_BURST_SIZE: u32 = 3;

/// Replenish interval for the `POST /api/attachments` per-session bucket,
/// in seconds.
///
/// Upload is the most CPU-expensive authenticated endpoint: it pulls
/// up-to-500-KiB multipart bodies, runs a header-dimensions probe, a
/// full decode, a downscale, and a re-encode — all on the
/// `spawn_blocking` pool, but still finite shared capacity. A tighter
/// per-session bucket than the general `user_limiter` prevents one
/// user from monopolising the encode pool by spamming the route. One
/// token every five seconds caps sustained throughput to ~12 uploads
/// per minute per session, which comfortably covers compose-time
/// burst patterns (up to 3 attachments per post) while shedding abuse.
const UPLOAD_REPLENISH_SECONDS: u64 = 5;

/// Burst size for the `POST /api/attachments` per-session bucket.
///
/// Six tokens absorb a compose flow where the user uploads a few
/// attachments in quick succession, or retries an upload after a
/// network hiccup, without dipping into rate-limit territory.
const UPLOAD_BURST_SIZE: u32 = 6;

/// Replenish interval for the `POST /api/users/by-trust-code` per-session
/// bucket, in seconds.
///
/// Redeeming a trust code is an unbounded write primitive: each successful
/// non-dry-run redeem can seed a brand-new federated stub user (`users` +
/// `user_homes` rows), sign a trust edge, and enqueue federation fanout
/// toward the code's named home instance. A single session sharing the
/// general `user_limiter` bucket could therefore mint a large number of
/// stub rows and fanout jobs at read-endpoint rates. Redeeming a code is a
/// deliberate, rare act (bootstrapping a cross-instance contact), so a
/// tight bucket — one token every fifteen seconds (~4/min sustained) —
/// sheds abuse while comfortably covering a user adding a handful of
/// contacts in one sitting.
const REDEEM_REPLENISH_SECONDS: u64 = 15;

/// Burst size for the `POST /api/users/by-trust-code` per-session bucket.
///
/// Five tokens absorb a user pasting several trust codes in quick
/// succession (e.g. importing a small contact list) without dipping into
/// rate-limit territory, while still bounding a single burst of stub
/// creation.
const REDEEM_BURST_SIZE: u32 = 5;

/// Replenish interval for the `/api/csp-report` per-IP bucket, in seconds.
///
/// CSP reports are browser-driven telemetry — a page that triggers one
/// violation on first load is normal, but a hostile page can generate a
/// flood of blocked-URI variations. Bucket refills every two seconds
/// keep legitimate reporters working while capping a single IP to ~30
/// reports per minute sustained.
const CSP_REPORT_REPLENISH_SECONDS: u64 = 2;

/// Burst size for the `/api/csp-report` per-IP bucket.
///
/// A single page load with a broken CSP may emit several reports back to
/// back (one per violated directive on the initial render). Five tokens
/// absorb that burst without dropping reports that are actually useful.
const CSP_REPORT_BURST_SIZE: u32 = 5;

/// Build rate limiting layers from configuration.
///
/// Returns the governor layers:
/// - General IP rate limit (applied to all API routes)
/// - Strict auth rate limit (applied to login/signup/setup endpoints)
/// - Per-user rate limit (applied to authenticated endpoints)
/// - Per-session report limit for `POST /api/posts/:id/report`, tighter
///   than the general user bucket since reports require admin attention
/// - Per-session upload limit for `POST /api/attachments`, tighter than
///   the general user bucket since image re-encoding is CPU-expensive
/// - Per-session redeem limit for `POST /api/users/by-trust-code`, tighter
///   than the general user bucket since redeeming is an unbounded write +
///   federation-fanout primitive
/// - Tight per-IP limit for the `/api/csp-report` endpoint, applied on
///   top of the general IP limit so a flood of reports cannot crowd out
///   the rest of the API.
///
/// `trust_proxy_headers` selects between peer-IP-only extraction (the
/// safe default when the server is directly exposed) and
/// [`SmartIpKeyExtractor`]-style extraction from `X-Forwarded-For` /
/// `X-Real-IP` / `Forwarded` headers (correct only behind a trusted
/// reverse proxy that strips client-supplied copies of those headers).
pub fn build_layers(
    config: &prismoire_config::RateLimitConfig,
    trust_proxy_headers: bool,
) -> RateLimitLayers {
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

    let report_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SessionKeyExtractor {
                ip_fallback: ip_extractor,
            })
            .per_second(REPORT_REPLENISH_SECONDS)
            .burst_size(REPORT_BURST_SIZE)
            .finish()
            .expect("invalid report rate limit config"),
    );

    let upload_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SessionKeyExtractor {
                ip_fallback: ip_extractor,
            })
            .per_second(UPLOAD_REPLENISH_SECONDS)
            .burst_size(UPLOAD_BURST_SIZE)
            .finish()
            .expect("invalid upload rate limit config"),
    );

    let redeem_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SessionKeyExtractor {
                ip_fallback: ip_extractor,
            })
            .per_second(REDEEM_REPLENISH_SECONDS)
            .burst_size(REDEEM_BURST_SIZE)
            .finish()
            .expect("invalid redeem rate limit config"),
    );

    let csp_report_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(ip_extractor)
            .per_second(CSP_REPORT_REPLENISH_SECONDS)
            .burst_size(CSP_REPORT_BURST_SIZE)
            .finish()
            .expect("invalid CSP report rate limit config"),
    );

    RateLimitLayers {
        ip: GovernorLayer::new(ip_config).error_handler(govern_error_handler),
        auth: GovernorLayer::new(auth_config).error_handler(govern_error_handler),
        user: GovernorLayer::new(user_config).error_handler(govern_error_handler),
        report: GovernorLayer::new(report_config).error_handler(govern_error_handler),
        upload: GovernorLayer::new(upload_config).error_handler(govern_error_handler),
        redeem: GovernorLayer::new(redeem_config).error_handler(govern_error_handler),
        csp_report: GovernorLayer::new(csp_report_config).error_handler(govern_error_handler),
    }
}
