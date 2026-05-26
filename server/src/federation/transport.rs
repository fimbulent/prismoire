//! Outbound HTTP transport abstraction.
//!
//! Every federation route is `instance → instance`. Production code
//! sends the request over TCP/TLS via `reqwest`; Layer-1 integration
//! tests route the request directly into the peer's Axum `Router`
//! via `tower::ServiceExt::oneshot`. Both implementations live behind
//! [`FederationTransport`] so the producer code (handlers, fanout
//! loops, backfill) is identical in both worlds.
//!
//! The trait deliberately speaks in raw `http::Request<Bytes>` /
//! `http::Response<Bytes>` rather than typed CBOR payloads: envelope
//! signing, body hashing, and the §6 verifier all need byte-exact
//! access to the wire bytes on both sides. Higher-level helpers
//! layer on top of this once Phase 3 (envelope auth) lands.
//!
//! See `docs/federation-impl-plan.md` §Phase 1.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use axum::body::Bytes;
use http::{HeaderName, Request, Response};

use crate::federation::domain::{is_blocked_ip_literal, parse_instance_domain};
use crate::federation::envelope::AUTH_HEADER;

/// Stable identifier for a peer instance.
///
/// Phase 1 carries the raw 32 bytes that will become the instance's
/// Ed25519 signing public key once Phase 2's identity/handshake
/// (`GET /federation/v1/identity`, protocol §5.4) is implemented.
/// Until then test harnesses populate it with deterministic per-label
/// bytes; the *shape* (`[u8; 32]`, primary-key compatible with the
/// existing `peers.instance_pubkey BLOB` column in `schema.sql`) is
/// what matters here.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Wrap raw bytes as a `PeerId`. No validation: the caller is
    /// responsible for ensuring the bytes are a valid Ed25519 public
    /// key once that becomes load-bearing in Phase 2.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32 bytes (e.g. for SQL binding to the
    /// `peers.instance_pubkey BLOB` column).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PeerId {
    /// Lowercase hex, no separator. Matches the encoding used by
    /// `tracing` field formatters elsewhere in the codebase (`%hex`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({self})")
    }
}

/// Failure modes a [`FederationTransport`] can surface to its caller.
///
/// Kept deliberately coarse for Phase 1 — higher-level federation
/// code does not yet make routing decisions based on the failure
/// class. Later phases (e.g. the §20 anomaly counters) will likely
/// need a richer split; expand this enum at that point rather than
/// shoehorning new state in here speculatively.
///
/// The [`Dispatch`] variant carries only a fixed category string —
/// no peer-resolved IPs, ports, DNS detail, or TLS subject info.
/// That detail is logged via `tracing` for the operator but kept off
/// the error surface so callers (and any future text-of-error-based
/// instrumentation) cannot be turned into an SSRF probe oracle.
#[derive(Debug)]
pub enum TransportError {
    /// The transport has no route to the requested peer. For the
    /// in-process harness this means the peer was never registered;
    /// for the production transport it means the peer record carries
    /// no resolvable domain.
    UnknownPeer(PeerId),
    /// The peer record's `instance_domain` is structurally invalid
    /// (post-validation drift, manual DB edit, or pre-validation
    /// row written by an older build). The transport refuses to
    /// dispatch to such a peer.
    InvalidPeerDomain(PeerId),
    /// The peer record's `instance_domain` resolves to an IP literal
    /// in a private / loopback / link-local / metadata range and
    /// the `PRISMOIRE_FEDERATION_ALLOW_PRIVATE_TARGETS` escape hatch
    /// is off. See [`crate::federation::domain`].
    BlockedTarget(PeerId),
    /// The transport reached the peer (or attempted to) but the
    /// request/response cycle failed. The category is one of a
    /// fixed enum-of-strings (`"timeout"`, `"connect"`, `"tls"`,
    /// `"body"`, `"build"`, `"other"`); do not parse it for
    /// anything other than coarse classification.
    Dispatch(&'static str),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::UnknownPeer(id) => {
                write!(f, "no transport route to peer {id}")
            }
            TransportError::InvalidPeerDomain(id) => {
                write!(f, "peer {id} has a malformed instance_domain")
            }
            TransportError::BlockedTarget(id) => {
                write!(f, "peer {id} resolves to a blocked target IP range")
            }
            TransportError::Dispatch(category) => {
                write!(f, "federation transport dispatch failed: {category}")
            }
        }
    }
}

impl std::error::Error for TransportError {}

/// Async return type for [`FederationTransport::request`].
///
/// Spelled out as a boxed-future alias rather than relying on the
/// 2024-edition `async fn` syntax so the trait stays object-safe:
/// later phases want `Arc<dyn FederationTransport>` in `AppState` so
/// production code and test code can be swapped without generics
/// propagating through every handler.
pub type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Response<Bytes>, TransportError>> + Send + 'a>>;

/// Outbound transport for federation requests.
///
/// Implementations:
///
/// - **Production** (later phase): a `reqwest`-backed impl that maps
///   `PeerId` → `peers.instance_domain` via the database and opens a
///   real HTTPS connection. Not yet written.
/// - **Test harness**: `InProcessTransport` in
///   `server/tests/common/federation.rs`, which holds a shared
///   `PeerId → Router` registry and dispatches via
///   `tower::ServiceExt::oneshot`.
///
/// The contract is intentionally byte-exact: callers hand in fully-
/// assembled `http::Request<Bytes>` (path, method, headers, signed
/// envelope header, raw body) and receive the peer's complete
/// response. Anything richer — signing, envelope construction, CBOR
/// (de)serialisation — layers on top once the relevant phase lands.
pub trait FederationTransport: Send + Sync + 'static {
    /// Dispatch `request` to `target` and return the peer's response.
    ///
    /// `request.uri()` is interpreted as a path-and-query against the
    /// peer; the scheme/authority components, if present, are
    /// ignored by the in-process transport and overwritten by the
    /// production transport from the peer record. This matches the
    /// way handlers will eventually construct requests (they know
    /// the federation path; they do not know which peer host serves
    /// it).
    fn request<'a>(&'a self, target: &'a PeerId, request: Request<Bytes>) -> TransportFuture<'a>;
}

/// Placeholder transport that rejects every outbound call as
/// [`TransportError::UnknownPeer`].
///
/// Retained for unit tests and any deployment that wants to disable
/// outbound federation entirely (e.g. a test-only run that should
/// never reach the network). Production binaries should bind the
/// [`ReqwestTransport`] instead.
pub struct NullTransport;

impl FederationTransport for NullTransport {
    fn request<'a>(&'a self, target: &'a PeerId, _request: Request<Bytes>) -> TransportFuture<'a> {
        let target = *target;
        Box::pin(async move { Err(TransportError::UnknownPeer(target)) })
    }
}

/// Production [`FederationTransport`] backed by `reqwest` over HTTPS.
///
/// Resolves `PeerId` → `peers.instance_domain` via the database, then
/// reassembles the caller's request against
/// `https://{instance_domain}{path-and-query}` and dispatches via a
/// shared `reqwest::Client` (HTTP/2 over rustls).
///
/// The constructor takes a pre-built [`reqwest::Client`] rather than
/// building one internally so deployments (and the Layer-2 smoke test)
/// can configure TLS roots, timeouts, proxies, and connection pooling
/// without each requiring a new constructor variant. [`default_client`]
/// returns a production-shaped client; the loopback smoke test builds
/// its own with `danger_accept_invalid_certs(true)` to trust its
/// self-signed cert.
pub struct ReqwestTransport {
    /// Shared HTTP/2 client. Cheap to clone (`reqwest::Client` is
    /// `Arc`-internal) but we hold one per transport since it owns
    /// the connection pool we want to share across all outbound
    /// federation requests.
    client: reqwest::Client,
    /// Handle to the `peers` table. Lookups are by primary key
    /// (`instance_pubkey`) so the pool footprint is one read per
    /// outbound request — well within SQLite's WAL concurrency
    /// envelope.
    db: sqlx::SqlitePool,
    /// Set explicitly by the caller. When `false` (the production
    /// default), IP-literal targets in loopback / link-local /
    /// RFC1918 / metadata ranges are refused before dispatch. When
    /// `true` (the Layer-2 smoke test), the check is bypassed so
    /// `127.0.0.1:PORT` works for the self-signed loopback peering
    /// test. Production binaries derive this from
    /// `PRISMOIRE_FEDERATION_ALLOW_PRIVATE_TARGETS` in `main.rs` via
    /// [`super::domain::allow_private_targets_from_env`]; tests pass `true`
    /// directly without touching process-wide env state.
    allow_private_targets: bool,
}

impl ReqwestTransport {
    /// Construct a [`ReqwestTransport`] over the supplied client.
    /// The SSRF policy is set explicitly by the caller — see the
    /// `allow_private_targets` field for the rationale.
    pub fn new(db: sqlx::SqlitePool, client: reqwest::Client, allow_private_targets: bool) -> Self {
        Self {
            client,
            db,
            allow_private_targets,
        }
    }

    /// Production-shaped `reqwest::Client`. Configured for the
    /// federation §6 envelope-signing model:
    ///
    /// - **Rustls + webpki roots.** Hermetic build, no system TLS
    ///   trust store. TLS does not pin peer identity (§22) — peer
    ///   identity rides on §6 envelope sigs, not the cert; this
    ///   protects against a passive eavesdropper but a (CA + DNS)
    ///   compromise still allows MITM-of-transport (not of the
    ///   protocol). Calls to non-signing routes (`/identity`) gain
    ///   only TLS-level assurance.
    /// - **HTTP/2.** Connection reuse across federation calls cuts
    ///   handshake cost dramatically when fanout drives many calls
    ///   per second to the same peer.
    /// - **`redirect::Policy::none()`.** Following a redirect breaks
    ///   the §6.5 envelope check on the receiving side (signature
    ///   covers the *original* method + path + body) AND opens a
    ///   second SSRF vector. Any non-2xx/4xx/5xx status is surfaced
    ///   to the caller, including 3xx — that's deliberate.
    /// - **Connect / total timeouts.** A hostile peer can stall a
    ///   TLS handshake; the 5-second connect cap bounds that. The
    ///   30-second total cap bounds slowloris-style response leaks.
    /// - **Generic `User-Agent`.** Advertises only `prismoire/
    ///   federation` (no version) so a CVE-pinned mass scanner has
    ///   to do more work to single us out.
    ///
    /// Returns an error only if `reqwest::ClientBuilder::build` fails
    /// — in practice that means the embedded TLS init is broken,
    /// which is a deploy-time problem, not a runtime one.
    pub fn default_client() -> Result<reqwest::Client, reqwest::Error> {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("prismoire/federation")
            .build()
    }
}

/// Headers the transport is willing to forward from the caller's
/// `http::Request` onto the outbound `reqwest::Request`.
///
/// Whitelist (not blacklist) so a future trait consumer that hands us
/// a request carrying inbound `Host`, `Cookie`, `Authorization`,
/// hop-by-hop, or `Content-Length` headers cannot accidentally
/// smuggle them onto an outbound federation call. Today's callers
/// (handshake handlers in `peering.rs`, the Phase-5 fanout) only set
/// `Content-Type` and the §6 envelope auth header; this list will
/// grow only when a new federation route legitimately needs a new
/// header.
fn header_is_forwardable(name: &HeaderName) -> bool {
    name == http::header::CONTENT_TYPE || name.as_str().eq_ignore_ascii_case(AUTH_HEADER)
}

impl FederationTransport for ReqwestTransport {
    fn request<'a>(&'a self, target: &'a PeerId, request: Request<Bytes>) -> TransportFuture<'a> {
        Box::pin(async move {
            let target_id = *target;

            // Step 1: resolve PeerId → instance_domain. The peers table
            // is keyed by the same 32 bytes the transport speaks in;
            // any status is acceptable — peering callbacks need to
            // reach pending peers, and fanout reaches active ones.
            let target_bytes: &[u8] = target.as_bytes();
            let row = sqlx::query!(
                "SELECT instance_domain FROM peers WHERE instance_pubkey = ?",
                target_bytes,
            )
            .fetch_optional(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(peer = %target_id, error = %e, "peers lookup failed");
                TransportError::Dispatch("other")
            })?;
            let Some(row) = row else {
                return Err(TransportError::UnknownPeer(target_id));
            };
            let instance_domain = row.instance_domain;

            // Step 2: re-validate the domain (defence in depth — the
            // inbound boundary in `peering.rs` already did this, but
            // a row written by an older build, a manual operator
            // edit, or a future caller that bypassed the boundary
            // would all reach us here).
            let parsed = match parse_instance_domain(&instance_domain) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        peer = %target_id,
                        error = %e,
                        "rejecting outbound: instance_domain failed re-validation",
                    );
                    return Err(TransportError::InvalidPeerDomain(target_id));
                }
            };

            // Step 3: SSRF kill-switch for IP-literal targets in
            // loopback / link-local / RFC1918 / metadata / CGNAT
            // ranges. Hostnames (anything not a parseable IP literal)
            // bypass this check — DNS-rebinding-resistant filtering
            // is the operational-hardening pass's job.
            if !self.allow_private_targets && is_blocked_ip_literal(&parsed.host) {
                tracing::warn!(
                    peer = %target_id,
                    host = %parsed.host,
                    "rejecting outbound: target IP is in a blocked range",
                );
                return Err(TransportError::BlockedTarget(target_id));
            }

            // Step 4: assemble the URL. We use `url::Url::parse` over
            // a pre-constructed `https://{authority}{path}` string,
            // and `reqwest::Url::parse` validates the result, so
            // anything still slippery after `parse_instance_domain`
            // fails closed at parse time rather than silently
            // dispatching somewhere unexpected.
            let path_and_query = request
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            let raw_url = format!("https://{instance_domain}{path_and_query}");
            let url = match reqwest::Url::parse(&raw_url) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(peer = %target_id, error = %e, "outbound URL parse failed");
                    return Err(TransportError::InvalidPeerDomain(target_id));
                }
            };

            // Step 5: convert http::Request<Bytes> into a reqwest
            // request. Method + body carry over byte-exactly so
            // envelope signatures (which cover method, path, body
            // bytes) stay valid in flight. Headers go through an
            // allow-list filter (see `header_is_forwardable`) — the
            // trait contract says the caller hands us a fully
            // assembled request, but trusting that across the
            // process for outbound HTTP is a liability.
            let (parts, body) = request.into_parts();
            let mut builder = self.client.request(parts.method.clone(), url);
            for (name, value) in parts.headers.iter() {
                if header_is_forwardable(name) {
                    builder = builder.header(name, value);
                }
            }
            let response = builder.body(body).send().await.map_err(|e| {
                let category = classify_reqwest_error(&e);
                tracing::warn!(peer = %target_id, error = %e, category, "outbound send failed");
                TransportError::Dispatch(category)
            })?;

            // Step 6: convert reqwest::Response back into
            // http::Response<Bytes>. Status + headers carry through;
            // body is collected to Bytes so callers see the same
            // shape regardless of which transport was bound.
            let status = response.status();
            let headers = response.headers().clone();
            let body_bytes = response.bytes().await.map_err(|e| {
                tracing::warn!(peer = %target_id, error = %e, "outbound body read failed");
                TransportError::Dispatch("body")
            })?;
            let mut http_response = Response::builder()
                .status(status)
                .body(body_bytes)
                .map_err(|e| {
                    tracing::error!(peer = %target_id, error = %e, "response build failed");
                    TransportError::Dispatch("build")
                })?;
            *http_response.headers_mut() = headers;
            Ok(http_response)
        })
    }
}

/// Classify a `reqwest::Error` into a fixed-enum category string.
///
/// The categories are deliberately coarse so callers can do simple
/// "timeout?" / "connect?" / "TLS?" branching without parsing free
/// text. Detail is dropped on the floor at this layer; the full
/// error is logged at `warn` (with the peer pubkey) at the call site
/// before this function is reached.
fn classify_reqwest_error(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_request() {
        // Catches malformed-URL / malformed-header errors that
        // sneak past our boundary validation.
        "build"
    } else if e.is_redirect() {
        "redirect"
    } else if e.is_body() || e.is_decode() {
        "body"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_display_is_lowercase_hex() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0xcd;
        let id = PeerId::from_bytes(bytes);
        let rendered = format!("{id}");
        assert_eq!(rendered.len(), 64);
        assert!(rendered.starts_with("ab"));
        assert!(rendered.ends_with("cd"));
        assert_eq!(rendered, rendered.to_lowercase());
    }

    #[test]
    fn peer_id_round_trips_through_bytes() {
        let bytes = [0x42u8; 32];
        let id = PeerId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn transport_error_display_mentions_peer() {
        let id = PeerId::from_bytes([0xff; 32]);
        let err = TransportError::UnknownPeer(id);
        let s = format!("{err}");
        assert!(s.contains(&format!("{id}")), "got {s}");
    }
}
