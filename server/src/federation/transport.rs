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
use http::{Request, Response};

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
#[derive(Debug)]
pub enum TransportError {
    /// The transport has no route to the requested peer. For the
    /// in-process harness this means the peer was never registered;
    /// for the production transport it means the peer record carries
    /// no resolvable domain.
    UnknownPeer(PeerId),
    /// The transport reached the peer (or attempted to) but the
    /// request/response cycle failed. The string is for diagnostics
    /// only — do not branch on its contents.
    Dispatch(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::UnknownPeer(id) => {
                write!(f, "no transport route to peer {id}")
            }
            TransportError::Dispatch(msg) => {
                write!(f, "federation transport dispatch failed: {msg}")
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
