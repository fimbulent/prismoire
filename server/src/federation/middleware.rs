//! Envelope-verify middleware (`docs/federation-protocol.md` §6, lifted
//! to router scope).
//!
//! Phase 2 ran the §6.5 13-step verifier per-handler call site. Phase 3
//! lifts that into a router-scoped Axum middleware so every handler
//! behind it can assume:
//!
//! 1. the verifier accepted the inbound envelope,
//! 2. the verified [`FedEnvelope`] is on the request extensions,
//! 3. the request body bytes are on the request extensions wrapped in
//!    [`VerifiedBody`] — handlers should read those *instead of*
//!    re-extracting `Bytes` (which would re-consume the body the
//!    middleware already drained for hash + length-cap purposes).
//!
//! Two flavours of the middleware are exported, one per
//! [`VerifyMode`]:
//!
//! - [`verify_bootstrap`] — for the §5.4 handshake routes
//!   (`POST /federation/v1/peer-request` and
//!   `POST /federation/v1/peer-response`) where the sender is not yet
//!   in our `peers WHERE status = 'active'` set, so the verifier skips
//!   its step-5 peers lookup and the handler performs a tighter
//!   self-consistency check (`envelope.sender == body.pubkey`).
//! - [`verify_known_peer`] — for every other authenticated route. The
//!   verifier requires `envelope.sender` to match an `active` peer row;
//!   anything else is collapsed to a `401 unauthorized` on the wire
//!   per §6.5 (the discriminated [`VerifyError`] variant is kept
//!   server-side for the §20 anomaly counter that lands with the
//!   operational-hardening pass).
//!
//! Unauthenticated routes (just `GET /federation/v1/identity` for now)
//! are mounted *outside* this layer.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{Method, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::AppState;
use crate::federation::envelope::{self, AUTH_HEADER, VerifyError, VerifyMode};
use crate::federation::errors::{internal_error, unauthorized, unsupported_media_type};
use crate::federation::identity::CBOR_CONTENT_TYPE;

/// Default body cap for any federation route not listed in
/// [`route_body_cap`].
///
/// 64 KiB comfortably covers Phase-3 handshake bodies (peer-request,
/// peer-response, peer-relationship — all small fixed-field CBOR
/// envelopes) while keeping a hostile peer's request from amplifying
/// memory pressure for routes that have not yet been thought through.
/// Routes that legitimately need more bytes opt in via the per-route
/// table below; anything else hits this ceiling.
pub const DEFAULT_FEDERATION_BODY_CAP: usize = 64 * 1024;

/// Body cap for `/federation/v1/frontier/announce` and
/// `/federation/v1/frontier/delta`.
///
/// 16 MiB matches the protocol's `MAX_ANNOUNCE_BODY` default
/// (`docs/federation-protocol.md` §8.8 — "covers both filters
/// combined"). §8.8 sizes this to a ≈ 13 M-key 3-hop closure at 1%
/// FPR; the content filter dominates by ≈ 10× over the edge-origin
/// filter, so almost the entire budget is the content filter's bits
/// with the §6 envelope adding negligible framing. Senders whose
/// pair exceeds this cap are required by the spec to trim. The §8.2
/// hard ceiling `MAX_M_BITS = 2³²` (≈ 512 MiB per filter) is the
/// protocol-level safety net; this cap is the operational one.
pub const FRONTIER_BODY_CAP: usize = 16 * 1024 * 1024;

/// Body cap for `/federation/v1/edges` (push) — Phase 5.
///
/// One push body carries a single signed trust-edge object (signed
/// payload + envelope). A V1 trust edge is bounded by signature +
/// pubkeys + a small score field; a few KiB in CBOR. 64 KiB is far
/// more than the protocol requires and matches the default so we
/// don't need a special-case entry until batched-push lands.
pub const EDGES_BODY_CAP: usize = 64 * 1024;

/// Resolve the body cap for a given federation path.
///
/// Match is path-prefix-aware but anchored on a trailing slash (or
/// exact equality) so neighbouring routes can't bleed into a cap
/// they weren't sized for — `/federation/v1/edges-foo` is *not*
/// `/federation/v1/edges`. Order matters: more specific prefixes
/// come first. Routes not listed fall through to
/// [`DEFAULT_FEDERATION_BODY_CAP`].
fn route_body_cap(path: &str) -> usize {
    // `/frontier/announce` and `/frontier/delta` are the only POSTs
    // under this prefix. `/frontier` (no trailing segment) is a GET
    // with no body, but charging it the larger cap costs nothing.
    if path == "/federation/v1/frontier" || path.starts_with("/federation/v1/frontier/") {
        FRONTIER_BODY_CAP
    // Both `/edges` (POST push) and `/edges/backfill` (GET pull,
    // empty body) land here. The push body sizing is bounded by a
    // single signed trust-edge object.
    } else if path == "/federation/v1/edges" || path.starts_with("/federation/v1/edges/") {
        EDGES_BODY_CAP
    } else {
        DEFAULT_FEDERATION_BODY_CAP
    }
}

/// Body bytes the middleware drained from the request.
///
/// Inserted into the request extensions after a successful verify so
/// handlers can read the *exact* bytes the verifier hashed. Pulling
/// these from extensions is required: the middleware has already
/// consumed the underlying `Body` stream once (to compute the SHA-256
/// for §6.5 step 10), so a handler-side `Bytes` extractor would see
/// nothing left. The wrapper type makes the intent explicit at the
/// handler signature instead of leaving a bare `Bytes` floating in
/// extensions next to whatever else might live there.
#[derive(Clone, Debug)]
pub struct VerifiedBody(pub Bytes);

/// Middleware variant for the `Bootstrap`-mode handshake routes. See
/// the module docs for the bootstrap exception's rationale.
pub async fn verify_bootstrap(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    verify(state, VerifyMode::Bootstrap, req, next).await
}

/// Middleware variant for every other authenticated route. The
/// verifier looks `envelope.sender` up in `peers WHERE status =
/// 'active'`; an unknown sender returns 401.
pub async fn verify_known_peer(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    verify(state, VerifyMode::KnownPeer, req, next).await
}

async fn verify(state: Arc<AppState>, mode: VerifyMode, req: Request, next: Next) -> Response {
    // Snapshot the routing fields the verifier needs before we tear
    // the request apart for body draining.
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let (parts, body) = req.into_parts();

    // Per §1.7 every body-carrying request must declare
    // `application/cbor` — there is no JSON surface here. Run the
    // header check *before* draining so a peer who sends a 64 KiB
    // JSON payload pays only the header inspection, not a full body
    // read. GET (and HEAD) carry no body and need no Content-Type.
    // A peer that fabricates a body on a GET still has it drained
    // and verified below; the 415 short-circuit is purely an
    // efficiency tightening for the methods that should declare CT.
    let body_expected = !matches!(method, Method::GET | Method::HEAD);
    if body_expected {
        let ct = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        if ct != Some(CBOR_CONTENT_TYPE) {
            return unsupported_media_type();
        }
    }

    // Drain the body once. §6.5 step 10 needs the exact bytes for the
    // body-hash check; handlers downstream read the same bytes back
    // via VerifiedBody so neither side re-encodes. The per-route cap
    // table keeps low-bandwidth routes from being abused while
    // letting frontier-announce bodies (which legitimately need
    // megabytes of Bloom-filter bits) through.
    let cap = route_body_cap(&path);
    let bytes = match axum::body::to_bytes(body, cap).await {
        Ok(b) => b,
        // `to_bytes` errors on both length-cap overruns and broken
        // transports. Either way the envelope cannot be verified, so
        // collapse to the same 401 the verifier would have produced
        // for a missing/invalid header — operators see the underlying
        // cause through the tower::layer trace, not the wire.
        Err(_) => return unauthorized(),
    };

    let auth_header = parts.headers.get(AUTH_HEADER);
    let envelope = match envelope::verify_inbound(
        &state.db,
        state.instance_key.public_bytes(),
        &state.federation_nonce_lru,
        mode,
        &method,
        &path,
        &bytes,
        auth_header,
    )
    .await
    {
        Ok(e) => e,
        Err(VerifyError::Db(e)) => {
            // A DB outage during peers lookup is *our* fault, not the
            // caller's — surface as 500 so the §20 anomaly counter
            // (when it lands) does not slander the caller for our
            // operational problem.
            tracing::error!(error = %e, "db error in federation envelope verify middleware");
            return internal_error();
        }
        // Every other variant collapses to 401 per §6.5. The
        // discriminated `VerifyError` stays in `tracing` for the
        // operator and is the input the §20 per-peer anomaly counter
        // will consume when that work lands.
        Err(e) => {
            tracing::debug!(?e, %method, %path, "federation envelope rejected");
            return unauthorized();
        }
    };

    // Reassemble the request with the drained bytes restored as the
    // body so downstream handlers can extract via `VerifiedBody`. The
    // `Body::from(Bytes)` round-trip is cheap (no copy — `Bytes` is
    // reference-counted internally).
    let mut req = Request::from_parts(parts, Body::from(bytes.clone()));
    req.extensions_mut().insert(envelope);
    req.extensions_mut().insert(VerifiedBody(bytes));
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_body_cap_picks_frontier_cap_for_announce_and_delta() {
        assert_eq!(
            route_body_cap("/federation/v1/frontier/announce"),
            FRONTIER_BODY_CAP,
        );
        assert_eq!(
            route_body_cap("/federation/v1/frontier/delta"),
            FRONTIER_BODY_CAP,
        );
    }

    #[test]
    fn route_body_cap_picks_edges_cap_for_edges_routes() {
        assert_eq!(route_body_cap("/federation/v1/edges"), EDGES_BODY_CAP);
        assert_eq!(
            route_body_cap("/federation/v1/edges/backfill"),
            EDGES_BODY_CAP,
        );
    }

    #[test]
    fn route_body_cap_falls_through_to_default_for_handshake_routes() {
        assert_eq!(
            route_body_cap("/federation/v1/peer-request"),
            DEFAULT_FEDERATION_BODY_CAP,
        );
        assert_eq!(
            route_body_cap("/federation/v1/peer-response"),
            DEFAULT_FEDERATION_BODY_CAP,
        );
        assert_eq!(
            route_body_cap("/federation/v1/peer-relationship"),
            DEFAULT_FEDERATION_BODY_CAP,
        );
        assert_eq!(
            route_body_cap("/federation/v1/peers"),
            DEFAULT_FEDERATION_BODY_CAP,
        );
    }

    #[test]
    fn route_body_cap_does_not_match_unrelated_paths() {
        // Defensive: the prefix match must not bleed into /api/*.
        assert_eq!(route_body_cap("/api/posts"), DEFAULT_FEDERATION_BODY_CAP);
        assert_eq!(route_body_cap("/"), DEFAULT_FEDERATION_BODY_CAP);
    }

    #[test]
    fn route_body_cap_does_not_bleed_into_sibling_paths() {
        // A hypothetical `/federation/v1/edges-foo` (or
        // `/federation/v1/frontier-extra`) MUST NOT inherit the
        // larger cap of its prefix-sibling. The slash-anchored
        // match guards against an attacker who could pick a route
        // name that prefix-matches and amplifies memory pressure.
        assert_eq!(
            route_body_cap("/federation/v1/edges-foo"),
            DEFAULT_FEDERATION_BODY_CAP,
        );
        assert_eq!(
            route_body_cap("/federation/v1/frontier-extra"),
            DEFAULT_FEDERATION_BODY_CAP,
        );
    }
}
