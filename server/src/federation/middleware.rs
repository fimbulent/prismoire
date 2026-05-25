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

/// Largest body the envelope-verify middleware will read off the wire
/// before short-circuiting.
///
/// Phase 3's authenticated surface is bounded by small fixed-field
/// bodies (handshake messages, termination notices, GETs with empty
/// bodies); 64 KiB is a generous cap that still keeps a hostile
/// peer's request from amplifying memory pressure. Phase 4's
/// frontier/delta routes will need a larger budget; expect this
/// constant to be replaced by a per-route table at that point.
pub const MAX_FEDERATION_BODY: usize = 64 * 1024;

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
    // via VerifiedBody so neither side re-encodes.
    let bytes = match axum::body::to_bytes(body, MAX_FEDERATION_BODY).await {
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
