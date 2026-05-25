//! Assembly of the `/federation/v1/*` subrouter.
//!
//! Mounted by `build_app` alongside the existing `/api` surface.
//! Phase 3 ships five routes split across three trust tiers:
//!
//! - `GET  /federation/v1/identity`           (§5.2; unauthenticated)
//! - `POST /federation/v1/peer-request`       (§5.4; envelope-verified, Bootstrap)
//! - `POST /federation/v1/peer-response`      (§5.4; envelope-verified, Bootstrap)
//! - `GET  /federation/v1/peers`              (§5.5; envelope-verified, KnownPeer)
//! - `DELETE /federation/v1/peer-relationship` (§5.4; envelope-verified, KnownPeer)
//!
//! The §6.5 13-step envelope verifier is applied by the [`middleware`]
//! layer rather than inline in each handler. Two verifier modes (and
//! therefore two middleware functions) are mounted as separate
//! sub-routers, then merged with the unauthenticated identity route:
//!
//! - `verify_bootstrap` wraps the two handshake routes whose sender
//!   is not yet in `peers WHERE status = 'active'`.
//! - `verify_known_peer` wraps every other authenticated route; the
//!   verifier rejects unknown senders with `VerifyError::UnknownSender`
//!   which the middleware collapses to a `401 unauthorized` on the
//!   wire.
//!
//! The unauthenticated identity route is intentionally mounted
//! *outside* both middleware layers — it has no envelope to verify
//! and no peer state to consult.
//!
//! [`middleware`]: crate::federation::middleware

use std::sync::Arc;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, post};

use crate::AppState;
use crate::federation::middleware::{verify_bootstrap, verify_known_peer};
use crate::federation::{frontier, identity, peering};

/// Build the `/federation/v1/*` subrouter.
///
/// Returned `Router` is `with_state`-bound to the supplied
/// `AppState`, so `build_app` can `.merge()` it directly into the
/// app-level router without re-supplying state.
pub fn federation_router(state: Arc<AppState>) -> Router {
    // Bootstrap-mode sub-router: §5.4 handshake POSTs. The verifier
    // skips its step-5 peers lookup; each handler enforces the
    // `envelope.sender == body.pubkey` self-consistency check itself.
    let bootstrap = Router::new()
        .route(
            "/federation/v1/peer-request",
            post(peering::handle_peer_request),
        )
        .route(
            "/federation/v1/peer-response",
            post(peering::handle_peer_response),
        )
        .layer(from_fn_with_state(state.clone(), verify_bootstrap));

    // KnownPeer-mode sub-router: every other authenticated route.
    // The verifier requires `envelope.sender` to be in
    // `peers WHERE status = 'active'`.
    let known_peer = Router::new()
        .route("/federation/v1/peers", get(peering::handle_peers_list))
        .route(
            "/federation/v1/peer-relationship",
            delete(peering::handle_peer_relationship_delete),
        )
        // §8 frontier sync: announce / delta / GET all sit behind the
        // KnownPeer envelope verifier per §8 ("only an active peer
        // may push or pull a frontier"). The GET is peers-only by
        // default — we don't expose our own frontier to anonymous
        // callers, since it materially leaks the local trust graph.
        .route(
            "/federation/v1/frontier/announce",
            post(frontier::handle_frontier_announce),
        )
        .route(
            "/federation/v1/frontier/delta",
            post(frontier::handle_frontier_delta),
        )
        .route(
            "/federation/v1/frontier",
            get(frontier::handle_frontier_get),
        )
        .layer(from_fn_with_state(state.clone(), verify_known_peer));

    // Unauthenticated route(s) live outside both middleware layers.
    Router::new()
        .route("/federation/v1/identity", get(identity::get_identity))
        .merge(bootstrap)
        .merge(known_peer)
        .with_state(state)
}
