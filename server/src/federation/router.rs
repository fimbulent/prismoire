//! Assembly of the `/federation/v1/*` subrouter.
//!
//! Mounted by `build_app` alongside the existing `/api` surface.
//! Phase 2 ships three routes:
//!
//! - `GET  /federation/v1/identity`      (§5.2; unauthenticated)
//! - `POST /federation/v1/peer-request`  (§5.4; bootstrap-verified)
//! - `POST /federation/v1/peer-response` (§5.4; envelope-verified)
//!
//! All envelope handling and §6.5 verification lives inside the
//! handlers themselves for now. Phase 3 will lift those checks
//! into a router-wide middleware so handlers can drop the
//! per-call-site verify glue; the route table here is what the
//! middleware will eventually wrap.

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::AppState;
use crate::federation::{identity, peering};

/// Build the `/federation/v1/*` subrouter.
///
/// Returned `Router` is `with_state`-bound to the supplied
/// `AppState`, so `build_app` can `.merge()` it directly into the
/// app-level router without re-supplying state.
pub fn federation_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/federation/v1/identity", get(identity::get_identity))
        .route(
            "/federation/v1/peer-request",
            post(peering::handle_peer_request),
        )
        .route(
            "/federation/v1/peer-response",
            post(peering::handle_peer_response),
        )
        .with_state(state)
}
