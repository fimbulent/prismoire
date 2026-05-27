//! Assembly of the `/federation/v1/*` subrouter.
//!
//! Mounted by `build_app` alongside the existing `/api` surface.
//! The router groups every federation route into one of three trust
//! tiers; the live route table lives in [`federation_router`] below
//! (see the `.route(...)` calls), with §-references back to
//! `docs/federation-protocol.md` next to each entry. New phases add
//! routes to the appropriate sub-router rather than introducing a
//! new tier:
//!
//! - **Unauthenticated** — only `GET /federation/v1/identity` (§5.2).
//!   No envelope, no peer state.
//! - **Bootstrap** — the §5.4 handshake POSTs. Sender is not yet in
//!   `peers WHERE status = 'active'`; the verifier skips its step-5
//!   peers lookup and each handler enforces
//!   `envelope.sender == body.pubkey` itself.
//! - **KnownPeer** — every other authenticated route (§5 peers list,
//!   §8 frontier sync, §9 edges push / chain-continuity backfill,
//!   and the routes future phases add — content push, admin-rm
//!   reports, attachments, etc.). The verifier requires
//!   `envelope.sender` to be in `peers WHERE status = 'active'` and
//!   collapses an unknown sender to `401 unauthorized` on the wire.
//!
//! The §6.5 13-step envelope verifier is applied by the [`middleware`]
//! layer rather than inline in each handler. The Bootstrap and
//! KnownPeer sub-routers wrap the verifier in their respective
//! modes (`verify_bootstrap` / `verify_known_peer`) and are then
//! merged with the unauthenticated identity route. The unauthenticated
//! route is intentionally mounted *outside* both middleware layers —
//! it has no envelope to verify and no peer state to consult.
//!
//! [`middleware`]: crate::federation::middleware

use std::sync::Arc;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, post};

use crate::AppState;
use crate::federation::middleware::{verify_bootstrap, verify_known_peer};
use crate::federation::{admin_rm, backfill, content, edges, frontier, identity, moves, peering};

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
        // §9.1 edge propagation push. KnownPeer-gated per §6 — only
        // active peers may push edges. Per-edge results in §9.1's
        // `{ canonical_hash, status, reason? }` shape; request-level
        // errors (malformed, empty_batch, batch_too_large) collapse
        // to a 400 with a single `{ "error": ... }` body.
        .route("/federation/v1/edges", post(edges::handle_edges_push))
        // §9.3 chain-continuity backfill — the narrow per-pair pull
        // route, sibling to the §9.1 push above. Phase 8 will add the
        // broader §10.5 bulk routes (`/backfill/by-hash`,
        // `/backfill/by-author`); both ride this same KnownPeer layer.
        .route(
            "/federation/v1/edges/backfill",
            get(backfill::handle_edges_backfill),
        )
        // §10.1 content push: the 6 inner signed classes (post-rev,
        // retract, admin-rm, profile, thread-create, deactivate)
        // batch-pushed by an author's home or by a forwarder along
        // the §7 routing fan-out. Per-object results follow the §10.1
        // `{ canonical_hash, status, reason? }` shape.
        .route("/federation/v1/content", post(content::handle_content_push))
        // §10.4 admin-rm advisory channel: a single signed `admin-rm`
        // from a non-home moderator, reporting a post hosted by us.
        // No propagation; queued for operator review.
        .route(
            "/federation/v1/admin-rm-report",
            post(admin_rm::handle_admin_rm_report),
        )
        // §12.1 move push: a batch of signed `move` declarations
        // pushed by the moving identity's home or by a forwarder along
        // the §12.2 unconditional-flood fanout. Per-object results
        // follow `{ canonical_hash, status, reason? }` with status in
        // `applied | duplicate | deferred | superseded | rejected`.
        .route("/federation/v1/moves", post(moves::handle_moves_push))
        // §12.3 move chain-continuity backfill — narrow per-key pull
        // so a receiver can fill a `deferred` gap by asking the home
        // for ancestors of an unresolved `prior_move_hash`.
        .route(
            "/federation/v1/moves/backfill",
            get(backfill::handle_moves_backfill),
        )
        .layer(from_fn_with_state(state.clone(), verify_known_peer));

    // Unauthenticated route(s) live outside both middleware layers.
    Router::new()
        .route("/federation/v1/identity", get(identity::get_identity))
        .merge(bootstrap)
        .merge(known_peer)
        .with_state(state)
}
