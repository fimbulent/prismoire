//! Federation subsystem.
//!
//! This module is the eventual home for every piece of wire-protocol
//! code: signed-class verifiers and dispatchers, the envelope-auth
//! middleware (§6), the frontier/Bloom routing primitives (§7, §8),
//! and the per-route handlers (`/federation/v1/...`).
//!
//! **Phase 1 scope.** Only the foundation lives here today: the
//! [`transport::FederationTransport`] trait that abstracts "how does
//! this instance's outbound HTTP reach a peer's router". The trait
//! exists so Layer-1 integration tests (see
//! `docs/federation-impl-plan.md` §1) can spin up N `AppState`s in a
//! single process and route requests between them via a direct
//! [`tower::ServiceExt::oneshot`] dispatch — no sockets, no TLS, no
//! `reqwest` — while production wiring uses a real HTTP client
//! against the same trait. Subsequent phases add identity/handshake
//! (Phase 2), envelope auth (Phase 3), frontier sync (Phase 4),
//! etc., each mounting routes under a dedicated `/federation/v1`
//! subrouter that `build_app` will eventually merge alongside `/api`.
//!
//! Phase 2 mounts the first wire surface: a `/federation/v1`
//! subrouter assembled by [`router::federation_router`] and merged
//! into the main Axum app in `crate::lib::build_app`. The §5
//! identity card and §5.4 handshake handlers live in
//! [`identity`] and [`peering`]; envelope sign / verify helpers
//! live in [`envelope`]; the per-instance signing-key vault sits
//! in [`instance_key`]. Later phases extend (envelope-auth
//! middleware, frontier sync, content propagation, …) rather than
//! reshaping these foundations.

pub mod admin_rm;
pub mod attachment_cache;
pub mod attachments;
pub mod backfill;
pub mod backfill_rate_limit;
pub mod bloom;
pub mod content;
pub mod content_rate_limit;
pub mod domain;
pub mod edge_backfill;
pub mod edges;
pub mod envelope;
pub mod errors;
pub mod forwarder;
pub mod frontier;
pub mod identity;
pub mod instance_key;
pub mod middleware;
pub mod moves;
pub mod outbound_queue;
pub mod peering;
pub mod registration;
pub mod remote_users;
pub mod router;
pub mod routing;
pub mod transport;
