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
//! No routes are mounted yet.

pub mod transport;
