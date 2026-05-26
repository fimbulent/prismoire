//! Multi-instance test harness for Layer-1 federation tests.
//!
//! The contract is the one set out in `docs/federation-impl-plan.md`
//! §Phase 1: stand up N independent `AppState`s sharing nothing,
//! register each one in a shared `PeerId -> Router` map, and let
//! every instance reach every other instance through the
//! [`FederationTransport`] trait — no sockets, no TLS, just a direct
//! `tower::ServiceExt::oneshot` dispatch into the peer's `Router`.
//!
//! Tests use this harness to express scenarios like "A pushes an
//! edge to B, B forwards to C, all three converge". Each
//! `InstanceHandle` exposes the raw `Router` (so existing
//! `common::send` / `json_request` helpers still apply) plus the
//! `transport` that handlers will eventually take from `AppState`.
//!
//! Helpers (`advance_gossip`, `assert_converged`, …) called out in
//! the plan land in this file as the phases that need them come up;
//! Phase 1 only requires `new`, `instance`, and direct transport
//! access to validate the ping/pong sanity test.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use http::{Request, Response};
use http_body_util::BodyExt;
use prismoire_server::AppState;
use prismoire_server::federation::transport::{
    FederationTransport, PeerId, TransportError, TransportFuture,
};
use tokio::sync::RwLock;
use tower::ServiceExt;

use super::test_app_with_transport_and_domain;

/// Shared `PeerId -> Router` registry. Every `InProcessTransport`
/// instantiated by the same [`MultiInstanceHarness`] points at the
/// same `Arc`, so registering instance B is immediately visible to
/// instance A's transport (no setup step beyond `harness.spawn`).
type Registry = Arc<RwLock<HashMap<PeerId, Router>>>;

/// In-process implementation of [`FederationTransport`].
///
/// Looks the target peer up in the shared [`Registry`], converts the
/// inbound `Request<Bytes>` to the `Request<Body>` shape that
/// `tower::ServiceExt::oneshot` wants, dispatches against the peer's
/// `Router`, then materialises the response body back into `Bytes`
/// so the caller sees a fully-buffered `Response<Bytes>` — same
/// shape it would get from a `reqwest` round-trip.
///
/// Unknown peers surface as [`TransportError::UnknownPeer`] rather
/// than panicking, so negative tests ("A tries to talk to a peer it
/// hasn't accepted yet") can assert on the error without
/// special-casing.
pub struct InProcessTransport {
    registry: Registry,
}

impl InProcessTransport {
    /// Build a transport that resolves peers against `registry`.
    pub fn new(registry: Registry) -> Self {
        Self { registry }
    }
}

impl FederationTransport for InProcessTransport {
    fn request<'a>(&'a self, target: &'a PeerId, request: Request<Bytes>) -> TransportFuture<'a> {
        let registry = self.registry.clone();
        let target = *target;
        Box::pin(async move {
            // Snapshot the router under the read lock, then drop the
            // guard before awaiting `oneshot` — holding it across the
            // dispatch would serialise the entire harness.
            let router = {
                let guard = registry.read().await;
                guard
                    .get(&target)
                    .cloned()
                    .ok_or(TransportError::UnknownPeer(target))?
            };
            let (parts, body) = request.into_parts();
            let req = Request::from_parts(parts, Body::from(body));
            let response = router
                .oneshot(req)
                .await
                .map_err(|_| TransportError::Dispatch("other"))?;
            let (parts, body) = response.into_parts();
            let bytes = body
                .collect()
                .await
                .map_err(|_| TransportError::Dispatch("body"))?
                .to_bytes();
            Ok(Response::from_parts(parts, bytes))
        })
    }
}

/// Everything tests need to drive one instance: its identity, its
/// `AppState` (for direct DB / trust-graph fixture setup), its
/// `Router` (for reusing the existing `common::send` helpers), and
/// its outbound `transport` (for issuing federation requests at the
/// peer-Router layer the way production code will).
pub struct InstanceHandle {
    /// Stable identifier — what other instances address this one by.
    pub peer_id: PeerId,
    /// Human-readable label (`"a"`, `"b"`, …) used by `instance()`.
    pub label: String,
    /// Shared `AppState`, same handle every instance helper holds.
    pub state: Arc<AppState>,
    /// The full Axum router, ready for `tower::ServiceExt::oneshot`
    /// or the existing `common::send` wrapper.
    pub router: Router,
    /// Outbound transport. Same shared registry as every other
    /// instance in the harness.
    pub transport: Arc<InProcessTransport>,
}

/// N independent `AppState`s + Routers wired together via a shared
/// in-process transport registry.
///
/// `MultiInstanceHarness::new(n)` returns a harness with `n`
/// instances labelled `"a"`, `"b"`, … (up to 26). Use `instance(...)`
/// to look one up; use `spawn(...)` to add a late-joining instance
/// (Phase 8 partition-heal scenarios will want this).
pub struct MultiInstanceHarness {
    instances: HashMap<String, InstanceHandle>,
    registry: Registry,
}

impl MultiInstanceHarness {
    /// Spin up `n` instances, labelled `"a"..="z"`.
    ///
    /// Panics if `n > 26`: that's well past the size any reasonable
    /// Layer-1 scenario should need, and giving a clean panic now
    /// beats discovering a duplicate-key collision in the registry
    /// at the 27th instance.
    pub async fn new(n: usize) -> Self {
        assert!(
            n <= 26,
            "MultiInstanceHarness supports up to 26 labelled instances, got {n}"
        );
        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let mut harness = MultiInstanceHarness {
            instances: HashMap::new(),
            registry,
        };
        for i in 0..n {
            let label = char::from(b'a' + i as u8).to_string();
            harness.spawn(&label).await;
        }
        harness
    }

    /// Add a single instance to the harness under `label`.
    ///
    /// The new instance is immediately reachable from every existing
    /// instance's transport (they share the registry). Panics if
    /// `label` is already in use — the harness is small enough that
    /// re-using a label is almost always a test bug.
    pub async fn spawn(&mut self, label: &str) -> &InstanceHandle {
        assert!(
            !self.instances.contains_key(label),
            "harness already has an instance labelled {label:?}"
        );

        // Phase 2 wires the transport into `AppState` *before* the
        // app is built, so handlers (and the operator-initiation
        // helpers in `federation::peering`) can dispatch outbound
        // calls via the shared registry. Each instance gets its own
        // `Arc<InProcessTransport>` wrapper but they all point at the
        // single shared `Registry`, so registering instance B
        // immediately makes B reachable from A's transport.
        let transport: Arc<dyn FederationTransport> =
            Arc::new(InProcessTransport::new(self.registry.clone()));
        // Per-label domain so harness scenarios with N ≥ 3 instances
        // don't collide on the `peers.instance_domain` UNIQUE constraint.
        let domain = format!("{label}.test.local");
        let (router, state) = test_app_with_transport_and_domain(transport.clone(), &domain).await;

        // Peer id == this instance's Ed25519 signing pubkey, as the
        // production transport will eventually use. The state's
        // `instance_key` was generated at `test_app_with_transport`
        // time; we just extract its public half here.
        let peer_id = PeerId::from_bytes(*state.instance_key.public_bytes());

        // Down-cast the `Arc<dyn ...>` into `Arc<InProcessTransport>`
        // for the `InstanceHandle.transport` field. We hold a single
        // shared `Arc` so the `with_state` clone in `test_app_with_transport`
        // and the harness's own handle point at the same underlying
        // `InProcessTransport`.
        let concrete_transport = Arc::new(InProcessTransport::new(self.registry.clone()));

        self.registry.write().await.insert(peer_id, router.clone());

        let handle = InstanceHandle {
            peer_id,
            label: label.to_string(),
            state,
            router,
            transport: concrete_transport,
        };
        self.instances.insert(label.to_string(), handle);
        self.instances.get(label).expect("just inserted")
    }

    /// Borrow the instance registered under `label`. Panics on miss
    /// because every Layer-1 test knows statically which labels it
    /// created — recovering from a typo here is never useful.
    pub fn instance(&self, label: &str) -> &InstanceHandle {
        self.instances
            .get(label)
            .unwrap_or_else(|| panic!("no harness instance labelled {label:?}"))
    }

    /// How many instances are currently registered.
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Whether the harness is empty. Mostly here so clippy doesn't
    /// complain about `len` without `is_empty`.
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Envelope-signed dispatch helpers
//
// Reused by phase5+ tests. Phase 4 still keeps its own near-identical
// copies (they predate this extraction); a future cleanup pass can
// fold those into these. The single source of truth here covers every
// new federation handler integration test.
// ---------------------------------------------------------------------------

use http::Method;
use prismoire_server::federation::envelope;
use prismoire_server::federation::identity::CBOR_CONTENT_TYPE;
use prismoire_server::federation::peering::{
    operator_accept_peer_request, operator_initiate_peer_request,
};

/// Drive A through the §5.4 initiate → B accepts dance so a test
/// starts from "mutual active peering" — the precondition for any
/// `verify_known_peer` route. Mirrors the phase4 helper but lives in
/// common so new test crates don't each copy it.
pub async fn establish_active_peering(
    harness: &MultiInstanceHarness,
    initiator: &str,
    target: &str,
) {
    let i = harness.instance(initiator);
    let t = harness.instance(target);
    let i_transport: Arc<dyn FederationTransport> = i.transport.clone();
    let request_id = operator_initiate_peer_request(
        &i.state.db,
        &i.state.instance_key,
        &i.state.instance_domain,
        &i_transport,
        *t.state.instance_key.public_bytes(),
        &t.state.instance_domain,
        vec!["edge-sync".into(), "content-sync".into()],
        None,
    )
    .await
    .expect("operator_initiate_peer_request");
    let t_transport: Arc<dyn FederationTransport> = t.transport.clone();
    operator_accept_peer_request(
        &t.state.db,
        &t.state.instance_key,
        &t.state.instance_domain,
        &t_transport,
        request_id,
    )
    .await
    .expect("operator_accept_peer_request");
}

/// Sign an envelope from `from` to `to`, dispatch via the shared
/// transport, and return `(status, body_bytes)`. Mirrors phase4's
/// private helper; lifted here so phase5+ can share it.
pub async fn send_envelope_signed(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    method: Method,
    path: &str,
    body: &[u8],
) -> (http::StatusCode, Vec<u8>) {
    send_envelope_signed_split(harness, from, to, method, path, path, body).await
}

/// Like [`send_envelope_signed`] but lets the caller sign over one
/// path and dispatch against a different URI. The split is needed for
/// GET routes that take query parameters: §6.5 step 9 normalises the
/// signed path to `req.uri().path()` (no query), but the dispatched
/// URI must carry the query so the handler's `Query` extractor sees it.
pub async fn send_envelope_signed_split(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    method: Method,
    signed_path: &str,
    dispatch_uri: &str,
    body: &[u8],
) -> (http::StatusCode, Vec<u8>) {
    let from_h = harness.instance(from);
    let to_h = harness.instance(to);

    let header = envelope::sign_outbound(
        &from_h.state.instance_key,
        *to_h.state.instance_key.public_bytes(),
        &method,
        signed_path,
        body,
    );

    let mut builder = http::Request::builder()
        .method(method.clone())
        .uri(dispatch_uri)
        .header(envelope::AUTH_HEADER, header);
    if method == Method::POST {
        builder = builder.header(http::header::CONTENT_TYPE, CBOR_CONTENT_TYPE);
    }
    let req = builder
        .body(Bytes::from(body.to_vec()))
        .expect("build request");

    let response = from_h
        .transport
        .request(
            &PeerId::from_bytes(*to_h.state.instance_key.public_bytes()),
            req,
        )
        .await
        .expect("transport dispatch");
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body().into(), usize::MAX)
        .await
        .expect("body bytes")
        .to_vec();
    (status, body_bytes)
}
