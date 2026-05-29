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

use super::test_app_with_pool_transport_domain_and_outbound_config;

/// Shared `PeerId -> Router` registry. Every `InProcessTransport`
/// instantiated by the same [`MultiInstanceHarness`] points at the
/// same `Arc`, so registering instance B is immediately visible to
/// instance A's transport (no setup step beyond `harness.spawn`).
type Registry = Arc<RwLock<HashMap<PeerId, Router>>>;

/// Shared `instance_domain -> PeerId` map, populated at `spawn` time
/// alongside the [`Registry`]. Lets [`InProcessTransport::fetch_identity`]
/// resolve an operator-typed domain (the `preview` flow reaches a
/// non-peer instance, so it can't go through the peers table) to the
/// right peer router without a real DNS/HTTP round-trip.
type DomainMap = Arc<RwLock<HashMap<String, PeerId>>>;

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
    domains: DomainMap,
}

impl InProcessTransport {
    /// Build a transport that resolves peers against `registry` (by
    /// [`PeerId`]) and `domains` (by `instance_domain`, for the
    /// unauthenticated identity probe).
    pub fn new(registry: Registry, domains: DomainMap) -> Self {
        Self { registry, domains }
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

    fn fetch_identity<'a>(&'a self, domain: &'a str) -> TransportFuture<'a> {
        let registry = self.registry.clone();
        let domains = self.domains.clone();
        let domain = domain.to_string();
        Box::pin(async move {
            // Resolve domain -> PeerId -> Router, then issue the same
            // unauthenticated GET the production transport would.
            let router = {
                let peer_id = {
                    let guard = domains.read().await;
                    guard
                        .get(&domain)
                        .copied()
                        .ok_or(TransportError::Dispatch("connect"))?
                };
                let guard = registry.read().await;
                guard
                    .get(&peer_id)
                    .cloned()
                    .ok_or(TransportError::Dispatch("connect"))?
            };
            let req = Request::builder()
                .method(Method::GET)
                .uri("/federation/v1/identity")
                .body(Body::empty())
                .expect("identity probe request build");
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
    domains: DomainMap,
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
        let domains: DomainMap = Arc::new(RwLock::new(HashMap::new()));
        let mut harness = MultiInstanceHarness {
            instances: HashMap::new(),
            registry,
            domains,
        };
        for i in 0..n {
            let label = char::from(b'a' + i as u8).to_string();
            harness.spawn(&label).await;
        }
        harness
    }

    /// As [`Self::new`], but every instance is built with the supplied
    /// [`OutboundQueueConfig`](prismoire_server::federation::outbound_queue::OutboundQueueConfig)
    /// instead of `test_fast()`'s prod-shaped defaults. Used by Phase
    /// 6.4.1 tests that need shrunken caps to exercise the §7.5
    /// eviction path within a reasonable test runtime.
    pub async fn new_with_outbound_config(
        n: usize,
        outbound_config: prismoire_server::federation::outbound_queue::OutboundQueueConfig,
    ) -> Self {
        assert!(
            n <= 26,
            "MultiInstanceHarness supports up to 26 labelled instances, got {n}"
        );
        let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
        let domains: DomainMap = Arc::new(RwLock::new(HashMap::new()));
        let mut harness = MultiInstanceHarness {
            instances: HashMap::new(),
            registry,
            domains,
        };
        for i in 0..n {
            let label = char::from(b'a' + i as u8).to_string();
            harness
                .spawn_with_outbound_config(&label, outbound_config.clone())
                .await;
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
        let cfg = prismoire_server::federation::outbound_queue::OutboundQueueConfig::test_fast();
        self.spawn_with_outbound_config(label, cfg).await
    }

    /// As [`Self::spawn`] but with a caller-supplied
    /// [`OutboundQueueConfig`](prismoire_server::federation::outbound_queue::OutboundQueueConfig).
    /// Used by Phase 6.4.1 tests that mix shrunken-cap and
    /// default-cap instances in the same harness — most tests should
    /// keep using `spawn` or `new_with_outbound_config`.
    pub async fn spawn_with_outbound_config(
        &mut self,
        label: &str,
        outbound_config: prismoire_server::federation::outbound_queue::OutboundQueueConfig,
    ) -> &InstanceHandle {
        self.spawn_with_outbound_config_and_transport(label, outbound_config, |t| t)
            .await
    }

    /// Most flexible spawn: caller supplies an
    /// [`OutboundQueueConfig`](prismoire_server::federation::outbound_queue::OutboundQueueConfig)
    /// *and* a wrap-closure that may decorate the default
    /// [`InProcessTransport`] (e.g. via [`FlakeyTransport`]). Used by
    /// the Layer-1 backoff test in Phase 6.4.1.
    ///
    /// The wrap-closure receives the bare `Arc<dyn FederationTransport>`
    /// that points at the shared registry; whatever it returns becomes
    /// the `AppState.federation_transport` for the new instance.
    /// `InstanceHandle.transport` still exposes the bare
    /// `Arc<InProcessTransport>` so test fixture helpers
    /// (`send_envelope_signed`, etc.) bypass any decorator and talk
    /// straight to the peer router.
    pub async fn spawn_with_outbound_config_and_transport<F>(
        &mut self,
        label: &str,
        outbound_config: prismoire_server::federation::outbound_queue::OutboundQueueConfig,
        wrap_transport: F,
    ) -> &InstanceHandle
    where
        F: FnOnce(Arc<dyn FederationTransport>) -> Arc<dyn FederationTransport>,
    {
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
        let base_transport: Arc<dyn FederationTransport> = Arc::new(InProcessTransport::new(
            self.registry.clone(),
            self.domains.clone(),
        ));
        let transport = wrap_transport(base_transport);
        // Per-label domain so harness scenarios with N ≥ 3 instances
        // don't collide on the `peers.instance_domain` UNIQUE constraint.
        let domain = format!("{label}.test.local");
        let pool = super::fresh_db().await;
        let (router, state) = test_app_with_pool_transport_domain_and_outbound_config(
            pool,
            transport.clone(),
            &domain,
            outbound_config,
        )
        .await;

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
        let concrete_transport = Arc::new(InProcessTransport::new(
            self.registry.clone(),
            self.domains.clone(),
        ));

        self.registry.write().await.insert(peer_id, router.clone());
        self.domains.write().await.insert(domain.clone(), peer_id);

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

    /// Remove the instance's router from the shared transport
    /// registry. The instance itself stays alive (its `AppState`,
    /// router, and DB are still reachable from the test) but any
    /// outbound transport call targeting it now returns
    /// [`TransportError::UnknownPeer`]. Used by Phase 6.4 tests to
    /// simulate a peer going offline mid-fanout. See [`reconnect`].
    pub async fn disconnect(&self, label: &str) {
        let h = self
            .instances
            .get(label)
            .unwrap_or_else(|| panic!("no harness instance labelled {label:?}"));
        self.registry.write().await.remove(&h.peer_id);
    }

    /// Re-register a previously-disconnected instance's router with
    /// the shared transport registry. Idempotent: re-inserting an
    /// already-present entry just overwrites the router handle (same
    /// `Router` Arc).
    pub async fn reconnect(&self, label: &str) {
        let h = self
            .instances
            .get(label)
            .unwrap_or_else(|| panic!("no harness instance labelled {label:?}"));
        self.registry
            .write()
            .await
            .insert(h.peer_id, h.router.clone());
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

/// Shared script handle for [`FlakeyTransport`]. Tests hold this
/// alongside the harness so they can push scripted statuses *after*
/// the active-peering handshake has completed cleanly — wrapping the
/// transport with a queue of 503s up front would also break the
/// handshake calls, which is rarely what the test is asking about.
#[derive(Default, Clone)]
pub struct FlakeyScript(Arc<std::sync::Mutex<std::collections::VecDeque<http::StatusCode>>>);

impl FlakeyScript {
    /// Push a status to the back of the FIFO. The next call through
    /// the wrapped [`FlakeyTransport`] returns this status (with an
    /// empty body) instead of dispatching to the inner transport.
    pub fn push(&self, status: http::StatusCode) {
        self.0.lock().expect("script mutex").push_back(status);
    }

    /// Push N copies of `status` for the next N calls. Convenience
    /// for backoff scenarios that want a run of 503s.
    pub fn push_n(&self, n: usize, status: http::StatusCode) {
        let mut q = self.0.lock().expect("script mutex");
        for _ in 0..n {
            q.push_back(status);
        }
    }

    /// How many scripted statuses are still pending. Tests use this
    /// to assert that all scripted failures were consumed (i.e. the
    /// worker actually retried that many times).
    pub fn remaining(&self) -> usize {
        self.0.lock().expect("script mutex").len()
    }
}

/// Decorator that wraps any [`FederationTransport`] and returns a
/// pre-programmed sequence of status codes (with empty bodies) before
/// falling through to the inner transport.
///
/// Use this to inject transient failures into a Layer-1 scenario
/// without touching the production retry path: push 503, 503 onto the
/// [`FlakeyScript`] and the next two drain attempts return 503; the
/// third proxies through to the real `InProcessTransport`.
///
/// The script is empty by default — handshake calls and other
/// preconditions proxy through cleanly. Tests push statuses only when
/// they want a transient-failure burst.
pub struct FlakeyTransport {
    inner: Arc<dyn FederationTransport>,
    script: FlakeyScript,
}

impl FlakeyTransport {
    /// Wrap `inner` with an initially-empty script. Returns the
    /// transport and a clone of the script handle so the test can
    /// push scripted statuses at the moment the scenario calls for
    /// them.
    pub fn new(inner: Arc<dyn FederationTransport>) -> (Self, FlakeyScript) {
        let script = FlakeyScript::default();
        (
            Self {
                inner,
                script: script.clone(),
            },
            script,
        )
    }
}

impl FederationTransport for FlakeyTransport {
    fn request<'a>(&'a self, target: &'a PeerId, request: Request<Bytes>) -> TransportFuture<'a> {
        let scripted = self.script.0.lock().expect("script mutex").pop_front();
        if let Some(status) = scripted {
            return Box::pin(async move {
                Ok(http::Response::builder()
                    .status(status)
                    .body(Bytes::new())
                    .expect("response build"))
            });
        }
        self.inner.request(target, request)
    }

    fn fetch_identity<'a>(&'a self, domain: &'a str) -> TransportFuture<'a> {
        // The script only models the retry path for envelope dispatch;
        // identity probes proxy straight through to the inner transport.
        self.inner.fetch_identity(domain)
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
