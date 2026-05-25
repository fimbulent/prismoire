//! Phase-1 self-test for [`common::federation::MultiInstanceHarness`].
//!
//! This file is the "harness sanity check" called out as the
//! Layer-1 meta gate in `docs/federation-impl-plan.md` §Phase 1:
//! it does not exercise any federation protocol surface (there
//! isn't one yet), it just proves the harness can stand up two
//! independent `AppState`s and route a trivial request from one
//! to the other through [`FederationTransport`].
//!
//! Every subsequent phase's Layer-1 tests build on this same
//! harness; if this file ever goes red the rest of the federation
//! test pyramid is meaningless.

mod common;

use axum::body::Bytes;
use http::{Method, Request, StatusCode};
use prismoire_server::federation::transport::{FederationTransport, PeerId};

use common::federation::MultiInstanceHarness;

#[tokio::test]
async fn harness_stands_up_two_instances() {
    let harness = MultiInstanceHarness::new(2).await;
    assert_eq!(harness.len(), 2);
    // Distinct identities. If two instances ever shared a PeerId,
    // the registry would silently overwrite one with the other and
    // every later "A talks to B" scenario would actually be talking
    // to itself.
    assert_ne!(harness.instance("a").peer_id, harness.instance("b").peer_id,);
}

#[tokio::test]
async fn transport_routes_request_between_instances() {
    let harness = MultiInstanceHarness::new(2).await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // `/api/health` is the smallest reachable endpoint: GET, no
    // auth, no setup-guard, no rate limit, no CSRF check. Perfect
    // ping target for the transport itself — if this round-trips
    // we know the registry lookup, request-body conversion, router
    // dispatch, and response-body collection are all wired up
    // before any actual federation route exists.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/health")
        .body(Bytes::new())
        .expect("build request");

    let response = a
        .transport
        .request(&b.peer_id, req)
        .await
        .expect("in-process transport dispatch");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body().as_ref(), b"ok");
}

#[tokio::test]
async fn transport_rejects_unknown_peer() {
    let harness = MultiInstanceHarness::new(1).await;
    let a = harness.instance("a");

    // Address a PeerId that was never registered. Production code
    // will eventually need to distinguish "I have no peer record
    // for this id" from "I have one but the peer is unreachable";
    // Phase 1's coarse `UnknownPeer` is enough for the harness
    // sanity gate, and later phases can refine the error split.
    let stranger = PeerId::from_bytes([0xff; 32]);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/health")
        .body(Bytes::new())
        .expect("build request");

    let err = a
        .transport
        .request(&stranger, req)
        .await
        .expect_err("unknown peer must fail, not panic");
    let rendered = format!("{err}");
    assert!(
        rendered.contains(&format!("{stranger}")),
        "error should name the missing peer; got {rendered}"
    );
}
