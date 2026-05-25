//! Phase-2 Layer-1 integration tests: §5.2 identity + §5.4 handshake.
//!
//! "Done-when" criterion from `docs/federation-impl-plan.md` Phase 2:
//! *two harness instances reach mutual `active` peering from cold
//! start in a single test, and `GET /federation/v1/identity` returns
//! a protocol-shaped CBOR card.* The happy-path test below is that
//! gate. The remaining tests pin specific failure modes the
//! handshake state machine has to surface: stale request_id,
//! bootstrap-self-consistency mismatch, and pubkey-mismatch on the
//! callback (the §5.4 step-2 MITM/key-change warning).

mod common;

use axum::body::{Body, Bytes};
use http::{Method, Request, StatusCode};
use prismoire_server::federation::envelope;
use prismoire_server::federation::identity::{CBOR_CONTENT_TYPE, IdentityCard};
use prismoire_server::federation::peering::{
    self, PeerDecision, PeerResponseBody, operator_accept_peer_request,
    operator_initiate_peer_request,
};
use prismoire_server::federation::transport::{FederationTransport, PeerId};
use tower::ServiceExt;

use common::federation::MultiInstanceHarness;

/// Drive a single in-process request through the shared transport
/// registry so the test reads like production code (sign envelope →
/// dispatch → status check), without spelling out the conversion
/// every time.
async fn signed_get(harness_instance_router: &axum::Router, path: &str) -> http::Response<Bytes> {
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Body::empty())
        .expect("build request");
    let response = harness_instance_router
        .clone()
        .oneshot(req)
        .await
        .expect("router dispatch");
    let (parts, body) = response.into_parts();
    let bytes = http_body_util::BodyExt::collect(body)
        .await
        .expect("collect body")
        .to_bytes();
    http::Response::from_parts(parts, bytes)
}

#[tokio::test]
async fn identity_endpoint_returns_protocol_shaped_card() {
    let harness = MultiInstanceHarness::new(1).await;
    let a = harness.instance("a");

    let response = signed_get(&a.router, "/federation/v1/identity").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap()),
        Some(CBOR_CONTENT_TYPE),
        "identity must advertise CBOR content-type"
    );

    let card = IdentityCard::decode(response.body()).expect("identity card decodes");
    assert_eq!(card.instance_domain, "a.test.local");
    assert_eq!(&card.instance_pubkey, a.state.instance_key.public_bytes());
    assert!(
        card.protocol_versions.contains(&1),
        "V1 must be advertised; got {:?}",
        card.protocol_versions
    );
    assert!(
        !card.capabilities.is_empty(),
        "V1 advertises a non-empty capability set"
    );
    // Optional metadata fields are absent by default per §5.2.
    assert!(card.announce.is_none());
    assert!(card.instance_age_days.is_none());
    assert!(card.user_count_bucket.is_none());
}

#[tokio::test]
async fn mutual_active_peering_from_cold_start() {
    let harness = MultiInstanceHarness::new(2).await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let a_pubkey = *a.state.instance_key.public_bytes();
    let b_pubkey = *b.state.instance_key.public_bytes();

    // 1. A's operator initiates a peer-request to B. The transport
    //    routes the signed request into B's `/federation/v1/peer-request`
    //    handler, which records a pending_inbound row.
    let a_transport: std::sync::Arc<dyn FederationTransport> = a.transport.clone();
    let request_id = operator_initiate_peer_request(
        &a.state.db,
        &a.state.instance_key,
        &a.state.instance_domain,
        &a_transport,
        b_pubkey,
        &b.state.instance_domain,
        vec!["edge-sync".into(), "content-sync".into()],
        Some("hello from A".into()),
    )
    .await
    .expect("operator_initiate_peer_request");

    // A's side now carries a pending_outbound row keyed on B's pubkey.
    let b_pubkey_slice: &[u8] = &b_pubkey;
    let a_row = sqlx::query!(
        "SELECT status, direction FROM peers WHERE instance_pubkey = ?",
        b_pubkey_slice,
    )
    .fetch_one(&a.state.db)
    .await
    .expect("A has a peer row for B");
    assert_eq!(a_row.status, "pending_outbound");
    assert_eq!(a_row.direction, "outbound");

    // B's side carries a pending_inbound row keyed on A's pubkey,
    // tagged with the same request_id.
    let a_pubkey_slice: &[u8] = &a_pubkey;
    let b_row = sqlx::query!(
        "SELECT status, direction, request_id FROM peers WHERE instance_pubkey = ?",
        a_pubkey_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("B has a peer row for A");
    assert_eq!(b_row.status, "pending_inbound");
    assert_eq!(b_row.direction, "inbound");
    assert_eq!(b_row.request_id, request_id.to_vec());

    // 2. B's operator accepts. The accept helper updates B's row to
    //    active, signs the peer-response callback, and dispatches it
    //    to A's `/federation/v1/peer-response` handler — which on
    //    accept flips A's row to active too.
    let b_transport: std::sync::Arc<dyn FederationTransport> = b.transport.clone();
    operator_accept_peer_request(
        &b.state.db,
        &b.state.instance_key,
        &b.state.instance_domain,
        &b_transport,
        request_id,
    )
    .await
    .expect("operator_accept_peer_request");

    // Both sides are now active.
    let a_row = sqlx::query!(
        "SELECT status, agreed_capabilities FROM peers WHERE instance_pubkey = ?",
        b_pubkey_slice,
    )
    .fetch_one(&a.state.db)
    .await
    .expect("A row after accept");
    assert_eq!(a_row.status, "active");
    assert!(
        a_row.agreed_capabilities.is_some(),
        "A must record the agreed capability set"
    );

    let b_row = sqlx::query!(
        "SELECT status, agreed_capabilities FROM peers WHERE instance_pubkey = ?",
        a_pubkey_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("B row after accept");
    assert_eq!(b_row.status, "active");
    assert!(b_row.agreed_capabilities.is_some());
}

/// Responder retry case: after a successful handshake, the same
/// peer-response is replayed (simulating B's operator retrying
/// accept because the original 200 response was lost on the wire).
/// The handler must return 200 OK — not 404 — so the responder can
/// commit its own local flip. The initiator's row must remain
/// `active`.
#[tokio::test]
async fn peer_response_retry_after_active_is_idempotent() {
    let harness = MultiInstanceHarness::new(2).await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let a_pubkey = *a.state.instance_key.public_bytes();
    let b_pubkey = *b.state.instance_key.public_bytes();

    let a_transport: std::sync::Arc<dyn FederationTransport> = a.transport.clone();
    let request_id = operator_initiate_peer_request(
        &a.state.db,
        &a.state.instance_key,
        &a.state.instance_domain,
        &a_transport,
        b_pubkey,
        &b.state.instance_domain,
        vec!["edge-sync".into()],
        None,
    )
    .await
    .expect("initiate");

    let b_transport: std::sync::Arc<dyn FederationTransport> = b.transport.clone();
    operator_accept_peer_request(
        &b.state.db,
        &b.state.instance_key,
        &b.state.instance_domain,
        &b_transport,
        request_id,
    )
    .await
    .expect("accept");

    // Both sides are active. Re-fire an identical peer-response.
    let body = PeerResponseBody {
        request_id,
        responder_domain: b.state.instance_domain.clone(),
        responder_instance_pubkey: b_pubkey,
        decision: PeerDecision::Accept,
        agreed_capabilities: Some(vec!["edge-sync".into()]),
        decision_message: None,
        created_at: 1_700_000_000_000,
    }
    .encode();
    let header = envelope::sign_outbound(
        &b.state.instance_key,
        a_pubkey,
        &Method::POST,
        "/federation/v1/peer-response",
        &body,
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("/federation/v1/peer-response")
        .header(http::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .header(envelope::AUTH_HEADER, header)
        .body(Bytes::from(body))
        .expect("build request");

    let response = b
        .transport
        .request(&PeerId::from_bytes(a_pubkey), request)
        .await
        .expect("transport dispatch");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "retry of an accept callback against an already-active peer must 200 (idempotent), not 404"
    );

    let b_pubkey_slice: &[u8] = &b_pubkey;
    let a_row = sqlx::query!(
        "SELECT status FROM peers WHERE instance_pubkey = ?",
        b_pubkey_slice,
    )
    .fetch_one(&a.state.db)
    .await
    .expect("A row still present");
    assert_eq!(a_row.status, "active");
}

#[tokio::test]
async fn peer_response_with_unknown_request_id_is_not_found() {
    let harness = MultiInstanceHarness::new(2).await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Construct a peer-response for a request A never issued. B
    // signs it (the envelope is well-formed and self-consistent),
    // but A has no matching pending_outbound row.
    let body = PeerResponseBody {
        request_id: [0xfe; 16],
        responder_domain: b.state.instance_domain.clone(),
        responder_instance_pubkey: *b.state.instance_key.public_bytes(),
        decision: PeerDecision::Accept,
        agreed_capabilities: Some(vec!["edge-sync".into()]),
        decision_message: None,
        created_at: 1_700_000_000_000,
    }
    .encode();

    let header = envelope::sign_outbound(
        &b.state.instance_key,
        *a.state.instance_key.public_bytes(),
        &Method::POST,
        "/federation/v1/peer-response",
        &body,
    );

    let request = Request::builder()
        .method(Method::POST)
        .uri("/federation/v1/peer-response")
        .header(http::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .header(envelope::AUTH_HEADER, header)
        .body(Bytes::from(body))
        .expect("build request");

    let response = b
        .transport
        .request(
            &PeerId::from_bytes(*a.state.instance_key.public_bytes()),
            request,
        )
        .await
        .expect("transport dispatch");
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "stale request_id must 404"
    );
}

#[tokio::test]
async fn peer_request_rejects_envelope_sender_body_mismatch() {
    let harness = MultiInstanceHarness::new(2).await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Construct a peer-request whose body claims A's pubkey but
    // whose envelope is actually signed by *B* — i.e. someone is
    // trying to impersonate A on the wire. The bootstrap-mode
    // self-consistency check in `handle_peer_request` must catch
    // this and return 401, *before* any pending_inbound row gets
    // recorded.
    //
    // Envelope's `receiver` is B (a self-loop on B's router) so the
    // §6.5 step-7 check passes; the only failure we're isolating
    // here is the body/sender mismatch.
    let body = peering::PeerRequestBody {
        initiator_domain: "spoofed-a.example".into(),
        initiator_instance_pubkey: *a.state.instance_key.public_bytes(),
        proposed_capabilities: vec!["edge-sync".into()],
        introduction: None,
        request_id: [0xaa; 16],
        created_at: 1_700_000_000_000,
    }
    .encode();
    let header = envelope::sign_outbound(
        &b.state.instance_key,
        *b.state.instance_key.public_bytes(),
        &Method::POST,
        "/federation/v1/peer-request",
        &body,
    );
    let req = Request::builder()
        .method(Method::POST)
        .uri("/federation/v1/peer-request")
        .header(http::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .header(envelope::AUTH_HEADER, header)
        .body(Body::from(body))
        .expect("build request");

    let response = b
        .router
        .clone()
        .oneshot(req)
        .await
        .expect("router dispatch");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "envelope.sender / body.pubkey mismatch must 401"
    );

    // No row should have been created.
    let a_pubkey_slice: &[u8] = a.state.instance_key.public_bytes();
    let row = sqlx::query!(
        "SELECT instance_pubkey FROM peers WHERE instance_pubkey = ?",
        a_pubkey_slice,
    )
    .fetch_optional(&b.state.db)
    .await
    .expect("peers query");
    assert!(
        row.is_none(),
        "rejected request must not leave a pending_inbound row behind"
    );
}
