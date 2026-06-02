#![cfg(feature = "test-auth")]
//! Peering, identity, and envelope-auth integration tests (§5 / §6).
//!
//! Three layers share this file because they all exercise the
//! instance-to-instance relationship surface:
//!
//! - **Protocol mechanics (§5.2 / §5.4).** `GET /federation/v1/identity`
//!   returns a protocol-shaped CBOR card, and two harness instances
//!   reach mutual `active` peering from cold start via the operator
//!   helpers. The remaining handshake tests pin the failure modes the
//!   state machine must surface: stale request_id, idempotent accept
//!   retry, and the §5.4 step-2 body/sender mismatch.
//! - **Envelope-auth middleware (§6) + peer-of-peer (§5.5) +
//!   termination (§5.4).** Replay defense, `KnownPeer`-mode rejection
//!   of non-peers, `/peers` returning the active set, and
//!   `DELETE /peer-relationship` flipping both sides to `terminated`
//!   and blocking subsequent traffic.
//! - **Operator HTTP surface (`/api/admin/federation/*`).** Admin
//!   gating, the preview→initiate→accept federate flow, and
//!   defederation (wire-DELETE for `active` rows, local cleanup for
//!   pending rows).

mod common;

use std::sync::Arc;

use axum::body::{Body, Bytes};
use ciborium::value::Value;
use http::{Method, Request, StatusCode};
use prismoire_server::federation::envelope;
use prismoire_server::federation::identity::{CBOR_CONTENT_TYPE, IdentityCard};
use prismoire_server::federation::peering::{
    self, PeerDecision, PeerResponseBody, TerminationReason, operator_accept_peer_request,
    operator_initiate_peer_request, operator_terminate_peer_relationship,
};
use prismoire_server::federation::transport::{FederationTransport, PeerId};
use serde_json::json;
use tower::ServiceExt;

use common::federation::{MultiInstanceHarness, establish_active_peering};
use common::{body_json, get_request, json_request, send, setup_admin, signup_as};

const PEERS: &str = "/api/admin/federation/peers";
const PREVIEW: &str = "/api/admin/federation/preview";

// ---------------------------------------------------------------------------
// §5.2 identity + §5.4 handshake state machine
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_endpoint_returns_protocol_shaped_card() {
    let harness = MultiInstanceHarness::new(1).await;
    let a = harness.instance("a");

    let req = Request::builder()
        .method(Method::GET)
        .uri("/federation/v1/identity")
        .body(Body::empty())
        .expect("build request");
    let response = a
        .router
        .clone()
        .oneshot(req)
        .await
        .expect("router dispatch");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap()),
        Some(CBOR_CONTENT_TYPE),
        "identity must advertise CBOR content-type"
    );

    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("collect body")
        .to_bytes();
    let card = IdentityCard::decode(&body).expect("identity card decodes");
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
    let a_transport: Arc<dyn FederationTransport> = a.transport.clone();
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
    let b_transport: Arc<dyn FederationTransport> = b.transport.clone();
    operator_accept_peer_request(
        &b.state.db,
        &b.state.instance_key,
        &b.state.instance_domain,
        &b_transport,
        request_id,
    )
    .await
    .expect("operator_accept_peer_request");

    // Both sides are now active and recorded the agreed capability set.
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
/// peer-response is replayed (simulating B's operator retrying accept
/// because the original 200 was lost on the wire). The handler must
/// return 200 OK — not 404 — so the responder can commit its own local
/// flip, and the initiator's row must remain `active`.
#[tokio::test]
async fn peer_response_retry_after_active_is_idempotent() {
    let harness = MultiInstanceHarness::new(2).await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let a_pubkey = *a.state.instance_key.public_bytes();
    let b_pubkey = *b.state.instance_key.public_bytes();

    let a_transport: Arc<dyn FederationTransport> = a.transport.clone();
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

    let b_transport: Arc<dyn FederationTransport> = b.transport.clone();
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

    // A peer-response for a request A never issued. B signs it (the
    // envelope is well-formed and self-consistent), but A has no
    // matching pending_outbound row.
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

    // A peer-request whose body claims A's pubkey but whose envelope is
    // actually signed by *B* — someone trying to impersonate A on the
    // wire. The bootstrap-mode self-consistency check in
    // `handle_peer_request` must catch this and 401 *before* any
    // pending_inbound row gets recorded. Envelope's `receiver` is B (a
    // self-loop on B's router) so the §6.5 step-7 check passes; the
    // only failure isolated here is the body/sender mismatch.
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

// ---------------------------------------------------------------------------
// §6 envelope-auth middleware + §5.5 peer-of-peer + §5.4 termination
// ---------------------------------------------------------------------------

/// Replaying an identical envelope is rejected by the middleware's
/// §6.5 step-12 nonce LRU. The first dispatch reaches the handler
/// (`/peer-request` is the smallest Bootstrap-mode surface); the
/// second must 401 *without* the handler running — confirmed by B's
/// table still holding exactly one row (a handler re-execution would
/// refresh `last_handshake`; a middleware 401 never touches the table).
#[tokio::test]
async fn replay_of_identical_envelope_is_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let body = peering::PeerRequestBody {
        initiator_domain: a.state.instance_domain.clone(),
        initiator_instance_pubkey: *a.state.instance_key.public_bytes(),
        proposed_capabilities: vec!["edge-sync".into()],
        introduction: None,
        request_id: [0x77; 16],
        created_at: 1_700_000_000_000,
    }
    .encode();
    let header = envelope::sign_outbound(
        &a.state.instance_key,
        *b.state.instance_key.public_bytes(),
        &Method::POST,
        "/federation/v1/peer-request",
        &body,
    );

    let build = || {
        Request::builder()
            .method(Method::POST)
            .uri("/federation/v1/peer-request")
            .header(http::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
            .header(envelope::AUTH_HEADER, &header)
            .body(Bytes::from(body.clone()))
            .expect("build request")
    };

    let first = a
        .transport
        .request(
            &PeerId::from_bytes(*b.state.instance_key.public_bytes()),
            build(),
        )
        .await
        .expect("transport dispatch");
    assert_eq!(
        first.status(),
        StatusCode::ACCEPTED,
        "first delivery must reach the handler"
    );

    let second = a
        .transport
        .request(
            &PeerId::from_bytes(*b.state.instance_key.public_bytes()),
            build(),
        )
        .await
        .expect("transport dispatch");
    assert_eq!(
        second.status(),
        StatusCode::UNAUTHORIZED,
        "identical envelope replay must 401 at the middleware"
    );

    let a_pubkey = *a.state.instance_key.public_bytes();
    let a_slice: &[u8] = &a_pubkey;
    let count = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM peers WHERE instance_pubkey = ?",
        a_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("peers count");
    assert_eq!(count, 1, "exactly one row for A on B's side");
}

/// A `KnownPeer`-mode route rejects an envelope whose sender is not in
/// `peers WHERE status = 'active'`. `/peers` is the smallest such
/// surface; using it here doubles as the §5.5 default-visibility check.
#[tokio::test]
async fn peers_list_rejects_unknown_sender() {
    let harness = MultiInstanceHarness::new(2).await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // No peering has been established; B is a stranger to A.
    let header = envelope::sign_outbound(
        &b.state.instance_key,
        *a.state.instance_key.public_bytes(),
        &Method::GET,
        "/federation/v1/peers",
        &[],
    );
    let req = Request::builder()
        .method(Method::GET)
        .uri("/federation/v1/peers")
        .header(envelope::AUTH_HEADER, header)
        .body(Body::empty())
        .expect("build request");

    let response = a.router.clone().oneshot(req).await.expect("dispatch");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "non-peer caller hits KnownPeer middleware and 401s"
    );
}

/// `/peers` returns the active peer set in the protocol-shaped CBOR
/// envelope. Three-instance scenario so the list is non-trivial: C
/// peers with A only, then asks A for its peer list and learns about B
/// (the §5.5 "peers of your peers" suggestion mechanism).
///
/// TODO(§5.5 discoverable flag): once the per-row "hide from
/// peer-of-peer discovery" flag lands, add a scenario for "B sets
/// `discoverable = false` on its A↔B row → A's `/peers` no longer lists
/// B to C". Tracked in the operational-hardening pass.
#[tokio::test]
async fn peers_list_returns_active_peers_to_a_peer_caller() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "c", "a").await;

    let a = harness.instance("a");
    let b = harness.instance("b");
    let c = harness.instance("c");

    let header = envelope::sign_outbound(
        &c.state.instance_key,
        *a.state.instance_key.public_bytes(),
        &Method::GET,
        "/federation/v1/peers",
        &[],
    );
    let req = Request::builder()
        .method(Method::GET)
        .uri("/federation/v1/peers")
        .header(envelope::AUTH_HEADER, header)
        .body(Bytes::from_static(b""))
        .expect("build request");

    let response = c
        .transport
        .request(
            &PeerId::from_bytes(*a.state.instance_key.public_bytes()),
            req,
        )
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap()),
        Some(CBOR_CONTENT_TYPE)
    );

    let value: Value = ciborium::de::from_reader(response.body().as_ref()).expect("CBOR decodes");
    let entries = match value {
        Value::Map(m) => m,
        _ => panic!("/peers must return a map"),
    };
    let peers = entries
        .into_iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(s), Value::Array(a)) if s == "peers" => Some(a),
            _ => None,
        })
        .expect("`peers` array present");
    let domains: Vec<String> = peers
        .iter()
        .filter_map(|entry| match entry {
            Value::Map(fields) => fields.iter().find_map(|(k, v)| match (k, v) {
                (Value::Text(k), Value::Text(d)) if k == "domain" => Some(d.clone()),
                _ => None,
            }),
            _ => None,
        })
        .collect();
    assert!(
        domains.contains(&b.state.instance_domain),
        "B should appear in A's /peers list, got {domains:?}"
    );
    assert!(
        domains.contains(&c.state.instance_domain),
        "C should appear in A's /peers list (the caller is included; the protocol \
         doesn't carve them out), got {domains:?}"
    );
}

/// `DELETE /peer-relationship` flips both sides to `terminated`,
/// persists the reason/message (the responder side via the real
/// inbound handler the operator helper dispatches to), and causes
/// subsequent envelope-signed traffic from the now-terminated peer to
/// 401 per §5.4 "post-termination request handling".
#[tokio::test]
async fn peer_relationship_termination_round_trips_and_blocks_future_traffic() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pubkey = *a.state.instance_key.public_bytes();
    let b_pubkey = *b.state.instance_key.public_bytes();

    // A's operator wants out. The helper signs and sends the wire
    // DELETE (driving B's inbound handler), then flips A's row.
    let a_transport: Arc<dyn FederationTransport> = a.transport.clone();
    operator_terminate_peer_relationship(
        &a.state.db,
        &a.state.instance_key,
        &a.state.instance_domain,
        &a_transport,
        b_pubkey,
        TerminationReason::PolicyViolation,
        Some("repeated policy violations".into()),
    )
    .await
    .expect("operator_terminate_peer_relationship");

    // A's row: terminated, reason persisted.
    let b_slice: &[u8] = &b_pubkey;
    let a_row = sqlx::query!(
        "SELECT status, termination_reason FROM peers WHERE instance_pubkey = ?",
        b_slice,
    )
    .fetch_one(&a.state.db)
    .await
    .expect("A row");
    assert_eq!(a_row.status, "terminated");
    assert_eq!(
        a_row.termination_reason.as_deref(),
        Some("policy_violation")
    );

    // B's row: also terminated, with reason and message persisted by
    // the inbound handler.
    let a_slice: &[u8] = &a_pubkey;
    let b_row = sqlx::query!(
        "SELECT status, termination_reason, decision_message \
         FROM peers WHERE instance_pubkey = ?",
        a_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("B row");
    assert_eq!(b_row.status, "terminated");
    assert_eq!(
        b_row.termination_reason.as_deref(),
        Some("policy_violation")
    );
    assert_eq!(
        b_row.decision_message.as_deref(),
        Some("repeated policy violations")
    );

    // §5.4 post-termination: B tries to call A's `/peers` (a
    // KnownPeer-mode route) and is rejected because A no longer has an
    // *active* row for B.
    let header = envelope::sign_outbound(
        &b.state.instance_key,
        a_pubkey,
        &Method::GET,
        "/federation/v1/peers",
        &[],
    );
    let req = Request::builder()
        .method(Method::GET)
        .uri("/federation/v1/peers")
        .header(envelope::AUTH_HEADER, header)
        .body(Bytes::from_static(b""))
        .expect("build request");
    let response = b
        .transport
        .request(&PeerId::from_bytes(a_pubkey), req)
        .await
        .expect("dispatch");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "after termination, B's envelope no longer matches an active peer on A; 401 per §5.4"
    );
}

// ---------------------------------------------------------------------------
// Operator HTTP surface: /api/admin/federation/*
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_peers_gates_on_admin_and_returns_identity() {
    let h = MultiInstanceHarness::new(1).await;
    let a = h.instance("a");
    let admin = setup_admin(&a.router, "alice").await;
    let bob = signup_as(&a.router, &admin, "bob").await;

    // Non-admin is rejected.
    let resp = send(&a.router, get_request(PEERS, Some(&bob.cookie))).await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "non-admin should be forbidden from listing peers"
    );

    // Admin gets this-instance identity plus an (empty) peer list.
    let resp = send(&a.router, get_request(PEERS, Some(&admin.cookie))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["instance"]["domain"], "a.test.local");
    assert_eq!(
        body["instance"]["pubkey_hex"].as_str().unwrap().len(),
        64,
        "instance pubkey should be 32-byte hex"
    );
    assert!(body["peers"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn preview_fetches_remote_card() {
    let h = MultiInstanceHarness::new(2).await;
    let a = h.instance("a");
    let admin = setup_admin(&a.router, "alice").await;

    let resp = send(
        &a.router,
        json_request(
            Method::POST,
            PREVIEW,
            Some(&admin.cookie),
            &json!({ "domain": "b.test.local" }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["domain"], "b.test.local");
    assert_eq!(body["pubkey_hex"].as_str().unwrap().len(), 64);
    assert_eq!(body["is_self"], false);
    assert!(body["existing_status"].is_null());
    assert!(!body["capabilities"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn preview_detects_self() {
    let h = MultiInstanceHarness::new(1).await;
    let a = h.instance("a");
    let admin = setup_admin(&a.router, "alice").await;

    let resp = send(
        &a.router,
        json_request(
            Method::POST,
            PREVIEW,
            Some(&admin.cookie),
            &json!({ "domain": "a.test.local" }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["is_self"], true);
}

#[tokio::test]
async fn preview_rejects_invalid_domain() {
    let h = MultiInstanceHarness::new(1).await;
    let a = h.instance("a");
    let admin = setup_admin(&a.router, "alice").await;

    let resp = send(
        &a.router,
        json_request(
            Method::POST,
            PREVIEW,
            Some(&admin.cookie),
            &json!({ "domain": "https://bad domain/path" }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "invalid_peer_domain");
}

#[tokio::test]
async fn preview_unreachable_instance() {
    let h = MultiInstanceHarness::new(1).await;
    let a = h.instance("a");
    let admin = setup_admin(&a.router, "alice").await;

    // Syntactically valid but not in the harness registry.
    let resp = send(
        &a.router,
        json_request(
            Method::POST,
            PREVIEW,
            Some(&admin.cookie),
            &json!({ "domain": "z.test.local" }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "peer_unreachable");
}

#[tokio::test]
async fn initiate_rejects_self_peering() {
    let h = MultiInstanceHarness::new(1).await;
    let a = h.instance("a");
    let admin = setup_admin(&a.router, "alice").await;

    // Get our own pubkey via preview.
    let body = body_json(
        send(
            &a.router,
            json_request(
                Method::POST,
                PREVIEW,
                Some(&admin.cookie),
                &json!({ "domain": "a.test.local" }),
            ),
        )
        .await,
    )
    .await;
    let own_pubkey = body["pubkey_hex"].as_str().unwrap().to_string();

    let resp = send(
        &a.router,
        json_request(
            Method::POST,
            PEERS,
            Some(&admin.cookie),
            &json!({
                "domain": "a.test.local",
                "pubkey_hex": own_pubkey,
                "capabilities": ["edge-sync"],
                "introduction": null,
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "self_peering");
}

/// Full operator flow through the HTTP surface: preview → initiate →
/// (B) accept → both active → (A) defederate via the wire-DELETE path.
#[tokio::test]
async fn full_federate_accept_and_defederate() {
    let h = MultiInstanceHarness::new(2).await;
    let a = h.instance("a");
    let b = h.instance("b");
    let admin_a = setup_admin(&a.router, "alice").await;
    let admin_b = setup_admin(&b.router, "bob").await;

    // Stage 1: preview b from a.
    let body = body_json(
        send(
            &a.router,
            json_request(
                Method::POST,
                PREVIEW,
                Some(&admin_a.cookie),
                &json!({ "domain": "b.test.local" }),
            ),
        )
        .await,
    )
    .await;
    let b_pubkey = body["pubkey_hex"].as_str().unwrap().to_string();

    // Stage 2: initiate.
    let resp = send(
        &a.router,
        json_request(
            Method::POST,
            PEERS,
            Some(&admin_a.cookie),
            &json!({
                "domain": "b.test.local",
                "pubkey_hex": b_pubkey,
                "capabilities": ["edge-sync", "content-sync"],
                "introduction": "hello from a",
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(
        body["request_id"].as_str().unwrap().len(),
        32,
        "request_id is a 16-byte hex"
    );

    // a now shows b as pending_outbound.
    let body = body_json(send(&a.router, get_request(PEERS, Some(&admin_a.cookie))).await).await;
    let peers = body["peers"].as_array().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["status"], "pending_outbound");
    assert_eq!(peers[0]["domain"], "b.test.local");
    assert_eq!(peers[0]["direction"], "outbound");

    // b sees a as pending_inbound; grab a's pubkey from b's view.
    let body = body_json(send(&b.router, get_request(PEERS, Some(&admin_b.cookie))).await).await;
    let b_peers = body["peers"].as_array().unwrap();
    assert_eq!(b_peers.len(), 1);
    assert_eq!(b_peers[0]["status"], "pending_inbound");
    let a_pubkey = b_peers[0]["pubkey_hex"].as_str().unwrap().to_string();

    // b accepts.
    let resp = send(
        &b.router,
        json_request(
            Method::POST,
            &format!("{PEERS}/{a_pubkey}/accept"),
            Some(&admin_b.cookie),
            &json!({}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Both sides active.
    let body = body_json(send(&a.router, get_request(PEERS, Some(&admin_a.cookie))).await).await;
    assert_eq!(body["peers"][0]["status"], "active");
    let body = body_json(send(&b.router, get_request(PEERS, Some(&admin_b.cookie))).await).await;
    assert_eq!(body["peers"][0]["status"], "active");

    // a defederates -> wire DELETE path -> terminated.
    let resp = send(
        &a.router,
        json_request(
            Method::DELETE,
            &format!("{PEERS}/{b_pubkey}"),
            Some(&admin_a.cookie),
            &json!({}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["action"], "terminated");

    // a's row is now terminated.
    let body = body_json(send(&a.router, get_request(PEERS, Some(&admin_a.cookie))).await).await;
    assert_eq!(body["peers"][0]["status"], "terminated");
}

/// Cancelling a *pending* outbound request removes the row locally with
/// no wire DELETE — the `"removed"` action, distinct from the
/// `"terminated"` wire path an `active` row takes.
#[tokio::test]
async fn defederate_pending_removes_row() {
    let h = MultiInstanceHarness::new(2).await;
    let a = h.instance("a");
    let admin_a = setup_admin(&a.router, "alice").await;

    let body = body_json(
        send(
            &a.router,
            json_request(
                Method::POST,
                PREVIEW,
                Some(&admin_a.cookie),
                &json!({ "domain": "b.test.local" }),
            ),
        )
        .await,
    )
    .await;
    let b_pubkey = body["pubkey_hex"].as_str().unwrap().to_string();

    send(
        &a.router,
        json_request(
            Method::POST,
            PEERS,
            Some(&admin_a.cookie),
            &json!({
                "domain": "b.test.local",
                "pubkey_hex": b_pubkey,
                "capabilities": ["edge-sync"],
                "introduction": null,
            }),
        ),
    )
    .await;

    // Cancel the pending request -> local removal, no wire DELETE.
    let resp = send(
        &a.router,
        json_request(
            Method::DELETE,
            &format!("{PEERS}/{b_pubkey}"),
            Some(&admin_a.cookie),
            &json!({}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["action"], "removed");

    // Row is gone.
    let body = body_json(send(&a.router, get_request(PEERS, Some(&admin_a.cookie))).await).await;
    assert!(body["peers"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn defederate_unknown_peer_404s() {
    let h = MultiInstanceHarness::new(1).await;
    let a = h.instance("a");
    let admin = setup_admin(&a.router, "alice").await;

    let bogus = "0".repeat(64);
    let resp = send(
        &a.router,
        json_request(
            Method::DELETE,
            &format!("{PEERS}/{bogus}"),
            Some(&admin.cookie),
            &json!({}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "peer_not_found");
}
