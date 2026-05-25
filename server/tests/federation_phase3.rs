//! Phase-3 Layer-1 integration tests: §6 envelope-auth middleware,
//! §5.5 peer-of-peer discovery, §5.4 peer-relationship termination.
//!
//! The Phase-3 gate calls for: (a) middleware-enforced replay
//! defense, (b) the `/peers` route returning the active peer set to
//! peers and rejecting non-peers, (c) the `DELETE /peer-relationship`
//! route flipping both sides to `terminated` and causing subsequent
//! envelope-signed traffic from the now-terminated peer to 401. Each
//! test below pins exactly one of those gates.

mod common;

use std::sync::Arc;

use axum::body::{Body, Bytes};
use ciborium::value::Value;
use http::{Method, Request, StatusCode};
use prismoire_server::federation::envelope;
use prismoire_server::federation::identity::CBOR_CONTENT_TYPE;
use prismoire_server::federation::peering::{
    PeerRelationshipDeleteBody, TerminationReason, operator_accept_peer_request,
    operator_initiate_peer_request, operator_terminate_peer_relationship,
};
use prismoire_server::federation::transport::{FederationTransport, PeerId};
use tower::ServiceExt;

use common::federation::MultiInstanceHarness;

/// Drive A through the initiate → B accepts dance so the rest of the
/// test starts from "mutual active peering". Returns nothing; tests
/// look up the resulting row state via SQL when they need to assert.
async fn establish_active_peering(harness: &MultiInstanceHarness, initiator: &str, target: &str) {
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

/// Phase-3 done-when criterion: replaying an identical envelope is
/// rejected by the middleware's §6.5 step-12 nonce LRU. The first
/// dispatch reaches the handler (`/federation/v1/peer-request` is
/// the smallest Bootstrap-mode surface to demonstrate this on); the
/// second must 401 *without* the handler running.
#[tokio::test]
async fn replay_of_identical_envelope_is_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Build a peer-request envelope from A → B and dispatch it twice
    // through the shared transport. Use a fixed body so the verifier
    // sees the *exact* same envelope on both dispatches (nonce, body
    // hash, signature, timestamp all identical).
    let body = prismoire_server::federation::peering::PeerRequestBody {
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

    // §6.5 step-12 (nonce LRU) is what we're pinning here. The
    // peer-request UPSERT on `instance_pubkey` would *also* make a
    // duplicate idempotent at the handler layer (success, not 401),
    // so a future refactor that accidentally bypasses the nonce
    // check would silently keep this test green if we only asserted
    // status. Belt + suspenders: confirm B's DB still has exactly
    // one row for A (the first delivery's). A handler-level
    // re-execution would also leave one row but with a refreshed
    // `last_handshake`; a 401 short-circuit at the middleware never
    // touches the table.
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

/// Phase-3 done-when criterion: a `KnownPeer`-mode route rejects an
/// envelope whose sender is not in `peers WHERE status = 'active'`.
/// `/peers` is the smallest such surface; using it here doubles as
/// the §5.5 default-visibility check.
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

/// Phase-3 done-when criterion: `/peers` returns the active peer set
/// in the protocol-shaped CBOR envelope. Three-instance scenario so
/// the returned list is non-trivial: C peers with A only, then asks
/// A for its peer list and learns about B (the §5.5 "peers of your
/// peers" suggestion mechanism).
///
/// TODO(§5.5 discoverable flag): once the per-row "hide from
/// peer-of-peer discovery" flag lands, this test must add a
/// scenario for "B sets `discoverable = false` on its A↔B row → A's
/// `/peers` no longer lists B to C". Tracked in the
/// operational-hardening pass (`docs/federation-impl-plan.md` §6).
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
    // From A's vantage, both B and C are active peers; both must
    // appear. Order is unspecified.
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

/// Phase-3 done-when criterion: `DELETE /peer-relationship` flips
/// both sides to `terminated`, persists the reason, and causes
/// subsequent envelope-signed traffic from the now-terminated peer
/// to 401 per §5.4 "post-termination request handling".
#[tokio::test]
async fn peer_relationship_termination_round_trips_and_blocks_future_traffic() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pubkey = *a.state.instance_key.public_bytes();
    let b_pubkey = *b.state.instance_key.public_bytes();

    // A's operator wants out. Dispatch the DELETE via the operator
    // helper; the helper signs and sends, then flips A's row.
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
    // the handler.
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
    // KnownPeer-mode route) and is rejected by the middleware
    // because A no longer has an *active* row for B.
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

/// Spec round-trip pin: an inbound `DELETE /peer-relationship` from
/// a peer correctly terminates *our* row even if our operator never
/// initiated the termination. Mirror of the above, but with B as
/// the terminator.
#[tokio::test]
async fn inbound_peer_relationship_delete_terminates_local_row() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pubkey = *a.state.instance_key.public_bytes();
    let b_pubkey = *b.state.instance_key.public_bytes();

    // Hand-craft B → A DELETE so we exercise the handler (not just
    // the operator helper that also calls it).
    let body = PeerRelationshipDeleteBody {
        terminator_domain: b.state.instance_domain.clone(),
        reason: TerminationReason::CompromiseResponse,
        message: None,
        created_at: 1_700_000_500_000,
    }
    .encode();
    let header = envelope::sign_outbound(
        &b.state.instance_key,
        a_pubkey,
        &Method::DELETE,
        "/federation/v1/peer-relationship",
        &body,
    );
    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/federation/v1/peer-relationship")
        .header(http::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .header(envelope::AUTH_HEADER, header)
        .body(Bytes::from(body))
        .expect("build request");
    let response = b
        .transport
        .request(&PeerId::from_bytes(a_pubkey), req)
        .await
        .expect("dispatch");
    assert_eq!(response.status(), StatusCode::OK);

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
        Some("compromise_response")
    );
}
