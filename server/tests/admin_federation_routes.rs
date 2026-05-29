#![cfg(feature = "test-auth")]
//! Operator-facing federation routes: `/api/admin/federation/*`.
//!
//! These exercise the HTTP surface over the §5.4 peering helpers
//! (`admin_federation.rs`) end-to-end through the real router: admin
//! gating, the two-stage preview→initiate federate flow, operator
//! accept of an inbound request, and defederation (both the wire-DELETE
//! path for `active` rows and the local-cleanup path for pending rows).
//!
//! The `MultiInstanceHarness` wires two `AppState`s together via the
//! in-process transport, so `preview` can fetch a real identity card
//! and `initiate`/`accept` drive real handshake traffic between them.

mod common;

use http::{Method, StatusCode};
use serde_json::json;

use common::federation::MultiInstanceHarness;
use common::{body_json, get_request, json_request, send, setup_admin, signup_as};

const PEERS: &str = "/api/admin/federation/peers";
const PREVIEW: &str = "/api/admin/federation/preview";

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
