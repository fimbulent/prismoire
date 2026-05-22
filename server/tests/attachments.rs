#![cfg(feature = "test-auth")]
//! Tier-1 handler tests for the attachments-on-replies invariant
//! (`docs/attachments.md` §3).
//!
//! Replies cannot carry attachments — those live on the thread OP only.
//! `create_reply` rejects this at request-parse time; `edit_post` has
//! the mirror guard so a reply author cannot smuggle bindings into a
//! signed revision by editing instead of creating. Both paths land in
//! signed CBOR if the guard is missing, which is a wire-invariant
//! violation that's only detectable by inspecting `signed_objects`
//! after the fact — exactly the layer-interaction class of bug that
//! `docs/handler_tests.md` says belongs in an integration test.

mod common;

use axum::http::{Method, StatusCode};
use common::{body_json, json_request, send, setup_admin, signup_as};

/// Bob replies to alice's thread, then PATCHes his reply with a
/// non-empty `attachments` array. The server must reject with 400
/// (`bad_request`) before signing the revision.
#[tokio::test]
async fn edit_reply_rejects_attachments() {
    let (app, _state) = common::test_app().await;
    let alice = setup_admin(&app, "alice").await;
    let bob = signup_as(&app, &alice, "bob").await;

    // Alice creates an OP that bob can reply to.
    let create_thread = json_request(
        Method::POST,
        "/api/threads",
        Some(&alice.cookie),
        &serde_json::json!({
            "room": "testroom",
            "title": "thread for the reply guard test",
            "body": "body",
        }),
    );
    let response = send(&app, create_thread).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = body_json(response).await;
    let thread_id = created["id"].as_str().expect("thread id").to_string();
    let op_id = created["post"]["id"]
        .as_str()
        .expect("op post id")
        .to_string();

    // Bob replies to the OP. `create_reply` already rejects a
    // non-empty `attachments` array; here we send an empty reply so
    // we have a reply post to edit.
    let create_reply = json_request(
        Method::POST,
        &format!("/api/threads/{thread_id}/posts"),
        Some(&bob.cookie),
        &serde_json::json!({
            "parent_id": op_id,
            "body": "bob's reply",
        }),
    );
    let response = send(&app, create_reply).await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "reply create should succeed"
    );
    let reply = body_json(response).await;
    let reply_id = reply["id"].as_str().expect("reply id").to_string();

    // Now the regression: bob PATCHes his reply with a non-empty
    // attachments array. The bind step never runs — the guard fires
    // before we touch the staging table — so the hash can be any
    // syntactically-valid 64-char hex string. The test asserts on
    // status only; what we're protecting against is the case where
    // the server accepts the request, signs the revision, and writes
    // `post_attachments` rows for a reply.
    let edit = json_request(
        Method::PATCH,
        &format!("/api/posts/{reply_id}"),
        Some(&bob.cookie),
        &serde_json::json!({
            "body": "bob's edited reply",
            "attachments": [
                {
                    "content_hash": "0".repeat(64),
                    "filename": "smuggled.png",
                }
            ],
        }),
    );
    let response = send(&app, edit).await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "edit_post must reject attachments on a reply; got {status} body={body}",
    );
    assert_eq!(
        body["code"].as_str(),
        Some("bad_request"),
        "expected code=bad_request, got body={body}",
    );
}

/// Sanity counterpart: editing the OP with an empty attachments array
/// is allowed and round-trips successfully. Guards against the guard
/// becoming overzealous and rejecting OP edits too.
#[tokio::test]
async fn edit_op_without_attachments_succeeds() {
    let (app, _state) = common::test_app().await;
    let alice = setup_admin(&app, "alice").await;

    let create_thread = json_request(
        Method::POST,
        "/api/threads",
        Some(&alice.cookie),
        &serde_json::json!({
            "room": "testroom",
            "title": "thread for the OP edit sanity test",
            "body": "original body",
        }),
    );
    let response = send(&app, create_thread).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = body_json(response).await;
    let op_id = created["post"]["id"]
        .as_str()
        .expect("op post id")
        .to_string();

    let edit = json_request(
        Method::PATCH,
        &format!("/api/posts/{op_id}"),
        Some(&alice.cookie),
        &serde_json::json!({
            "body": "edited body",
            "attachments": [],
        }),
    );
    let response = send(&app, edit).await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "OP edit with empty attachments should succeed; got {status} body={body}",
    );
    assert_eq!(body["body"].as_str(), Some("edited body"));
}
