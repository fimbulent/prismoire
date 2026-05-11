#![cfg(feature = "test-auth")]
//! Tier-1 handler tests for the thread/post FTS trigger surface.
//!
//! These tests exist primarily to catch SQL-trigger regressions of the
//! shape that prompted `docs/handler_tests.md` (FTS triggers that pass
//! `cargo test` cleanly but fail at runtime). Each test creates content
//! through a real HTTP handler so the live trigger graph fires, then
//! queries the search endpoint to prove the trigger had the intended
//! effect.

mod common;

use axum::http::{Method, StatusCode};
use common::{body_json, json_request, send, setup_admin};

#[tokio::test]
async fn create_thread_appears_in_search_results() {
    let (app, _state) = common::test_app().await;
    let alice = setup_admin(&app, "alice").await;

    // Use a word in the title and body unlikely to collide with any
    // boilerplate in the schema or in the search infrastructure, so a
    // hit in the search response is unambiguous evidence that this
    // thread's FTS row was indexed.
    let unique_word = "kumquat";
    let create_req = json_request(
        Method::POST,
        "/api/threads",
        Some(&alice.cookie),
        &serde_json::json!({
            "room": "testroom",
            "title": format!("a thread about a {unique_word}"),
            "body": format!("the {unique_word} is a small citrus"),
        }),
    );
    let response = send(&app, create_req).await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "thread create should succeed"
    );
    let created = body_json(response).await;
    let thread_id = created["id"]
        .as_str()
        .expect("create response includes thread id");

    // Now hit the search endpoint with the unique word — this fires
    // the read side of the FTS trigger surface. If any of the
    // INSERT/UPDATE triggers on `threads_fts` or `posts_fts` are
    // broken, the thread creation above would have errored already;
    // this assertion just proves the row made it into the index.
    let search_req = common::get_request(
        &format!("/api/search/threads?q={unique_word}"),
        Some(&alice.cookie),
    );
    let response = send(&app, search_req).await;
    assert_eq!(response.status(), StatusCode::OK, "search should succeed");
    let body = body_json(response).await;
    let hits = body["threads"]
        .as_array()
        .expect("search response includes a threads array");
    assert!(
        hits.iter().any(|t| t["id"].as_str() == Some(thread_id)),
        "search for {unique_word:?} should return the new thread; got {body}"
    );
}
