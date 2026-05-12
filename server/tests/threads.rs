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
use common::{
    body_json, get_request, json_request, refresh_trust_graph, send, setup_admin, signup_as,
};

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

/// `GET /api/threads/by-link` returns existing threads that share the
/// same normalized URL, gated by the same trust-visibility rules as
/// `list_all_threads` — a thread the reader can't see in /r/foo must
/// not surface as a dupe suggestion either.
///
/// Setup: 3-user fixture (alice admin → bob invited → carol invited).
/// Carol posts a link thread. Alice (transitively connected via bob)
/// should see it as a suggestion; once alice directly distrusts carol,
/// it should disappear. As a bonus the test also asserts the
/// normalization: the carol-posted URL has a leading `www.` and uses
/// `http://`, while the query URL is `https://` with no `www.` — the
/// shared `normalize_url_for_fts` collapses both to the same key, so
/// the lookup still hits.
#[tokio::test]
async fn by_link_returns_visible_dupe_then_hides_after_distrust() {
    let (app, state) = common::test_app().await;

    let alice = setup_admin(&app, "alice").await;
    let bob = signup_as(&app, &alice, "bob").await;
    let carol = signup_as(&app, &bob, "carol").await;
    refresh_trust_graph(&state).await;

    // Suppress unused-warning on bob — he's the trust-path intermediary,
    // not directly named on any handler call.
    let _ = &bob;

    // Carol posts a link thread. The stored URL has `http://www.`; the
    // query below will use `https://` with no `www.` to exercise the
    // scheme + www collapse done by `normalize_url_for_fts`.
    let posted_link = "http://www.example.com/articles/tangerine-2026";
    let query_link = "https://example.com/articles/tangerine-2026";
    let create_req = json_request(
        Method::POST,
        "/api/threads",
        Some(&carol.cookie),
        &serde_json::json!({
            "room": "citrus",
            "title": "a thread about tangerines",
            "body": "see link",
            "link": posted_link,
        }),
    );
    let response = send(&app, create_req).await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "link thread create should succeed"
    );
    let created = body_json(response).await;
    let thread_id = created["id"].as_str().expect("thread id").to_string();

    // Alice queries with a differently-cased / different-scheme form —
    // should still find carol's thread thanks to normalization.
    let hits = by_link_thread_ids(&app, &alice.cookie, query_link).await;
    assert!(
        hits.contains(&thread_id),
        "alice should see carol's link thread via transitive trust + url normalization, got {hits:?}"
    );

    // Alice distrusts carol. The by-link endpoint shares
    // `is_thread_visible` with the listings, so the same direct-distrust
    // short-circuit should hide the thread.
    let distrust_req = json_request(
        Method::PUT,
        "/api/users/carol/trust-edge",
        Some(&alice.cookie),
        &serde_json::json!({ "type": "distrust" }),
    );
    let response = send(&app, distrust_req).await;
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "set_trust_edge should return 204"
    );
    refresh_trust_graph(&state).await;

    let hits = by_link_thread_ids(&app, &alice.cookie, query_link).await;
    assert!(
        !hits.contains(&thread_id),
        "after distrusting carol, alice should no longer see her link thread, got {hits:?}"
    );
}

/// Helper: hit `/api/threads/by-link?url=...` as the given session and
/// return the list of thread IDs in the response. URL-encodes the
/// query value via `url::form_urlencoded` so colons, slashes, and the
/// `=` of any embedded query string round-trip cleanly through the
/// querystring parser.
async fn by_link_thread_ids(app: &axum::Router, cookie: &str, link: &str) -> Vec<String> {
    let encoded: String = url::form_urlencoded::byte_serialize(link.as_bytes()).collect();
    let req = get_request(&format!("/api/threads/by-link?url={encoded}"), Some(cookie));
    let response = send(app, req).await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "by-link should return 200; got {status} body={body}"
    );
    body["threads"]
        .as_array()
        .expect("threads array")
        .iter()
        .filter_map(|t| t["id"].as_str().map(str::to_string))
        .collect()
}
