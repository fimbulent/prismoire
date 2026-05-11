#![cfg(feature = "test-auth")]
//! Tier-2 handler tests: trust-visibility through real read endpoints.
//!
//! Trust filtering only emerges from the intersection of graph state +
//! handler logic + DB state, so it can't be unit-tested in isolation.
//! These tests build the canonical 3-user fixture (alice ↔ bob ↔
//! carol), refresh the trust graph cache synchronously, and assert on
//! the same content rendered to different readers.

mod common;

use axum::http::{Method, StatusCode};
use common::{
    body_json, get_request, json_request, refresh_trust_graph, send, setup_admin, signup_as,
};

/// alice trusts bob; bob trusts carol. After a synchronous graph
/// rebuild, alice can find carol's thread via transitive trust. Once
/// alice directly distrusts carol, the same thread disappears from
/// alice's search results.
///
/// Note: the search visibility filter uses the reverse-BFS score map
/// (which intentionally does NOT propagate distrust — see
/// `trust::reverse_bfs` docs) combined with the reader's direct
/// `distrust_set`. So distrusting an *intermediary* (bob) would not
/// hide carol's content through this endpoint — that's a known
/// approximation. This test exercises the direct-distrust short-
/// circuit in `is_thread_visible`, which is the visibility-flipping
/// mechanism the search endpoint actually applies.
#[tokio::test]
async fn transitive_trust_then_direct_distrust_flips_visibility() {
    let (app, state) = common::test_app().await;

    let alice = setup_admin(&app, "alice").await;
    let bob = signup_as(&app, &alice, "bob").await;
    let carol = signup_as(&app, &bob, "carol").await;
    refresh_trust_graph(&state).await;

    // Carol posts in a room she creates. The unique word lets us key
    // the search assertion cleanly.
    let unique_word = "tangerine";
    let create_req = json_request(
        Method::POST,
        "/api/threads",
        Some(&carol.cookie),
        &serde_json::json!({
            "room": "citrus",
            "title": format!("a thread mentioning {unique_word}"),
            "body": format!("{unique_word} is also a citrus"),
        }),
    );
    let response = send(&app, create_req).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = body_json(response).await;
    let thread_id = created["id"].as_str().expect("thread id").to_string();

    // Suppress unused-warning on bob — he's part of the fixture's
    // transitive-trust path even though no handler call directly
    // references his session.
    let _ = &bob;

    // Sanity: carol sees her own thread.
    let hits = search_thread_ids(&app, &carol.cookie, unique_word).await;
    assert!(
        hits.contains(&thread_id),
        "carol should see her own thread, got {hits:?}"
    );

    // Transitive visibility: alice trusts bob, bob trusts carol →
    // alice's reverse score for carol picks up the carol→bob→alice
    // path, so carol's thread is visible to alice.
    let hits = search_thread_ids(&app, &alice.cookie, unique_word).await;
    assert!(
        hits.contains(&thread_id),
        "alice should transitively see carol's thread via bob, got {hits:?}"
    );

    // alice directly distrusts carol. `is_thread_visible` checks the
    // reader's distrust_set first and short-circuits to `false`, which
    // is the documented visibility-flip mechanism for the search
    // endpoint. `load_distrust_set` reads directly from the DB, so the
    // next request sees the new edge without a graph refresh — but we
    // still refresh to keep cached state consistent with the DB for
    // any downstream code that consults the cached graph.
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

    let hits = search_thread_ids(&app, &alice.cookie, unique_word).await;
    assert!(
        !hits.contains(&thread_id),
        "after distrusting carol, alice should no longer see carol's thread, got {hits:?}"
    );
}

/// Helper: hit `/api/search/threads?q=...` as the given session and
/// return the list of thread IDs in the response.
async fn search_thread_ids(app: &axum::Router, cookie: &str, query: &str) -> Vec<String> {
    let req = get_request(&format!("/api/search/threads?q={query}"), Some(cookie));
    let response = send(app, req).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    body["threads"]
        .as_array()
        .expect("threads array")
        .iter()
        .filter_map(|t| t["id"].as_str().map(str::to_string))
        .collect()
}
