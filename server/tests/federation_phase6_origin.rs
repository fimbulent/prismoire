//! Phase 6.3 originator-fanout tripwires.
//!
//! Lightweight Layer-1 assertions that the seven local-origin handlers
//! wired in Phase 6.3 (create_thread OP `post-rev` + `thread-create`,
//! create_reply, edit, retract, profile update, admin-rm, deactivate)
//! each actually invoke `forward_signed_object` so the canonical bytes
//! land on an interested peer's `signed_objects` table.
//!
//! Scope is intentionally narrow: each test exercises exactly one
//! origin site against a single interested peer whose `content_filter`
//! is the all-ones sentinel, so the assertion is "the wiring exists"
//! rather than "the propagation matrix is correct under interest
//! filtering". The full matrix (multi-hop, partition-heal, queue retry
//! / overflow / backoff) lands with Phase 6.4 when the per-peer
//! outbound queue provides a deterministic drain hook.
//!
//! Phase 6.4 rewrite: the polling-with-timeout loop has been replaced
//! with a single `state.outbound_queues.wait_idle(...)` call. The
//! per-peer outbound queue provides a deterministic "everything
//! drained" hook (worker marks idle + signals an `idle_notify`) so we
//! no longer need to poll the receiver's `signed_objects` table at
//! 10ms intervals waiting for the spawned dispatch task to land.

#![cfg(feature = "test-auth")]

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use http::Request;
use prismoire_server::federation::bloom::BloomFilter;
use prismoire_server::federation::frontier::{FilterSpec, FrontierAnnounce};
use serde_json::{Value, json};
use sqlx::SqlitePool;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};
use common::{body_json, json_request, send, setup_admin};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a §8.3 `FrontierAnnounce` whose both filters are the
/// all-ones sentinel — every routing key matches, so the receiver
/// sees every Authored or TrustEdge object the sender fans out. This
/// lets the tripwire avoid pre-computing per-user pubkeys for the
/// peer's `content_filter`.
fn announce_all_ones() -> FrontierAnnounce {
    FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        content_filter: FilterSpec::from_bloom(&BloomFilter::all_ones_sentinel()),
        edge_origin_filter: FilterSpec::from_bloom(&BloomFilter::all_ones_sentinel()),
    }
}

/// Count `signed_objects` rows of a given inner class on a peer's DB.
async fn count_class(db: &SqlitePool, class: &str) -> i64 {
    sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE inner_class = ?",
        class,
    )
    .fetch_one(db)
    .await
    .expect("count signed_objects by class")
}

/// Wait for A's outbound queue to fully drain, then return. Asserts
/// that drain completed within the timeout. Phase 6.4 hook: the
/// per-peer drain worker marks itself idle (empty + no in-flight)
/// after the egress write completes, and `wait_idle` rides the
/// `OutboundQueues::idle_notify` signal rather than polling.
///
/// Phase 6.4.1 lifted the `tokio::spawn` out of `forward_signed_object`
/// so the originating handler awaits the enqueue inline — by the time
/// the handler call returns, every selected peer's queue is already
/// populated and `wait_idle()` is genuinely deterministic.
async fn wait_outbound_idle(harness: &MultiInstanceHarness, label: &str) {
    let a = harness.instance(label);
    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(2))
            .await,
        "outbound queue from {label} did not drain within 2s",
    );
}

/// Build a two-instance harness with active peering and B's all-ones
/// frontier announced to A — A's `peers_interested_in` returns B for
/// every routing key, so any origin-side fanout from A targets B.
async fn setup_tripwire() -> MultiInstanceHarness {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let (status, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce_all_ones().encode(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "B → A frontier announce must apply");
    harness
}

/// Create a thread via the real `POST /api/threads` handler and
/// return `(thread_id, op_post_id)`. Panics on non-201 with the body
/// included so failures are self-diagnosing.
async fn create_thread_as(
    router: &axum::Router,
    cookie: &str,
    room: &str,
    title: &str,
    body: &str,
) -> (String, String) {
    let response = send(
        router,
        json_request(
            Method::POST,
            "/api/threads",
            Some(cookie),
            &json!({ "room": room, "title": title, "body": body }),
        ),
    )
    .await;
    let status = response.status();
    let json = body_json(response).await;
    assert_eq!(status, StatusCode::CREATED, "create_thread failed: {json}");
    let thread_id = json["id"].as_str().expect("thread.id").to_string();
    let post_id = json["post"]["id"].as_str().expect("post.id").to_string();
    (thread_id, post_id)
}

/// Create a reply via the real `POST /api/threads/{id}/posts` handler
/// and return the new post id.
async fn create_reply_as(
    router: &axum::Router,
    cookie: &str,
    thread_id: &str,
    parent_id: &str,
    body: &str,
) -> String {
    let response = send(
        router,
        json_request(
            Method::POST,
            &format!("/api/threads/{thread_id}/posts"),
            Some(cookie),
            &json!({ "parent_id": parent_id, "body": body }),
        ),
    )
    .await;
    let status = response.status();
    let json: Value = body_json(response).await;
    assert_eq!(status, StatusCode::CREATED, "create_reply failed: {json}");
    json["id"].as_str().expect("reply.id").to_string()
}

// ---------------------------------------------------------------------------
// Tripwires — one per origin site
// ---------------------------------------------------------------------------

/// `POST /api/threads` must fan out both the OP `post-rev` and the
/// paired `thread-create` (signed-payload-format.md §5.9) to B.
#[tokio::test]
async fn create_thread_fans_out_post_rev_and_thread_create() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let _ = create_thread_as(&a.router, &alice.cookie, "general", "tripwire", "hello").await;

    wait_outbound_idle(&harness, "a").await;
    let post_rev = count_class(&b.state.db, "post-rev").await;
    assert_eq!(
        post_rev, 1,
        "post-rev did not fan out to B (count={post_rev})"
    );
    let thread_create = count_class(&b.state.db, "thread-create").await;
    assert_eq!(
        thread_create, 1,
        "thread-create did not fan out to B (count={thread_create})",
    );
}

/// `POST /api/threads/{id}/posts` must fan out the reply `post-rev`.
/// After create_thread (1 post-rev) + reply (1 post-rev), B should
/// hold at least 2 `post-rev` rows.
#[tokio::test]
async fn create_reply_fans_out_post_rev() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let (thread_id, op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "with-reply", "op body").await;
    let _ = create_reply_as(&a.router, &alice.cookie, &thread_id, &op_id, "reply body").await;

    wait_outbound_idle(&harness, "a").await;
    let post_rev = count_class(&b.state.db, "post-rev").await;
    assert_eq!(
        post_rev, 2,
        "reply post-rev did not fan out to B (count={post_rev})",
    );
}

/// `PATCH /api/posts/{id}` must fan out the new revision's `post-rev`.
/// After create + edit, B should hold at least 2 `post-rev` rows
/// (revision 0 from the OP, revision 1 from the edit).
#[tokio::test]
async fn edit_post_fans_out_post_rev() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let (_thread_id, op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "to-edit", "original").await;
    let response = send(
        &a.router,
        json_request(
            Method::PATCH,
            &format!("/api/posts/{op_id}"),
            Some(&alice.cookie),
            &json!({ "body": "edited" }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "edit_post failed");

    wait_outbound_idle(&harness, "a").await;
    let post_rev = count_class(&b.state.db, "post-rev").await;
    assert_eq!(
        post_rev, 2,
        "edit post-rev did not fan out to B (count={post_rev})",
    );
}

/// `DELETE /api/posts/{id}` must fan out a `retract`. We retract a
/// reply rather than the OP so any future "OP retract → thread
/// implicitly retracted" behaviour doesn't perturb the assertion.
#[tokio::test]
async fn retract_post_fans_out_retract() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let (thread_id, op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "to-retract", "op body").await;
    let reply_id =
        create_reply_as(&a.router, &alice.cookie, &thread_id, &op_id, "reply body").await;

    let response = send(
        &a.router,
        Request::builder()
            .method(Method::DELETE)
            .uri(format!("/api/posts/{reply_id}"))
            .header(axum::http::header::COOKIE, &alice.cookie)
            .header(axum::http::header::ORIGIN, common::TEST_ORIGIN)
            .body(axum::body::Body::empty())
            .expect("build retract request"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "retract failed");

    wait_outbound_idle(&harness, "a").await;
    let retract = count_class(&b.state.db, "retract").await;
    assert_eq!(retract, 1, "retract did not fan out to B (count={retract})");
}

/// `PATCH /api/users/{username}` (update_bio) must fan out a
/// `profile` revision.
#[tokio::test]
async fn update_bio_fans_out_profile() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let response = send(
        &a.router,
        json_request(
            Method::PATCH,
            &format!("/api/users/{}", alice.display_name),
            Some(&alice.cookie),
            &json!({ "bio": "new bio text" }),
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "update_bio failed",
    );

    wait_outbound_idle(&harness, "a").await;
    let profile = count_class(&b.state.db, "profile").await;
    assert_eq!(profile, 1, "profile did not fan out to B (count={profile})");
}

/// `DELETE /api/admin/posts/{id}` (admin-rm) must fan out an
/// `admin-rm`. Alice is admin (via setup_admin) so she can remove her
/// own post here.
#[tokio::test]
async fn admin_remove_post_fans_out_admin_rm() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let (_thread_id, op_id) = create_thread_as(
        &a.router,
        &alice.cookie,
        "general",
        "to-admin-rm",
        "op body",
    )
    .await;

    // admin::remove_post requires a JSON body with `reason` — that
    // string is bound into the §10.1 `admin-rm` signed payload.
    let response = send(
        &a.router,
        json_request(
            Method::DELETE,
            &format!("/api/admin/posts/{op_id}"),
            Some(&alice.cookie),
            &json!({ "reason": "tripwire" }),
        ),
    )
    .await;
    let status = response.status();
    assert!(
        status.is_success() || status == StatusCode::NO_CONTENT,
        "admin remove_post failed: {status}",
    );

    wait_outbound_idle(&harness, "a").await;
    let admin_rm = count_class(&b.state.db, "admin-rm").await;
    assert_eq!(
        admin_rm, 1,
        "admin-rm did not fan out to B (count={admin_rm})",
    );
}

/// `DELETE /api/me` (soft_delete_user) must fan out the `deactivate`
/// umbrella. Alice has no posts in this scenario so no `retract` rows
/// are emitted — the assertion is purely on the deactivate object,
/// which the privacy.rs refactor packages into `DeactivationFanout`.
#[tokio::test]
async fn deactivate_fans_out_deactivate() {
    let harness = setup_tripwire().await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let alice = setup_admin(&a.router, "alice").await;

    let response = send(
        &a.router,
        Request::builder()
            .method(Method::DELETE)
            .uri("/api/me")
            .header(axum::http::header::COOKIE, &alice.cookie)
            .header(axum::http::header::ORIGIN, common::TEST_ORIGIN)
            .body(axum::body::Body::empty())
            .expect("build delete-me request"),
    )
    .await;
    let status = response.status();
    assert!(
        status.is_success() || status == StatusCode::NO_CONTENT,
        "delete_my_account failed: {status}",
    );

    wait_outbound_idle(&harness, "a").await;
    let deactivate = count_class(&b.state.db, "deactivate").await;
    assert_eq!(
        deactivate, 1,
        "deactivate did not fan out to B (count={deactivate})",
    );
}
