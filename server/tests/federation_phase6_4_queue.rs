//! Phase 6.4 outbound-queue integration tests.
//!
//! Layer-1 assertions against the per-peer outbound FIFO + drain
//! workers landed in `server/src/federation/outbound_queue.rs`. The
//! Layer-0 tests inside that module cover queue-state semantics
//! (caps, backoff, staleness) deterministically; this file covers the
//! end-to-end "originate on A, drain via per-peer worker, land on B's
//! signed_objects" path through the real Axum handler stack.
//!
//! Three scenarios:
//!
//! 1. `kill_and_restart_peer_drains_backlog` — disconnect B from the
//!    transport, originate N posts on A (they queue up against B with
//!    no successful drains), reconnect B, assert the worker drains
//!    everything.
//! 2. `overflow_drops_oldest_and_continues` — flood A's queue past
//!    its per-peer object cap; assert the queue stays bounded, no
//!    panic, B receives at least some objects.
//! 3. (Backoff coverage) — covered by the deterministic Layer-0
//!    `backoff_grows_until_success` unit test in `outbound_queue.rs`.
//!    A faithful Layer-1 reproduction would require wrapping the
//!    in-process transport in a flake-injection decorator just for
//!    this test; the per-config-shaped Layer-0 suite gives the same
//!    coverage with less harness surgery. See TODO at the bottom of
//!    this file.

#![cfg(feature = "test-auth")]

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use prismoire_server::federation::bloom::BloomFilter;
use prismoire_server::federation::frontier::{FilterSpec, FrontierAnnounce};
use serde_json::json;
use sqlx::SqlitePool;

use common::federation::{
    MultiInstanceHarness, establish_active_peering, send_envelope_signed, settle_forwarder_spawn,
};
use common::{body_json, json_request, send, setup_admin};

// ---------------------------------------------------------------------------
// Helpers (duplicated from federation_phase6_origin.rs deliberately —
// see the note at the top of that file about a future cleanup pass).
// ---------------------------------------------------------------------------

fn announce_all_ones() -> FrontierAnnounce {
    FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        content_filter: FilterSpec::from_bloom(&BloomFilter::all_ones_sentinel()),
        edge_origin_filter: FilterSpec::from_bloom(&BloomFilter::all_ones_sentinel()),
    }
}

async fn count_class(db: &SqlitePool, class: &str) -> i64 {
    sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE inner_class = ?",
        class,
    )
    .fetch_one(db)
    .await
    .expect("count signed_objects by class")
}

async fn setup_a_to_b() -> MultiInstanceHarness {
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

/// Create a reply via the real `POST /api/threads/{id}/posts` handler
/// and return the new post id. Panics on non-201.
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
    let json = body_json(response).await;
    assert_eq!(status, StatusCode::CREATED, "create_reply failed: {json}");
    json["id"].as_str().expect("reply.id").to_string()
}

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

// ---------------------------------------------------------------------------
// Test 1: kill / restart peer drains backlog
// ---------------------------------------------------------------------------

/// While B is disconnected, originate several posts on A → A's
/// outbound queue to B grows (no successful drains, items requeue on
/// `UnknownPeer` transient errors). Reconnect B; assert `wait_idle`
/// returns true and B's `signed_objects` table is populated.
#[tokio::test]
async fn kill_and_restart_peer_drains_backlog() {
    let harness = setup_a_to_b().await;
    let a = harness.instance("a");
    let b_peer_id = harness.instance("b").peer_id;
    let alice = setup_admin(&a.router, "alice").await;

    // Originate one thread + several replies while B is online — this
    // also seeds A's forwarding-LRU and creates an OP we can reply to.
    let (thread_id, op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "backlog", "op body").await;

    // Drain whatever's already in flight from the create_thread call.
    settle_forwarder_spawn().await;
    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(2))
            .await,
        "initial create_thread should drain to B"
    );

    // Now disconnect B and originate N replies. Each enqueue lands on
    // A's outbound queue to B, the drain worker fails transiently
    // (UnknownPeer), re-queues, and backs off. The queue depth grows.
    harness.disconnect("b").await;

    const N: usize = 8;
    for i in 0..N {
        create_reply_as(
            &a.router,
            &alice.cookie,
            &thread_id,
            &op_id,
            &format!("reply {i}"),
        )
        .await;
    }
    settle_forwarder_spawn().await;

    // Reconnect B and let the queue drain. The drain-worker backoff
    // window is at most `BackoffPolicy::test_fast().max` = 100ms, so
    // a 5-second cap is plenty.
    harness.reconnect("b").await;
    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(5))
            .await,
        "queue did not drain after B reconnected (depth={:?})",
        a.state.outbound_queues.depth_for(b_peer_id.as_bytes()),
    );

    // B should now hold N replies + the original OP = N+1 post-revs.
    let b = harness.instance("b");
    let post_rev = count_class(&b.state.db, "post-rev").await;
    assert_eq!(
        post_rev,
        (N as i64) + 1,
        "B should have received all {} post-revs (got {post_rev})",
        N + 1,
    );
}

// ---------------------------------------------------------------------------
// Test 2: queue stays within caps under sustained flood
// ---------------------------------------------------------------------------

/// Disconnect B and originate ~25 posts on A. With the `test_fast`
/// config still using prod-default caps (50k objects, 32 MiB per
/// peer, 512 MiB total), this volume does NOT actually trigger
/// drop-oldest eviction — overflow at realistic numbers needs the
/// config-injection plumbing landing in Phase 6.4.1.
///
/// What this test does verify is the no-panic + accounting-stays-
/// consistent path: `depth_for()` and `total_bytes()` both report
/// values under their respective caps after the flood, the drain
/// worker continues to function across the disconnect, and
/// `wait_idle()` returns true after reconnect even though dozens of
/// objects went through the requeue-on-transient-failure path.
///
/// Phase 6.4.1 supersedes this with the sharpened "set per-peer-
/// objects = 5, originate 10, assert ≤ 5 retained" eviction test.
#[tokio::test]
async fn queue_stays_within_caps_under_flood() {
    let harness = setup_a_to_b().await;
    let a = harness.instance("a");
    let b_peer_id = harness.instance("b").peer_id;
    let alice = setup_admin(&a.router, "alice").await;
    let (thread_id, op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "overflow", "op body").await;
    settle_forwarder_spawn().await;
    let _ = a
        .state
        .outbound_queues
        .wait_idle(Duration::from_secs(2))
        .await;

    harness.disconnect("b").await;

    // Originate ~25 replies. At default test_fast() caps (50k
    // objects, 32 MiB) we don't actually overflow — but the tripwire
    // is that the queue stays bounded and the process keeps running.
    const N: usize = 25;
    for i in 0..N {
        create_reply_as(
            &a.router,
            &alice.cookie,
            &thread_id,
            &op_id,
            &format!("flood {i}"),
        )
        .await;
    }
    settle_forwarder_spawn().await;

    let (depth_objects, depth_bytes) = a.state.outbound_queues.depth_for(b_peer_id.as_bytes());
    let total_bytes = a.state.outbound_queues.total_bytes();

    // Hard tripwire: per-peer cap and global cap held.
    let cfg_per_peer_objects =
        prismoire_server::federation::outbound_queue::MAX_OUTBOUND_QUEUE_OBJECTS_PER_PEER;
    let cfg_per_peer_bytes =
        prismoire_server::federation::outbound_queue::MAX_OUTBOUND_QUEUE_BYTES_PER_PEER;
    let cfg_total_bytes =
        prismoire_server::federation::outbound_queue::MAX_OUTBOUND_QUEUE_TOTAL_BYTES;
    assert!(
        depth_objects <= cfg_per_peer_objects,
        "per-peer object cap violated: {depth_objects} > {cfg_per_peer_objects}",
    );
    assert!(
        depth_bytes <= cfg_per_peer_bytes,
        "per-peer byte cap violated: {depth_bytes} > {cfg_per_peer_bytes}",
    );
    assert!(
        total_bytes <= cfg_total_bytes,
        "global byte cap violated: {total_bytes} > {cfg_total_bytes}",
    );

    // Reconnect B and confirm the queue drains cleanly even after
    // the flood (no orphaned in-flight state).
    harness.reconnect("b").await;
    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(10))
            .await,
        "queue did not drain after overflow flood",
    );
}

// ---------------------------------------------------------------------------
// TODO: Layer-1 backoff test
//
// A faithful Layer-1 "retries-then-succeeds" assertion would require
// wrapping `InProcessTransport` in a `FlakeyTransport` decorator that
// returns 503 for the first N calls then proxies through. The
// Layer-0 `backoff_grows_until_success` unit test inside
// `outbound_queue.rs` already covers the worker's retry-and-backoff
// semantics against a stub transport with deterministic statuses;
// duplicating that here would just re-test the same code path through
// a thicker harness. Revisit once the decorator infra is needed for
// another scenario (e.g. Phase 6.4.1 operator-tunable backoff).
// ---------------------------------------------------------------------------
