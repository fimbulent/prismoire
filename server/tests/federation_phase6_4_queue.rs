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
use prismoire_server::federation::routing::Mode;
use serde_json::json;
use sqlx::SqlitePool;

use common::federation::{
    FlakeyTransport, MultiInstanceHarness, establish_active_peering, send_envelope_signed,
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
        mode: Mode::Filtered,
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
// Test 2: backoff retries until the inner transport recovers
// ---------------------------------------------------------------------------

/// A Layer-1 reproduction of the deterministic Layer-0
/// `backoff_grows_until_success` unit test in `outbound_queue.rs`.
/// Scripts A's outbound transport to return 503 for the first three
/// drain attempts, then proxies through to B's real router. With the
/// `test_fast` backoff (initial=10ms, max=100ms) the worker reaches
/// success in well under the 5-second cap; we assert that all three
/// scripted failures were consumed (i.e. the retry path actually ran)
/// and that B ultimately received the post-rev.
#[tokio::test]
async fn backoff_retries_then_succeeds() {
    use prismoire_server::federation::outbound_queue::OutboundQueueConfig;

    // Build A with a FlakeyTransport wrapping its InProcessTransport.
    // The script starts empty so the active-peering handshake proxies
    // through cleanly; we push 503s only after handshake completes.
    let mut harness = MultiInstanceHarness::new(0).await;
    let script = std::sync::Arc::new(std::sync::Mutex::new(None));
    let script_setter = script.clone();
    harness
        .spawn_with_outbound_config_and_transport(
            "a",
            OutboundQueueConfig::test_fast(),
            move |inner| {
                let (flakey, handle) = FlakeyTransport::new(inner);
                *script_setter.lock().unwrap() = Some(handle);
                std::sync::Arc::new(flakey)
            },
        )
        .await;
    harness.spawn("b").await;
    let script = script.lock().unwrap().clone().expect("flakey script set");

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
    assert_eq!(status, StatusCode::OK);

    let a = harness.instance("a");
    let alice = setup_admin(&a.router, "alice").await;

    // Script three transient failures BEFORE originating the post.
    // The outbound queue worker will then see 503 → backoff → 503 →
    // backoff → 503 → backoff → real dispatch. Pushing after the
    // create-thread call would race the worker, which usually
    // succeeds in the first dispatch before the test code wakes up.
    script.push_n(3, StatusCode::SERVICE_UNAVAILABLE);

    let (_thread_id, _op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "retry", "op body").await;

    // The thread-create call enqueued the post-rev push; wait_idle
    // covers the retry + backoff cycle.
    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(5))
            .await,
        "queue did not drain under scripted-503 retries",
    );

    assert_eq!(
        script.remaining(),
        0,
        "all three scripted 503s should have been consumed by retries",
    );

    let b = harness.instance("b");
    let post_rev = count_class(&b.state.db, "post-rev").await;
    assert_eq!(
        post_rev, 1,
        "B should have received the OP post-rev after retries succeeded",
    );
}

// ---------------------------------------------------------------------------
// Test 3: per-peer object cap evicts oldest under sustained flood
// ---------------------------------------------------------------------------

/// Sharpened overflow test (Phase 6.4.1 supersedes Phase 6.4's soft
/// tripwire). Builds a harness with `objects_per_peer = 5`, disconnects
/// B, originates 10 replies on A, asserts:
///   1. A's queue depth to B never exceeds 5 (the per-peer cap).
///   2. After reconnect, B receives at most 5 of the 10 replies
///      (drop-oldest semantics — the first replies are evicted as
///      newer ones arrive past the cap).
///   3. The §10.5 pull-backfill backstop heals the gap (deferred to
///      Phase 8 — until then, the dropped items are simply lost from
///      this test's vantage point, which is acceptable for the eviction
///      assertion).
#[tokio::test]
async fn overflow_evicts_oldest_per_peer() {
    use prismoire_server::federation::outbound_queue::OutboundQueueConfig;

    // Shrunken cap: only 5 queued objects per peer. Everything else
    // stays at the spec defaults (translated through the TOML config
    // type) so this remains a realistic shape minus the one knob.
    let mut shrunken = OutboundQueueConfig::test_fast();
    shrunken.objects_per_peer = 5;

    let harness =
        common::federation::MultiInstanceHarness::new_with_outbound_config(2, shrunken).await;
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
    assert_eq!(status, StatusCode::OK);

    let a = harness.instance("a");
    let b_peer_id = harness.instance("b").peer_id;
    let alice = setup_admin(&a.router, "alice").await;
    let (thread_id, op_id) =
        create_thread_as(&a.router, &alice.cookie, "general", "overflow", "op body").await;
    let _ = a
        .state
        .outbound_queues
        .wait_idle(Duration::from_secs(2))
        .await;

    harness.disconnect("b").await;

    // Originate 10 replies — twice the cap. Each new enqueue past the
    // 5th must drop the oldest pending item from A's queue to B.
    const N: usize = 10;
    for i in 0..N {
        create_reply_as(
            &a.router,
            &alice.cookie,
            &thread_id,
            &op_id,
            &format!("evict {i}"),
        )
        .await;
    }

    let (depth_objects, _) = a.state.outbound_queues.depth_for(b_peer_id.as_bytes());
    assert!(
        depth_objects <= 5,
        "per-peer object cap (5) violated: depth={depth_objects}",
    );

    // Reconnect B and let what's left drain. With the cap at 5, B
    // sees at most 5 post-revs (plus the OP from before the
    // disconnect). The dropped replies are lost until Phase 8's
    // §10.5 pull-backfill lands.
    harness.reconnect("b").await;
    assert!(
        a.state
            .outbound_queues
            .wait_idle(Duration::from_secs(5))
            .await,
        "queue did not drain after reconnect",
    );

    let b = harness.instance("b");
    let post_rev = count_class(&b.state.db, "post-rev").await;
    assert!(
        post_rev <= 6,
        "B should receive at most cap+OP = 6 post-revs (got {post_rev}); \
         the cap evicted older replies before B reconnected",
    );
    assert!(
        post_rev >= 1,
        "B should at minimum still have the OP from before the disconnect (got {post_rev})",
    );

    // The load-bearing claim is drop-OLDEST, not just "stays under
    // the cap". With objects_per_peer = 5 and N = 10, the queue
    // should retain the last 5 replies ("evict 5".."evict 9") and
    // evict the first 5 ("evict 0".."evict 4"). Phase 6 doesn't
    // project post_revisions on receivers (the wire bytes land in
    // signed_objects but remote-user hydration is deferred), so map
    // body → canonical_hash on A (origin) then check which of those
    // hashes arrived in B's signed_objects.
    let body_to_hash: Vec<(String, Vec<u8>)> = sqlx::query!(
        "SELECT pr.body AS \"body!: String\", pr.canonical_hash AS \"canonical_hash!: Vec<u8>\" \
         FROM post_revisions pr \
         JOIN posts p ON p.id = pr.post_id \
         WHERE p.parent IS NOT NULL AND pr.body LIKE 'evict %'",
    )
    .fetch_all(&a.state.db)
    .await
    .expect("query A's reply hashes")
    .into_iter()
    .map(|r| (r.body, r.canonical_hash))
    .collect();
    assert_eq!(
        body_to_hash.len(),
        N,
        "A should hold all 10 originated replies"
    );

    let mut survivors: Vec<usize> = Vec::new();
    for (body, hash) in &body_to_hash {
        let n: usize = body
            .strip_prefix("evict ")
            .and_then(|n| n.parse().ok())
            .expect("evict-N body");
        let arrived = sqlx::query_scalar!(
            "SELECT 1 AS \"x!: i64\" FROM signed_objects \
             WHERE canonical_hash = ? AND inner_class = 'post-rev'",
            hash,
        )
        .fetch_optional(&b.state.db)
        .await
        .expect("query B for reply hash")
        .is_some();
        if arrived {
            survivors.push(n);
        }
    }
    survivors.sort_unstable();
    assert_eq!(
        survivors,
        vec![5, 6, 7, 8, 9],
        "drop-oldest should retain the newer 5 replies, not the older 5",
    );
}
