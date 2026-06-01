#![cfg(feature = "test-auth")]
//! Phase 1 — §7.3 bootstrap frontier pull (failing-first).
//!
//! Confirms the live "sam2 sees none of sam1's content" bug class from
//! the *recovery* angle: the §8.6 first-contact announce is a
//! fire-and-forget push (see `spawn_first_contact_announce`), so a lost
//! or failed announce leaves the receiver permanently on an empty/stale
//! peer filter with no backstop — exactly the live 18-minute gap where
//! instance1 never held instance2's frontier and so dropped the
//! `sam1 -> sam2` edge at origination.
//!
//! The spec's redundant mechanism is §7.3 step 2: at peering activation
//! *each side* issues `GET /federation/v1/frontier` against the other
//! and applies the returned snapshot locally. That client-side pull is
//! not yet wired — only the server-side §8.5 handler exists. These
//! tests pin the pull entry point (`bootstrap_frontier_pull`) the wiring
//! will add; until it exists this crate fails to compile (red), and once
//! the pull applies the frontier through the shared apply path (which
//! runs §7.6 replay-on-apply) both go green.
//!
//! Handshake is driven over the real HTTP admin surface (preview →
//! peer-request → accept), mirroring `federation_phase11_9_4` and
//! `trust_code` so the activation path under test is the production one.

mod common;

use axum::http::{Method, StatusCode};
use serde_json::json;

use common::federation::MultiInstanceHarness;
use common::{Session, body_json, get_request, json_request, send, setup_admin};
use prismoire_server::federation::frontier::bootstrap_frontier_pull;

const PEERS: &str = "/api/admin/federation/peers";
const PREVIEW: &str = "/api/admin/federation/preview";

fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "pubkey hex must be 64 chars");
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    out
}

/// Spin until `predicate` is true or `timeout_ms` elapses.
async fn poll_until<F, Fut>(timeout_ms: u64, mut predicate: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        if predicate().await {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn row_exists(db: &sqlx::SqlitePool, peer: &[u8]) -> bool {
    let v: Option<i64> =
        sqlx::query_scalar("SELECT applied_version FROM peer_frontiers WHERE peer_pubkey = ?")
            .bind(peer)
            .fetch_optional(db)
            .await
            .unwrap();
    v.is_some()
}

async fn current_version(db: &sqlx::SqlitePool, peer: &[u8]) -> u64 {
    let v: i64 =
        sqlx::query_scalar("SELECT applied_version FROM peer_frontiers WHERE peer_pubkey = ?")
            .bind(peer)
            .fetch_one(db)
            .await
            .unwrap();
    v as u64
}

/// Latest-wins count of `source -> target` trust edges (by pubkey).
async fn count_trust_edge(
    db: &sqlx::SqlitePool,
    source_pk: &[u8; 32],
    target_pk: &[u8; 32],
) -> i64 {
    let s: &[u8] = source_pk;
    let t: &[u8] = target_pk;
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM trust_edges te \
         JOIN users su ON su.id = te.source_user \
         JOIN users tu ON tu.id = te.target_user \
         WHERE su.public_key = ? AND tu.public_key = ? AND te.trust_type = 'trust'",
    )
    .bind(s)
    .bind(t)
    .fetch_one(db)
    .await
    .unwrap()
}

/// Drive the §5.4 handshake (preview → initiate → accept) over the real
/// HTTP admin surface so both §8.6 first-contact activation sites fire.
/// `name_a`/`name_b` become the single local admin on each instance, so
/// neither frontier is empty. Returns the two admin sessions.
async fn http_handshake(
    name_a: &str,
    name_b: &str,
    h: &MultiInstanceHarness,
) -> (Session, Session) {
    let a = h.instance("a");
    let b = h.instance("b");
    let admin_a = setup_admin(&a.router, name_a).await;
    let admin_b = setup_admin(&b.router, name_b).await;

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

    let body = body_json(send(&b.router, get_request(PEERS, Some(&admin_b.cookie))).await).await;
    let a_pubkey = body["peers"][0]["pubkey_hex"].as_str().unwrap().to_string();

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

    (admin_a, admin_b)
}

/// §7.3 bootstrap GET, in isolation: after the first-contact push has
/// landed B's frontier on A, simulate that push having been *lost* by
/// deleting A's stored frontier for B (the live 18-minute-gap state),
/// then assert the explicit bootstrap pull re-acquires it. With no pull
/// wired there is nothing to recover a dropped announce.
#[tokio::test]
async fn bootstrap_pull_reacquires_frontier_after_lost_first_contact_push() {
    let h = MultiInstanceHarness::new(2).await;
    let _ = http_handshake("alice", "bob", &h).await;

    let a = h.instance("a");
    let b = h.instance("b");
    let b_pub = b.state.instance_key.public_bytes().to_vec();
    let b_pub32 = *b.state.instance_key.public_bytes();

    // The §8.6 first-contact push should have delivered B's frontier to
    // A; capture its version as the recovery target.
    assert!(
        poll_until(3_000, || async { row_exists(&a.state.db, &b_pub).await }).await,
        "precondition: first-contact push must land B's frontier on A",
    );
    let pushed_version = current_version(&a.state.db, &b_pub).await;

    // Live failure: the announce from B was lost in flight, so A holds no
    // frontier for B and routes nothing toward it (§7.4 empty-filter).
    sqlx::query("DELETE FROM peer_frontiers WHERE peer_pubkey = ?")
        .bind(&b_pub)
        .execute(&a.state.db)
        .await
        .unwrap();
    assert!(
        !row_exists(&a.state.db, &b_pub).await,
        "precondition: A must hold no frontier for B after the lost push",
    );

    // §7.3 step 2: A pulls B's current frontier directly over the §8.5
    // GET route and applies it. This is the redundant backstop the push
    // lacks.
    let applied = bootstrap_frontier_pull(&a.state, b_pub32)
        .await
        .expect("bootstrap pull succeeds");

    assert!(
        row_exists(&a.state.db, &b_pub).await,
        "BUG: §7.3 bootstrap GET did not re-land B's frontier on A",
    );
    assert!(
        applied >= pushed_version,
        "pulled frontier version ({applied}) must be at least the pushed baseline ({pushed_version})",
    );
}

/// End-to-end live-bug repro: a lost first-contact push strands the
/// reciprocal `sam1 -> sam2` edge on A, and the §7.3 bootstrap pull —
/// applied through the shared frontier path, which runs §7.6
/// replay-on-apply — is what finally delivers it to B.
#[tokio::test]
async fn lost_push_then_bootstrap_pull_delivers_stranded_reciprocal_edge() {
    let h = MultiInstanceHarness::new(2).await;
    let (sam1, sam2) = http_handshake("sam1", "sam2", &h).await;

    let a = h.instance("a");
    let b = h.instance("b");
    let sam1_pk = hex32(&sam1.public_key_hex);
    let sam2_pk = hex32(&sam2.public_key_hex);
    let b_pub = b.state.instance_key.public_bytes().to_vec();
    let b_pub32 = *b.state.instance_key.public_bytes();

    // Let B's first-contact push land, then simulate it having been lost.
    assert!(
        poll_until(3_000, || async { row_exists(&a.state.db, &b_pub).await }).await,
        "precondition: B's first-contact frontier must reach A first",
    );
    sqlx::query("DELETE FROM peer_frontiers WHERE peer_pubkey = ?")
        .bind(&b_pub)
        .execute(&a.state.db)
        .await
        .unwrap();

    // sam2 mints on B; sam1 redeems on A, signing sam1 -> sam2. A holds no
    // frontier for B, so the forwarder finds no interested peer and the
    // edge is stranded on A.
    let code = body_json(
        send(
            &b.router,
            get_request("/api/me/trust-code", Some(&sam2.cookie)),
        )
        .await,
    )
    .await["code"]
        .as_str()
        .expect("code field")
        .to_string();
    let redeem = send(
        &a.router,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&sam1.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(
        redeem.status(),
        StatusCode::OK,
        "sam1 redeems sam2's code on A"
    );

    assert_eq!(
        count_trust_edge(&a.state.db, &sam1_pk, &sam2_pk).await,
        1,
        "sam1 -> sam2 edge is signed and stored on A",
    );
    assert_eq!(
        count_trust_edge(&b.state.db, &sam1_pk, &sam2_pk).await,
        0,
        "edge had no interested peer at creation, so it is not yet on B",
    );

    // §7.3 bootstrap pull recovers B's frontier on A; applying it runs
    // §7.6 replay-on-apply, which re-pushes the stranded edge to B.
    bootstrap_frontier_pull(&a.state, b_pub32)
        .await
        .expect("bootstrap pull succeeds");

    let delivered = poll_until(3_000, || async {
        count_trust_edge(&b.state.db, &sam1_pk, &sam2_pk).await >= 1
    })
    .await;
    assert!(
        delivered,
        "BUG: bootstrap pull + replay-on-apply did not deliver the stranded sam1 -> sam2 edge to B",
    );
}
