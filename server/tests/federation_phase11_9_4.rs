#![cfg(feature = "test-auth")]
//! Phase 11.9.4 — frontier-announce production wiring (§8.6 / §8.7 / §7.6).
//!
//! Pins the three frontier-change-driven triggers this phase added a
//! production caller for, using the in-process `MultiInstanceHarness`
//! (two real `AppState`s exchanging real §6-signed announces over the
//! transport — the Layer-2 scenario minus real TLS):
//!
//! - **Closure key-set diff (Task 12 + Trigger 3 input).**
//!   `refresh_local_frontier_detailed` reports `changed` and the
//!   `new − old` author set when a local user expands the closure, and
//!   is a no-op on an unchanged re-run.
//! - **Trigger 1 — §8.6 first-contact.** Completing the handshake over
//!   the real HTTP admin surface fires a first-contact announce from
//!   *both* activation sites: the responder's `accept_peer` handler and
//!   the initiator's `handle_peer_response` callback handler. Asserted
//!   by both sides ending up with a `peer_frontiers` row for the other.
//! - **Trigger 2 — §8.7 change-fanout.** A trust-graph change that
//!   expands the local frontier, fed to `frontier_fanout_loop`, fans
//!   out a re-announce that advances the peer's stored version.
//!
//! Trigger 3's *content arrival* (proactive by-author backfill seeding
//! a newly-frontier'd author's existing posts) only becomes meaningful
//! once a *cross-instance* author enters the frontier — that scenario
//! is owned by the Phase 11.9.5 trust-code tests. The backfill plumbing
//! itself (`paginate_peer_backfill` / `ingest_content_object` /
//! `list_active_peers`) is already covered by the §13.3 recovery tests.

mod common;

use std::sync::Arc;
use std::time::Duration;

use http::{Method, StatusCode};
use serde_json::json;

use common::federation::MultiInstanceHarness;
use common::{
    Session, body_json, get_request, json_request, refresh_trust_graph, send, setup_admin,
    signup_as,
};
use prismoire_server::federation::frontier::{
    frontier_fanout_loop, refresh_local_frontier_detailed,
};

const PEERS: &str = "/api/admin/federation/peers";
const PREVIEW: &str = "/api/admin/federation/preview";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Drive the full §5.4 handshake (preview → initiate → accept) over the
/// real HTTP admin surface so *both* §8.6 first-contact activation
/// sites fire: `b` accepts via `accept_peer`, and the accept callback
/// reaches `a`'s `handle_peer_response`. Each instance gets one local
/// admin user, so neither frontier is empty. Returns the two admin
/// sessions.
async fn http_handshake_to_active(h: &MultiInstanceHarness) -> (Session, Session) {
    let a = h.instance("a");
    let b = h.instance("b");
    let admin_a = setup_admin(&a.router, "alice").await;
    let admin_b = setup_admin(&b.router, "bob").await;

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

/// Poll up to ~2s for a `peer_frontiers` row keyed by `peer` to exist.
async fn poll_until_row(db: &sqlx::SqlitePool, peer: &[u8]) -> bool {
    for _ in 0..100 {
        let exists = sqlx::query!(
            "SELECT applied_version FROM peer_frontiers WHERE peer_pubkey = ?",
            peer,
        )
        .fetch_optional(db)
        .await
        .unwrap()
        .is_some();
        if exists {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

async fn current_version(db: &sqlx::SqlitePool, peer: &[u8]) -> u64 {
    sqlx::query!(
        "SELECT applied_version FROM peer_frontiers WHERE peer_pubkey = ?",
        peer,
    )
    .fetch_one(db)
    .await
    .unwrap()
    .applied_version as u64
}

/// Poll up to ~2s for the stored version of `peer` to exceed `baseline`.
async fn poll_until_version_above(db: &sqlx::SqlitePool, peer: &[u8], baseline: u64) -> bool {
    for _ in 0..100 {
        if let Some(r) = sqlx::query!(
            "SELECT applied_version FROM peer_frontiers WHERE peer_pubkey = ?",
            peer,
        )
        .fetch_optional(db)
        .await
        .unwrap()
            && (r.applied_version as u64) > baseline
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// Task 12 + Trigger 3 input: the first refresh after a local user is
/// created reports `changed`, bumps the version, and names that user as
/// a newly-added content author. A second refresh with no change is a
/// no-op with an empty added set.
#[tokio::test]
async fn refresh_detailed_reports_added_authors_and_version_bump() {
    let h = MultiInstanceHarness::new(1).await;
    let a = h.instance("a");
    let alice = setup_admin(&a.router, "alice").await;
    refresh_trust_graph(&a.state).await;

    let r1 = refresh_local_frontier_detailed(&a.state)
        .await
        .expect("refresh");
    assert!(r1.changed, "creating a local user changes the frontier");
    assert!(r1.frontier.version >= 1, "version bumped on change");
    assert_eq!(
        r1.added_visible_keys.len(),
        1,
        "exactly alice newly entered the content closure",
    );
    assert_eq!(
        to_hex(&r1.added_visible_keys[0]),
        alice.public_key_hex.to_lowercase(),
        "the added author is alice's signing pubkey",
    );

    let r2 = refresh_local_frontier_detailed(&a.state)
        .await
        .expect("refresh #2");
    assert!(!r2.changed, "an unchanged re-run is a no-op");
    assert!(
        r2.added_visible_keys.is_empty(),
        "no new authors on an unchanged refresh",
    );
}

/// Trigger 1 (§8.6): completing the handshake over HTTP fires a
/// first-contact announce from *both* activation sites, so each side
/// ends up holding a `peer_frontiers` row for the other and leaves
/// empty-filter routing mode.
#[tokio::test]
async fn handshake_fires_first_contact_announce_on_both_sides() {
    let h = MultiInstanceHarness::new(2).await;
    let _ = http_handshake_to_active(&h).await;

    let a = h.instance("a");
    let b = h.instance("b");
    let a_pub = a.state.instance_key.public_bytes().to_vec();
    let b_pub = b.state.instance_key.public_bytes().to_vec();

    // a's handle_peer_response → first-contact announce a→b.
    assert!(
        poll_until_row(&b.state.db, &a_pub).await,
        "b did not receive a's first-contact announce (initiator-side hook)",
    );
    // b's accept_peer handler → first-contact announce b→a.
    assert!(
        poll_until_row(&a.state.db, &b_pub).await,
        "a did not receive b's first-contact announce (responder-side hook)",
    );
}

/// Trigger 2 (§8.7): a trust-graph change that expands a's frontier,
/// fed to the fanout worker, re-announces to the active peer and
/// advances the version b has stored for a.
#[tokio::test]
async fn frontier_change_fans_out_reannounce_to_active_peers() {
    let h = MultiInstanceHarness::new(2).await;
    let (admin_a, _admin_b) = http_handshake_to_active(&h).await;

    let a = h.instance("a");
    let b = h.instance("b");
    let a_pub = a.state.instance_key.public_bytes().to_vec();

    // Wait for the handshake's first-contact announce to settle, then
    // capture the version b currently holds for a as the baseline.
    assert!(
        poll_until_row(&b.state.db, &a_pub).await,
        "first-contact baseline row never landed",
    );
    let baseline = current_version(&b.state.db, &a_pub).await;

    // Expand a's content closure: invite a new local user under alice.
    let _carol = signup_as(&a.router, &admin_a, "carol").await;
    refresh_trust_graph(&a.state).await;

    // Run the §8.7 change-fanout worker and signal a completed rebuild.
    let frontier_dirty = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(frontier_fanout_loop(
        a.state.clone(),
        frontier_dirty.clone(),
    ));
    frontier_dirty.notify_one();

    assert!(
        poll_until_version_above(&b.state.db, &a_pub, baseline).await,
        "change-fanout did not re-announce a's expanded frontier to b (baseline={baseline})",
    );
}
