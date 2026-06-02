#![cfg(feature = "test-auth")]
//! Frontier-sync integration tests (§7 / §8).
//!
//! Consolidates four formerly-separate phase files into the single
//! protocol surface they all exercise — instance-to-instance frontier
//! announce / delta / get plus its production wiring:
//!
//! - **§8 announce / delta / get handler mechanics.** An active peer's
//!   `POST /frontier/announce` persists a `peer_frontiers` row; a
//!   same-version replay is idempotent; `POST /frontier/delta` OR-masks
//!   the stored bytes when `prev_version` matches and 409s with the
//!   stored `current_version` otherwise (including `current_version = 0`
//!   when no prior announce exists); `GET /frontier` returns the local
//!   snapshot and short-circuits to 304 on a matching cursor. The §8.3
//!   `age_ceilings` snapshot persists / replaces wholesale, and a §8.4
//!   ceiling-only delta merges + tightens (an entirely-empty delta is
//!   rejected `empty_delta`).
//! - **§7.2 outbound-mode wire signal.** Receiving an announce whose
//!   `visible_filter` covers ≥ `HIGH_THRESHOLD` of the receiver's local
//!   users promotes the stored `outbound_mode` to `'all'`; coverage
//!   below `LOW_THRESHOLD` demotes it back; a fresh instance with zero
//!   local users never bogus-promotes.
//! - **§8.6 / §8.7 / §7.6 production wiring.**
//!   `refresh_local_frontier_detailed` reports the `new − old` author
//!   set and version bump on a closure change (no-op on an unchanged
//!   re-run); completing the handshake over the real HTTP admin surface
//!   fires a first-contact announce from *both* activation sites; a
//!   trust-graph change that expands the local frontier fans out a
//!   re-announce that advances the peer's stored version.
//! - **§7.3 bootstrap pull.** A lost first-contact push leaves the
//!   receiver on an empty/stale peer filter; the explicit
//!   `bootstrap_frontier_pull` GET re-acquires the frontier, and
//!   applying it runs §7.6 replay-on-apply, which delivers a stranded
//!   reciprocal edge to the peer.
//!
//! The §7.4 `peers_interested_in` routing path itself is covered by the
//! unit tests in `src/federation/routing.rs`; the round-trip through
//! `peer_frontiers` is asserted here via the direct DB reads below.
//!
//! Convergence-driven scenarios use the [`settle`] harness driver rather
//! than spawning `frontier_fanout_loop` + polling: `settle` pumps the
//! trust-graph rebuild, an inline `frontier_fanout_once` pass (cold-start
//! suppression disabled), and the outbound drain across all instances
//! until quiescent — deterministic, no spawn-loop race.

mod common;

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::Value;
use http::{Method, StatusCode};
use serde_json::json;
use sqlx::SqlitePool;
use uuid::Uuid;

use prismoire_server::federation::bloom::BloomFilter;
use prismoire_server::federation::frontier::{
    FilterSpec, FrontierAnnounce, FrontierDelta, FrontierSnapshot, bootstrap_frontier_pull,
    operator_announce_frontier, refresh_local_frontier_detailed,
};
use prismoire_server::federation::routing::Mode;
use prismoire_server::federation::transport::FederationTransport;

use common::federation::{
    MultiInstanceHarness, establish_active_peering, send_envelope_signed,
    send_envelope_signed_split, settle,
};
use common::{
    Session, body_json, get_request, json_request, refresh_trust_graph, send, setup_admin,
    signup_as,
};

const PEERS: &str = "/api/admin/federation/peers";
const PREVIEW: &str = "/api/admin/federation/preview";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "pubkey hex must be 64 chars");
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    out
}

// ---------------------------------------------------------------------------
// §8 announce / delta / get handler mechanics
//
// Single-instance request/response tests: they assert directly on the
// handler response and the resulting `peer_frontiers` row, so no
// convergence driver (`settle`) is involved.
// ---------------------------------------------------------------------------

/// Announce reaches the handler, the envelope-verifier accepts it
/// because the sender is an active peer, and the row lands in
/// `peer_frontiers` keyed by the sender's pubkey.
#[tokio::test]
async fn announce_persists_a_peer_frontiers_row() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let a = harness.instance("a");
    let b = harness.instance("b");
    let b_pub = *b.state.instance_key.public_bytes();

    // A announces *its own* frontier to B. The operator helper
    // refreshes the local snapshot before dispatch, so this also
    // exercises the BFS / bloom path end-to-end (empty trust graph
    // here → empty bloom but a valid wire body).
    let version = operator_announce_frontier(
        &a.state,
        &a.state.instance_key,
        &(a.transport.clone() as Arc<dyn FederationTransport>),
        b_pub,
    )
    .await
    .expect("operator_announce_frontier");

    // The row B persisted should be keyed by A's pubkey, not B's.
    let a_pub_bytes: &[u8] = a.state.instance_key.public_bytes();
    let row = sqlx::query!(
        "SELECT applied_version, visible_family, expansion_family FROM peer_frontiers WHERE peer_pubkey = ?",
        a_pub_bytes,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("peer_frontiers row");
    assert_eq!(row.applied_version as u64, version);
    assert_eq!(row.visible_family, "prismoire-bloom-v1");
    assert_eq!(row.expansion_family, "prismoire-bloom-v1");
}

/// A same-version replay of the announce is idempotent (200 OK, same
/// cursor) and does not bump the stored version. The §8.3 spec requires
/// "same `version` is a no-op".
#[tokio::test]
async fn announce_at_same_version_is_idempotent() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Hand-roll the announce body so we can dispatch the *exact same
    // wire bytes* twice (the operator helper would refresh and
    // potentially bump the version between calls).
    let body = FrontierAnnounce {
        version: 1_000,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: empty_filter_spec(),
        expansion_filter: empty_filter_spec(),
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
    .encode();

    let resp1 = send_announce_envelope(&harness, "a", "b", &body).await;
    assert_eq!(resp1.status, StatusCode::OK);
    let resp2 = send_announce_envelope(&harness, "a", "b", &body).await;
    assert_eq!(resp2.status, StatusCode::OK);
    assert_eq!(
        resp1.cursor, resp2.cursor,
        "same-version replay returns the same cursor"
    );

    // And the row's applied_version is still 1000, not bumped.
    let a_pub: &[u8] = a.state.instance_key.public_bytes();
    let stored = sqlx::query_scalar!(
        "SELECT applied_version FROM peer_frontiers WHERE peer_pubkey = ?",
        a_pub,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("applied_version");
    assert_eq!(stored as u64, 1_000);
}

/// A delta OR-masked on top of an existing announce updates the stored
/// bytes and bumps `applied_version`.
#[tokio::test]
async fn delta_or_mask_updates_filter_bytes_and_version() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Announce a baseline at version 5.
    let baseline = FrontierAnnounce {
        version: 5,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: empty_filter_spec(),
        expansion_filter: empty_filter_spec(),
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
    .encode();
    let announce_resp = send_announce_envelope(&harness, "a", "b", &baseline).await;
    assert_eq!(announce_resp.status, StatusCode::OK);

    // Send a delta at version 6 that flips one byte in the content
    // mask. Filter shape is m=64 → 8 bytes; mask shape matches.
    let mut mask = vec![0u8; 8];
    mask[3] = 0b1010_1010;
    let delta_body = FrontierDelta {
        prev_version: 5,
        new_version: 6,
        visible_mask: Some(mask.clone()),
        expansion_mask: None,
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
    .encode();
    let delta_resp = send_delta_envelope(&harness, "a", "b", &delta_body).await;
    assert_eq!(delta_resp.status, StatusCode::OK);

    let a_pub: &[u8] = a.state.instance_key.public_bytes();
    let row = sqlx::query!(
        "SELECT applied_version, visible_bytes FROM peer_frontiers WHERE peer_pubkey = ?",
        a_pub,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("peer_frontiers row");
    assert_eq!(row.applied_version as u64, 6, "version bumped to 6");
    assert_eq!(
        row.visible_bytes[3], 0b1010_1010,
        "byte index 3 reflects the OR-mask"
    );
}

/// A delta whose `prev_version` does not match the stored
/// `applied_version` returns 409 with a `current_version` field set to
/// what we *do* have.
#[tokio::test]
async fn delta_with_stale_prev_version_returns_409_with_current() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // Establish a baseline at version 10.
    let body = FrontierAnnounce {
        version: 10,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: empty_filter_spec(),
        expansion_filter: empty_filter_spec(),
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
    .encode();
    assert_eq!(
        send_announce_envelope(&harness, "a", "b", &body)
            .await
            .status,
        StatusCode::OK
    );

    // Now send a delta claiming prev=7 (stale).
    let delta = FrontierDelta {
        prev_version: 7,
        new_version: 11,
        visible_mask: Some(vec![0u8; 8]),
        expansion_mask: None,
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
    .encode();
    let resp = send_delta_envelope(&harness, "a", "b", &delta).await;
    assert_eq!(resp.status, StatusCode::CONFLICT);
    assert_eq!(
        cbor_current_version(&resp.body),
        10,
        "409 carries our actual applied_version"
    );
}

/// A delta with no prior announce returns 409 with `current_version = 0`
/// so the sender knows it must re-announce.
#[tokio::test]
async fn delta_without_prior_announce_returns_409_with_zero() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let delta = FrontierDelta {
        prev_version: 0,
        new_version: 1,
        visible_mask: Some(vec![0u8; 8]),
        expansion_mask: None,
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
    .encode();
    let resp = send_delta_envelope(&harness, "a", "b", &delta).await;
    assert_eq!(resp.status, StatusCode::CONFLICT);
    assert_eq!(cbor_current_version(&resp.body), 0);
}

/// A peer pulling `GET /frontier` receives the responder's *own* current
/// snapshot, then a follow-up GET with the returned cursor
/// short-circuits to 304.
#[tokio::test]
async fn get_frontier_returns_snapshot_then_304_on_matching_cursor() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // First GET: cold cursor, returns the snapshot.
    let resp = send_frontier_get(&harness, "a", "b", None).await;
    assert_eq!(resp.status, StatusCode::OK);
    let snapshot = FrontierSnapshot::decode(&resp.body).expect("decode snapshot");
    let cursor = snapshot.cursor.clone();
    assert!(!cursor.is_empty(), "snapshot carries a cursor");

    // Second GET with the cursor encoded base64-url: 304.
    let cursor_b64 = URL_SAFE_NO_PAD.encode(&cursor);
    let resp2 = send_frontier_get(&harness, "a", "b", Some(&cursor_b64)).await;
    assert_eq!(resp2.status, StatusCode::NOT_MODIFIED);
}

/// §8.3: an announce carrying `age_ceilings` persists one
/// `peer_frontier_age_ceilings` row per cleaved root, keyed by the
/// sender's pubkey, with the supplied cutoffs intact.
#[tokio::test]
async fn announce_persists_age_ceilings() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let root1 = [0x11u8; 32];
    let root2 = [0x22u8; 32];
    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(root1, 1_600_000_000_000u64);
    ceilings.insert(root2, 1_650_000_000_000u64);

    let body = FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: empty_filter_spec(),
        expansion_filter: empty_filter_spec(),
        mode: Mode::Filtered,
        age_ceilings: ceilings,
    }
    .encode();
    assert_eq!(
        send_announce_envelope(&harness, "a", "b", &body)
            .await
            .status,
        StatusCode::OK
    );

    let a_pub: &[u8] = a.state.instance_key.public_bytes();
    let rows = sqlx::query!(
        "SELECT root_key, cutoff FROM peer_frontier_age_ceilings \
         WHERE peer_pubkey = ? ORDER BY root_key",
        a_pub,
    )
    .fetch_all(&b.state.db)
    .await
    .expect("ceiling rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].root_key, root1.to_vec());
    assert_eq!(rows[0].cutoff, 1_600_000_000_000);
    assert_eq!(rows[1].root_key, root2.to_vec());
    assert_eq!(rows[1].cutoff, 1_650_000_000_000);
}

/// §8.3: `/announce` carries the *full* cleave snapshot, so a later
/// announce replaces the stored ceiling set wholesale — a root dropped
/// from the new announce is cleared, not retained.
#[tokio::test]
async fn announce_replaces_age_ceilings_snapshot() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pub: &[u8] = a.state.instance_key.public_bytes();

    let root1 = [0x11u8; 32];
    let root2 = [0x22u8; 32];
    let root3 = [0x33u8; 32];

    let mut first = std::collections::BTreeMap::new();
    first.insert(root1, 1_600_000_000_000u64);
    first.insert(root2, 1_650_000_000_000u64);
    let body1 = FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: empty_filter_spec(),
        expansion_filter: empty_filter_spec(),
        mode: Mode::Filtered,
        age_ceilings: first,
    }
    .encode();
    assert_eq!(
        send_announce_envelope(&harness, "a", "b", &body1)
            .await
            .status,
        StatusCode::OK
    );

    // Second announce (newer version) lists only root3.
    let mut second = std::collections::BTreeMap::new();
    second.insert(root3, 1_550_000_000_000u64);
    let body2 = FrontierAnnounce {
        version: 2,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: empty_filter_spec(),
        expansion_filter: empty_filter_spec(),
        mode: Mode::Filtered,
        age_ceilings: second,
    }
    .encode();
    assert_eq!(
        send_announce_envelope(&harness, "a", "b", &body2)
            .await
            .status,
        StatusCode::OK
    );

    let rows = sqlx::query!(
        "SELECT root_key, cutoff FROM peer_frontier_age_ceilings \
         WHERE peer_pubkey = ? ORDER BY root_key",
        a_pub,
    )
    .fetch_all(&b.state.db)
    .await
    .expect("ceiling rows");
    assert_eq!(rows.len(), 1, "snapshot replace dropped root1/root2");
    assert_eq!(rows[0].root_key, root3.to_vec());
    assert_eq!(rows[0].cutoff, 1_550_000_000_000);
}

/// §8.4: a ceiling-only delta (no masks) is accepted and merges its
/// roots over the stored set — adding new roots and tightening existing
/// ones (last-writer-wins).
#[tokio::test]
async fn delta_merges_and_tightens_age_ceilings() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pub: &[u8] = a.state.instance_key.public_bytes();

    let root1 = [0x11u8; 32];
    let root2 = [0x22u8; 32];

    // Baseline announce at v5 with root1 at a loose cutoff.
    let mut base = std::collections::BTreeMap::new();
    base.insert(root1, 1_700_000_000_000u64);
    let baseline = FrontierAnnounce {
        version: 5,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: empty_filter_spec(),
        expansion_filter: empty_filter_spec(),
        mode: Mode::Filtered,
        age_ceilings: base,
    }
    .encode();
    assert_eq!(
        send_announce_envelope(&harness, "a", "b", &baseline)
            .await
            .status,
        StatusCode::OK
    );

    // Delta at v6: no masks, only ceilings — tighten root1, add root2.
    let mut delta_ceilings = std::collections::BTreeMap::new();
    delta_ceilings.insert(root1, 1_500_000_000_000u64);
    delta_ceilings.insert(root2, 1_650_000_000_000u64);
    let delta = FrontierDelta {
        prev_version: 5,
        new_version: 6,
        visible_mask: None,
        expansion_mask: None,
        mode: Mode::Filtered,
        age_ceilings: delta_ceilings,
    }
    .encode();
    assert_eq!(
        send_delta_envelope(&harness, "a", "b", &delta).await.status,
        StatusCode::OK
    );

    let rows = sqlx::query!(
        "SELECT root_key, cutoff FROM peer_frontier_age_ceilings \
         WHERE peer_pubkey = ? ORDER BY root_key",
        a_pub,
    )
    .fetch_all(&b.state.db)
    .await
    .expect("ceiling rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].root_key, root1.to_vec());
    assert_eq!(rows[0].cutoff, 1_500_000_000_000, "root1 tightened");
    assert_eq!(rows[1].root_key, root2.to_vec());
    assert_eq!(rows[1].cutoff, 1_650_000_000_000, "root2 added");
}

/// §8.4: a delta carrying neither masks nor age_ceilings is rejected as
/// `empty_delta`.
#[tokio::test]
async fn delta_with_no_masks_or_ceilings_returns_empty_delta() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let delta = FrontierDelta {
        prev_version: 0,
        new_version: 1,
        visible_mask: None,
        expansion_mask: None,
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
    .encode();
    let resp = send_delta_envelope(&harness, "a", "b", &delta).await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    let body: Value = ciborium::de::from_reader(resp.body.as_slice()).expect("cbor parse");
    let map = match body {
        Value::Map(m) => m,
        _ => panic!("expected CBOR map"),
    };
    let code = map
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(t), Value::Text(c)) if t == "error" => Some(c.clone()),
            _ => None,
        })
        .expect("error field");
    assert_eq!(code, "empty_delta");
}

// ---------------------------------------------------------------------------
// §7.2 outbound-mode wire signal fold-in
//
// Each test drives the wire path end-to-end: B builds a §8.3
// `FrontierAnnounce`, signs and dispatches it; A's handler reads coverage
// against its own seeded local-user pubkeys, runs `classify_mode`, and
// persists `inbound_mode` / `outbound_mode`. The assertion is a direct DB
// read of the `peer_frontiers` row keyed by B's pubkey.
// ---------------------------------------------------------------------------

/// Number of local active users seeded into the receiver's DB. Ten is
/// well above the smallest set yielding meaningful coverage ratios at the
/// §7.2 0.80 / 0.60 thresholds and keeps each test cheap.
const LOCAL_USERS: usize = 10;
const TEST_K: u32 = 7;
const TEST_M: u32 = 1024;
const TEST_FPR: f32 = 0.01;

/// Bootstrap pitfall regression (review finding): on a fresh instance
/// with zero local active users, the receiver-side `classify_mode` call
/// against an empty local-key set would historically promote every peer
/// to `All` on first announce (because `BloomFilter::coverage` of zero
/// keys returns 1.0). The guard in `classify_mode` preserves the
/// conservative `Filtered` default per §7.2 "fresh peering never starts
/// in all-mode."
#[tokio::test]
async fn fresh_instance_with_no_local_users_stays_in_filtered() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Deliberately do *not* seed local users on A. B sends an announce
    // whose visible_filter is densely populated — the kind of input that
    // would maximise the bogus-promote bait.
    let mut fat_filter =
        BloomFilter::new_empty(TEST_K, TEST_M, 16, TEST_FPR).expect("bloom params in range");
    for i in 0..16u8 {
        fat_filter.insert(&[i + 100; 32]);
    }
    let body = FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: FilterSpec::from_bloom(&fat_filter),
        expansion_filter: empty_coverage_filter(),
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
    .encode();
    let (status, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let b_pub: &[u8] = b.state.instance_key.public_bytes();
    assert_eq!(
        read_outbound_mode(&a.state.db, b_pub).await,
        "filtered",
        "no local users → no coverage signal → outbound_mode must stay 'filtered'"
    );
}

/// Receiving an announce whose `visible_filter` fully covers the
/// local-user set promotes the receiver's stored `outbound_mode` for that
/// sender to `'all'`. `inbound_mode` mirrors the sender's wire claim
/// (Filtered) — pinned so a column-swap regression surfaces immediately.
#[tokio::test]
async fn announce_with_full_coverage_promotes_outbound_to_all() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Seed A's local users so its `fetch_local_user_pubkeys` returns a
    // known set; build B's announce visible_filter to cover all of them.
    let a_local_keys = seed_local_users(&a.state.db).await;
    let covering = covering_filter(&a_local_keys);

    // B → A: announce at version 1 with the covering filter. We stamp
    // `mode: Filtered` on the wire — the receiver-side outbound mode is
    // classified independently from coverage, regardless of what the
    // sender claims.
    let body = FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: covering,
        expansion_filter: empty_coverage_filter(),
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
    .encode();
    let (status, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "announce accepted");

    let b_pub: &[u8] = b.state.instance_key.public_bytes();
    assert_eq!(
        read_outbound_mode(&a.state.db, b_pub).await,
        "all",
        "high coverage must promote outbound_mode to 'all'"
    );
    assert_eq!(
        read_inbound_mode(&a.state.db, b_pub).await,
        "filtered",
        "inbound_mode reflects sender's wire claim, not local coverage"
    );
}

/// An `all`-mode pair demotes back to `'filtered'` when a follow-up
/// announce's `visible_filter` drops the receiver's coverage below
/// `LOW_THRESHOLD`.
#[tokio::test]
async fn follow_up_announce_with_no_coverage_demotes_outbound_to_filtered() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let a_local_keys = seed_local_users(&a.state.db).await;
    let b_pub: &[u8] = b.state.instance_key.public_bytes();

    // Step 1 — promote: announce at version 1 with the covering filter.
    let promote_body = FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: covering_filter(&a_local_keys),
        expansion_filter: empty_coverage_filter(),
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
    .encode();
    let (status, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &promote_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "promote announce accepted");
    assert_eq!(
        read_outbound_mode(&a.state.db, b_pub).await,
        "all",
        "precondition: pair sits in 'all' before the demote step"
    );

    // Step 2 — demote: a fresh announce at version 2 carrying an empty
    // visible_filter. Coverage drops to 0.0 → below LOW_THRESHOLD (0.60)
    // → `classify_mode(All, …)` returns Filtered.
    let demote_body = FrontierAnnounce {
        version: 2,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: empty_coverage_filter(),
        expansion_filter: empty_coverage_filter(),
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
    .encode();
    let (status, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &demote_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "demote announce accepted");

    assert_eq!(
        read_outbound_mode(&a.state.db, b_pub).await,
        "filtered",
        "coverage below LOW_THRESHOLD must demote outbound_mode to 'filtered'"
    );
}

// ---------------------------------------------------------------------------
// §8.6 / §8.7 / §7.6 production wiring
// ---------------------------------------------------------------------------

/// Task 12 + Trigger 3 input: the first refresh after a local user is
/// created reports `changed`, bumps the version, and names that user as a
/// newly-added content author. A second refresh with no change is a no-op
/// with an empty added set.
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
/// first-contact announce from *both* activation sites, so each side ends
/// up holding a `peer_frontiers` row for the other. `settle` drives the
/// fire-and-forget announce fanout + apply to quiescence.
#[tokio::test]
async fn handshake_fires_first_contact_announce_on_both_sides() {
    let h = MultiInstanceHarness::new(2).await;
    let _ = http_handshake_to_active("alice", "bob", &h).await;
    settle(&h).await;

    let a = h.instance("a");
    let b = h.instance("b");
    let a_pub = a.state.instance_key.public_bytes().to_vec();
    let b_pub = b.state.instance_key.public_bytes().to_vec();

    // a's handle_peer_response → first-contact announce a→b.
    assert!(
        row_exists(&b.state.db, &a_pub).await,
        "b did not receive a's first-contact announce (initiator-side hook)",
    );
    // b's accept_peer handler → first-contact announce b→a.
    assert!(
        row_exists(&a.state.db, &b_pub).await,
        "a did not receive b's first-contact announce (responder-side hook)",
    );
}

/// Trigger 2 (§8.7): a trust-graph change that expands a's frontier fans
/// out a re-announce that advances the version b has stored for a.
/// `settle` pumps the change-fanout pass deterministically (replacing the
/// old spawn-`frontier_fanout_loop`-and-poll pattern).
#[tokio::test]
async fn frontier_change_fans_out_reannounce_to_active_peers() {
    let h = MultiInstanceHarness::new(2).await;
    let (admin_a, _admin_b) = http_handshake_to_active("alice", "bob", &h).await;

    let a = h.instance("a");
    let b = h.instance("b");
    let a_pub = a.state.instance_key.public_bytes().to_vec();

    // Settle the handshake's first-contact announce, then capture the
    // version b currently holds for a as the baseline.
    settle(&h).await;
    assert!(
        row_exists(&b.state.db, &a_pub).await,
        "first-contact baseline row never landed",
    );
    let baseline = current_version(&b.state.db, &a_pub).await;

    // Expand a's content closure: invite a new local user under alice.
    let _carol = signup_as(&a.router, &admin_a, "carol").await;
    refresh_trust_graph(&a.state).await;

    // Drive the §8.7 change-fanout to quiescence; b's stored version for
    // a must advance past the baseline.
    settle(&h).await;
    assert!(
        current_version(&b.state.db, &a_pub).await > baseline,
        "change-fanout did not re-announce a's expanded frontier to b (baseline={baseline})",
    );
}

// ---------------------------------------------------------------------------
// §7.3 bootstrap pull
//
// The §8.6 first-contact announce is a fire-and-forget push: a lost or
// failed announce leaves the receiver permanently on an empty/stale peer
// filter with no backstop. §7.3 step 2's redundant mechanism — each side
// issuing `GET /frontier` against the other — is the recovery path
// `bootstrap_frontier_pull` implements, asserted here in isolation.
// ---------------------------------------------------------------------------

/// §7.3 bootstrap GET, in isolation: after the first-contact push has
/// landed B's frontier on A, simulate that push having been *lost* by
/// deleting A's stored frontier for B (the live 18-minute-gap state),
/// then assert the explicit bootstrap pull re-acquires it.
#[tokio::test]
async fn bootstrap_pull_reacquires_frontier_after_lost_first_contact_push() {
    let h = MultiInstanceHarness::new(2).await;
    let _ = http_handshake_to_active("alice", "bob", &h).await;

    let a = h.instance("a");
    let b = h.instance("b");
    let b_pub = b.state.instance_key.public_bytes().to_vec();
    let b_pub32 = *b.state.instance_key.public_bytes();

    // The §8.6 first-contact push should have delivered B's frontier to
    // A; settle the fire-and-forget announce, then capture its version as
    // the recovery target.
    settle(&h).await;
    assert!(
        row_exists(&a.state.db, &b_pub).await,
        "precondition: first-contact push must land B's frontier on A",
    );
    let pushed_version = current_version(&a.state.db, &b_pub).await;

    // Live failure: the announce from B was lost in flight, so A holds no
    // frontier for B and routes nothing toward it (§7.4 empty-filter).
    //
    // Determinism note: activation fires *two* spawn-and-forget writers of
    // `peer_frontiers[B]` on A — the inbound §8.6 announce (already
    // landed) and A's own §7.3 bootstrap pull (`spawn_bootstrap_frontier_pull`,
    // a GET to B). The latter can still be in flight and would race our
    // DELETE, re-landing the row. Fence B out of the transport first so no
    // *new* pull can fetch B's frontier, then delete in a settle loop to
    // absorb a pull that fetched just before the disconnect and is
    // mid-write.
    h.disconnect("b").await;
    let cleared = poll_until_cleared(&a.state.db, &b_pub).await;
    assert!(
        cleared,
        "precondition: A must hold no frontier for B after the lost push",
    );
    h.reconnect("b").await;

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
/// replay-on-apply — is what finally delivers it to B. `settle` drains
/// the replay-on-apply re-push.
#[tokio::test]
async fn lost_push_then_bootstrap_pull_delivers_stranded_reciprocal_edge() {
    let h = MultiInstanceHarness::new(2).await;
    let (sam1, sam2) = http_handshake_to_active("sam1", "sam2", &h).await;

    let a = h.instance("a");
    let b = h.instance("b");
    let sam1_pk = hex32(&sam1.public_key_hex);
    let sam2_pk = hex32(&sam2.public_key_hex);
    let b_pub = b.state.instance_key.public_bytes().to_vec();
    let b_pub32 = *b.state.instance_key.public_bytes();

    // Let B's first-contact push land, then simulate it having been lost.
    settle(&h).await;
    assert!(
        row_exists(&a.state.db, &b_pub).await,
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
    // §7.6 replay-on-apply, which enqueues a re-push of the stranded edge
    // to B. `settle` drains that outbound push.
    bootstrap_frontier_pull(&a.state, b_pub32)
        .await
        .expect("bootstrap pull succeeds");
    settle(&h).await;

    assert!(
        count_trust_edge(&b.state.db, &sam1_pk, &sam2_pk).await >= 1,
        "BUG: bootstrap pull + replay-on-apply did not deliver the stranded sam1 -> sam2 edge to B",
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal empty FilterSpec compatible with the announce CHECK
/// constraints. Uses `bloom::recommend_k(m, 0)` so the fixture matches
/// the `k` value production-side `build_bloom_from_keys` would emit for an
/// empty user set.
fn empty_filter_spec() -> FilterSpec {
    let m: u32 = 64;
    let k = prismoire_server::federation::bloom::recommend_k(m, 0);
    let bloom = BloomFilter::new_empty(k, m, 0, 0.01).unwrap();
    FilterSpec::from_bloom(&bloom)
}

/// Larger empty FilterSpec (m=1024, k=7) used by the §7.2 coverage tests
/// so a non-empty seeded local-key set scores 0.0 coverage — comfortably
/// below `LOW_THRESHOLD`.
fn empty_coverage_filter() -> FilterSpec {
    let bloom = BloomFilter::new_empty(TEST_K, TEST_M, 0, TEST_FPR).expect("bloom params in range");
    FilterSpec::from_bloom(&bloom)
}

/// Insert `LOCAL_USERS` rows into `users` with deterministic 32-byte
/// pubkeys ([1; 32], [2; 32], …). Returns the pubkeys so the test can
/// build a covering bloom against the exact same key set the receiver
/// queries in `fetch_local_user_pubkeys`.
async fn seed_local_users(db: &SqlitePool) -> Vec<[u8; 32]> {
    let mut keys = Vec::with_capacity(LOCAL_USERS);
    for i in 0..LOCAL_USERS {
        let key = [(i + 1) as u8; 32];
        let id = Uuid::new_v4().to_string();
        let display = format!("local-user-{i}");
        let pk_slice: &[u8] = &key;
        sqlx::query!(
            "INSERT INTO users (id, display_name, display_name_skeleton, signup_method, status, public_key) \
             VALUES (?, ?, ?, 'invite', 'active', ?)",
            id,
            display,
            display,
            pk_slice,
        )
        .execute(db)
        .await
        .expect("insert local user");
        keys.push(key);
    }
    keys
}

/// Build a `FilterSpec` whose underlying bloom contains every key in
/// `keys` (100% coverage against the seeded local-user set).
fn covering_filter(keys: &[[u8; 32]]) -> FilterSpec {
    let mut bloom = BloomFilter::new_empty(TEST_K, TEST_M, keys.len() as u64, TEST_FPR)
        .expect("bloom params in range");
    for k in keys {
        bloom.insert(k);
    }
    FilterSpec::from_bloom(&bloom)
}

/// Read `outbound_mode` on the receiver's `peer_frontiers` row keyed by
/// the sender's pubkey. Panics if no row exists.
async fn read_outbound_mode(db: &SqlitePool, sender_pubkey: &[u8]) -> String {
    sqlx::query_scalar!(
        "SELECT outbound_mode FROM peer_frontiers WHERE peer_pubkey = ?",
        sender_pubkey,
    )
    .fetch_one(db)
    .await
    .expect("peer_frontiers row for sender")
}

/// Read `inbound_mode` on the receiver's `peer_frontiers` row.
/// `inbound_mode` mirrors whatever the sender stamped on the wire —
/// independent of the local coverage-based outbound classification.
async fn read_inbound_mode(db: &SqlitePool, sender_pubkey: &[u8]) -> String {
    sqlx::query_scalar!(
        "SELECT inbound_mode FROM peer_frontiers WHERE peer_pubkey = ?",
        sender_pubkey,
    )
    .fetch_one(db)
    .await
    .expect("peer_frontiers row for sender")
}

/// Whether a `peer_frontiers` row keyed by `peer` exists.
async fn row_exists(db: &SqlitePool, peer: &[u8]) -> bool {
    sqlx::query!(
        "SELECT applied_version FROM peer_frontiers WHERE peer_pubkey = ?",
        peer,
    )
    .fetch_optional(db)
    .await
    .unwrap()
    .is_some()
}

async fn current_version(db: &SqlitePool, peer: &[u8]) -> u64 {
    sqlx::query!(
        "SELECT applied_version FROM peer_frontiers WHERE peer_pubkey = ?",
        peer,
    )
    .fetch_one(db)
    .await
    .unwrap()
    .applied_version as u64
}

/// Latest-wins count of `source -> target` trust edges (by pubkey).
async fn count_trust_edge(db: &SqlitePool, source_pk: &[u8; 32], target_pk: &[u8; 32]) -> i64 {
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

/// Repeatedly DELETE the `peer_frontiers[peer]` row and confirm it stays
/// gone, absorbing a spawn-and-forget pull that fetched just before the
/// caller disconnected the peer and is mid-write. Returns whether the row
/// was cleared within ~3s.
async fn poll_until_cleared(db: &SqlitePool, peer: &[u8]) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(3_000);
    loop {
        sqlx::query("DELETE FROM peer_frontiers WHERE peer_pubkey = ?")
            .bind(peer)
            .execute(db)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if !row_exists(db, peer).await {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
    }
}

/// Drive the full §5.4 handshake (preview → initiate → accept) over the
/// real HTTP admin surface so *both* §8.6 first-contact activation sites
/// fire: `b` accepts via `accept_peer`, and the accept callback reaches
/// `a`'s `handle_peer_response`. `name_a`/`name_b` become the single local
/// admin on each instance, so neither frontier is empty. Returns the two
/// admin sessions.
async fn http_handshake_to_active(
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

/// Tuple of `(status, body, cursor)` from an envelope-signed announce
/// dispatch.
struct AnnounceResponse {
    status: StatusCode,
    cursor: Vec<u8>,
}

async fn send_announce_envelope(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    body: &[u8],
) -> AnnounceResponse {
    let (status, body) = send_envelope_signed(
        harness,
        from,
        to,
        Method::POST,
        "/federation/v1/frontier/announce",
        body,
    )
    .await;
    let cursor = if status == StatusCode::OK {
        extract_cursor_from_announce_ok(&body)
    } else {
        Vec::new()
    };
    AnnounceResponse { status, cursor }
}

struct DeltaResponse {
    status: StatusCode,
    body: Vec<u8>,
}

async fn send_delta_envelope(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    body: &[u8],
) -> DeltaResponse {
    let (status, body) = send_envelope_signed(
        harness,
        from,
        to,
        Method::POST,
        "/federation/v1/frontier/delta",
        body,
    )
    .await;
    DeltaResponse { status, body }
}

struct GetResponse {
    status: StatusCode,
    body: Vec<u8>,
}

async fn send_frontier_get(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    since: Option<&str>,
) -> GetResponse {
    // The envelope is signed over the path *without* the query string
    // (§6.5 step 9 normalises to `req.uri().path()`); the dispatched URI
    // carries the query so the `since` param reaches the handler.
    let signed_path = "/federation/v1/frontier";
    let dispatch_uri = match since {
        Some(s) => format!("/federation/v1/frontier?since={s}"),
        None => signed_path.to_string(),
    };
    let (status, body) = send_envelope_signed_split(
        harness,
        from,
        to,
        Method::GET,
        signed_path,
        &dispatch_uri,
        &[],
    )
    .await;
    GetResponse { status, body }
}

/// Pull the cursor field out of an announce 200 body
/// (`{ applied_version, cursor }`).
fn extract_cursor_from_announce_ok(body: &[u8]) -> Vec<u8> {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse announce body");
    let Value::Map(m) = v else {
        panic!("expected CBOR map");
    };
    for (k, v) in m {
        if let Value::Text(t) = &k
            && t == "cursor"
            && let Value::Bytes(b) = v
        {
            return b;
        }
    }
    panic!("no cursor field in announce body");
}

/// Pull the `current_version` field out of a 409 delta-conflict CBOR map.
fn cbor_current_version(body: &[u8]) -> u64 {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("expected CBOR map");
    };
    m.iter()
        .find_map(|(k, v)| match k {
            Value::Text(t) if t == "current_version" => match v {
                Value::Integer(i) => Some(u64::try_from(*i).expect("u64 cast")),
                _ => None,
            },
            _ => None,
        })
        .expect("current_version field")
}
