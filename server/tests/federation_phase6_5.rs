//! Phase-6.5 Layer-1 integration tests: §7.2 mode wire signal fold-in.
//!
//! Pins the Phase-6.5 done-when criteria from
//! `docs/federation-impl-plan.md`:
//!
//! - Receiving an announce whose `visible_filter` covers ≥
//!   `HIGH_THRESHOLD` of the receiver's local users promotes the
//!   receiver's `outbound_mode` for that sender to `'all'`.
//! - A follow-up announce whose `visible_filter` covers <
//!   `LOW_THRESHOLD` demotes a previously-`all` pair back to
//!   `'filtered'`.
//!
//! Both tests drive the wire path end-to-end through the
//! `MultiInstanceHarness`: B builds a §8.3 `FrontierAnnounce`, signs
//! and dispatches via the shared in-process transport, A's handler
//! reads coverage against its own local-user pubkeys (inserted as
//! fixtures), runs `classify_mode`, and persists both `inbound_mode`
//! and `outbound_mode` on the `peer_frontiers` row keyed by B's
//! pubkey. The assertion is a direct DB read of that row.
//!
//! These tests deliberately stop at the persisted-mode boundary —
//! exercising `peers_interested_in`'s skip-the-bloom behaviour is
//! already covered by the routing-module unit tests; the new surface
//! Phase 6.5 introduces is the *transition* path, and that's what
//! this file pins.

#![cfg(feature = "test-auth")]

mod common;

use http::{Method, StatusCode};
use prismoire_server::federation::bloom::BloomFilter;
use prismoire_server::federation::frontier::{FilterSpec, FrontierAnnounce};
use prismoire_server::federation::routing::Mode;
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};

/// Bloom shape used by both fixtures. Large enough (m=1024, k=7) that
/// inserting 10 known keys gives effectively zero false positives, so
/// `coverage(empty_filter, local_keys) == 0.0` and
/// `coverage(filter_of_all_locals, local_keys) == 1.0` are both
/// reliable signals across the HIGH / LOW thresholds.
const TEST_K: u32 = 7;
const TEST_M: u32 = 1024;
const TEST_FPR: f32 = 0.01;

/// Number of local active users we seed into the receiver's DB. Ten is
/// well above the smallest set that yields meaningful coverage ratios
/// at the §7.2 0.80 / 0.60 thresholds and keeps each test cheap.
const LOCAL_USERS: usize = 10;

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
/// `keys`. With the spec's m=1024, this gives 100% coverage against
/// the seeded local-user set.
fn covering_filter(keys: &[[u8; 32]]) -> FilterSpec {
    let mut bloom = BloomFilter::new_empty(TEST_K, TEST_M, keys.len() as u64, TEST_FPR)
        .expect("bloom params in range");
    for k in keys {
        bloom.insert(k);
    }
    FilterSpec::from_bloom(&bloom)
}

/// Build a `FilterSpec` whose underlying bloom contains nothing. The
/// receiver's coverage scan against any non-empty local-key set is 0.0,
/// which sits comfortably below `LOW_THRESHOLD` (0.60) and demotes a
/// previously-promoted pair.
fn empty_filter() -> FilterSpec {
    let bloom = BloomFilter::new_empty(TEST_K, TEST_M, 0, TEST_FPR).expect("bloom params in range");
    FilterSpec::from_bloom(&bloom)
}

/// Helper: read `outbound_mode` on the receiver's `peer_frontiers` row
/// keyed by the sender's pubkey. Panics if no row exists — every test
/// here drives at least one announce before asserting, so a missing
/// row is a test bug, not a tolerated state.
async fn read_outbound_mode(db: &SqlitePool, sender_pubkey: &[u8]) -> String {
    sqlx::query_scalar!(
        "SELECT outbound_mode FROM peer_frontiers WHERE peer_pubkey = ?",
        sender_pubkey,
    )
    .fetch_one(db)
    .await
    .expect("peer_frontiers row for sender")
}

/// Helper: read `inbound_mode` on the receiver's `peer_frontiers` row.
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

/// Bootstrap pitfall regression (review finding): on a fresh instance
/// with zero local active users, the receiver-side `classify_mode`
/// call against an empty local-key set would historically promote
/// every peer to `All` on first announce (because
/// `BloomFilter::coverage` of zero keys returns 1.0). The guard in
/// `classify_mode` preserves the conservative `Filtered` default per
/// §7.2 "fresh peering never starts in all-mode."
#[tokio::test]
async fn fresh_instance_with_no_local_users_stays_in_filtered() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Deliberately do *not* seed local users on A. B sends an announce
    // whose visible_filter is densely populated — the kind of input
    // that would maximise the bogus-promote bait.
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
        expansion_filter: empty_filter(),
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

/// Done-when (1) of Phase 6.5: receiving an announce whose
/// `visible_filter` fully covers the local-user set promotes the
/// receiver's stored `outbound_mode` for that sender to `'all'`.
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
        expansion_filter: empty_filter(),
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

    // A persisted the row keyed by B's pubkey; `outbound_mode` flipped
    // to 'all' because coverage (1.0) ≥ HIGH_THRESHOLD (0.80).
    let b_pub: &[u8] = b.state.instance_key.public_bytes();
    assert_eq!(
        read_outbound_mode(&a.state.db, b_pub).await,
        "all",
        "high coverage must promote outbound_mode to 'all'"
    );
    // `inbound_mode` mirrors what B stamped on the wire (Filtered) —
    // pin that too so a regression that swapped the two columns surfaces
    // immediately rather than silently flipping inbound to 'all'.
    assert_eq!(
        read_inbound_mode(&a.state.db, b_pub).await,
        "filtered",
        "inbound_mode reflects sender's wire claim, not local coverage"
    );
}

/// Done-when (2) of Phase 6.5: an `all`-mode pair demotes back to
/// `'filtered'` when a follow-up announce's `visible_filter` drops the
/// receiver's coverage below `LOW_THRESHOLD`.
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
        expansion_filter: empty_filter(),
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
        visible_filter: empty_filter(),
        expansion_filter: empty_filter(),
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
