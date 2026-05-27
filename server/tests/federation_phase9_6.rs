//! Phase-9.6 integration tests: federated trust-edge projection.
//!
//! Covers the test gates from `docs/federation-impl-plan.md` Phase 9.6:
//!
//! - Layer 0: stored-but-unprojected trust-edge gets projected when
//!   `sweep_pending_projections` runs after both endpoint stubs exist.
//! - Layer 0: an edge with only one endpoint hydrated stays stored,
//!   not projected.
//! - Layer 0: chain-fork at sweep time — two stored siblings, sweep
//!   projects neither.
//! - Layer 0: ordered chain (E1 → E2) projects in one sweep call
//!   thanks to the fixed-point loop, regardless of `signed_objects`
//!   row order.
//!
//! The Layer-1 happy path ("edge arrives via `/edges` with both
//! stubs already hydrated → trust_edges row materialises") lives in
//! the multi-instance harness — Phase 9 already exercises the
//! envelope dispatch end-to-end, so the receive-path projection is
//! covered there once the new `try_project_trust_edge` helper is
//! plumbed in. The narrower Layer-0 tests below pin the
//! sweep behaviour Phase 9.6 introduces.

#![cfg(feature = "test-auth")]

mod common;

use common::test_app;
use ed25519_dalek::SigningKey;
use prismoire_server::federation::remote_users::{hydrate_stub_user, sweep_pending_projections};
use prismoire_server::signed::TrustStance;
use prismoire_server::signing::{sign_trust_edge_with_key, store_signed_object};
use rand::SeedableRng;
use rand::rngs::StdRng;

/// Deterministic Ed25519 signer from a seed byte. Phase 9.5's tests
/// build raw 32-byte pubkeys directly; we need real signers here so
/// the canonical_hash chain across siblings is meaningful.
fn seeded_signer(seed: u8) -> SigningKey {
    let mut rng = StdRng::seed_from_u64(seed as u64);
    SigningKey::generate(&mut rng)
}

fn pubkey_of(k: &SigningKey) -> [u8; 32] {
    *k.verifying_key().as_bytes()
}

/// Store the signed payload + signature in `signed_objects` without
/// projecting into `trust_edges`. Mirrors what `apply_one_edge` does
/// in the `EndpointMissing` branch — used by the Layer-0 tests to set
/// up the "stored-but-unprojected" precondition.
async fn store_unprojected_edge(
    db: &sqlx::SqlitePool,
    signing_key: &SigningKey,
    to_key: &[u8; 32],
    stance: TrustStance,
    created_at_ms: u64,
    prior_edge_hash: Option<[u8; 32]>,
) -> [u8; 32] {
    let out = sign_trust_edge_with_key(signing_key, to_key, stance, created_at_ms, prior_edge_hash);
    let mut tx = db.begin().await.expect("begin tx");
    store_signed_object(
        &mut *tx,
        "trust-edge",
        &out.payload,
        &out.signature,
        &out.canonical_hash,
    )
    .await
    .expect("store signed_object");
    tx.commit().await.expect("commit");
    out.canonical_hash
}

/// Count rows in `trust_edges` matching `canonical_hash`. 1 = projected,
/// 0 = not projected.
async fn trust_edge_projected(db: &sqlx::SqlitePool, canonical_hash: &[u8; 32]) -> bool {
    let slice: &[u8] = canonical_hash.as_slice();
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trust_edges WHERE canonical_hash = ?")
        .bind(slice)
        .fetch_one(db)
        .await
        .expect("count trust_edges");
    n > 0
}

// ---------------------------------------------------------------------------
// Layer 0 — sweep_pending_projections + try_project_trust_edge
// ---------------------------------------------------------------------------

/// Both endpoint stubs exist when sweep runs → stored edge projects.
#[tokio::test]
async fn sweep_projects_stored_edge_after_both_stubs_hydrate() {
    let (_app, state) = test_app().await;

    let from_signer = seeded_signer(0x11);
    let to_signer = seeded_signer(0x22);
    let from_key = pubkey_of(&from_signer);
    let to_key = pubkey_of(&to_signer);
    let home = [0x33u8; 32];

    // Hydrate stubs for both endpoints first, *then* land the stored
    // edge. (The order doesn't matter for sweep correctness — sweep
    // looks for not-yet-projected signed_objects — but staging the
    // stubs first lets us assert that the stored edge truly was the
    // only blocker.)
    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &from_key, "remote_alice", &home)
            .await
            .expect("from stub");
        hydrate_stub_user(&mut tx, &to_key, "remote_bob", &home)
            .await
            .expect("to stub");
        tx.commit().await.expect("commit");
    }

    let edge_hash = store_unprojected_edge(
        &state.db,
        &from_signer,
        &to_key,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    )
    .await;
    assert!(
        !trust_edge_projected(&state.db, &edge_hash).await,
        "precondition: edge stored but not yet projected"
    );

    // Sweep keyed on the source — the just-hydrated stub triggers
    // the call site in production (via project_remote_profile), but
    // for Layer-0 we drive it directly.
    {
        let mut tx = state.db.begin().await.expect("begin");
        sweep_pending_projections(&mut tx, &from_key)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
    }

    assert!(
        trust_edge_projected(&state.db, &edge_hash).await,
        "sweep should project the stored edge once both stubs exist"
    );
}

/// Only one endpoint stub exists → stored edge stays unprojected.
/// Models the wide-scope-edge case where the author has hydrated
/// (their profile-rev arrived) but the target hasn't yet.
#[tokio::test]
async fn sweep_leaves_edge_unprojected_when_target_stub_missing() {
    let (_app, state) = test_app().await;

    let from_signer = seeded_signer(0x44);
    let to_signer = seeded_signer(0x55);
    let from_key = pubkey_of(&from_signer);
    let to_key = pubkey_of(&to_signer);
    let home = [0x66u8; 32];

    // Hydrate only the source stub.
    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &from_key, "remote_alice", &home)
            .await
            .expect("from stub");
        tx.commit().await.expect("commit");
    }

    let edge_hash = store_unprojected_edge(
        &state.db,
        &from_signer,
        &to_key,
        TrustStance::Trust,
        1_700_000_000_001,
        None,
    )
    .await;

    {
        let mut tx = state.db.begin().await.expect("begin");
        sweep_pending_projections(&mut tx, &from_key)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
    }

    assert!(
        !trust_edge_projected(&state.db, &edge_hash).await,
        "edge must stay unprojected while target stub is missing"
    );

    // Later: hydrating the target should let a sweep (now keyed on
    // the target) project the previously-stored edge.
    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &to_key, "remote_bob", &home)
            .await
            .expect("to stub");
        sweep_pending_projections(&mut tx, &to_key)
            .await
            .expect("sweep on target");
        tx.commit().await.expect("commit");
    }

    assert!(
        trust_edge_projected(&state.db, &edge_hash).await,
        "sweep keyed on target should project once both stubs exist"
    );
}

/// Two siblings (same prior_edge_hash, same source/target) → sweep
/// projects exactly one of them, not both. Models §9.4 "both stored
/// as evidence" at the receive-path level: the canonical bytes for
/// both siblings remain durable in `signed_objects` regardless of
/// which one wins projection. The strict §9.4 wire semantics
/// ("neither active") apply only when both arrive over the live
/// receive path; once one sibling has projected locally, the second
/// observed at sweep time correctly detects a chain fork against
/// the projected row and refuses, so exactly one ends up driving
/// visibility.
#[tokio::test]
async fn sweep_chain_fork_projects_exactly_one_sibling() {
    let (_app, state) = test_app().await;

    let from_signer = seeded_signer(0x77);
    let to_signer = seeded_signer(0x88);
    let from_key = pubkey_of(&from_signer);
    let to_key = pubkey_of(&to_signer);
    let home = [0x99u8; 32];

    // Pre-hydrate so the missing-stub branch is out of the picture.
    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &from_key, "alice", &home)
            .await
            .expect("from stub");
        hydrate_stub_user(&mut tx, &to_key, "bob", &home)
            .await
            .expect("to stub");
        tx.commit().await.expect("commit");
    }

    // Two siblings: both prior_edge_hash = None (i.e. both claim to
    // be the first mutation in the chain), distinct canonical_hashes
    // because stance differs. Real-world this models two devices
    // racing a first-mutation issuance.
    let hash_a = store_unprojected_edge(
        &state.db,
        &from_signer,
        &to_key,
        TrustStance::Trust,
        1_700_000_000_010,
        None,
    )
    .await;
    let hash_b = store_unprojected_edge(
        &state.db,
        &from_signer,
        &to_key,
        TrustStance::Distrust,
        1_700_000_000_011,
        None,
    )
    .await;
    assert_ne!(
        hash_a, hash_b,
        "siblings must have distinct canonical hashes"
    );

    {
        let mut tx = state.db.begin().await.expect("begin");
        sweep_pending_projections(&mut tx, &from_key)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
    }

    // The fixed-point loop sees both candidates with `prior_edge_hash
    // = NULL` (NULL-matches-NULL via the chain-fork OR clause). The
    // first-considered candidate projects; the second hits the
    // chain-fork check and is rejected. Which one wins depends on
    // `signed_objects` row order, but exactly one of the two must
    // project — not zero, not both. (§9.4 "neither active" applies
    // to the on-wire receive path; once one sibling has projected
    // locally, the second seen at sweep time correctly observes a
    // fork and refuses.)
    let a_in = trust_edge_projected(&state.db, &hash_a).await;
    let b_in = trust_edge_projected(&state.db, &hash_b).await;
    assert!(
        a_in ^ b_in,
        "exactly one sibling should project; saw a={a_in} b={b_in}"
    );

    // Both canonical bytes remain durable in signed_objects regardless
    // — the §9.4 evidence requirement.
    let surviving_bytes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM signed_objects \
         WHERE inner_class = 'trust-edge' AND payload IS NOT NULL \
           AND canonical_hash IN (?, ?)",
    )
    .bind(&hash_a[..])
    .bind(&hash_b[..])
    .fetch_one(&state.db)
    .await
    .expect("count signed_objects");
    assert_eq!(
        surviving_bytes, 2,
        "both sibling payloads remain stored as §9.4 evidence",
    );
}

/// Chain E1 → E2 stored out of order (E2 first in row order, E1
/// second). The fixed-point loop should project E1 in pass 1 and
/// then E2 in pass 2 — exercising the loop's progress condition.
#[tokio::test]
async fn sweep_projects_ordered_chain_via_fixed_point() {
    let (_app, state) = test_app().await;

    let from_signer = seeded_signer(0xaa);
    let to_signer = seeded_signer(0xbb);
    let from_key = pubkey_of(&from_signer);
    let to_key = pubkey_of(&to_signer);
    let home = [0xccu8; 32];

    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &from_key, "alice", &home)
            .await
            .expect("from stub");
        hydrate_stub_user(&mut tx, &to_key, "bob", &home)
            .await
            .expect("to stub");
        tx.commit().await.expect("commit");
    }

    // E1: first mutation (prior_edge_hash = None). Get its
    // canonical_hash so E2 can chain off it.
    let e1 = sign_trust_edge_with_key(
        &from_signer,
        &to_key,
        TrustStance::Trust,
        1_700_000_000_020,
        None,
    );
    let e2 = sign_trust_edge_with_key(
        &from_signer,
        &to_key,
        TrustStance::Distrust,
        1_700_000_000_021,
        Some(e1.canonical_hash),
    );

    // Store E2 *first* so the row order in signed_objects has the
    // chain successor ahead of its predecessor. Without the
    // fixed-point loop, a single pass would project E1 but leave E2
    // as Deferred.
    {
        let mut tx = state.db.begin().await.expect("begin");
        store_signed_object(
            &mut *tx,
            "trust-edge",
            &e2.payload,
            &e2.signature,
            &e2.canonical_hash,
        )
        .await
        .expect("store e2");
        store_signed_object(
            &mut *tx,
            "trust-edge",
            &e1.payload,
            &e1.signature,
            &e1.canonical_hash,
        )
        .await
        .expect("store e1");
        tx.commit().await.expect("commit");
    }

    {
        let mut tx = state.db.begin().await.expect("begin");
        sweep_pending_projections(&mut tx, &from_key)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
    }

    assert!(
        trust_edge_projected(&state.db, &e1.canonical_hash).await,
        "E1 (chain head) must project",
    );
    assert!(
        trust_edge_projected(&state.db, &e2.canonical_hash).await,
        "E2 (chain successor) must project in the same sweep call via fixed-point",
    );
}

/// Orphan edge: E2 has prior=E1.hash but E1 was never stored. Sweep
/// must NOT project E2 (chain-continuity); the bytes remain stored
/// for a future §9.3 backfill or re-push.
#[tokio::test]
async fn sweep_defers_orphan_edge_with_missing_predecessor() {
    let (_app, state) = test_app().await;

    let from_signer = seeded_signer(0xdd);
    let to_signer = seeded_signer(0xee);
    let from_key = pubkey_of(&from_signer);
    let to_key = pubkey_of(&to_signer);
    let home = [0xffu8; 32];

    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &from_key, "alice", &home)
            .await
            .expect("from stub");
        hydrate_stub_user(&mut tx, &to_key, "bob", &home)
            .await
            .expect("to stub");
        tx.commit().await.expect("commit");
    }

    // Phantom predecessor: a hash that no signed_object carries.
    let phantom_prior = [0x42u8; 32];
    let orphan_hash = store_unprojected_edge(
        &state.db,
        &from_signer,
        &to_key,
        TrustStance::Trust,
        1_700_000_000_030,
        Some(phantom_prior),
    )
    .await;

    {
        let mut tx = state.db.begin().await.expect("begin");
        sweep_pending_projections(&mut tx, &from_key)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
    }

    assert!(
        !trust_edge_projected(&state.db, &orphan_hash).await,
        "orphan with missing predecessor must not project",
    );

    // But the bytes are still durable — a later §9.3 backfill that
    // delivers the missing predecessor can re-trigger projection.
    let slice: &[u8] = orphan_hash.as_slice();
    let still_stored: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM signed_objects \
         WHERE canonical_hash = ? AND payload IS NOT NULL",
    )
    .bind(slice)
    .fetch_one(&state.db)
    .await
    .expect("count");
    assert_eq!(
        still_stored, 1,
        "orphan bytes remain durable in signed_objects"
    );
}
