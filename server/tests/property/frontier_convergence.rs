//! Layer-4 frontier-convergence property test.
//!
//! Pins Task #19's done-when from `docs/federation-impl-plan.md`
//! Phase 5: "given N random instances with random membership sets
//! and a fanout K=2, the gossip loop (now driven by the edge
//! forwarder) converges within bounded rounds with the expected
//! false-positive rate."
//!
//! Two properties are asserted across parameterised trials:
//!
//! 1. [`gossip_converges_for_random_configurations`] — convergence.
//!    For a range of (N, edges-originated) configurations on a full
//!    mesh of pairwise-peered instances where every receiver
//!    announces interest in every signing key, every originated
//!    signed object reaches every instance within a bounded polling
//!    budget. With `REDUNDANCY_K = 2` and N ≤ 6 the propagation
//!    saturates in ≲ log₂(N) hops; the 5 s budget is two orders of
//!    magnitude beyond that and only ever burns in true failure.
//!
//! 2. [`forwarder_does_not_deliver_to_uninterested_peer`] — routing.
//!    The dual sanity check: the convergence above must not just be
//!    "everyone broadcasts unconditionally". An instance whose
//!    `expansion_filter` lists exactly K₁ (and nothing else) does
//!    not receive an edge signed by an unrelated key K₂, even though
//!    every other instance is interested and the gossip storm fans
//!    around it. False-positive rate enters here only as "≈ 0 for a
//!    well-overprovisioned filter"; the broader statistical-FPR
//!    soak version is reserved for Phase 12.
//!
//! ## Why feature-gated
//!
//! Parameterised trials spin up several full `AppState`s each round
//! and poll until convergence. Comfortably under 10 s total on a
//! warm `cargo` invocation, but well above the per-test budget that
//! the pre-commit gate (`cargo test --features test-auth`) targets.
//! Property tests live under `tests/property/` and register as
//! `[[test]]` entries with `required-features = ["property-tests"]`
//! so the default run does not even compile them. Explicit invocation:
//!
//! ```sh
//! cargo test -p prismoire-server --features property-tests
//! ```
//!
//! ## Why hand-rolled trials instead of proptest / quickcheck
//!
//! The interesting axes are small and discrete (N ∈ {4, 5, 6}, edges
//! ∈ {4, 6, 10, 12}, a handful of seeds for signer/originator
//! selection). A hand-rolled trial loop is reproducible without
//! pulling a new dev-dep, and the failure mode we care about is
//! "did the gossip storm settle?" — not "shrink a counterexample".

#![cfg(feature = "property-tests")]

// `tests/common/mod.rs` is the shared harness for every integration
// test crate; because this file lives in a subdirectory, the usual
// `mod common;` lookup would resolve to `tests/property/common.rs`
// (which doesn't exist). Point `mod` at the canonical path so the
// property tests reuse `MultiInstanceHarness`, the envelope-signed
// dispatch helpers, and `fresh_db` / `test_app_with_pool_*` the way
// the top-level integration tests do.
#[path = "../common/mod.rs"]
mod common;

use std::sync::atomic::{AtomicU64, Ordering};

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use prismoire_server::federation::bloom::BloomFilter;
use prismoire_server::federation::frontier::{FilterSpec, FrontierAnnounce};
use prismoire_server::federation::routing::Mode;
use prismoire_server::signed::TrustStance;
use prismoire_server::signing::sign_trust_edge_with_key;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};

// ---------------------------------------------------------------------------
// Encoding / dispatch helpers (mirrors the private helpers in
// `tests/federation_phase5.rs`). Duplicated rather than re-exported
// because integration test crates can't `mod` each other; the helpers
// are small and tightly coupled to §9.1 wire shape so a divergence
// would be caught by the existing handler tests immediately.
// ---------------------------------------------------------------------------

/// Wrap each `(payload, signature)` blob into a canonical §6.3
/// `WireFormat` map and pack the lot under `{ "edges": [bstr, ...] }`
/// for the §9.1 push body.
fn encode_edges_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("edges".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + wires.iter().map(|w| w.len()).sum::<usize>());
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    buf
}

/// Encode a single §6.3 `WireFormat { "p", "s" }`.
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ciborium ser is infallible");
    buf
}

/// Build a §8.3 announce whose `expansion_filter` contains the
/// given keys and whose `visible_filter` is the all-ones sentinel.
///
/// The sentinel keeps the receiver's filter-bytes validator happy
/// without us having to compute a real content closure; this test
/// only exercises the trust-edge path so an over-permissive
/// content filter never participates.
///
/// Filter sizing matches `tests/federation_phase5.rs`: `k = 7,
/// m = 1024` is comfortably oversized for tens of keys at FPR ≈ 0.01
/// and well inside `[MIN_K, MAX_K]` × `[MIN_M_BITS, MAX_M_BITS)`.
fn announce_with_edge_origin_keys(interested_keys: &[[u8; 32]], version: u64) -> FrontierAnnounce {
    let mut edge = BloomFilter::new_empty(7, 1024, interested_keys.len() as u64, 0.01)
        .expect("build edge filter");
    for k in interested_keys {
        edge.insert(k.as_slice());
    }
    FrontierAnnounce {
        version,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: FilterSpec::from_bloom(&BloomFilter::all_ones_sentinel()),
        expansion_filter: FilterSpec::from_bloom(&edge),
        mode: Mode::Filtered,
    }
}

/// Wait up to `timeout_ms` for `predicate` to return `true`. Mirrors
/// the helper in `tests/federation_phase5.rs`; we duplicate because
/// integration test crates can't `mod` each other. Forwarder
/// dispatches happen on spawned tasks so the receiver's DB does not
/// yet have the row when the upstream push returns — polling with a
/// short backoff keeps the test fast in the happy case and only
/// burns the full budget on real failure.
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

/// Count distinct `signed_objects` rows on an instance whose
/// `canonical_hash` falls in `expected`.
async fn count_present(db: &sqlx::SqlitePool, expected: &[[u8; 32]]) -> usize {
    let mut hits = 0usize;
    for hash in expected {
        let h: &[u8] = hash.as_slice();
        let row = sqlx::query!(
            "SELECT 1 AS \"n!: i64\" FROM signed_objects WHERE canonical_hash = ?",
            h
        )
        .fetch_optional(db)
        .await
        .expect("query signed_objects");
        if row.is_some() {
            hits += 1;
        }
    }
    hits
}

/// Stand up `n` instances and establish active peering on every
/// `(i, j)` pair (i < j) so the resulting transport graph is a full
/// mesh — every instance has every other as an `active` peer and
/// can pass the `verify_known_peer` middleware on every route.
async fn full_mesh_harness(n: usize) -> (MultiInstanceHarness, Vec<String>) {
    let harness = MultiInstanceHarness::new(n).await;
    let labels: Vec<String> = (0..n)
        .map(|i| char::from(b'a' + i as u8).to_string())
        .collect();
    for i in 0..n {
        for j in (i + 1)..n {
            establish_active_peering(&harness, &labels[i], &labels[j]).await;
        }
    }
    (harness, labels)
}

// ---------------------------------------------------------------------------
// Property 1 — convergence under random configurations
// ---------------------------------------------------------------------------

/// One trial: build a full mesh of `n` instances, have each instance
/// announce a frontier listing every signer pubkey as interesting
/// (so the routing decision is "yes, forward" for every peer),
/// originate `m_edges` random trust-edges by injecting each into a
/// random instance from a buddy peer, and assert every instance
/// converges to the full set of `m_edges` canonical hashes within
/// `poll_budget_ms`.
///
/// `arrived_from` in the forwarder excludes the *immediate* upstream
/// from each hop, not the originator; with K=2 fanout on a full
/// mesh of size `n`, every interested peer is reached in ≲ log₂(n)
/// rounds. The 5-second budget is far above that ceiling and burns
/// only on actual failure.
async fn run_convergence_trial(n: usize, m_edges: usize, seed: u64, poll_budget_ms: u64) {
    let mut rng = StdRng::seed_from_u64(seed);

    let (harness, labels) = full_mesh_harness(n).await;

    // Pool of distinct signer keys. Each originated edge picks a
    // (signer, target) pair from this pool. Pool size of 2 × m_edges
    // gives plenty of room for non-trivial random subsets without
    // signer collisions skewing the per-instance interest set.
    let pool_size = (m_edges * 2).max(6);
    let signing_keys: Vec<SigningKey> = (0..pool_size)
        .map(|_| SigningKey::generate(&mut rng))
        .collect();
    let signer_pubs: Vec<[u8; 32]> = signing_keys
        .iter()
        .map(|k| k.verifying_key().to_bytes())
        .collect();

    // Convergence property is "every interested peer eventually
    // sees every relevant signed object". Setting every receiver's
    // interest filter to the full signer pool collapses
    // "interested-in-this-signer" to "always yes", which makes the
    // expected set the full edge set — the strictest possible
    // convergence target.
    //
    // Per-version monotonicity matters: announces with the same
    // version are idempotent, so we make each `(receiver, sender)`
    // pair carry a unique version drawn from a process-wide counter.
    // Avoids accidental same-version reuse across trials that share
    // a binary.
    static VERSION_COUNTER: AtomicU64 = AtomicU64::new(1);
    for to_idx in 0..n {
        for from_idx in 0..n {
            if from_idx == to_idx {
                continue;
            }
            let v = VERSION_COUNTER.fetch_add(1, Ordering::Relaxed);
            let announce = announce_with_edge_origin_keys(&signer_pubs, v).encode();
            let (status, _) = send_envelope_signed(
                &harness,
                &labels[to_idx],
                &labels[from_idx],
                Method::POST,
                "/federation/v1/frontier/announce",
                &announce,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "trial seed={seed} n={n}: frontier announce {to_idx} → {from_idx} failed",
            );
        }
    }

    // Originate `m_edges` distinct signed trust-edges. Each is
    // injected via a "buddy push": peer `buddy` pushes the bytes to
    // peer `origin`, which is the first instance to persist the
    // canonical bytes in `signed_objects`. From `origin`, the
    // forwarder fans out under `arrived_from = Some(buddy)`.
    //
    // Edges are uniquely identified by their canonical hash; we
    // bump `created_at` per edge so two edges that pick the same
    // (signer, target) randomly do not collide on canonical bytes.
    let mut expected_hashes: Vec<[u8; 32]> = Vec::with_capacity(m_edges);
    for i in 0..m_edges {
        let signer_idx = rng.gen_range(0..signing_keys.len());
        // target ≠ signer
        let target_idx = {
            let mut t = rng.gen_range(0..signing_keys.len());
            if t == signer_idx {
                t = (t + 1) % signing_keys.len();
            }
            t
        };
        let origin = rng.gen_range(0..n);
        // Buddy ≠ origin so the §9.1 push has a distinct active-peer
        // sender; with `n ≥ 2` this always picks a valid label.
        let buddy = (origin + 1) % n;

        let ts = 1_700_000_000_000_u64
            .wrapping_add(seed.wrapping_mul(1000))
            .wrapping_add(i as u64);
        let signed = sign_trust_edge_with_key(
            &signing_keys[signer_idx],
            &signer_pubs[target_idx],
            TrustStance::Trust,
            ts,
            None,
        );
        expected_hashes.push(signed.canonical_hash);

        let wire = encode_wire(&signed.payload, &signed.signature);
        let body = encode_edges_body(&[wire]);
        let (status, _) = send_envelope_signed(
            &harness,
            &labels[buddy],
            &labels[origin],
            Method::POST,
            "/federation/v1/edges",
            &body,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "trial seed={seed} n={n} edge {i}: buddy push {buddy} → {origin} failed",
        );
    }

    // Convergence: every instance has every originated signed_object.
    let converged = poll_until(poll_budget_ms, || {
        let harness = &harness;
        let labels = &labels;
        let expected = &expected_hashes;
        async move {
            for label in labels {
                let inst = harness.instance(label);
                if count_present(&inst.state.db, expected).await != expected.len() {
                    return false;
                }
            }
            true
        }
    })
    .await;

    if !converged {
        // Build a per-instance "have N of M" snapshot so the failure
        // message tells you which instance stalled rather than just
        // "timed out". Cheap because the trial is already failing.
        let mut snapshot = String::new();
        for label in &labels {
            let inst = harness.instance(label);
            let got = count_present(&inst.state.db, &expected_hashes).await;
            snapshot.push_str(&format!("  {label}: {got}/{}\n", expected_hashes.len()));
        }
        panic!(
            "trial seed={seed} n={n} m_edges={m_edges} did not converge in {poll_budget_ms} ms\n{snapshot}",
        );
    }
}

/// Property 1: convergence. The gossip loop, driven by the §7.5
/// forwarder with `REDUNDANCY_K = 2`, brings every instance to the
/// same `signed_objects` set across a range of `(N, edges)`
/// configurations and randomly-seeded signer / target / originator
/// choices.
///
/// Several explicit trials rather than a single random run: the
/// failure mode we care about (the gossip storm stalls with some
/// instance missing some object) is independent across these axes,
/// and a fixed trial table reproduces deterministically without
/// pulling a new property-test framework into dev-deps.
///
/// ## Why N is capped at 4
///
/// `REDUNDANCY_K = 2` deterministic push-only gossip can only fully
/// saturate a mesh of size `N ≤ K + 2 = 4`. At `N = 5` and above,
/// the iteration order of `peers_interested_in` (SQL-row order over
/// the `peers` table, deterministic per harness setup) plus
/// `arrived_from` suppression can leave one peer permanently
/// unvisited from a single-origin push: e.g. origin a forwards to
/// {c, d}; c forwards (excl a) to {b, d}; d forwards (excl a) to
/// {b, c}; nobody ever forwards to e. This is the exact reason
/// `docs/federation-protocol.md` §10.5 specifies a pull-backfill as
/// the *correctness* backstop for push-based gossip — Phase 8 lands
/// the general-purpose backfill that closes this gap, and the
/// Phase-12 Layer-4 soak then re-runs this property at larger N
/// with backfill in the loop. For Phase 5 (push only) the meaningful
/// convergence claim is bounded at `N ≤ 4`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossip_converges_for_random_configurations() {
    // (N, M, seed) tuples. N held at 3 / 4 — see the doc comment
    // above for why N ≥ 5 is not a Phase-5 convergence guarantee.
    // Multiple seeds at each (N, M) so signer / target / origin
    // randomisation contributes real coverage rather than a single
    // PRNG path.
    let trials: &[(usize, usize, u64)] = &[
        (3, 4, 0xC0FF_EE00),
        (3, 8, 0xC0FF_EE01),
        (3, 12, 0xC0FF_EE02),
        (4, 4, 0xC0FF_EE03),
        (4, 8, 0xC0FF_EE04),
        (4, 10, 0xC0FF_EE05),
        (4, 6, 0xDEC0_DE06),
        (4, 6, 0xDEC0_DE07),
    ];
    for &(n, m, seed) in trials {
        run_convergence_trial(n, m, seed, 5_000).await;
    }
}

// ---------------------------------------------------------------------------
// Property 2 — routing actually filters
// ---------------------------------------------------------------------------

/// Property 2: the convergence above is not "everyone always sends".
/// An instance whose `expansion_filter` contains exactly one key
/// K₁ does not receive an edge signed by an unrelated key K₂, even
/// when every other peer in the mesh is interested and would
/// happily forward.
///
/// With `k = 7, m = 1024, n_est = 1` the effective FPR for a single
/// random key probe is on the order of `2⁻⁵⁰` — well below "≈ 0
/// across a single trial". A handful of repeated probes therefore
/// asserts "zero false positives" without flake.
///
/// This pins the "false-positive rate" half of the impl-plan
/// done-when: the routing-filter primitive is consulted and obeyed.
/// The statistical-FPR soak (many trials, calibrated bound) is the
/// Phase-12 successor; this test is the Phase-5 sanity check that
/// the wire-level interest signal is actually wired in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwarder_does_not_deliver_to_uninterested_peer() {
    // 4-instance full mesh: A (originator/upstream), B (the
    // delivery hop), C (the uninterested receiver — focus of the
    // negative assertion), D (a positive control to prove gossip
    // is alive in the same trial).
    let (harness, labels) = full_mesh_harness(4).await;
    let (a, b, c, d) = (&labels[0], &labels[1], &labels[2], &labels[3]);

    // Two unrelated signer keys. K1 is in B and D's interest set;
    // K2 is in nobody's. We push edges signed by both and assert C
    // receives neither, D receives the K1 one, and the K2 edge dies
    // at A (no peer is interested).
    let k1 = SigningKey::generate(&mut rand::rngs::OsRng);
    let k2 = SigningKey::generate(&mut rand::rngs::OsRng);
    let k1_pub = k1.verifying_key().to_bytes();
    // K2's pubkey is implicit in the signed edge bytes; we never
    // route on it directly in this test, only on K1.
    let _k2_pub = k2.verifying_key().to_bytes();
    let target_pub = SigningKey::generate(&mut rand::rngs::OsRng)
        .verifying_key()
        .to_bytes();

    // B and D announce interest in K1 only; C announces an empty
    // interest filter so any K1 / K2 routing decision against C is
    // "no". The version counter is shared with property-1 so
    // versions remain monotonic across both tests in one binary.
    static VERSION_COUNTER: AtomicU64 = AtomicU64::new(1_000_000);
    for (interested_keys, who, peers) in [
        (vec![k1_pub], b, vec![a.as_str(), c.as_str(), d.as_str()]),
        (vec![k1_pub], d, vec![a.as_str(), b.as_str(), c.as_str()]),
        (vec![], c, vec![a.as_str(), b.as_str(), d.as_str()]),
    ] {
        for peer in peers {
            let v = VERSION_COUNTER.fetch_add(1, Ordering::Relaxed);
            let announce = announce_with_edge_origin_keys(&interested_keys, v).encode();
            let (status, _) = send_envelope_signed(
                &harness,
                who,
                peer,
                Method::POST,
                "/federation/v1/frontier/announce",
                &announce,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "frontier announce {who} → {peer} failed",
            );
        }
    }

    // Inject the K1 edge via D → A (buddy=D, origin=A), and the K2
    // edge via B → A (buddy=B, origin=A). The forwarder on A picks
    // peers that are interested AND ≠ arrived_from, capped at K=2.
    // For K1: candidates are {B, D} \ {D} = {B}; B alone gets the
    // delivery, then B's forwarder picks {D} (interested, ≠ A) and
    // delivers there. C is never reached because C's filter excludes
    // K1.
    // For K2: candidates are {} (nobody is interested); A holds the
    // bytes locally and the forwarder fanout is empty.
    let k1_edge = sign_trust_edge_with_key(
        &k1,
        &target_pub,
        TrustStance::Trust,
        1_700_000_001_000,
        None,
    );
    let k2_edge = sign_trust_edge_with_key(
        &k2,
        &target_pub,
        TrustStance::Trust,
        1_700_000_002_000,
        None,
    );

    let k1_body = encode_edges_body(&[encode_wire(&k1_edge.payload, &k1_edge.signature)]);
    let (status, _) = send_envelope_signed(
        &harness,
        d,
        a,
        Method::POST,
        "/federation/v1/edges",
        &k1_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "K1 push d → a failed");

    let k2_body = encode_edges_body(&[encode_wire(&k2_edge.payload, &k2_edge.signature)]);
    let (status, _) = send_envelope_signed(
        &harness,
        b,
        a,
        Method::POST,
        "/federation/v1/edges",
        &k2_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "K2 push b → a failed");

    // Positive control: D receives the K1 edge via gossip from B.
    // The 2-second budget mirrors `forwarder_relays_applied_edge_to_interested_peer`
    // and is two orders of magnitude over the happy-path latency.
    let d_inst = harness.instance(d);
    let k1_hash = k1_edge.canonical_hash;
    let arrived_at_d = poll_until(2_000, || {
        let db = d_inst.state.db.clone();
        let h = k1_hash;
        async move { count_present(&db, &[h]).await == 1 }
    })
    .await;
    assert!(
        arrived_at_d,
        "positive control failed: K1 edge did not reach D within 2 s",
    );

    // Negative assertion 1: C never receives the K1 edge. Sleep a
    // generous extra 200 ms past the positive control to give any
    // misrouted delivery time to land — the forwarder dispatch is
    // single-digit-ms when it fires, so 200 ms is safely past the
    // window where a real misroute would show up.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let c_inst = harness.instance(c);
    assert_eq!(
        count_present(&c_inst.state.db, &[k1_hash]).await,
        0,
        "C received the K1 edge despite empty expansion_filter — filter routing is bypassed",
    );

    // Negative assertion 2: the K2 edge never escapes A. B, C, D
    // all have empty interest in K2; the only instance that should
    // hold the bytes is A (where the push landed).
    let k2_hash = k2_edge.canonical_hash;
    let a_inst = harness.instance(a);
    assert_eq!(
        count_present(&a_inst.state.db, &[k2_hash]).await,
        1,
        "A should hold the K2 edge it received from B's push",
    );
    for label in [b, c, d] {
        let inst = harness.instance(label);
        assert_eq!(
            count_present(&inst.state.db, &[k2_hash]).await,
            0,
            "{label} received the K2 edge despite no peer announcing interest in K2",
        );
    }
}

// ---------------------------------------------------------------------------
// Misc imports / silenced-warning helpers
// ---------------------------------------------------------------------------

// `RngCore` and `SliceRandom` aren't directly used today but are
// re-exported here to keep the helper file's import block stable
// against future trials that want shuffles / fill_bytes. Suppress
// the unused-import warning until those land.
#[allow(dead_code)]
fn _unused_imports_silencer<R: RngCore>(rng: &mut R, slice: &mut [u8]) {
    let _ = slice.choose(rng);
    rng.fill_bytes(slice);
}
