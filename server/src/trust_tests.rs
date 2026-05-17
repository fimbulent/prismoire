use super::*;
use crate::trust::{PendingDeltas, TrustGraph, TrustPath, TrustStance, ViewerDelta};
use std::collections::HashMap;
use uuid::Uuid;

const A: Uuid = Uuid::from_u128(0xa);
const B: Uuid = Uuid::from_u128(0xb);
const C: Uuid = Uuid::from_u128(0xc);
const D: Uuid = Uuid::from_u128(0xd);
const E: Uuid = Uuid::from_u128(0xe);
const F: Uuid = Uuid::from_u128(0xf);
const H: Uuid = Uuid::from_u128(0x10);
const M: Uuid = Uuid::from_u128(0x11);
const S1: Uuid = Uuid::from_u128(0x12);
const S2: Uuid = Uuid::from_u128(0x13);

/// Build a TrustGraph directly from UUID edges (no database).
fn graph_from_edges(edges: &[(Uuid, Uuid)]) -> TrustGraph {
    graph_from_edges_with_distrusts(edges, &[])
}

/// Build a TrustGraph with both trust and distrust edges (no database).
fn graph_from_edges_with_distrusts(
    edges: &[(Uuid, Uuid)],
    distrust_edges: &[(Uuid, Uuid)],
) -> TrustGraph {
    let index = crate::trust::NodeIndex::from_edges(edges);
    let dense: Vec<(u32, u32)> = edges
        .iter()
        .map(|(s, t)| (index.get_id(s).unwrap(), index.get_id(t).unwrap()))
        .collect();
    let forward = crate::trust::CsrGraph::from_edges(index.num_nodes(), &dense);
    let reverse = forward.transpose();

    let mut distrust_sets: crate::trust::DistrustSets = HashMap::new();
    for &(distruster, distrusted) in distrust_edges {
        if let (Some(distruster_id), Some(distrusted_id)) =
            (index.get_id(&distruster), index.get_id(&distrusted))
        {
            distrust_sets
                .entry(distruster_id)
                .or_default()
                .insert(distrusted_id);
        }
    }

    TrustGraph {
        forward,
        reverse,
        index,
        distrust_sets,
        forward_cache: TrustGraph::make_bfs_cache(1024 * 1024),
        reverse_cache: TrustGraph::make_bfs_cache(1024 * 1024),
        delta_forward_cache: TrustGraph::make_delta_bfs_cache(1024 * 1024),
        metrics: None,
    }
}

// -- Score-to-distance tests --

#[test]
fn test_score_to_distance_direct_trust() {
    let d = crate::trust::score_to_distance(1.0);
    assert!((d - 1.0).abs() < f64::EPSILON);
}

#[test]
fn test_score_to_distance_two_hop() {
    let d = crate::trust::score_to_distance(crate::trust::DECAY);
    assert!((d - 2.0).abs() < 0.01);
}

#[test]
fn test_score_to_distance_three_hop() {
    let d = crate::trust::score_to_distance(crate::trust::DECAY * crate::trust::DECAY);
    assert!((d - 3.0).abs() < 0.01);
}

#[test]
fn test_score_to_distance_zero() {
    assert!((crate::trust::score_to_distance(0.0) - 3.0).abs() < f64::EPSILON);
}

// -- PathGroups unit tests --

#[test]
fn test_path_groups_single() {
    let mut pg = crate::trust::PathGroups::new();
    pg.add(0, 0.49);
    assert!((pg.combined_score() - 0.49).abs() < f64::EPSILON);
}

#[test]
fn test_path_groups_two_independent() {
    let mut pg = crate::trust::PathGroups::new();
    pg.add(0, 0.49);
    pg.add(1, 0.49);
    // 1 - (1-0.49)(1-0.49) = 0.7399
    assert!((pg.combined_score() - 0.7399).abs() < 0.001);
}

#[test]
fn test_path_groups_same_group_takes_max() {
    let mut pg = crate::trust::PathGroups::new();
    pg.add(0, 0.49);
    pg.add(0, 0.343);
    assert!((pg.combined_score() - 0.49).abs() < f64::EPSILON);
}

#[test]
fn test_sybil_resistance_path_groups() {
    // All through same first hop — max = 0.49
    let mut pg = crate::trust::PathGroups::new();
    pg.add(0, 0.49);
    pg.add(0, 0.343);
    pg.add(0, 0.343);
    assert!((pg.combined_score() - 0.49).abs() < f64::EPSILON);
}

// -- Forward BFS tests (via TrustGraph public API) --

#[test]
fn test_forward_linear_chain() {
    // A → B → C → D
    let g = graph_from_edges(&[(A, B), (B, C), (C, D)]);
    let scores = g.forward_scores(A);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

    assert!((map[&B] - 1.0).abs() < 0.001);
    assert!((map[&C] - 0.7).abs() < 0.001);
    assert!((map[&D] - 0.49).abs() < 0.001);
}

#[test]
fn test_forward_two_independent_paths() {
    // A → B → D, A → C → D
    let g = graph_from_edges(&[(A, B), (A, C), (B, D), (C, D)]);
    let scores = g.forward_scores(A);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

    // 1-(1-0.7)(1-0.7) = 0.91
    assert!((map[&D] - 0.91).abs() < 0.001);
}

#[test]
fn test_forward_sybil_attack() {
    // A → H → M, A → H → S1 → M, A → H → S2 → M
    let g = graph_from_edges(&[(A, H), (H, M), (H, S1), (H, S2), (S1, M), (S2, M)]);
    let scores = g.forward_scores(A);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

    // All through first hop H — max in group H is A→H→M = 0.7
    assert!((map[&M] - 0.7).abs() < 0.001);
}

#[test]
fn test_forward_depth_limit() {
    // A → B → C → D → E (4 hops, E unreachable)
    let g = graph_from_edges(&[(A, B), (B, C), (C, D), (D, E)]);
    let scores = g.forward_scores(A);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

    assert!(map.contains_key(&D));
    assert!(!map.contains_key(&E));
}

#[test]
fn test_forward_no_self_loop() {
    // A → B → A
    let g = graph_from_edges(&[(A, B), (B, A)]);
    let scores = g.forward_scores(A);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

    assert!(!map.contains_key(&A));
    assert!(map.contains_key(&B));
}

// -- Reverse BFS tests --

#[test]
fn test_reverse_linear_chain() {
    // A → B → C → D. Reverse from D.
    let g = graph_from_edges(&[(A, B), (B, C), (C, D)]);
    let rev = g.reverse_scores(D);

    assert!((rev[&C] - 1.0).abs() < 0.001);
    assert!((rev[&B] - 0.7).abs() < 0.001);
    assert!((rev[&A] - 0.49).abs() < 0.001);
}

#[test]
fn test_reverse_two_paths_matches_forward() {
    // A → B → D, A → C → D
    let g = graph_from_edges(&[(A, B), (A, C), (B, D), (C, D)]);

    let fwd = g.forward_scores(A);
    let fwd_d = fwd.iter().find(|s| s.target_user == D).unwrap().score;

    let rev = g.reverse_scores(D);

    assert!((rev[&A] - fwd_d).abs() < 0.001);
}

#[test]
fn test_reverse_sybil_resistance() {
    // A → H → R, A → H → S1 → R, A → H → S2 → R
    let r = Uuid::from_u128(0xf);
    let g = graph_from_edges(&[(A, H), (H, r), (H, S1), (H, S2), (S1, r), (S2, r)]);

    let fwd = g.forward_scores(A);
    let fwd_r = fwd.iter().find(|s| s.target_user == r).unwrap().score;

    let rev = g.reverse_scores(r);

    assert!((fwd_r - 0.7).abs() < 0.001);
    assert!((rev[&A] - 0.7).abs() < 0.001);
}

#[test]
fn test_reverse_mixed_depth() {
    // A→X→R and A→Y→X→R (different first-hops from A)
    let x = Uuid::from_u128(0x20);
    let y = Uuid::from_u128(0x21);
    let r = Uuid::from_u128(0x22);
    let g = graph_from_edges(&[(A, x), (A, y), (x, r), (y, x)]);

    let fwd = g.forward_scores(A);
    let fwd_r = fwd.iter().find(|s| s.target_user == r).unwrap().score;

    let rev = g.reverse_scores(r);

    // group X = 0.7, group Y = 0.49 → 1-(0.3)(0.51) = 0.847
    assert!((fwd_r - 0.847).abs() < 0.001);
    assert!((rev[&A] - fwd_r).abs() < 0.001);
}

#[test]
fn test_reverse_no_self_loop() {
    let g = graph_from_edges(&[(A, B), (B, A)]);
    let rev = g.reverse_scores(A);

    assert!(!rev.contains_key(&A));
    assert!((rev[&B] - 1.0).abs() < 0.001);
}

#[test]
fn test_reverse_depth_limit() {
    // A → B → C → D → E
    let g = graph_from_edges(&[(A, B), (B, C), (C, D), (D, E)]);
    let rev = g.reverse_scores(E);

    assert!((rev[&D] - 1.0).abs() < 0.001);
    assert!((rev[&C] - 0.7).abs() < 0.001);
    assert!((rev[&B] - 0.49).abs() < 0.001);
    assert!(!rev.contains_key(&A));
}

// -- trust_between tests --

#[test]
fn test_trust_between_direct() {
    let g = graph_from_edges(&[(A, B)]);
    let (score, distance) = g.trust_between(A, B).unwrap();
    assert!((score - 1.0).abs() < 0.001);
    assert!((distance.unwrap() - 1.0).abs() < 0.01);
}

#[test]
fn test_trust_between_unreachable() {
    let g = graph_from_edges(&[(A, B)]);
    assert!(g.trust_between(B, A).is_none());
}

#[test]
fn test_empty_graph() {
    let g = TrustGraph::empty();
    assert!(g.forward_scores(A).is_empty());
    assert!(g.reverse_scores(A).is_empty());
    assert!(g.trust_between(A, B).is_none());
}

#[test]
fn test_unknown_user() {
    let g = graph_from_edges(&[(A, B)]);
    // C is not in the graph
    assert!(g.forward_scores(C).is_empty());
    assert!(g.reverse_scores(C).is_empty());
}

// -- paths_to tests --

#[test]
fn test_paths_to_direct() {
    let g = graph_from_edges(&[(A, B)]);
    let paths = g.paths_to(A, B);
    assert_eq!(paths, vec![TrustPath::Direct]);
}

#[test]
fn test_paths_to_two_hop() {
    let g = graph_from_edges(&[(A, B), (B, C)]);
    let paths = g.paths_to(A, C);
    assert_eq!(paths, vec![TrustPath::TwoHop { via: B }]);
}

#[test]
fn test_paths_to_three_hop() {
    let g = graph_from_edges(&[(A, B), (B, C), (C, D)]);
    let paths = g.paths_to(A, D);
    assert_eq!(paths, vec![TrustPath::ThreeHop { via1: B, via2: C }]);
}

#[test]
fn test_paths_to_multiple() {
    // A → B → D and A → C → D
    let g = graph_from_edges(&[(A, B), (A, C), (B, D), (C, D)]);
    let paths = g.paths_to(A, D);
    assert_eq!(paths.len(), 2);
    assert!(paths.contains(&TrustPath::TwoHop { via: B }));
    assert!(paths.contains(&TrustPath::TwoHop { via: C }));
}

#[test]
fn test_paths_to_unreachable() {
    let g = graph_from_edges(&[(A, B)]);
    assert!(g.paths_to(B, A).is_empty());
}

#[test]
fn test_paths_to_beyond_depth() {
    // A → B → C → D → E (4 hops to E, no paths)
    let g = graph_from_edges(&[(A, B), (B, C), (C, D), (D, E)]);
    assert!(g.paths_to(A, E).is_empty());
}

#[test]
fn test_paths_to_self() {
    let g = graph_from_edges(&[(A, B), (B, A)]);
    assert!(g.paths_to(A, A).is_empty());
}

#[test]
fn test_paths_to_mixed_depths() {
    // A → B (direct to B), A → B → C (2-hop to C), plus A → C directly
    let g = graph_from_edges(&[(A, B), (A, C), (B, C)]);
    let paths = g.paths_to(A, C);
    assert!(paths.contains(&TrustPath::Direct));
    assert!(paths.contains(&TrustPath::TwoHop { via: B }));
}

// -- Distrust propagation tests --

#[test]
fn test_distrust_single_target_penalizes_intermediary() {
    // A→B→C, B trusts E (distrusted by A)
    let g = graph_from_edges_with_distrusts(&[(A, B), (B, C), (B, E)], &[(A, E)]);
    let scores = g.forward_scores(A);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

    // B trusts E (distrusted) → reliability = 0.75
    assert!((map[&B] - 0.75).abs() < 0.001);
    // C = 0.75 * DECAY * 1.0 = 0.525
    assert!((map[&C] - 0.525).abs() < 0.001);
    // E is directly distrusted → 0.0, filtered out by threshold
    assert!(!map.contains_key(&E));
}

#[test]
fn test_distrust_multiple_targets_compound() {
    // A→B, B trusts C and D (both distrusted by A)
    let g = graph_from_edges_with_distrusts(&[(A, B), (B, C), (B, D)], &[(A, C), (A, D)]);
    let scores = g.forward_scores(A);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

    // B trusts 2 distrusted → reliability = 0.75^2 = 0.5625
    assert!((map[&B] - 0.5625).abs() < 0.001);
    // C and D are directly distrusted → filtered out by threshold
    assert!(!map.contains_key(&C));
    assert!(!map.contains_key(&D));
}

#[test]
fn test_distrust_no_penalty_clean_node() {
    // A→B→C, A→E. A distrusts E. B doesn't trust E → no penalty.
    let g = graph_from_edges_with_distrusts(&[(A, B), (B, C), (A, E)], &[(A, E)]);
    let scores = g.forward_scores(A);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

    assert!((map[&B] - 1.0).abs() < 0.001);
    assert!((map[&C] - 0.7).abs() < 0.001);
}

#[test]
fn test_distrust_multipath_recovery() {
    // A→B→D, A→C→D. B trusts E (distrusted by A), C is clean.
    let g = graph_from_edges_with_distrusts(&[(A, B), (A, C), (B, D), (C, D), (B, E)], &[(A, E)]);
    let scores = g.forward_scores(A);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

    // Group B: 0.75 * 0.7 = 0.525, Group C: 1.0 * 0.7 = 0.7
    // Combined: 1 - (1-0.525)(1-0.7) = 0.8575
    assert!((map[&D] - 0.8575).abs() < 0.001);
}

#[test]
fn test_distrust_compounds_along_path() {
    // A→B→C→D, B trusts E (distrusted), C trusts F (distrusted)
    let g = graph_from_edges_with_distrusts(
        &[(A, B), (B, C), (C, D), (B, E), (C, F)],
        &[(A, E), (A, F)],
    );
    let scores = g.forward_scores(A);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

    // B: reliability = 0.75 → 0.75
    assert!((map[&B] - 0.75).abs() < 0.001);
    // C: 0.75 * 0.7 * 0.75 = 0.39375 — below threshold, filtered
    assert!(!map.contains_key(&C));
    // D: 0.39375 * 0.7 ≈ 0.2756 — below threshold, filtered
    assert!(!map.contains_key(&D));
    // E, F distrusted → filtered
    assert!(!map.contains_key(&E));
    assert!(!map.contains_key(&F));
}

#[test]
fn test_distrust_sybil_resistance() {
    // A→H, H→M, H→S1→M, H→S2→M, H→E. A distrusts E.
    let g = graph_from_edges_with_distrusts(
        &[(A, H), (H, M), (H, S1), (H, S2), (S1, M), (S2, M), (H, E)],
        &[(A, E)],
    );
    let scores = g.forward_scores(A);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

    // All via first-hop H. H reliability = 0.75 (trusts E, distrusted by A).
    // Best in group: H→M = 0.75 * 0.7 = 0.525
    assert!((map[&M] - 0.525).abs() < 0.001);
}

// -- Delta-aware BFS overlay tests --

/// A delta with no edits must produce identical results to the cached
/// path — `is_empty()` is the hot-path guard for unmutated viewers.
#[test]
fn test_delta_empty_matches_cached() {
    let g = graph_from_edges(&[(A, B), (B, C)]);
    let delta = ViewerDelta::default();
    assert!(delta.is_empty());

    assert_eq!(g.distance_map(A), g.distance_map_with_delta(A, &delta));
    // TrustScore lacks PartialEq/Debug; compare on the (uuid, score) tuples.
    let cached_scores: Vec<(Uuid, f64)> = g
        .forward_scores(A)
        .into_iter()
        .map(|s| (s.target_user, s.score))
        .collect();
    let delta_scores: Vec<(Uuid, f64)> = g
        .forward_scores_with_delta(A, &delta)
        .into_iter()
        .map(|s| (s.target_user, s.score))
        .collect();
    assert_eq!(cached_scores, delta_scores);
    assert_eq!(
        g.trust_between(A, C),
        g.trust_between_with_delta(A, C, &delta),
    );
    assert_eq!(g.paths_to(A, C), g.paths_to_with_delta(A, C, &delta));
}

/// Adding a trust edge to the delta should make a previously
/// unreachable target reachable as a direct hop. The target must be
/// a node already known to the graph index — `apply_delta_overlay`
/// drops references to unknown UUIDs (e.g., a user signed up but
/// not yet absorbed into the rebuild's node set).
#[test]
fn test_delta_trust_added_creates_direct_path() {
    // Cached: A→B and D→C. C is in the index but unreachable from A.
    let g = graph_from_edges(&[(A, B), (D, C)]);
    assert!(g.trust_between(A, C).is_none());

    let mut delta = ViewerDelta::default();
    delta.trust_added.insert(C);
    delta.seq = 1;

    let (score, distance) = g.trust_between_with_delta(A, C, &delta).unwrap();
    assert!((score - 1.0).abs() < f64::EPSILON);
    assert!((distance.unwrap() - 1.0).abs() < f64::EPSILON);

    let paths = g.paths_to_with_delta(A, C, &delta);
    assert!(paths.contains(&TrustPath::Direct));
}

/// Removing a direct trust edge via the delta should drop the target
/// out of the score set.
#[test]
fn test_delta_trust_removed_drops_target() {
    let g = graph_from_edges(&[(A, B), (A, C)]);
    // Cached: both B and C are direct.
    let cached_map = g.distance_map(A);
    assert!(cached_map.contains_key(&B.to_string()));
    assert!(cached_map.contains_key(&C.to_string()));

    let mut delta = ViewerDelta::default();
    delta.trust_removed.insert(C);
    delta.seq = 1;

    let dm = g.distance_map_with_delta(A, &delta);
    assert!(dm.contains_key(&B.to_string()));
    assert!(!dm.contains_key(&C.to_string()));
}

/// Adding a distrust to the delta should both zero the direct score
/// and penalise paths through intermediaries that trust the
/// newly-distrusted node.
#[test]
fn test_delta_distrust_added_penalises_paths() {
    // A→B→C, B→E. Without distrust, A reaches C with reliability 1.0
    // at B (B trusts only C and E, neither distrusted ⇒ 1.0).
    let g = graph_from_edges(&[(A, B), (B, C), (B, E)]);
    let baseline = g.trust_between(A, C).unwrap().0;

    let mut delta = ViewerDelta::default();
    delta.distrust_added.insert(E);
    delta.seq = 1;

    let with_distrust = g.trust_between_with_delta(A, C, &delta).unwrap().0;
    // B's reliability factor drops from 1.0 to (1 - 0.25) = 0.75 because
    // B trusts the now-distrusted E.
    assert!(with_distrust < baseline);
    assert!((with_distrust - baseline * 0.75).abs() < 0.01);
}

/// When a viewer flips from trust to distrust, the BFS no longer
/// reaches the target via the (now removed) direct edge. If no
/// alternate path exists the target falls out of results entirely
/// — same behaviour as the cached path when a viewer distrusts a
/// node they have no path to. Distrust state is surfaced to the
/// UI from the DB-loaded distrust set, not from the BFS result.
#[test]
fn test_delta_flip_trust_to_distrust_drops_unreachable_target() {
    let g = graph_from_edges(&[(A, B)]);
    assert!(g.trust_between(A, B).is_some());

    let mut delta = ViewerDelta::default();
    delta.trust_removed.insert(B);
    delta.distrust_added.insert(B);
    delta.seq = 1;

    // No path remains, so trust_between returns None.
    assert!(g.trust_between_with_delta(A, B, &delta).is_none());
    // distance_map should not contain B either.
    assert!(
        !g.distance_map_with_delta(A, &delta)
            .contains_key(&B.to_string())
    );
}

/// When the viewer distrusts a target reachable via an intermediary,
/// the BFS finds the target through the alternate path and the
/// direct-distrust override zeros its score.
#[test]
fn test_delta_distrust_zeros_target_reachable_via_intermediary() {
    // A→B, A→C, B→C. After delta: A removes direct trust to C and
    // distrusts C. C is still reachable via B.
    let g = graph_from_edges(&[(A, B), (A, C), (B, C)]);

    let mut delta = ViewerDelta::default();
    delta.trust_removed.insert(C);
    delta.distrust_added.insert(C);
    delta.seq = 1;

    let score = g.trust_between_with_delta(A, C, &delta).unwrap().0;
    assert!((score - 0.0).abs() < f64::EPSILON);
}

/// Removing a cached distrust via the delta should restore the
/// original (unpenalised) trust through the formerly distrusted
/// intermediary.
#[test]
fn test_delta_distrust_removed_restores_path() {
    // Cached graph: A distrusts E, intermediary B trusts E.
    let g = graph_from_edges_with_distrusts(&[(A, B), (B, C), (B, E)], &[(A, E)]);
    let with_cached_distrust = g.trust_between(A, C).unwrap().0;

    let mut delta = ViewerDelta::default();
    delta.distrust_removed.insert(E);
    delta.seq = 1;

    let without_distrust = g.trust_between_with_delta(A, C, &delta).unwrap().0;
    // Removing the distrust should raise the score by the inverse of
    // the prior penalty (reliability 0.75 → 1.0).
    assert!(without_distrust > with_cached_distrust);
    assert!((without_distrust - with_cached_distrust / 0.75).abs() < 0.01);
}

/// A delta whose `trust_added` duplicates an edge already in the
/// cached graph must NOT cause double-seeding (which would
/// double-count the score for that first-hop group).
#[test]
fn test_delta_trust_added_duplicate_is_idempotent() {
    let g = graph_from_edges(&[(A, B), (B, C)]);
    let baseline = g.trust_between(A, C).unwrap().0;

    let mut delta = ViewerDelta::default();
    delta.trust_added.insert(B); // duplicate of cached A→B
    delta.seq = 1;

    let with_dup = g.trust_between_with_delta(A, C, &delta).unwrap().0;
    assert!((with_dup - baseline).abs() < 1e-9);
}

// -- PendingDeltas semantics tests --

/// Adding then removing the same edge collapses to an empty entry
/// and is dropped from the map.
#[test]
fn test_pending_apply_then_revert_drops_entry() {
    let pd = PendingDeltas::new(None);
    // Edge not in cached graph; viewer trusts then goes neutral.
    pd.apply(A, B, false, false, TrustStance::Trust);
    assert!(!pd.get(A).is_empty());

    // Apply requires the caller's view of "current cached state". The
    // first apply hasn't been absorbed yet, so the cached state for
    // the second apply is still false/false.
    pd.apply(A, B, false, false, TrustStance::Neutral);
    assert!(pd.get(A).is_empty());
}

/// Flipping from trust to distrust should populate `trust_removed`
/// and `distrust_added` together.
#[test]
fn test_pending_flip_trust_to_distrust() {
    let pd = PendingDeltas::new(None);
    // Cached: A trusts B. New stance: Distrust.
    pd.apply(A, B, true, false, TrustStance::Distrust);
    let d = pd.get(A);
    assert!(d.trust_removed.contains(&B));
    assert!(d.distrust_added.contains(&B));
    assert!(!d.trust_added.contains(&B));
    assert!(!d.distrust_removed.contains(&B));
}

/// `purge_below(high_water)` keeps entries whose latest seq is at or
/// above the high-water mark and drops the rest.
#[test]
fn test_pending_purge_below_keeps_recent() {
    let pd = PendingDeltas::new(None);
    pd.apply(A, B, false, false, TrustStance::Trust); // seq = 1
    let high_water = pd.current_seq(); // = 2 after the fetch_add
    pd.apply(C, D, false, false, TrustStance::Trust); // seq = 2

    pd.purge_below(high_water);

    // A's delta had seq=1 < high_water → dropped.
    assert!(pd.get(A).is_empty());
    // C's delta had seq=2 ≥ high_water → kept.
    assert!(!pd.get(C).is_empty());
}

/// `current_seq()` should observe the latest assigned seq + 1
/// (the next value the counter would hand out).
#[test]
fn test_pending_seq_advances_on_apply() {
    let pd = PendingDeltas::new(None);
    let before = pd.current_seq();
    pd.apply(A, B, false, false, TrustStance::Trust);
    let after = pd.current_seq();
    assert!(after > before);
}

// -- Delta-keyed forward cache tests --
//
// We cannot read quick_cache hit/miss counters directly, so these
// tests use `Arc::ptr_eq` on the returned distance map: the cache
// hands out an `Arc` clone of the stored value, so a hit yields a
// pointer-equal Arc and a miss yields a freshly allocated one.

/// Two calls with the same `(reader, seq)` return the same Arc —
/// the second call hits the delta cache.
#[test]
fn test_delta_cache_hits_on_same_seq() {
    let g = graph_from_edges(&[(A, B), (D, C)]);
    let mut delta = ViewerDelta::default();
    delta.trust_added.insert(C);
    delta.seq = 7;

    let first = g.distance_map_with_delta(A, &delta);
    let second = g.distance_map_with_delta(A, &delta);
    assert!(
        Arc::ptr_eq(&first, &second),
        "same seq should reuse the cached Arc"
    );
}

/// Bumping `delta.seq` invalidates the cached entry — the cache
/// stores per-seq, so the next call is a miss and produces a new
/// Arc. The previous entry is naturally orphaned.
#[test]
fn test_delta_cache_misses_when_seq_bumps() {
    let g = graph_from_edges(&[(A, B), (D, C)]);
    let mut delta = ViewerDelta::default();
    delta.trust_added.insert(C);
    delta.seq = 1;
    let first = g.distance_map_with_delta(A, &delta);

    // Simulate a follow-up click that advances the seq.
    delta.seq = 2;
    let second = g.distance_map_with_delta(A, &delta);
    assert!(
        !Arc::ptr_eq(&first, &second),
        "different seq should miss the cache"
    );
}

/// An empty delta short-circuits to the regular forward cache,
/// which means it does NOT populate the delta cache and instead
/// shares an Arc with the normal `distance_map(reader)` call.
#[test]
fn test_delta_empty_uses_regular_forward_cache() {
    let g = graph_from_edges(&[(A, B), (B, C)]);
    let delta = ViewerDelta::default();

    let cached = g.distance_map(A);
    let via_delta = g.distance_map_with_delta(A, &delta);
    assert!(
        Arc::ptr_eq(&cached, &via_delta),
        "empty delta must reuse the regular forward cache"
    );
}

/// Different viewers populate independent entries in the delta
/// cache, even at the same seq value (seq is only required to be
/// monotonic within a single viewer's mutation stream).
#[test]
fn test_delta_cache_isolates_by_viewer() {
    let g = graph_from_edges(&[(A, B), (D, C), (D, E)]);

    let mut delta_a = ViewerDelta::default();
    delta_a.trust_added.insert(C);
    delta_a.seq = 1;

    let mut delta_d = ViewerDelta::default();
    delta_d.trust_added.insert(E);
    delta_d.seq = 1;

    let from_a = g.distance_map_with_delta(A, &delta_a);
    let from_d = g.distance_map_with_delta(D, &delta_d);

    // Different viewers must not share an entry — same seq value
    // does not collide because the viewer Uuid is part of the key.
    assert!(!Arc::ptr_eq(&from_a, &from_d));
}

// -- Hub dampening tests --
//
// HUB_DAMPEN_THRESHOLD = 5000. Tests below construct graphs with hubs
// whose in-degree exceeds the threshold (10K trusters → factor =
// 0.7^ln(2) ≈ 0.783) to produce assertable score differences. Tests
// elsewhere in this file use small graphs (max in-degree ≤ a few), so
// dampening is a no-op for them — that they all still pass is itself
// a regression guard.

/// Direct unit test of the dampening curve.
#[test]
fn test_hub_dampening_factor_curve() {
    // Below threshold: no penalty.
    assert_eq!(crate::trust::hub_dampening_factor(0), 1.0);
    assert_eq!(crate::trust::hub_dampening_factor(1), 1.0);
    assert_eq!(crate::trust::hub_dampening_factor(4999), 1.0);
    assert_eq!(crate::trust::hub_dampening_factor(5000), 1.0);

    // Spot-check the formula at a couple of points by recomputing it
    // independently. `0.7 ^ ln(d / 5000)` for d > 5000.
    let k = 5000.0_f64;
    for d in [10_000_u32, 50_000, 200_000] {
        let expected = (0.7_f64).powf((d as f64 / k).ln());
        let got = crate::trust::hub_dampening_factor(d);
        assert!(
            (got - expected).abs() < 1e-9,
            "d={d}: expected {expected}, got {got}"
        );
    }

    // Monotonic decreasing above threshold.
    let f_6k = crate::trust::hub_dampening_factor(6_000);
    let f_10k_in = crate::trust::hub_dampening_factor(10_000);
    let f_50k = crate::trust::hub_dampening_factor(50_000);
    let f_500k = crate::trust::hub_dampening_factor(500_000);
    assert!(f_6k > f_10k_in);
    assert!(f_10k_in > f_50k);
    assert!(f_50k > f_500k);
    assert!(f_500k > 0.0, "factor never reaches zero");
}

/// Build a graph with a hub at the given trust in-degree, plus a single
/// outbound edge `hub → friend`. Returns the `TrustGraph` and the UUIDs
/// of the first truster (useful as a BFS source), the hub, and the friend.
///
/// Truster UUIDs are deterministic: `Uuid::from_u128(0x10_0000 + i)` for
/// i in 0..trust_in_degree. Hub UUID is `0x20_0000`, friend UUID is
/// `0x20_0001`.
fn build_hub_graph(trust_in_degree: u32) -> (TrustGraph, Uuid, Uuid, Uuid) {
    let hub = Uuid::from_u128(0x20_0000);
    let friend = Uuid::from_u128(0x20_0001);
    let mut edges: Vec<(Uuid, Uuid)> = Vec::with_capacity(trust_in_degree as usize + 1);
    for i in 0..trust_in_degree {
        let truster = Uuid::from_u128(0x10_0000 + i as u128);
        edges.push((truster, hub));
    }
    edges.push((hub, friend));
    let first_truster = Uuid::from_u128(0x10_0000);
    (graph_from_edges(&edges), first_truster, hub, friend)
}

/// Direct trust into a hub is unaffected by the hub's in-degree —
/// dampening applies to traversal *through* the hub, not arrival at it.
#[test]
fn test_hub_dampening_direct_trust_unaffected() {
    let (g, truster, hub, _) = build_hub_graph(10_000);
    let scores = g.forward_scores(truster);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();
    // First-hop arrival: full strength (= 1.0) regardless of hub's in-degree.
    assert!(
        (map[&hub] - 1.0).abs() < 0.001,
        "direct trust into hub should be 1.0, got {}",
        map[&hub]
    );
}

/// Traversal *through* a hub attenuates as a function of the hub's
/// in-degree. With a hub at 2k×threshold (= 10K trusters), the friend's
/// score is 0.7 × 0.783 ≈ 0.548 (vs undamped 0.7).
#[test]
fn test_hub_dampening_through_traversal_attenuated() {
    let (g, truster, _, friend) = build_hub_graph(10_000);
    let scores = g.forward_scores(truster);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

    // Expected: 1.0 * DECAY * hub_dampening_factor(10000)
    //         = 1.0 * 0.7   * 0.7^ln(2)
    //         ≈ 0.548
    let expected = 0.7 * (0.7_f64).powf((2.0_f64).ln());
    assert!(
        (map[&friend] - expected).abs() < 0.001,
        "through-hub score: expected {expected}, got {}",
        map[&friend]
    );
    // And the dampened score is materially below the undamped baseline.
    assert!(map[&friend] < 0.6, "should be dampened well below 0.7");
}

/// Hub-in-degree dampening grows with in-degree: a bigger hub attenuates
/// more strongly than a smaller-but-still-above-threshold one.
#[test]
fn test_hub_dampening_grows_with_in_degree() {
    let (g1, t1, _, f1) = build_hub_graph(6_000);
    let (g2, t2, _, f2) = build_hub_graph(20_000);

    // Use `trust_between` rather than `forward_scores` so we get the raw
    // score even when it drops below `MINIMUM_TRUST_THRESHOLD` (a 20K-
    // in-degree hub dampens enough that the friend falls below 0.45).
    let s1 = g1.trust_between(t1, f1).unwrap().0;
    let s2 = g2.trust_between(t2, f2).unwrap().0;

    // Bigger hub → more dampening → lower friend score.
    assert!(
        s2 < s1,
        "20k-in-degree friend score ({s2}) should be lower than 6k-in-degree ({s1})"
    );
}

/// A hub's own forward BFS as a source is unpenalised — dampening only
/// applies to traversal *through* intermediate nodes. The hub's direct
/// trustee (friend) sees score 1.0 from the hub.
#[test]
fn test_hub_dampening_source_unpenalised() {
    let (g, _, hub, friend) = build_hub_graph(10_000);
    let scores = g.forward_scores(hub);
    let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();
    // Hub's direct outbound (hub → friend) is hop-1, full strength.
    assert!(
        (map[&friend] - 1.0).abs() < 0.001,
        "hub-as-source → friend should be 1.0, got {}",
        map[&friend]
    );
}

/// Reverse BFS applies the same dampening as forward BFS. The friend
/// (who can be reached transitively via the hub) sees trust(friend, reader)
/// from any of the original trusters reduced by the same factor.
///
/// Setup mirrors `build_hub_graph` but rooted at `friend`: trusters trust
/// hub, hub trusts friend. Reverse BFS from friend should compute
/// trust(truster, friend) by traversing friend ← hub ← truster, with
/// dampening at the hub.
#[test]
fn test_hub_dampening_reverse_bfs_symmetric() {
    let (g, truster, _, friend) = build_hub_graph(10_000);

    // Forward score from truster to friend (the value we already test
    // for in `test_hub_dampening_through_traversal_attenuated`).
    let fwd = g
        .forward_scores(truster)
        .into_iter()
        .find(|s| s.target_user == friend)
        .unwrap()
        .score;

    // Reverse BFS from friend: should produce the same trust value for
    // truster. `reverse_scores` does not apply distrust propagation, but
    // there are no distrust edges in this graph, so the values match.
    let rev = g.reverse_scores(friend);
    assert!(
        (rev[&truster] - fwd).abs() < 0.001,
        "reverse dampening symmetric: expected {fwd}, got {}",
        rev[&truster]
    );
    assert!(rev[&truster] < 0.6, "reverse score should also be dampened");
}
