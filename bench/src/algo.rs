//! Trust propagation algorithm under test.
//!
//! Bottleneck-grouped probabilistic BFS with distrust propagation and hub
//! dampening. Mirrors `server/src/trust.rs` — the bench treats this module
//! as the reference implementation for the production algorithm, and the
//! synthetic graph in `graph.rs` is what feeds into it.
//!
//! Algorithm essentials:
//! - **Forward BFS** (relevance): reader → authors. Groups paths by the
//!   reader's first-hop neighbor; within a group, max wins; across groups,
//!   probabilistic independence combines them.
//! - **Reverse BFS** (visibility): authors → reader, via the transposed
//!   graph. Group key = predecessor in the reverse traversal.
//! - **Distrust** is consumed per-viewer as a multiplicative reliability
//!   factor at each hop; direct distrusts override to 0.
//! - **Hub dampening** attenuates the per-hop decay when BFS traverses
//!   *through* a node with forward in-degree above `HUB_DAMPEN_THRESHOLD`.
//!   The `_with_threshold` variants accept the threshold as a parameter so
//!   the bench can A/B dampening on/off; production code uses the default
//!   `HUB_DAMPEN_THRESHOLD` const via the non-`_with_threshold` wrappers.

use std::collections::{HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Per-hop decay constant for trust propagation (matches server/src/trust.rs).
pub const DECAY: f64 = 0.7;

/// Maximum BFS depth for trust traversal.
pub const MAX_DEPTH: u32 = 3;

/// Per-distrusted-target penalty for reliability computation.
pub const DISTRUST_PENALTY: f64 = 0.25;

/// In-degree above which transitive trust propagation *through* a node
/// is attenuated. Mirrors `HUB_DAMPEN_THRESHOLD` in server/src/trust.rs.
/// See `docs/federation-bfs-analysis.md` "Hub dampening for transitive
/// propagation."
pub const HUB_DAMPEN_THRESHOLD: u32 = 5000;

/// Maps distruster's dense node ID → set of distrusted dense node IDs.
pub type DistrustSets = HashMap<u32, HashSet<u32>>;

// ---------------------------------------------------------------------------
// CSR graph representation
// ---------------------------------------------------------------------------

/// Compressed Sparse Row graph for cache-friendly BFS traversal.
///
/// Nodes are identified by dense u32 indices. Edge targets for node `i` are
/// stored in `targets[offsets[i]..offsets[i+1]]`. This is ~3-5x more memory
/// efficient than `HashMap<K, Vec<K>>` and yields sequential memory access
/// during BFS.
pub struct CsrGraph {
    /// Per-node offset into `targets`. Length = num_nodes + 1.
    /// Node i's neighbors are `targets[offsets[i]..offsets[i+1]]`.
    pub offsets: Vec<u32>,
    /// Flat array of all edge targets (dense node indices).
    pub targets: Vec<u32>,
    pub num_nodes: u32,
}

impl CsrGraph {
    /// Build a CSR graph from an edge list over dense node indices.
    ///
    /// `num_nodes` is the total number of nodes (indices 0..num_nodes).
    /// `edges` is a list of (source, target) pairs using dense indices.
    pub fn from_edges(num_nodes: u32, edges: &[(u32, u32)]) -> Self {
        // Count outgoing edges per node.
        let n = num_nodes as usize;
        let mut degree = vec![0u32; n];
        for &(src, _) in edges {
            degree[src as usize] += 1;
        }

        // Build offset array (exclusive prefix sum).
        let mut offsets = vec![0u32; n + 1];
        for i in 0..n {
            offsets[i + 1] = offsets[i] + degree[i];
        }

        // Fill targets using a write cursor per node.
        let mut targets = vec![0u32; edges.len()];
        let mut cursor = offsets[..n].to_vec();
        for &(src, tgt) in edges {
            let pos = cursor[src as usize] as usize;
            targets[pos] = tgt;
            cursor[src as usize] += 1;
        }

        Self {
            offsets,
            targets,
            num_nodes,
        }
    }

    /// Return the neighbors of node `i` as a slice.
    #[inline]
    pub fn neighbors(&self, i: u32) -> &[u32] {
        let start = self.offsets[i as usize] as usize;
        let end = self.offsets[i as usize + 1] as usize;
        &self.targets[start..end]
    }

    /// Build the transpose (reverse) graph — same nodes, all edges flipped.
    pub fn transpose(&self) -> Self {
        let mut reverse_edges = Vec::with_capacity(self.targets.len());
        for src in 0..self.num_nodes {
            for &tgt in self.neighbors(src) {
                reverse_edges.push((tgt, src));
            }
        }
        Self::from_edges(self.num_nodes, &reverse_edges)
    }

    /// Approximate memory usage in bytes.
    pub fn memory_bytes(&self) -> usize {
        self.offsets.len() * size_of::<u32>() + self.targets.len() * size_of::<u32>()
    }
}

/// Paired forward and reverse CSR graphs for dual BFS.
pub struct DualCsrGraph {
    pub forward: CsrGraph,
    pub reverse: CsrGraph,
    #[allow(dead_code)]
    pub num_nodes: u32,
}

impl DualCsrGraph {
    pub fn from_edges(num_nodes: u32, edges: &[(u32, u32)]) -> Self {
        let forward = CsrGraph::from_edges(num_nodes, edges);
        let reverse = forward.transpose();
        Self {
            forward,
            reverse,
            num_nodes,
        }
    }

    pub fn memory_bytes(&self) -> usize {
        self.forward.memory_bytes() + self.reverse.memory_bytes()
    }
}

// ---------------------------------------------------------------------------
// Path group combination (shared by forward and reverse BFS)
// ---------------------------------------------------------------------------

/// Per-target accumulator for bottleneck-grouped probabilistic scores.
///
/// Groups are keyed by u32 node index (the "evidence source" — first-hop
/// neighbor in forward BFS, predecessor in reverse BFS). Within each group,
/// only the maximum path score is kept. Across groups, scores combine via
/// probabilistic independence: combined = 1 - ∏(1 - max_per_group).
struct PathGroupsU32 {
    /// (group_key, best_score) pairs. Small enough that linear scan beats
    /// HashMap for typical group counts (≤ source out-degree, usually < 20).
    groups: Vec<(u32, f64)>,
}

impl PathGroupsU32 {
    fn new() -> Self {
        Self { groups: Vec::new() }
    }

    /// Record a path contribution under the given group key.
    #[inline]
    fn add(&mut self, group: u32, score: f64) {
        for entry in &mut self.groups {
            if entry.0 == group {
                if score > entry.1 {
                    entry.1 = score;
                }
                return;
            }
        }
        self.groups.push((group, score));
    }

    /// Combine group maxima via probabilistic independence.
    fn combined_score(&self) -> f64 {
        if self.groups.is_empty() {
            return 0.0;
        }
        let product: f64 = self.groups.iter().map(|&(_, s)| 1.0 - s).product();
        1.0 - product
    }
}

// ---------------------------------------------------------------------------
// Distrust reliability
// ---------------------------------------------------------------------------

/// Compute the reliability factor for a node given its outgoing neighbors and
/// the viewer's distrust set. Each neighbor that appears in `viewer_distrusts`
/// contributes an independent multiplicative penalty.
#[inline]
fn reliability(neighbors: &[u32], viewer_distrusts: &HashSet<u32>) -> f64 {
    let count = neighbors
        .iter()
        .filter(|n| viewer_distrusts.contains(n))
        .count() as i32;
    (1.0 - DISTRUST_PENALTY).powi(count)
}

/// Hub-dampening multiplier applied to the per-hop decay when BFS traverses
/// *through* a node with the given forward in-degree. Parameterized on the
/// threshold so the bench can A/B by passing `u32::MAX` to disable dampening.
#[inline]
fn hub_dampening_factor(in_degree: u32, threshold: u32) -> f64 {
    if threshold == u32::MAX || in_degree <= threshold {
        1.0
    } else {
        let penalty = (in_degree as f64 / threshold as f64).ln();
        DECAY.powf(penalty)
    }
}

// ---------------------------------------------------------------------------
// Forward BFS: reader → authors (relevance)
// ---------------------------------------------------------------------------

/// Compute trust scores from a single source using bottleneck-grouped BFS
/// on the forward CSR graph with distrust propagation.
///
/// Paths are grouped by the source's direct (first-hop) neighbor. Within each
/// group, only the max path score is kept. Across groups, scores combine via
/// probabilistic independence.
///
/// Distrust propagation: each visited node's score is multiplied by a reliability
/// factor based on how many of its trust targets the viewer has distrusted.
/// After BFS, directly distrusted users are overridden to score 0.0.
///
/// Returns a vec of (target_node, combined_score) for all reachable nodes.
///
/// Hub dampening: when BFS leaves a high-in-degree node to expand to its
/// outgoing neighbours, the per-hop decay is attenuated (see
/// [`hub_dampening_factor`]). `reverse` supplies forward in-degree via
/// its outgoing-edge counts.
pub fn forward_bfs(
    source: u32,
    graph: &CsrGraph,
    reverse: &CsrGraph,
    distrust_sets: &DistrustSets,
) -> Vec<(u32, f64)> {
    forward_bfs_with_threshold(source, graph, reverse, distrust_sets, HUB_DAMPEN_THRESHOLD)
}

/// Same as [`forward_bfs`] but with a configurable hub-dampening threshold.
///
/// Pass `HUB_DAMPEN_THRESHOLD` for production-equivalent behaviour, or
/// `u32::MAX` to disable dampening entirely (used by the bench's A/B
/// measurement of dampening's frontier impact).
pub fn forward_bfs_with_threshold(
    source: u32,
    graph: &CsrGraph,
    reverse: &CsrGraph,
    distrust_sets: &DistrustSets,
    dampen_threshold: u32,
) -> Vec<(u32, f64)> {
    let empty = HashSet::new();
    let viewer_distrusts = distrust_sets.get(&source).unwrap_or(&empty);

    // BFS state: (current_node, depth, first_hop, path_score)
    let mut queue: VecDeque<(u32, u32, u32, f64)> = VecDeque::new();
    let mut target_groups: HashMap<u32, PathGroupsU32> = HashMap::new();

    // Per-first-hop visited sets prevent cycles within a group while allowing
    // the same node to be reached via different first-hop neighbors (those
    // represent independent evidence sources).
    let mut visited_per_group: HashMap<u32, HashSet<u32>> = HashMap::new();

    for &neighbor in graph.neighbors(source) {
        if neighbor == source {
            continue;
        }
        let penalized = reliability(graph.neighbors(neighbor), viewer_distrusts);
        queue.push_back((neighbor, 1, neighbor, penalized));
        target_groups
            .entry(neighbor)
            .or_insert_with(PathGroupsU32::new)
            .add(neighbor, penalized);
        visited_per_group
            .entry(neighbor)
            .or_default()
            .insert(neighbor);
    }

    while let Some((current, depth, first_hop, path_score)) = queue.pop_front() {
        if depth >= MAX_DEPTH {
            continue;
        }

        // Hub dampening (mirrors trust.rs forward_bfs_inner): traversal
        // *through* `current` attenuates by an extra factor based on
        // `current`'s forward in-degree. First-hop seeding above is at
        // full strength; dampening only applies when leaving `current`.
        let dampening =
            hub_dampening_factor(reverse.neighbors(current).len() as u32, dampen_threshold);

        for &next in graph.neighbors(current) {
            if next == source {
                continue;
            }

            let visited = visited_per_group.entry(first_hop).or_default();
            if visited.contains(&next) {
                continue;
            }
            visited.insert(next);

            let r = reliability(graph.neighbors(next), viewer_distrusts);
            let next_score = path_score * DECAY * dampening * r;

            target_groups
                .entry(next)
                .or_insert_with(PathGroupsU32::new)
                .add(first_hop, next_score);

            queue.push_back((next, depth + 1, first_hop, next_score));
        }
    }

    let mut results: Vec<(u32, f64)> = target_groups
        .into_iter()
        .map(|(target, groups)| (target, groups.combined_score()))
        .collect();

    // Direct distrust override: distrusted users get effective trust 0.0.
    if !viewer_distrusts.is_empty() {
        for entry in &mut results {
            if viewer_distrusts.contains(&entry.0) {
                entry.1 = 0.0;
            }
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Reverse BFS: who trusts the reader (visibility)
// ---------------------------------------------------------------------------

/// Compute trust-in-reader for all users who can reach `reader` within
/// MAX_DEPTH hops, using the reverse (transposed) graph.
///
/// For each discovered node A, computes trust(A, reader) using bottleneck-
/// grouped probabilistic combination. The group key for A is the
/// **predecessor** in the reverse traversal — which equals A's direct
/// forward-graph neighbor on the path toward `reader`. This correctly
/// implements the same "group by source's first-hop" semantics as the
/// forward BFS, but from every discovered source's perspective simultaneously.
///
/// Visited set semantics differ from forward BFS:
/// - A **global** visited set controls expansion (each node expanded at most
///   once, at its shallowest depth — BFS guarantees this is the highest
///   path_score).
/// - Group contributions are still recorded from later arrivals (different
///   predecessors at greater depths) without re-expanding the node. This is
///   safe because re-expansion would only produce lower scores downstream
///   (deeper paths have strictly lower path_score due to multiplicative decay).
///
/// NOTE: This function does NOT apply distrust propagation. Distrust penalties are
/// viewer-specific (each source A has its own distrust set), so they cannot be
/// folded into the shared path_score of a single reverse pass. The scores
/// returned here are an approximation that ignores distrusts. For exact
/// distrust-penalized trust(A, reader), use forward_bfs from A directly.
pub fn reverse_bfs(reader: u32, reverse_graph: &CsrGraph) -> Vec<(u32, f64)> {
    reverse_bfs_with_threshold(reader, reverse_graph, HUB_DAMPEN_THRESHOLD)
}

/// Same as [`reverse_bfs`] but with a configurable hub-dampening threshold.
pub fn reverse_bfs_with_threshold(
    reader: u32,
    reverse_graph: &CsrGraph,
    dampen_threshold: u32,
) -> Vec<(u32, f64)> {
    // BFS state: (current_node, depth, path_score)
    // No first_hop tag — the group key is determined by expansion context.
    let mut queue: VecDeque<(u32, u32, f64)> = VecDeque::new();
    let mut target_groups: HashMap<u32, PathGroupsU32> = HashMap::new();

    // Global visited set: controls which nodes get expanded (enqueued).
    // A node is expanded only on its first visit (shallowest depth).
    let mut visited: HashSet<u32> = HashSet::new();

    // Seed: reader's in-neighbors in forward graph = reader's out-neighbors
    // in the reverse graph. Each such node N has a direct forward edge to
    // reader, so trust(N, reader) has group key = reader itself, score 1.0.
    for &neighbor in reverse_graph.neighbors(reader) {
        if neighbor == reader {
            continue;
        }
        target_groups
            .entry(neighbor)
            .or_insert_with(PathGroupsU32::new)
            .add(reader, 1.0);
        if visited.insert(neighbor) {
            queue.push_back((neighbor, 1, 1.0));
        }
    }

    while let Some((current, depth, path_score)) = queue.pop_front() {
        if depth >= MAX_DEPTH {
            continue;
        }

        // Hub dampening (mirrors trust.rs reverse_bfs): traversal *through*
        // `current` attenuates by an extra factor based on `current`'s
        // forward in-degree, which equals its reverse out-degree — the
        // neighbours we are about to iterate over.
        let dampening = hub_dampening_factor(
            reverse_graph.neighbors(current).len() as u32,
            dampen_threshold,
        );
        let next_score = path_score * DECAY * dampening;

        // In the reverse graph, an edge current → next means next → current
        // in the forward graph. So `current` is `next`'s direct forward
        // neighbor on this path toward reader. The group key for `next` on
        // this path is therefore `current`.
        for &next in reverse_graph.neighbors(current) {
            if next == reader {
                continue;
            }

            // Always record the group contribution, even if `next` was
            // already visited — different predecessors represent different
            // groups for `next`'s trust calculation.
            target_groups
                .entry(next)
                .or_insert_with(PathGroupsU32::new)
                .add(current, next_score);

            // Only expand (enqueue) on first visit. Re-expansion is
            // unnecessary: BFS visits shallowest-first, so the first
            // expansion produces the highest path_score downstream.
            // Later arrivals at greater depth contribute lower scores
            // that are only relevant for the arrived node's own groups,
            // not for anything further downstream.
            if visited.insert(next) {
                queue.push_back((next, depth + 1, next_score));
            }
        }
    }

    target_groups
        .into_iter()
        .map(|(target, groups)| (target, groups.combined_score()))
        .collect()
}

// ---------------------------------------------------------------------------
// Distrust helpers
// ---------------------------------------------------------------------------

/// Build a DistrustSets lookup from a list of (distruster, distrusted) pairs.
pub fn build_distrust_sets(distrust_edges: &[(u32, u32)]) -> DistrustSets {
    let mut sets: DistrustSets = HashMap::new();
    for &(distruster, distrusted) in distrust_edges {
        sets.entry(distruster).or_default().insert(distrusted);
    }
    sets
}

// ---------------------------------------------------------------------------
// HashMap reference implementation (correctness oracle)
// ---------------------------------------------------------------------------

/// HashMap-based adjacency list (same shape as server/src/trust.rs, using u32).
pub struct HashMapGraph {
    pub adj: HashMap<u32, Vec<u32>>,
}

impl HashMapGraph {
    pub fn from_edges(edges: &[(u32, u32)]) -> Self {
        let mut adj: HashMap<u32, Vec<u32>> = HashMap::new();
        for &(src, tgt) in edges {
            adj.entry(src).or_default().push(tgt);
        }
        Self { adj }
    }
}

/// Reference forward BFS on HashMap graph (mirrors server/src/trust.rs logic)
/// with distrust propagation and hub dampening.
///
/// Used as a correctness oracle against the CSR `forward_bfs`. For
/// correctness this builds an inbound-degree map by iterating all
/// adjacency lists once — O(V·E_avg), fine for the small test graphs.
pub fn reference_forward_bfs(
    source: u32,
    graph: &HashMapGraph,
    distrust_sets: &DistrustSets,
) -> Vec<(u32, f64)> {
    let empty_distrusts = HashSet::new();
    let viewer_distrusts = distrust_sets.get(&source).unwrap_or(&empty_distrusts);
    let empty_neighbors: Vec<u32> = Vec::new();

    // Precompute forward in-degrees for hub dampening. The HashMap graph
    // has no transpose primitive, so we tally inbound counts by scanning
    // every outgoing edge once.
    let mut in_degrees: HashMap<u32, u32> = HashMap::new();
    for neighbors in graph.adj.values() {
        for &tgt in neighbors {
            *in_degrees.entry(tgt).or_insert(0) += 1;
        }
    }

    let mut queue: VecDeque<(u32, u32, u32, f64)> = VecDeque::new();
    let mut target_groups: HashMap<u32, PathGroupsU32> = HashMap::new();
    let mut visited_per_group: HashMap<u32, HashSet<u32>> = HashMap::new();

    if let Some(neighbors) = graph.adj.get(&source) {
        for &neighbor in neighbors {
            if neighbor == source {
                continue;
            }
            let nbr_targets = graph.adj.get(&neighbor).unwrap_or(&empty_neighbors);
            let r = reliability(nbr_targets, viewer_distrusts);
            let penalized = 1.0 * r;
            queue.push_back((neighbor, 1, neighbor, penalized));
            target_groups
                .entry(neighbor)
                .or_insert_with(PathGroupsU32::new)
                .add(neighbor, penalized);
            visited_per_group
                .entry(neighbor)
                .or_default()
                .insert(neighbor);
        }
    }

    while let Some((current, depth, first_hop, path_score)) = queue.pop_front() {
        if depth >= MAX_DEPTH {
            continue;
        }

        // Hub dampening: traversal *through* `current` attenuates by an
        // extra factor based on its inbound count.
        let dampening = hub_dampening_factor(
            in_degrees.get(&current).copied().unwrap_or(0),
            HUB_DAMPEN_THRESHOLD,
        );

        if let Some(neighbors) = graph.adj.get(&current) {
            for &next in neighbors {
                if next == source {
                    continue;
                }
                let visited = visited_per_group.entry(first_hop).or_default();
                if visited.contains(&next) {
                    continue;
                }
                visited.insert(next);

                let next_targets = graph.adj.get(&next).unwrap_or(&empty_neighbors);
                let r = reliability(next_targets, viewer_distrusts);
                let next_score = path_score * DECAY * dampening * r;
                target_groups
                    .entry(next)
                    .or_insert_with(PathGroupsU32::new)
                    .add(first_hop, next_score);
                queue.push_back((next, depth + 1, first_hop, next_score));
            }
        }
    }

    let mut results: Vec<(u32, f64)> = target_groups
        .into_iter()
        .map(|(target, groups)| (target, groups.combined_score()))
        .collect();

    if !viewer_distrusts.is_empty() {
        for entry in &mut results {
            if viewer_distrusts.contains(&entry.0) {
                entry.1 = 0.0;
            }
        }
    }

    results
}
