use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use quick_cache::Weighter;
use quick_cache::sync::Cache;
use sqlx::SqlitePool;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::metrics::Metrics;

/// Per-hop decay constant for trust propagation.
const DECAY: f64 = 0.7;

/// Maximum BFS depth for trust traversal.
const MAX_DEPTH: u32 = 3;

/// Minimum trust score to be considered trusted. Scores below this are
/// treated as untrusted (no trust relationship).
pub const MINIMUM_TRUST_THRESHOLD: f64 = 0.45;

/// In-degree (number of inbound trust edges) above which transitive
/// propagation *through* a node is attenuated. See
/// `docs/federation-bfs-analysis.md` ("Hub dampening for transitive
/// propagation") for the design rationale.
///
/// Penalty is applied to traversal *through* a node — i.e. when BFS leaves
/// the node to expand to its outgoing neighbours — not to arrival *at* the
/// node. Direct trust into a hub is full strength; a hub's own outbound
/// BFS as a source is unpenalised. What attenuates is the hub acting as a
/// transitive bridge.
///
/// In-degree counts only inbound *trust* edges (not distrust). Measured
/// against the locally-observed forward in-degree — under federation each
/// instance dampens against its own view, consistent with "federate data,
/// not computation."
const HUB_DAMPEN_THRESHOLD: u32 = 5000;

/// Default total BFS cache budget (in bytes). Carved 7/16 to the
/// per-viewer forward cache, 1/16 to the delta-keyed forward cache (only
/// active mutators populate it), and 8/16 to the reverse cache.
///
/// This value is mirrored in the seed `INSERT` of the
/// `instance_config` migration. If you change it, write a new
/// migration that updates the seeded default — otherwise existing
/// deployments stay on the old value (the migration's `INSERT OR
/// IGNORE` is a no-op once the row exists) while new deployments
/// pick up the new one.
const DEFAULT_BFS_CACHE_BYTES: u64 = 64 * 1024 * 1024;

/// Fraction (in sixteenths) of the total BFS cache budget reserved for
/// the delta-keyed forward cache. Most viewers have no pending delta,
/// so a small share is sufficient.
const DELTA_CACHE_BUDGET_SIXTEENTHS: u64 = 1;

/// Approximate bytes per entry in a `HashMap<String, f64>` BFS result map.
/// Accounts for: 36-byte UUID string + 24-byte String overhead + 8-byte f64
/// value + ~16 bytes HashMap per-bucket overhead.
const BYTES_PER_MAP_ENTRY: u64 = 84;

/// Base overhead per cached BFS result (Arc + HashMap allocation).
const MAP_BASE_OVERHEAD: u64 = 48;

/// Weighter that estimates the heap size of a cached BFS result map.
///
/// Implemented for both the per-viewer key (`Uuid`) used by the
/// stable forward/reverse caches and the per-viewer-per-seq key
/// (`(Uuid, u64)`) used by the delta-keyed forward cache. The weight
/// ignores the key — only the map size matters for the byte budget.
#[derive(Clone)]
struct BfsWeighter;

impl Weighter<Uuid, Arc<HashMap<String, f64>>> for BfsWeighter {
    fn weight(&self, _key: &Uuid, val: &Arc<HashMap<String, f64>>) -> u64 {
        MAP_BASE_OVERHEAD + (val.len() as u64 * BYTES_PER_MAP_ENTRY)
    }
}

impl Weighter<(Uuid, u64), Arc<HashMap<String, f64>>> for BfsWeighter {
    fn weight(&self, _key: &(Uuid, u64), val: &Arc<HashMap<String, f64>>) -> u64 {
        MAP_BASE_OVERHEAD + (val.len() as u64 * BYTES_PER_MAP_ENTRY)
    }
}

type BfsCache = Cache<Uuid, Arc<HashMap<String, f64>>, BfsWeighter>;
type DeltaBfsCache = Cache<(Uuid, u64), Arc<HashMap<String, f64>>, BfsWeighter>;

/// Per-distrusted-target penalty for reliability computation.
const DISTRUST_PENALTY: f64 = 0.25;

/// Maps distruster's dense node ID → set of distrusted dense node IDs.
type DistrustSets = HashMap<u32, HashSet<u32>>;

// ---------------------------------------------------------------------------
// CSR graph representation
// ---------------------------------------------------------------------------

/// Compressed Sparse Row graph for cache-friendly BFS traversal.
///
/// Nodes are identified by dense u32 indices. Edge targets for node `i` are
/// stored in `targets[offsets[i]..offsets[i+1]]`. This is ~3-5x more memory
/// efficient than `HashMap<Uuid, Vec<Uuid>>` and yields sequential memory
/// access during BFS.
struct CsrGraph {
    /// Per-node offset into `targets`. Length = num_nodes + 1.
    /// Node i's neighbors are `targets[offsets[i]..offsets[i+1]]`.
    offsets: Vec<u32>,
    /// Flat array of all edge targets (dense node indices).
    targets: Vec<u32>,
    num_nodes: u32,
}

impl CsrGraph {
    /// Build a CSR graph from an edge list over dense node indices.
    fn from_edges(num_nodes: u32, edges: &[(u32, u32)]) -> Self {
        let n = num_nodes as usize;
        let mut degree = vec![0u32; n];
        for &(src, _) in edges {
            degree[src as usize] += 1;
        }

        // Exclusive prefix sum to build offset array.
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

    #[inline]
    fn neighbors(&self, i: u32) -> &[u32] {
        let start = self.offsets[i as usize] as usize;
        let end = self.offsets[i as usize + 1] as usize;
        &self.targets[start..end]
    }

    /// Build the transpose (reverse) graph — same nodes, all edges flipped.
    fn transpose(&self) -> Self {
        let mut reverse_edges = Vec::with_capacity(self.targets.len());
        for src in 0..self.num_nodes {
            for &tgt in self.neighbors(src) {
                reverse_edges.push((tgt, src));
            }
        }
        Self::from_edges(self.num_nodes, &reverse_edges)
    }
}

// ---------------------------------------------------------------------------
// Bidirectional UUID ↔ u32 index mapping
// ---------------------------------------------------------------------------

/// Bidirectional mapping between UUIDs and dense u32 node indices.
///
/// Built during graph construction from trust_edges. Allows the CSR to work
/// with compact u32 indices while the public API uses UUIDs.
struct NodeIndex {
    uuid_to_id: HashMap<Uuid, u32>,
    id_to_uuid: Vec<Uuid>,
}

impl NodeIndex {
    /// Build a node index from an edge list, assigning dense IDs in discovery
    /// order.
    fn from_edges(edges: &[(Uuid, Uuid)]) -> Self {
        let mut uuid_to_id: HashMap<Uuid, u32> = HashMap::new();
        let mut id_to_uuid: Vec<Uuid> = Vec::new();

        let intern = |uuid: Uuid, map: &mut HashMap<Uuid, u32>, vec: &mut Vec<Uuid>| -> u32 {
            if let Some(&id) = map.get(&uuid) {
                id
            } else {
                let id = vec.len() as u32;
                map.insert(uuid, id);
                vec.push(uuid);
                id
            }
        };

        for &(src, tgt) in edges {
            intern(src, &mut uuid_to_id, &mut id_to_uuid);
            intern(tgt, &mut uuid_to_id, &mut id_to_uuid);
        }

        Self {
            uuid_to_id,
            id_to_uuid,
        }
    }

    fn num_nodes(&self) -> u32 {
        self.id_to_uuid.len() as u32
    }

    fn get_id(&self, uuid: &Uuid) -> Option<u32> {
        self.uuid_to_id.get(uuid).copied()
    }

    fn get_uuid(&self, id: u32) -> Uuid {
        self.id_to_uuid[id as usize]
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
struct PathGroups {
    /// (group_key, best_score) pairs. Linear scan beats HashMap for typical
    /// group counts (≤ source out-degree, usually < 20).
    groups: Vec<(u32, f64)>,
}

impl PathGroups {
    fn new() -> Self {
        Self { groups: Vec::new() }
    }

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
/// *through* a node with the given forward in-degree.
///
/// Returns `1.0` (no penalty) when `in_degree <= HUB_DAMPEN_THRESHOLD`, so
/// the curve is continuous at the threshold. Above the threshold an extra
/// logarithmic penalty is folded into the decay:
///
/// ```text
/// effective_decay_through_C = DECAY ^ (1 + ln(d / k))
/// ```
///
/// Applied as a multiplier on the existing `DECAY` term: the expanding
/// edge's score becomes `path_score * DECAY * dampening_factor(d) * r`.
///
/// Natural-log shape matches the intuition that "meaningfully different
/// in-degree" is logarithmic — 5K vs 50K matters more than 50K vs 51K.
#[inline]
fn hub_dampening_factor(in_degree: u32) -> f64 {
    if in_degree <= HUB_DAMPEN_THRESHOLD {
        1.0
    } else {
        let penalty = (in_degree as f64 / HUB_DAMPEN_THRESHOLD as f64).ln();
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
/// Hub dampening: when BFS leaves a high-in-degree node to expand to its
/// outgoing neighbours, the per-hop decay is attenuated (see
/// [`hub_dampening_factor`]). `reverse` supplies the in-degree by mirroring
/// inbound trust edges.
fn forward_bfs(
    source: u32,
    graph: &CsrGraph,
    reverse: &CsrGraph,
    distrust_sets: &DistrustSets,
) -> Vec<(u32, f64)> {
    let empty = HashSet::new();
    let viewer_distrusts = distrust_sets.get(&source).unwrap_or(&empty);
    let source_neighbors: Vec<u32> = graph.neighbors(source).to_vec();
    forward_bfs_inner(source, graph, reverse, &source_neighbors, viewer_distrusts)
}

/// Inner BFS that operates on caller-provided seed neighbors and distrust set.
///
/// Factored out so both the cached-graph path (`forward_bfs`) and the
/// delta-aware path (`forward_bfs_with_delta`) can share traversal logic
/// while differing only in how the viewer's own outgoing edges and distrust
/// set are sourced.
///
/// `source_neighbors` is the effective first-hop list (may include edges the
/// viewer added since the last rebuild and exclude edges they removed).
/// `viewer_distrusts` is the effective distrust set with the same overlay
/// semantics. Only the source's outgoing edges are overlaid — every other
/// node's neighbors come from the cached `graph` directly.
///
/// `reverse` is the transposed graph, used to look up each intermediate
/// node's forward in-degree for hub dampening. Note that the source's own
/// effective in-degree under a delta overlay is not recomputed — dampening
/// applies to nodes the BFS traverses *through*, never to the source.
fn forward_bfs_inner(
    source: u32,
    graph: &CsrGraph,
    reverse: &CsrGraph,
    source_neighbors: &[u32],
    viewer_distrusts: &HashSet<u32>,
) -> Vec<(u32, f64)> {
    // BFS state: (current_node, depth, first_hop, path_score)
    let mut queue: VecDeque<(u32, u32, u32, f64)> = VecDeque::new();
    let mut target_groups: HashMap<u32, PathGroups> = HashMap::new();

    // Per-first-hop visited sets prevent cycles within a group while allowing
    // the same node to be reached via different first-hop neighbors (those
    // represent independent evidence sources).
    let mut visited_per_group: HashMap<u32, HashSet<u32>> = HashMap::new();

    // Track first-hops we've already seeded so a stale delta entry that
    // duplicates an edge already in the cached graph (or any other source
    // of duplicates) does not cause double-seeding.
    let mut seeded_first_hops: HashSet<u32> = HashSet::new();

    for &neighbor in source_neighbors {
        if neighbor == source || !seeded_first_hops.insert(neighbor) {
            continue;
        }
        let penalized = reliability(graph.neighbors(neighbor), viewer_distrusts);
        queue.push_back((neighbor, 1, neighbor, penalized));
        target_groups
            .entry(neighbor)
            .or_insert_with(PathGroups::new)
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

        // Hub dampening: traversal *through* `current` attenuates by an
        // extra factor proportional to `current`'s forward in-degree.
        // Forward in-degree of a node equals its reverse out-degree, which
        // is exactly `reverse.neighbors(current).len()`. The penalty is
        // computed once per pop (it only depends on `current`) and applied
        // to every outgoing expansion below.
        //
        // Not applied at first-hop arrival — the seeding loop above adds
        // first-hop neighbours at full strength, consistent with "direct
        // trust into a hub stays full strength."
        let dampening = hub_dampening_factor(reverse.neighbors(current).len() as u32);

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
                .or_insert_with(PathGroups::new)
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

/// Compute the effective source neighbors and distrust set for `source`
/// after applying `delta` against the cached graph.
///
/// Returns `(source_neighbors, viewer_distrusts)` ready to feed into
/// `forward_bfs_inner`. Centralised so every delta-aware entry point on
/// `TrustGraph` overlays edges identically.
fn apply_delta_overlay(
    source: u32,
    graph: &TrustGraph,
    delta: &ViewerDelta,
) -> (Vec<u32>, HashSet<u32>) {
    let mut neighbors: Vec<u32> = graph.forward.neighbors(source).to_vec();

    if !delta.trust_removed.is_empty() {
        let removed: HashSet<u32> = delta
            .trust_removed
            .iter()
            .filter_map(|u| graph.index.get_id(u))
            .collect();
        if !removed.is_empty() {
            neighbors.retain(|n| !removed.contains(n));
        }
    }
    if !delta.trust_added.is_empty() {
        let existing: HashSet<u32> = neighbors.iter().copied().collect();
        for added_uuid in &delta.trust_added {
            if let Some(added_id) = graph.index.get_id(added_uuid)
                && !existing.contains(&added_id)
            {
                neighbors.push(added_id);
            }
        }
    }

    let mut distrusts: HashSet<u32> = graph
        .distrust_sets
        .get(&source)
        .cloned()
        .unwrap_or_default();
    for removed_uuid in &delta.distrust_removed {
        if let Some(removed_id) = graph.index.get_id(removed_uuid) {
            distrusts.remove(&removed_id);
        }
    }
    for added_uuid in &delta.distrust_added {
        if let Some(added_id) = graph.index.get_id(added_uuid) {
            distrusts.insert(added_id);
        }
    }

    (neighbors, distrusts)
}

// ---------------------------------------------------------------------------
// Pending deltas: per-viewer in-memory record of recent edge mutations
// ---------------------------------------------------------------------------

/// Outgoing-edge stance the viewer expresses toward a single target.
///
/// Mirrors the three values the trust UI buttons can produce. Used by
/// mutation handlers to communicate the post-write state to
/// [`PendingDeltas::apply`], which translates it into delta-set membership.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TrustStance {
    Neutral,
    Trust,
    Distrust,
}

/// Per-viewer record of trust-edge mutations not yet absorbed by a graph
/// rebuild.
///
/// The cached `TrustGraph` is rebuilt on a debounced schedule, so between
/// a viewer clicking Trust/Distrust/Neutral and the next rebuild firing
/// their own outgoing edges in the cached graph are stale. To give
/// immediate feedback (badge color updates without waiting for the
/// rebuild), forward BFS layers a `ViewerDelta` on top of the cached
/// graph for the source node only.
///
/// Other people's edges and the transitive ripple from this viewer's
/// change still come from the cached graph — that is the staleness the
/// debounce was intentionally amortising and is not (and should not be)
/// affected by deltas.
///
/// Membership invariants:
/// - For any target, at most one of `trust_added` / `trust_removed`
///   contains it (likewise for distrust). Both being set simultaneously
///   would be a self-cancelling delta.
/// - A target may appear in both `trust_removed` and `distrust_added`
///   (the viewer flipped from trust to distrust without going through
///   neutral). [`PendingDeltas::apply`] computes the correct combination.
#[derive(Clone, Default, Debug)]
pub struct ViewerDelta {
    /// Trust edges (viewer → target) the viewer has set since the last
    /// rebuild that the cached graph does not yet contain.
    pub trust_added: HashSet<Uuid>,
    /// Trust edges (viewer → target) the viewer has cleared since the
    /// last rebuild that the cached graph still contains.
    pub trust_removed: HashSet<Uuid>,
    /// Distrust edges the viewer has added since the last rebuild that
    /// the cached graph's distrust set does not yet contain.
    pub distrust_added: HashSet<Uuid>,
    /// Distrust edges the viewer has cleared since the last rebuild
    /// that the cached graph's distrust set still contains.
    pub distrust_removed: HashSet<Uuid>,
    /// Highest mutation sequence number contributing to this delta.
    /// The rebuild loop captures a high-water seq before reading the DB
    /// and purges entries with `seq < high_water` after the swap, which
    /// drops deltas the new graph has fully absorbed.
    pub seq: u64,
}

impl ViewerDelta {
    /// Returns true if the delta carries no pending mutations.
    ///
    /// Hot-path callers short-circuit on this to take the cached BFS
    /// fast path and skip the per-request BFS recompute.
    pub fn is_empty(&self) -> bool {
        self.trust_added.is_empty()
            && self.trust_removed.is_empty()
            && self.distrust_added.is_empty()
            && self.distrust_removed.is_empty()
    }
}

/// Process-wide store of per-viewer pending edge mutations.
///
/// Lives on `AppState` alongside the `TrustGraph` Arc. Mutation handlers
/// call [`PendingDeltas::apply`] after their DB write commits; the
/// rebuild loop calls [`PendingDeltas::current_seq`] before reading the
/// DB and [`PendingDeltas::purge_below`] after the Arc swap to drop
/// absorbed entries.
///
/// All entries are in-memory only — on process restart the rebuild reads
/// the canonical state from the database, so no recovery is needed.
pub struct PendingDeltas {
    inner: std::sync::RwLock<HashMap<Uuid, ViewerDelta>>,
    /// Monotonic sequence counter assigned at mutation-record time.
    /// `AcqRel` on `fetch_add` synchronises with `Acquire` on the rebuild's
    /// `current_seq` read so the rebuild's high-water value reliably
    /// includes every mutation that committed before the rebuild started.
    seq_counter: std::sync::atomic::AtomicU64,
    /// Optional metrics handle. When present, lock-poisoning observations
    /// bump `pending_deltas_lock_poisoned` so the admin dashboard can
    /// surface them. `None` for tests that exercise this struct in
    /// isolation.
    metrics: Option<Arc<Metrics>>,
}

impl Default for PendingDeltas {
    fn default() -> Self {
        Self::new(None)
    }
}

impl PendingDeltas {
    pub fn new(metrics: Option<Arc<Metrics>>) -> Self {
        Self {
            inner: std::sync::RwLock::new(HashMap::new()),
            seq_counter: std::sync::atomic::AtomicU64::new(1),
            metrics,
        }
    }

    /// Record a poisoned-lock observation against the metrics handle if
    /// one is attached. Centralised so every poison branch routes
    /// through the same point and stays consistent with the trust-graph
    /// poison-handling pattern (`AppState::get_trust_graph`).
    fn record_poisoned(&self) {
        if let Some(m) = &self.metrics {
            m.record_pending_deltas_lock_poisoned();
        }
        tracing::error!("pending deltas lock poisoned");
    }

    /// Capture the current high-water sequence value.
    ///
    /// Called by the rebuild loop **before** it reads the trust edges
    /// from the database. After the rebuild's Arc swap completes,
    /// `purge_below(captured_value)` drops any delta whose mutations
    /// committed before this capture — those mutations are reflected in
    /// the new graph, so the delta is now redundant.
    pub fn current_seq(&self) -> u64 {
        self.seq_counter.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Read the viewer's current delta.
    ///
    /// Returns `Default::default()` (an empty delta) if the viewer has no
    /// pending mutations. Most callers hit this path; the empty delta
    /// short-circuits to the cached BFS fast path inside
    /// `distance_map_with_delta` and friends.
    ///
    /// On lock poisoning the metric is bumped and an empty delta is
    /// returned — the BFS path then degrades to the stable cached graph
    /// without the per-viewer overlay, which is the safe behaviour
    /// (slightly stale, never wrong).
    pub fn get(&self, viewer: Uuid) -> ViewerDelta {
        match self.inner.read() {
            Ok(guard) => guard.get(&viewer).cloned().unwrap_or_default(),
            Err(_) => {
                self.record_poisoned();
                ViewerDelta::default()
            }
        }
    }

    /// Record a mutation against the viewer's pending delta.
    ///
    /// `cached_was_trust` and `cached_was_distrust` describe what the
    /// cached graph currently says about the (viewer → target) edge —
    /// the caller should query [`TrustGraph::has_trust_edge`] /
    /// [`TrustGraph::has_distrust_edge`] against the current graph just
    /// before calling this method. They cannot both be true (a target
    /// is either trusted, distrusted, or neutral in the cached graph).
    ///
    /// `new_stance` is the post-mutation DB state.
    ///
    /// Must be called **after** the DB transaction commits — the rebuild
    /// loop's high-water-mark logic relies on the seq counter advancing
    /// only for mutations that are durably committed. Calling before the
    /// commit risks a window where the rebuild reads the DB without the
    /// new edge yet observes a seq ≥ the delta's seq, which would cause
    /// `purge_below` to drop a delta the rebuild did not absorb.
    pub fn apply(
        &self,
        viewer: Uuid,
        target: Uuid,
        cached_was_trust: bool,
        cached_was_distrust: bool,
        new_stance: TrustStance,
    ) {
        debug_assert!(
            !(cached_was_trust && cached_was_distrust),
            "edge cannot be both trust and distrust in the cached graph"
        );

        // Fetch a fresh seq AFTER the caller's DB commit. AcqRel ensures
        // the rebuild's later Acquire load observes everything the caller
        // produced before this fetch_add (the SQLite commit on this
        // connection has already returned, so subsequent SELECTs from any
        // pool connection will see the new row).
        let seq = self
            .seq_counter
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        let mut guard = match self.inner.write() {
            Ok(g) => g,
            Err(_) => {
                // Lock poisoned: skip recording the delta. The DB has
                // already accepted the mutation, so the next rebuild
                // will absorb it; transient BFS results just won't see
                // the per-viewer overlay until then.
                self.record_poisoned();
                return;
            }
        };
        let entry = guard.entry(viewer).or_default();

        // Recompute this target's delta membership from scratch — clear any
        // stale entries from prior clicks on the same target before
        // reapplying based on the freshly observed cached state.
        entry.trust_added.remove(&target);
        entry.trust_removed.remove(&target);
        entry.distrust_added.remove(&target);
        entry.distrust_removed.remove(&target);

        let now_trust = matches!(new_stance, TrustStance::Trust);
        let now_distrust = matches!(new_stance, TrustStance::Distrust);

        if now_trust && !cached_was_trust {
            entry.trust_added.insert(target);
        }
        if !now_trust && cached_was_trust {
            entry.trust_removed.insert(target);
        }
        if now_distrust && !cached_was_distrust {
            entry.distrust_added.insert(target);
        }
        if !now_distrust && cached_was_distrust {
            entry.distrust_removed.insert(target);
        }

        entry.seq = entry.seq.max(seq);

        // If the new mutation cancels out the prior pending change (back
        // to the cached graph's state) and the entry is now empty, drop
        // it to keep the map sparse.
        if entry.is_empty() {
            guard.remove(&viewer);
        }
    }

    /// Drop entries whose latest mutation is older than `high_water`.
    ///
    /// Called by the rebuild loop after the Arc swap completes. Any
    /// delta with `seq < high_water` was committed before the rebuild
    /// captured its high-water mark and is therefore reflected in the
    /// new graph; the delta entry is now redundant.
    ///
    /// Entries with `seq >= high_water` are kept: they represent
    /// mutations that arrived after the rebuild started reading the DB
    /// and may not have been included in the new graph. They will be
    /// reconsidered on the next rebuild cycle.
    pub fn purge_below(&self, high_water: u64) {
        let mut guard = match self.inner.write() {
            Ok(g) => g,
            Err(_) => {
                // Lock poisoned: skip the purge. Stale entries will be
                // re-evaluated on the next rebuild cycle; the worst
                // case is a few extra delta-cache misses until then.
                self.record_poisoned();
                return;
            }
        };
        guard.retain(|_, delta| delta.seq >= high_water);
    }
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
fn reverse_bfs(reader: u32, reverse_graph: &CsrGraph) -> Vec<(u32, f64)> {
    // BFS state: (current_node, depth, path_score)
    // No first_hop tag — the group key is determined by expansion context.
    let mut queue: VecDeque<(u32, u32, f64)> = VecDeque::new();
    let mut target_groups: HashMap<u32, PathGroups> = HashMap::new();

    // Global visited set: controls which nodes get expanded (enqueued).
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
            .or_insert_with(PathGroups::new)
            .add(reader, 1.0);
        if visited.insert(neighbor) {
            queue.push_back((neighbor, 1, 1.0));
        }
    }

    while let Some((current, depth, path_score)) = queue.pop_front() {
        if depth >= MAX_DEPTH {
            continue;
        }

        // Hub dampening: traversal *through* `current` attenuates by an
        // extra factor proportional to `current`'s forward in-degree.
        // Forward in-degree of `current` is exactly its reverse out-degree
        // — the neighbours we are about to iterate over.
        //
        // Applied symmetrically with forward BFS (same "through, not at"
        // rule): seeding above attaches `reader`'s direct trusters at full
        // strength; dampening only kicks in when we leave them to expand
        // to *their* trusters.
        let dampening = hub_dampening_factor(reverse_graph.neighbors(current).len() as u32);
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
                .or_insert_with(PathGroups::new)
                .add(current, next_score);

            // Only expand (enqueue) on first visit. Re-expansion is
            // unnecessary: BFS visits shallowest-first, so the first
            // expansion produces the highest path_score downstream.
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
// UserStatus / TrustInfo: shared types for API responses
// ---------------------------------------------------------------------------

/// Account status for a user, as exposed on the wire.
///
/// `Active`, `Banned`, `Suspended` come directly from the `users.status`
/// TEXT column (`"active"` / `"banned"` / `"suspended"`). `Deleted` is
/// **never** stored in that column — it is a projection computed at
/// serialization time from the `users.deleted_at` tombstone via
/// [`UserStatus::effective`]. Keeping `status` and `deleted_at` as two
/// separate DB fields avoids a drift hazard (two sources of truth for
/// "is this user deleted?"); the enum unifies them only at the API
/// boundary.
///
/// `TryFrom<&str>` therefore accepts only the three moderation strings
/// and rejects `"deleted"` — if it ever appears in the column that's a
/// data-integrity bug, not a valid state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Banned,
    Suspended,
    Deleted,
}

impl UserStatus {
    /// Returns `true` if the user is active (not banned, suspended, or deleted).
    pub fn is_active(&self) -> bool {
        *self == Self::Active
    }

    /// Project the raw moderation status to the effective wire status.
    ///
    /// If `deleted_at` is `Some`, the user has been self-deleted and
    /// the effective status is `Deleted` regardless of what the
    /// `users.status` column says. Call this once at each SQL parse
    /// site that surfaces a status for API output; everything
    /// downstream can then treat `UserStatus` as the single source of
    /// truth.
    pub fn effective(raw: UserStatus, deleted_at: Option<&str>) -> UserStatus {
        if deleted_at.is_some() {
            UserStatus::Deleted
        } else {
            raw
        }
    }
}

impl TryFrom<&str> for UserStatus {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "active" => Ok(Self::Active),
            "banned" => Ok(Self::Banned),
            "suspended" => Ok(Self::Suspended),
            other => Err(format!("unknown user status: {other}")),
        }
    }
}

/// Per-viewer metadata attached to any user reference in API responses.
///
/// Carries every per-viewer fact about a referenced user: trust
/// distance, the viewer's distrust flag, the target's effective
/// account status, and the viewer's optional private tag.
///
/// Built via `UserViewerInfo::build` from a distance map (forward BFS
/// results), the viewer's distrust set, the viewer's tag map, and the
/// target user's status. Serialized on the wire as a `"viewer"` object
/// nested inside whatever envelope referenced the user, e.g.
/// `{ "viewer": { "distance": 1.5, "distrusted": false, "tag": "Alice" } }`.
#[derive(Clone, serde::Serialize)]
pub struct UserViewerInfo {
    pub distance: Option<f64>,
    pub distrusted: bool,
    #[serde(skip_serializing_if = "UserStatus::is_active")]
    pub status: UserStatus,
    /// Viewer-private tag the current viewer has attached to this user
    /// (max 35 grapheme clusters, plain text, see `users.rs::set_user_tag`).
    /// Suppressed for the viewer themselves and for deleted users; absent
    /// when the viewer has not tagged this user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

impl UserViewerInfo {
    /// Build per-viewer info for a user from the viewer's distance map,
    /// distrust set, tag map, and the target user's account status.
    ///
    /// The tag is suppressed for deleted users — the display name on a
    /// deleted account is anonymised to `deleted-<hex>`, so a stale tag
    /// pointing at it would just be a dangling note with no recognition
    /// value (see UserName.svelte's deleted-user branch).
    pub fn build(
        user_id: &str,
        distance_map: &HashMap<String, f64>,
        distrust_set: &HashSet<String>,
        tag_map: &HashMap<String, String>,
        status: UserStatus,
    ) -> Self {
        let tag = if matches!(status, UserStatus::Deleted) {
            None
        } else {
            tag_map.get(user_id).cloned()
        };
        Self {
            distance: distance_map.get(user_id).copied(),
            distrusted: distrust_set.contains(user_id),
            status,
            tag,
        }
    }

    /// Per-viewer info for the viewer themselves (distance 0, not
    /// distrusted, no tag — self-tag is rejected at the endpoint).
    pub fn self_view() -> Self {
        Self {
            distance: None,
            distrusted: false,
            status: UserStatus::Active,
            tag: None,
        }
    }
}

/// Load the set of user IDs that the viewer has distrusted.
pub async fn load_distrust_set(
    db: &sqlx::SqlitePool,
    viewer_id: &str,
) -> Result<HashSet<String>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT target_user FROM current_trust_edges WHERE source_user = ? AND trust_type = 'distrust'",
        viewer_id,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| r.target_user).collect())
}

/// Load all of the viewer's private user tags as a `target_id -> tag` map.
///
/// Loaded once per request (mirroring `load_distrust_set`) and merged into
/// `UserViewerInfo::build`. Bounded by however many users this viewer has
/// tagged — expected to stay small in practice.
pub async fn load_tag_map(
    db: &sqlx::SqlitePool,
    viewer_id: &str,
) -> Result<HashMap<String, String>, sqlx::Error> {
    // TODO: No enforcement in practice that this will be a small result set. Maybe we should limit
    //  the total number of tags a user can have? (e.g. limit of 2000, auto-delete the tag
    //  associated with the least recently active tagged user?)
    let rows = sqlx::query!(
        "SELECT target_id, tag FROM user_tags WHERE viewer_id = ?",
        viewer_id,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.target_id, r.tag)).collect())
}

// ---------------------------------------------------------------------------
// Score-to-distance conversion
// ---------------------------------------------------------------------------

/// Convert a trust score to an effective distance in the range [1.0, 3.0].
///
/// Uses the formula: distance = 1 + log(score) / log(DECAY)
/// Direct trust (1.0) → distance 1.0
/// Single 2-hop path (DECAY) → distance 2.0
/// Single 3-hop path (DECAY²) → distance 3.0 (clamped)
fn score_to_distance(score: f64) -> f64 {
    if score >= 1.0 {
        return 1.0;
    }
    if score <= 0.0 {
        return 3.0;
    }
    let d = 1.0 + score.ln() / DECAY.ln();
    d.clamp(1.0, 3.0)
}

// ---------------------------------------------------------------------------
// TrustGraph: public API
// ---------------------------------------------------------------------------

/// A trust score with effective distance for a single (source, target) pair.
pub struct TrustScore {
    pub target_user: Uuid,
    #[allow(dead_code)]
    pub score: f64,
    pub distance: f64,
}

/// A concrete trust path from source to target through the graph.
#[derive(Debug, Clone, PartialEq)]
pub enum TrustPath {
    Direct,
    TwoHop { via: Uuid },
    ThreeHop { via1: Uuid, via2: Uuid },
}

/// In-memory trust graph using dual CSR (forward + reverse) for on-demand
/// bottleneck-grouped probabilistic BFS.
///
/// Built from trust_edges at startup and rebuilt by the background task when
/// trust edges are mutated. Stored behind an `Arc` in `AppState`; readers
/// clone the Arc for zero-contention concurrent access. Per-user BFS results
/// are cached internally with byte-budgeted eviction.
pub struct TrustGraph {
    forward: CsrGraph,
    reverse: CsrGraph,
    index: NodeIndex,
    distrust_sets: DistrustSets,
    /// Per-user cache of forward BFS distance maps (reader → {target_uuid_str → distance}).
    forward_cache: BfsCache,
    /// Per-user cache of reverse BFS score maps (reader → {author_uuid_str → score}).
    reverse_cache: BfsCache,
    /// Delta-keyed forward cache for viewers with pending mutations.
    /// Keyed by `(reader, delta.seq)` so each click on Trust/Distrust/
    /// Neutral by the same viewer naturally orphans the previous entry
    /// (the seq advances on every `PendingDeltas::apply`); the orphaned
    /// entry is evicted by the byte budget. When the rebuild absorbs
    /// the delta, callers fall back to the regular `forward_cache` and
    /// the delta entry ages out without explicit invalidation.
    delta_forward_cache: DeltaBfsCache,
    /// Metrics sink for BFS hit/miss counters. Optional so that ad-hoc
    /// graphs (`empty`, test fixtures) don't require a Metrics instance.
    metrics: Option<Arc<Metrics>>,
}

impl TrustGraph {
    /// Build the trust graph from the database.
    ///
    /// Loads all trust edges from `trust_edges`, builds the UUID↔u32
    /// index, and constructs forward and reverse CSR graphs.
    /// `bfs_cache_bytes` is the total memory budget (in bytes) for
    /// cached BFS results. Half goes to the reverse cache; the other
    /// half is split between the per-viewer forward cache and a
    /// smaller delta-keyed forward cache used only by viewers with
    /// pending edge mutations (see `DELTA_CACHE_BUDGET_SIXTEENTHS`).
    ///
    /// `metrics` is an optional sink that receives BFS hit/miss counters
    /// so the admin dashboard can surface cache health. Pass `None` for
    /// ad-hoc graphs (tests, one-off scripts) that don't need metrics.
    pub async fn build(
        db: &SqlitePool,
        bfs_cache_bytes: u64,
        metrics: Option<Arc<Metrics>>,
    ) -> Result<Self, sqlx::Error> {
        // Exclude trust edges where either endpoint is a banned user.
        // Banned users should not propagate trust. Distrust edges pointing
        // at banned users are kept (loaded separately below) so that
        // existing distrust relationships remain visible.
        let rows = sqlx::query!(
            "SELECT te.source_user, te.target_user FROM current_trust_edges te \
             JOIN users u1 ON u1.id = te.source_user \
             JOIN users u2 ON u2.id = te.target_user \
             WHERE te.trust_type = 'trust' \
             AND u1.status != 'banned' AND u2.status != 'banned'",
        )
        .fetch_all(db)
        .await?;

        // Invariant: `trust_edges.source_user` / `target_user` are only ever
        // written as `Uuid::to_string()`. A parse failure here means the row
        // was corrupted or edited externally — crash loudly at startup rather
        // than silently dropping edges.
        let uuid_edges: Vec<(Uuid, Uuid)> = rows
            .into_iter()
            .map(|r| {
                let src_uuid = Uuid::parse_str(&r.source_user)
                    .expect("invalid UUID in trust_edges.source_user");
                let tgt_uuid = Uuid::parse_str(&r.target_user)
                    .expect("invalid UUID in trust_edges.target_user");
                (src_uuid, tgt_uuid)
            })
            .collect();

        let index = NodeIndex::from_edges(&uuid_edges);

        // Safe: `index` was just built from `uuid_edges`, so every endpoint is present.
        let dense_edges: Vec<(u32, u32)> = uuid_edges
            .iter()
            .map(|(src, tgt)| {
                (
                    index.get_id(src).expect("edge endpoint must be in index"),
                    index.get_id(tgt).expect("edge endpoint must be in index"),
                )
            })
            .collect();

        let forward = CsrGraph::from_edges(index.num_nodes(), &dense_edges);
        let reverse = forward.transpose();

        // Load distrust edges into per-user distrust sets (not into the CSR graph).
        let distrust_rows = sqlx::query!(
            "SELECT source_user, target_user FROM current_trust_edges WHERE trust_type = 'distrust'",
        )
        .fetch_all(db)
        .await?;

        let mut distrust_sets: DistrustSets = HashMap::new();
        for r in &distrust_rows {
            let src_uuid =
                Uuid::parse_str(&r.source_user).expect("invalid UUID in trust_edges.source_user");
            let tgt_uuid =
                Uuid::parse_str(&r.target_user).expect("invalid UUID in trust_edges.target_user");
            if let (Some(src_id), Some(tgt_id)) = (index.get_id(&src_uuid), index.get_id(&tgt_uuid))
            {
                distrust_sets.entry(src_id).or_default().insert(tgt_id);
            }
        }

        tracing::info!(
            nodes = index.num_nodes(),
            trust_edges = dense_edges.len(),
            distrust_edges = distrust_rows.len(),
            "trust graph built"
        );

        let (forward_budget, delta_budget, reverse_budget) =
            Self::split_cache_budget(bfs_cache_bytes);
        Ok(Self {
            forward,
            reverse,
            index,
            distrust_sets,
            forward_cache: Self::make_bfs_cache(forward_budget),
            reverse_cache: Self::make_bfs_cache(reverse_budget),
            delta_forward_cache: Self::make_delta_bfs_cache(delta_budget),
            metrics,
        })
    }

    /// Build an empty trust graph (no nodes, no edges).
    pub fn empty() -> Self {
        Self {
            forward: CsrGraph::from_edges(0, &[]),
            reverse: CsrGraph::from_edges(0, &[]),
            index: NodeIndex {
                uuid_to_id: HashMap::new(),
                id_to_uuid: Vec::new(),
            },
            distrust_sets: HashMap::new(),
            forward_cache: Self::make_bfs_cache(0),
            reverse_cache: Self::make_bfs_cache(0),
            delta_forward_cache: Self::make_delta_bfs_cache(0),
            metrics: None,
        }
    }

    /// Total weight (in bytes) currently held across all three BFS
    /// caches. Surfaced to the admin overview so operators can see
    /// how close to the configured budget the cache is actually
    /// running — a low hit rate with usage well below budget means
    /// the working set is too spread out for caching to help, not
    /// that the budget is too small.
    pub fn bfs_cache_weight(&self) -> u64 {
        self.forward_cache.weight()
            + self.reverse_cache.weight()
            + self.delta_forward_cache.weight()
    }

    /// Split the total BFS cache budget across forward, delta, and
    /// reverse caches. The reverse cache always gets half; the
    /// forward half is sliced into the stable per-viewer cache and the
    /// smaller delta-keyed cache (see `DELTA_CACHE_BUDGET_SIXTEENTHS`).
    /// Returns `(forward_budget, delta_budget, reverse_budget)`.
    fn split_cache_budget(total: u64) -> (u64, u64, u64) {
        let reverse = total / 2;
        let delta = total * DELTA_CACHE_BUDGET_SIXTEENTHS / 16;
        // Use saturating subtraction so a tiny test budget doesn't underflow.
        let forward = (total / 2).saturating_sub(delta);
        (forward, delta, reverse)
    }

    /// Create a byte-weighted BFS cache with the given budget.
    fn make_bfs_cache(budget_bytes: u64) -> BfsCache {
        let estimated_items = if budget_bytes == 0 {
            0
        } else {
            // Rough estimate assuming ~200 reachable users per BFS result.
            (budget_bytes / (MAP_BASE_OVERHEAD + 200 * BYTES_PER_MAP_ENTRY)) as usize
        };
        Cache::with_weighter(estimated_items, budget_bytes, BfsWeighter)
    }

    /// Create a byte-weighted delta-keyed BFS cache with the given
    /// budget. Same per-entry footprint as `make_bfs_cache` — the
    /// extra `u64` in the key is negligible against the map payload.
    fn make_delta_bfs_cache(budget_bytes: u64) -> DeltaBfsCache {
        let estimated_items = if budget_bytes == 0 {
            0
        } else {
            (budget_bytes / (MAP_BASE_OVERHEAD + 200 * BYTES_PER_MAP_ENTRY)) as usize
        };
        Cache::with_weighter(estimated_items, budget_bytes, BfsWeighter)
    }

    /// Returns true if the cached graph contains a (`viewer` → `target`)
    /// trust edge.
    ///
    /// Mutation handlers call this just before [`PendingDeltas::apply`] to
    /// record the cached state of the edge being mutated, so the delta
    /// store can compute the correct add/remove membership.
    pub fn has_trust_edge(&self, viewer: Uuid, target: Uuid) -> bool {
        let Some(viewer_id) = self.index.get_id(&viewer) else {
            return false;
        };
        let Some(target_id) = self.index.get_id(&target) else {
            return false;
        };
        self.forward.neighbors(viewer_id).contains(&target_id)
    }

    /// Returns true if the cached graph records `viewer` as distrusting
    /// `target`.
    ///
    /// Companion to [`has_trust_edge`] used by mutation handlers when
    /// recording deltas. Cannot be `true` simultaneously with
    /// [`has_trust_edge`] for the same pair — the DB schema enforces
    /// at most one edge per (source, target).
    pub fn has_distrust_edge(&self, viewer: Uuid, target: Uuid) -> bool {
        let Some(viewer_id) = self.index.get_id(&viewer) else {
            return false;
        };
        let Some(target_id) = self.index.get_id(&target) else {
            return false;
        };
        self.distrust_sets
            .get(&viewer_id)
            .is_some_and(|s| s.contains(&target_id))
    }

    /// Compute forward trust scores from `reader` to all reachable users
    /// (relevance ranking).
    ///
    /// Returns trust scores sorted by distance (closest first).
    pub fn forward_scores(&self, reader: Uuid) -> Vec<TrustScore> {
        let Some(source_id) = self.index.get_id(&reader) else {
            return Vec::new();
        };

        let mut scores: Vec<TrustScore> =
            forward_bfs(source_id, &self.forward, &self.reverse, &self.distrust_sets)
                .into_iter()
                .filter(|&(_, score)| score >= MINIMUM_TRUST_THRESHOLD)
                .map(|(target_id, score)| {
                    let distance = score_to_distance(score);
                    TrustScore {
                        target_user: self.index.get_uuid(target_id),
                        score,
                        distance,
                    }
                })
                .collect();

        scores.sort_by(|a, b| a.distance.total_cmp(&b.distance));
        scores
    }

    /// Build a lookup map from user UUID string to trust distance for the given reader.
    ///
    /// Results are cached per reader for the lifetime of this `TrustGraph`
    /// instance. Returns a shared `Arc` — callers should clone if they need
    /// to mutate (e.g., inserting the reader's own entry).
    // TODO: Use HashMap<Uuid, f64> once we migrate to typed sqlx::query!() macros
    //  so author IDs are already Uuid instead of String. When we do this, we need to update
    //  BfsWeighter impl (BYTES_PER_MAP_ENTRY would drop from 84 to ~32 bytes)
    pub fn distance_map(&self, reader: Uuid) -> Arc<HashMap<String, f64>> {
        // Probe the cache first so we can record hit vs. miss. Between
        // the probe and the `get_or_insert_with` call another thread may
        // insert, turning a would-be miss into an effective hit. The
        // metric is ±1 per race, which is acceptable for a hit-rate
        // gauge — the alternative (splitting insert into explicit steps)
        // would defeat quick_cache's single-flight guarantee.
        if let Some(cached) = self.forward_cache.get(&reader) {
            if let Some(m) = &self.metrics {
                m.record_bfs_forward_hit();
            }
            return cached;
        }
        if let Some(m) = &self.metrics {
            m.record_bfs_forward_miss();
        }
        self.forward_cache
            .get_or_insert_with(&reader, || {
                let map = self
                    .forward_scores(reader)
                    .into_iter()
                    .map(|s| (s.target_user.to_string(), s.distance))
                    .collect();
                Ok::<_, ()>(Arc::new(map))
            })
            .unwrap()
    }

    /// Build a lookup map from author UUID string to their trust-in-reader score.
    ///
    /// Used for visibility filtering: a post is visible if the author's score
    /// for the reader meets the author's threshold (default 0.45).
    ///
    /// Results are cached per reader for the lifetime of this `TrustGraph`
    /// instance. Returns a shared `Arc`.
    pub fn reverse_score_map(&self, reader: Uuid) -> Arc<HashMap<String, f64>> {
        // See `distance_map` for the hit/miss accounting note.
        if let Some(cached) = self.reverse_cache.get(&reader) {
            if let Some(m) = &self.metrics {
                m.record_bfs_reverse_hit();
            }
            return cached;
        }
        if let Some(m) = &self.metrics {
            m.record_bfs_reverse_miss();
        }
        self.reverse_cache
            .get_or_insert_with(&reader, || {
                let Some(reader_id) = self.index.get_id(&reader) else {
                    return Ok::<_, ()>(Arc::new(HashMap::new()));
                };

                let map = self
                    .reverse_scores(reader)
                    .into_iter()
                    .map(|(uuid, score)| {
                        // Direct distrust override: if this author has distrusted the
                        // reader, their trust-in-reader is 0.0 regardless of
                        // graph paths.
                        let effective = if let Some(author_id) = self.index.get_id(&uuid)
                            && let Some(distrusted) = self.distrust_sets.get(&author_id)
                            && distrusted.contains(&reader_id)
                        {
                            0.0
                        } else {
                            score
                        };
                        (uuid.to_string(), effective)
                    })
                    .collect();
                Ok(Arc::new(map))
            })
            .unwrap()
    }

    /// Compute reverse trust scores: all users who trust `reader` within
    /// MAX_DEPTH hops (visibility check).
    ///
    /// Returns a map from user UUID to their trust-in-reader score. Use this
    /// to check whether a given author's content should be visible to the
    /// reader: if the author is in this map and their score meets their read
    /// threshold, the content is visible.
    ///
    /// NOTE: These scores do NOT include distrust propagation — they are an
    /// approximation. For exact distrust-penalized trust(author, reader), use
    /// `trust_between(author, reader)` which runs forward BFS from the author.
    pub fn reverse_scores(&self, reader: Uuid) -> HashMap<Uuid, f64> {
        let Some(reader_id) = self.index.get_id(&reader) else {
            return HashMap::new();
        };

        reverse_bfs(reader_id, &self.reverse)
            .into_iter()
            .map(|(source_id, score)| (self.index.get_uuid(source_id), score))
            .collect()
    }

    /// Enumerate all concrete paths from `source` to `target` up to 3 hops.
    ///
    /// Returns paths as Direct / TwoHop / ThreeHop variants. Bounded by
    /// O(d²) where d is the average out-degree — fast on typical graphs.
    pub fn paths_to(&self, source: Uuid, target: Uuid) -> Vec<TrustPath> {
        let Some(source_id) = self.index.get_id(&source) else {
            return Vec::new();
        };
        let Some(target_id) = self.index.get_id(&target) else {
            return Vec::new();
        };
        if source_id == target_id {
            return Vec::new();
        }

        let empty_distrusts = HashSet::new();
        let distrusted = self
            .distrust_sets
            .get(&source_id)
            .unwrap_or(&empty_distrusts);

        let mut paths = Vec::new();

        let source_neighbors = self.forward.neighbors(source_id);

        if source_neighbors.contains(&target_id) {
            paths.push(TrustPath::Direct);
        }

        for &mid in source_neighbors {
            if mid == source_id || mid == target_id || distrusted.contains(&mid) {
                continue;
            }
            if self.forward.neighbors(mid).contains(&target_id) {
                paths.push(TrustPath::TwoHop {
                    via: self.index.get_uuid(mid),
                });
            }
        }

        for &mid1 in source_neighbors {
            if mid1 == source_id || mid1 == target_id || distrusted.contains(&mid1) {
                continue;
            }
            for &mid2 in self.forward.neighbors(mid1) {
                if mid2 == source_id
                    || mid2 == target_id
                    || mid2 == mid1
                    || distrusted.contains(&mid2)
                {
                    continue;
                }
                if self.forward.neighbors(mid2).contains(&target_id) {
                    paths.push(TrustPath::ThreeHop {
                        via1: self.index.get_uuid(mid1),
                        via2: self.index.get_uuid(mid2),
                    });
                }
            }
        }

        paths
    }

    /// Count how many users `user` can read (forward trust score ≥ threshold).
    pub fn reads_count(&self, user: Uuid, threshold: f64) -> u32 {
        let Some(source_id) = self.index.get_id(&user) else {
            return 0;
        };
        forward_bfs(source_id, &self.forward, &self.reverse, &self.distrust_sets)
            .into_iter()
            .filter(|&(_, score)| score >= threshold)
            .count() as u32
    }

    /// Count how many users trust `user` enough to read their content
    /// (reverse trust score ≥ threshold).
    pub fn readers_count(&self, user: Uuid, threshold: f64) -> u32 {
        let Some(reader_id) = self.index.get_id(&user) else {
            return 0;
        };
        reverse_bfs(reader_id, &self.reverse)
            .into_iter()
            .filter(|&(_, score)| score >= threshold)
            .count() as u32
    }

    /// Look up the forward trust score from `source` to `target`.
    ///
    /// Returns `None` if the target is unreachable from the source.
    /// When reachable, returns `(score, Some(distance))` if above threshold,
    /// or `(score, None)` if below threshold (untrusted but reachable).
    pub fn trust_between(&self, source: Uuid, target: Uuid) -> Option<(f64, Option<f64>)> {
        let source_id = self.index.get_id(&source)?;
        let target_id = self.index.get_id(&target)?;

        for (node, score) in
            forward_bfs(source_id, &self.forward, &self.reverse, &self.distrust_sets)
        {
            if node == target_id {
                let distance = if score >= MINIMUM_TRUST_THRESHOLD {
                    Some(score_to_distance(score))
                } else {
                    None
                };
                return Some((score, distance));
            }
        }

        None
    }

    /// Delta-aware variant of [`forward_scores`](Self::forward_scores).
    ///
    /// Short-circuits to the cached path when `delta` is empty. Otherwise
    /// runs a per-call BFS from `reader` overlaying the viewer's pending
    /// edge mutations on top of the cached graph (only the source node's
    /// outgoing edges and distrust set are overlaid — every other node's
    /// neighbours come from the cached graph). Results are not cached.
    pub fn forward_scores_with_delta(&self, reader: Uuid, delta: &ViewerDelta) -> Vec<TrustScore> {
        if delta.is_empty() {
            return self.forward_scores(reader);
        }
        let Some(source_id) = self.index.get_id(&reader) else {
            return Vec::new();
        };

        let (source_neighbors, viewer_distrusts) = apply_delta_overlay(source_id, self, delta);
        let mut scores: Vec<TrustScore> = forward_bfs_inner(
            source_id,
            &self.forward,
            &self.reverse,
            &source_neighbors,
            &viewer_distrusts,
        )
        .into_iter()
        .filter(|&(_, score)| score >= MINIMUM_TRUST_THRESHOLD)
        .map(|(target_id, score)| {
            let distance = score_to_distance(score);
            TrustScore {
                target_user: self.index.get_uuid(target_id),
                score,
                distance,
            }
        })
        .collect();
        scores.sort_by(|a, b| a.distance.total_cmp(&b.distance));
        scores
    }

    /// Delta-aware variant of [`distance_map`](Self::distance_map).
    ///
    /// Short-circuits to the cached path when `delta` is empty.
    /// Otherwise consults the delta-keyed forward cache, computing a
    /// fresh BFS on miss. The cache key includes `delta.seq`, so the
    /// next click by the same viewer (which advances the seq via
    /// `PendingDeltas::apply`) naturally orphans the previous entry —
    /// it gets evicted by the byte budget without explicit
    /// invalidation. After the rebuild absorbs the delta the
    /// short-circuit above kicks in, and the orphaned delta entries
    /// age out the same way.
    pub fn distance_map_with_delta(
        &self,
        reader: Uuid,
        delta: &ViewerDelta,
    ) -> Arc<HashMap<String, f64>> {
        if delta.is_empty() {
            return self.distance_map(reader);
        }
        let key = (reader, delta.seq);
        // Probe-then-insert (mirrors `distance_map`'s pattern): the
        // probe drives the hit/miss metric, while `get_or_insert_with`
        // preserves quick_cache's single-flight guarantee under
        // concurrent misses.
        if let Some(cached) = self.delta_forward_cache.get(&key) {
            if let Some(m) = &self.metrics {
                m.record_bfs_delta_hit();
            }
            return cached;
        }
        if let Some(m) = &self.metrics {
            m.record_bfs_delta_miss();
        }
        self.delta_forward_cache
            .get_or_insert_with(&key, || {
                let map: HashMap<String, f64> = self
                    .forward_scores_with_delta(reader, delta)
                    .into_iter()
                    .map(|s| (s.target_user.to_string(), s.distance))
                    .collect();
                Ok::<_, ()>(Arc::new(map))
            })
            .unwrap()
    }

    /// Delta-aware variant of [`trust_between`](Self::trust_between).
    ///
    /// Short-circuits to the cached path when `delta` is empty. Otherwise
    /// runs a single overlaid forward BFS from `source` and returns the
    /// score for `target` (or `None` if unreachable).
    pub fn trust_between_with_delta(
        &self,
        source: Uuid,
        target: Uuid,
        delta: &ViewerDelta,
    ) -> Option<(f64, Option<f64>)> {
        if delta.is_empty() {
            return self.trust_between(source, target);
        }
        let source_id = self.index.get_id(&source)?;
        let target_id = self.index.get_id(&target)?;

        let (source_neighbors, viewer_distrusts) = apply_delta_overlay(source_id, self, delta);
        for (node, score) in forward_bfs_inner(
            source_id,
            &self.forward,
            &self.reverse,
            &source_neighbors,
            &viewer_distrusts,
        ) {
            if node == target_id {
                let distance = if score >= MINIMUM_TRUST_THRESHOLD {
                    Some(score_to_distance(score))
                } else {
                    None
                };
                return Some((score, distance));
            }
        }
        None
    }

    /// Delta-aware variant of [`paths_to`](Self::paths_to).
    ///
    /// The overlay applies to the source's outgoing first-hop set and
    /// the source's distrust set. Mid-hop neighbours still come from the
    /// cached graph — consistent with `forward_bfs_inner`, which only
    /// overlays edges leaving the source node.
    pub fn paths_to_with_delta(
        &self,
        source: Uuid,
        target: Uuid,
        delta: &ViewerDelta,
    ) -> Vec<TrustPath> {
        if delta.is_empty() {
            return self.paths_to(source, target);
        }
        let Some(source_id) = self.index.get_id(&source) else {
            return Vec::new();
        };
        let Some(target_id) = self.index.get_id(&target) else {
            return Vec::new();
        };
        if source_id == target_id {
            return Vec::new();
        }

        let (source_neighbors, distrusted) = apply_delta_overlay(source_id, self, delta);

        let mut paths = Vec::new();

        if source_neighbors.contains(&target_id) {
            paths.push(TrustPath::Direct);
        }

        for &mid in &source_neighbors {
            if mid == source_id || mid == target_id || distrusted.contains(&mid) {
                continue;
            }
            if self.forward.neighbors(mid).contains(&target_id) {
                paths.push(TrustPath::TwoHop {
                    via: self.index.get_uuid(mid),
                });
            }
        }

        for &mid1 in &source_neighbors {
            if mid1 == source_id || mid1 == target_id || distrusted.contains(&mid1) {
                continue;
            }
            for &mid2 in self.forward.neighbors(mid1) {
                if mid2 == source_id
                    || mid2 == target_id
                    || mid2 == mid1
                    || distrusted.contains(&mid2)
                {
                    continue;
                }
                if self.forward.neighbors(mid2).contains(&target_id) {
                    paths.push(TrustPath::ThreeHop {
                        via1: self.index.get_uuid(mid1),
                        via2: self.index.get_uuid(mid2),
                    });
                }
            }
        }

        paths
    }
}

// ---------------------------------------------------------------------------
// Debounced rebuild task
// ---------------------------------------------------------------------------

/// Timing parameters for the trust graph rebuild scheduler.
///
/// Three parameters control when a rebuild fires after a mutation:
/// - `debounce`: wait this long after the *last* mutation before rebuilding,
///   coalescing rapid changes (e.g., federation sync bursts).
/// - `min_interval`: minimum time between consecutive rebuilds, preventing
///   thrashing under sustained mutation load.
/// - `max_interval`: maximum staleness — if dirty, rebuild after this long
///   even if mutations are still arriving.
#[derive(Debug, Clone, Copy)]
pub struct RebuildSchedule {
    pub debounce: Duration,
    pub min_interval: Duration,
    pub max_interval: Duration,
    /// Total memory budget (in bytes) for cached BFS results, split evenly
    /// between the forward and reverse caches. Entries are evicted when
    /// either half exceeds its share.
    pub bfs_cache_bytes: u64,
}

impl Default for RebuildSchedule {
    fn default() -> Self {
        // Values here are mirrored in the seed `INSERT` of the
        // `instance_config` migration (and in DB-level CHECK
        // constraints for the valid range). If you change any of
        // these defaults, write a new migration that updates the
        // seeded default — otherwise existing deployments stay on
        // the old value (the migration's `INSERT OR IGNORE` is a
        // no-op once the row exists) while new deployments pick up
        // the new one.
        Self {
            debounce: Duration::from_secs(5),
            min_interval: Duration::from_secs(30),
            max_interval: Duration::from_secs(300),
            bfs_cache_bytes: DEFAULT_BFS_CACHE_BYTES,
        }
    }
}

/// Rebuild the trust graph from the database and swap it into the shared Arc.
///
/// Builds a new dual CSR graph and replaces the old one atomically; in-flight
/// queries using the old Arc continue unaffected until they drop their
/// reference.
///
/// If `metrics` is provided, the rebuild's wall-clock duration is
/// recorded in the graph-load histogram and `set_last_rebuild` is
/// called on success. The new graph is also given a clone of the same
/// metrics handle so its BFS hit/miss counters flow into the dashboard.
pub async fn rebuild_trust_graph(
    db: &SqlitePool,
    graph: &std::sync::RwLock<Arc<TrustGraph>>,
    bfs_cache_bytes: u64,
    metrics: Option<Arc<Metrics>>,
) -> Result<(), sqlx::Error> {
    let started = std::time::Instant::now();
    let new_graph = TrustGraph::build(db, bfs_cache_bytes, metrics.clone()).await?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let new_arc = Arc::new(new_graph);
    *graph.write().unwrap() = new_arc;
    if let Some(m) = &metrics {
        // Record timing and reset per-graph BFS counters so the hit-rate
        // reflects only the new graph (the old caches are gone with the
        // previous Arc).
        m.record_graph_load_ms(elapsed_ms);
        m.reset_bfs_counters();
        m.set_last_rebuild(chrono::Utc::now());
    }
    Ok(())
}

/// Run the debounced trust graph rebuild loop.
///
/// Waits for notifications from mutation sites, then rebuilds the graph
/// subject to the timing constraints in the live `schedule`. The loop
/// ensures:
/// - At least `min_interval` between rebuilds (prevents thrashing).
/// - At least `debounce` of quiet time after the last mutation (coalesces bursts).
/// - At most `max_interval` of staleness when mutations are continuous.
/// - No rebuild if the graph hasn't changed (dirty flag is false).
///
/// The schedule lives behind a [`std::sync::RwLock`] so admin edits via
/// `/api/admin/config` are picked up on the *next* scheduling window
/// without a server restart. We snapshot the schedule once per window
/// (after the first mutation notification arrives) so a config change
/// can't perturb timing decisions mid-window; a change made during an
/// active wait will apply to the wait that follows. The
/// `bfs_cache_bytes` value is also snapshotted at the moment of each
/// rebuild call — so growing or shrinking the cache takes effect on the
/// next rebuild, not retroactively against the in-flight one.
// TODO: Accept a CancellationToken for graceful shutdown.
pub async fn rebuild_loop(
    db: SqlitePool,
    graph: Arc<std::sync::RwLock<Arc<TrustGraph>>>,
    notify: Arc<Notify>,
    schedule: Arc<std::sync::RwLock<RebuildSchedule>>,
    metrics: Arc<Metrics>,
    pending_deltas: Arc<PendingDeltas>,
) {
    use tokio::time::{Instant, sleep_until};

    /// Snapshot the shared schedule. `RebuildSchedule` is `Copy`, so
    /// the lock is held only long enough to read four fields. On
    /// poisoning we fall back to the compile-time defaults so the
    /// loop keeps making forward progress and surface the breakage
    /// in the log — losing trust-graph rebuilds is worse than running
    /// on stale-but-sensible parameters.
    fn snapshot(schedule: &std::sync::RwLock<RebuildSchedule>) -> RebuildSchedule {
        match schedule.read() {
            Ok(guard) => *guard,
            Err(poisoned) => {
                tracing::error!("rebuild_loop: schedule RwLock poisoned; using defaults");
                // Recover the poisoned guard to keep using the last
                // good value instead of dropping it.
                *poisoned.into_inner()
            }
        }
    }

    // Run an initial build immediately (graph starts empty).
    // TODO: Retry with backoff if the initial build fails, rather than
    //  silently continuing with an empty graph.
    //
    // Capture the pending-deltas high-water mark BEFORE reading the DB,
    // then purge entries below it after the swap. The AcqRel ordering on
    // the seq counter guarantees we observe every mutation that committed
    // before this load, so any delta with a lower seq is fully reflected
    // in the new graph.
    let initial_high_water = pending_deltas.current_seq();
    let initial_bytes = snapshot(&schedule).bfs_cache_bytes;
    if let Err(e) = rebuild_trust_graph(&db, &graph, initial_bytes, Some(metrics.clone())).await {
        tracing::error!(error = %e, "trust graph initial build failed");
    } else {
        pending_deltas.purge_below(initial_high_water);
    }

    let mut last_rebuild = Instant::now();

    loop {
        // Wait for the first mutation notification.
        notify.notified().await;

        // Mutation received — enter the scheduling window. Snapshot
        // the schedule once here so an admin edit can't reshape the
        // window mid-wait (it will instead apply to the next window).
        let window = snapshot(&schedule);
        let mut last_mutation = Instant::now();
        let earliest_rebuild = last_rebuild + window.min_interval;
        let deadline = last_mutation + window.max_interval;

        loop {
            let debounce_at = last_mutation + window.debounce;
            // Next rebuild attempt: respect both debounce and min_interval,
            // but never exceed the max_interval deadline.
            let target = debounce_at.max(earliest_rebuild).min(deadline);

            // Wait until target, but wake early if a new mutation arrives
            // (to reset the debounce timer).
            tokio::select! {
                _ = sleep_until(target) => break,
                _ = notify.notified() => {
                    last_mutation = Instant::now();
                    continue;
                }
            }
        }

        // Re-snapshot just `bfs_cache_bytes` so a config change applied
        // during the debounce wait takes effect on this rebuild rather
        // than waiting another full window.
        let bytes = snapshot(&schedule).bfs_cache_bytes;
        // See the initial-build comment above for the ordering rationale.
        let high_water = pending_deltas.current_seq();
        match rebuild_trust_graph(&db, &graph, bytes, Some(metrics.clone())).await {
            Ok(()) => {
                pending_deltas.purge_below(high_water);
            }
            Err(e) => {
                tracing::error!(error = %e, "trust graph rebuild failed");
            }
        }
        last_rebuild = Instant::now();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "trust_tests.rs"]
mod tests;
