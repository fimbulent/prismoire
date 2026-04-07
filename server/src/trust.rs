use std::collections::{HashMap, HashSet, VecDeque};

use sqlx::SqlitePool;
use uuid::Uuid;

/// Per-hop decay constant for trust propagation.
const DECAY: f64 = 0.7;

/// Maximum BFS depth for trust traversal.
const MAX_DEPTH: u32 = 3;

/// Minimum trust score to be considered trusted. Scores below this are
/// treated as untrusted (no trust relationship).
pub const MINIMUM_TRUST_THRESHOLD: f64 = 0.45;

/// Per-blocked-target penalty for reliability computation.
const BLOCK_PENALTY: f64 = 0.25;

/// Maps blocker's dense node ID → set of blocked dense node IDs.
type BlockSets = HashMap<u32, HashSet<u32>>;

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
// Block reliability
// ---------------------------------------------------------------------------

/// Compute the reliability factor for a node given its outgoing neighbors and
/// the viewer's block set. Each neighbor that appears in `viewer_blocks`
/// contributes an independent multiplicative penalty.
#[inline]
fn reliability(neighbors: &[u32], viewer_blocks: &HashSet<u32>) -> f64 {
    let count = neighbors
        .iter()
        .filter(|n| viewer_blocks.contains(n))
        .count() as i32;
    (1.0 - BLOCK_PENALTY).powi(count)
}

// ---------------------------------------------------------------------------
// Forward BFS: reader → authors (relevance)
// ---------------------------------------------------------------------------

/// Compute trust scores from a single source using bottleneck-grouped BFS
/// on the forward CSR graph with block propagation.
///
/// Paths are grouped by the source's direct (first-hop) neighbor. Within each
/// group, only the max path score is kept. Across groups, scores combine via
/// probabilistic independence.
///
/// Block propagation: each visited node's score is multiplied by a reliability
/// factor based on how many of its trust targets the viewer has blocked.
/// After BFS, directly blocked users are overridden to score 0.0.
fn forward_bfs(source: u32, graph: &CsrGraph, block_sets: &BlockSets) -> Vec<(u32, f64)> {
    let empty = HashSet::new();
    let viewer_blocks = block_sets.get(&source).unwrap_or(&empty);

    // BFS state: (current_node, depth, first_hop, path_score)
    let mut queue: VecDeque<(u32, u32, u32, f64)> = VecDeque::new();
    let mut target_groups: HashMap<u32, PathGroups> = HashMap::new();

    // Per-first-hop visited sets prevent cycles within a group while allowing
    // the same node to be reached via different first-hop neighbors (those
    // represent independent evidence sources).
    let mut visited_per_group: HashMap<u32, HashSet<u32>> = HashMap::new();

    for &neighbor in graph.neighbors(source) {
        if neighbor == source {
            continue;
        }
        let penalized = reliability(graph.neighbors(neighbor), viewer_blocks);
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

        for &next in graph.neighbors(current) {
            if next == source {
                continue;
            }

            let visited = visited_per_group.entry(first_hop).or_default();
            if visited.contains(&next) {
                continue;
            }
            visited.insert(next);

            let r = reliability(graph.neighbors(next), viewer_blocks);
            let next_score = path_score * DECAY * r;

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

    // Direct block override: blocked users get effective trust 0.0.
    if !viewer_blocks.is_empty() {
        for entry in &mut results {
            if viewer_blocks.contains(&entry.0) {
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
/// NOTE: This function does NOT apply block propagation. Block penalties are
/// viewer-specific (each source A has its own block set), so they cannot be
/// folded into the shared path_score of a single reverse pass. The scores
/// returned here are an approximation that ignores blocks. For exact
/// block-penalized trust(A, reader), use forward_bfs from A directly.
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

        let next_score = path_score * DECAY;

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
// TrustInfo: shared trust metadata for API responses
// ---------------------------------------------------------------------------

/// Trust metadata attached to any user reference in API responses.
///
/// Built from a distance map (forward BFS results) and block set (viewer's
/// block targets) via `TrustInfo::build`. Serializes as a nested `"trust"`
/// object, e.g. `{ "trust": { "distance": 1.5, "blocked": false } }`.
#[derive(Clone, serde::Serialize)]
pub struct TrustInfo {
    pub distance: Option<f64>,
    pub blocked: bool,
}

impl TrustInfo {
    /// Build TrustInfo for a user from the viewer's distance map and block set.
    pub fn build(
        user_id: &str,
        distance_map: &HashMap<String, f64>,
        block_set: &HashSet<String>,
    ) -> Self {
        Self {
            distance: distance_map.get(user_id).copied(),
            blocked: block_set.contains(user_id),
        }
    }

    /// TrustInfo for the viewer themselves (distance 0, not blocked).
    pub fn self_trust() -> Self {
        Self {
            distance: None,
            blocked: false,
        }
    }

    /// Unknown/absent trust (no viewer context available).
    pub fn unknown() -> Self {
        Self {
            distance: None,
            blocked: false,
        }
    }
}

/// Load the set of user IDs that the viewer has blocked.
pub async fn load_block_set(
    db: &sqlx::SqlitePool,
    viewer_id: &str,
) -> Result<HashSet<String>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String,)>(
        "SELECT target_user FROM trust_edges WHERE source_user = ? AND trust_type = 'block'",
    )
    .bind(viewer_id)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
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
/// Built from trust_edges at startup and rebuilt periodically when the dirty
/// flag is set. Stored behind an `Arc` in `AppState`; readers clone the Arc
/// for zero-contention concurrent access.
// TODO: If more call sites need multiple BFS operations from the same source,
//  consider a per-request `TrustQuery` context that lazily computes and caches
//  forward/reverse BFS results internally. Currently only get_trust_detail
//  benefits, and it consolidates manually via forward_scores().
pub struct TrustGraph {
    forward: CsrGraph,
    reverse: CsrGraph,
    index: NodeIndex,
    block_sets: BlockSets,
}

impl TrustGraph {
    /// Build the trust graph from the database.
    ///
    /// Loads all trust edges from `trust_edges`, builds the UUID↔u32 index,
    /// and constructs forward and reverse CSR graphs.
    pub async fn build(db: &SqlitePool) -> Result<Self, sqlx::Error> {
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT source_user, target_user FROM trust_edges WHERE trust_type = 'trust'",
        )
        .fetch_all(db)
        .await?;

        let uuid_edges: Vec<(Uuid, Uuid)> = rows
            .into_iter()
            .map(|(src, tgt)| {
                let src_uuid =
                    Uuid::parse_str(&src).expect("invalid UUID in trust_edges.source_user");
                let tgt_uuid =
                    Uuid::parse_str(&tgt).expect("invalid UUID in trust_edges.target_user");
                (src_uuid, tgt_uuid)
            })
            .collect();

        let index = NodeIndex::from_edges(&uuid_edges);

        let dense_edges: Vec<(u32, u32)> = uuid_edges
            .iter()
            .map(|(src, tgt)| (index.get_id(src).unwrap(), index.get_id(tgt).unwrap()))
            .collect();

        let forward = CsrGraph::from_edges(index.num_nodes(), &dense_edges);
        let reverse = forward.transpose();

        // Load block edges into per-user block sets (not into the CSR graph).
        let block_rows = sqlx::query_as::<_, (String, String)>(
            "SELECT source_user, target_user FROM trust_edges WHERE trust_type = 'block'",
        )
        .fetch_all(db)
        .await?;

        let mut block_sets: BlockSets = HashMap::new();
        for (src_str, tgt_str) in &block_rows {
            let src_uuid =
                Uuid::parse_str(src_str).expect("invalid UUID in trust_edges.source_user");
            let tgt_uuid =
                Uuid::parse_str(tgt_str).expect("invalid UUID in trust_edges.target_user");
            if let (Some(src_id), Some(tgt_id)) = (index.get_id(&src_uuid), index.get_id(&tgt_uuid))
            {
                block_sets.entry(src_id).or_default().insert(tgt_id);
            }
        }

        eprintln!(
            "trust graph built: {} nodes, {} trust edges, {} block edges",
            index.num_nodes(),
            dense_edges.len(),
            block_rows.len()
        );

        Ok(Self {
            forward,
            reverse,
            index,
            block_sets,
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
            block_sets: HashMap::new(),
        }
    }

    /// Compute forward trust scores from `reader` to all reachable users
    /// (relevance ranking).
    ///
    /// Returns trust scores sorted by distance (closest first).
    pub fn forward_scores(&self, reader: Uuid) -> Vec<TrustScore> {
        let Some(source_id) = self.index.get_id(&reader) else {
            return Vec::new();
        };

        let mut scores: Vec<TrustScore> = forward_bfs(source_id, &self.forward, &self.block_sets)
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

        scores.sort_by(|a, b| a.distance.partial_cmp(&b.distance).unwrap());
        scores
    }

    /// Build a lookup map from user UUID string to trust distance for the given reader.
    // TODO: Use HashMap<Uuid, f64> once we migrate to typed sqlx::query!() macros
    // so author IDs are already Uuid instead of String.
    pub fn distance_map(&self, reader: Uuid) -> HashMap<String, f64> {
        self.forward_scores(reader)
            .into_iter()
            .map(|s| (s.target_user.to_string(), s.distance))
            .collect()
    }

    /// Compute reverse trust scores: all users who trust `reader` within
    /// MAX_DEPTH hops (visibility check).
    ///
    /// Returns a map from user UUID to their trust-in-reader score. Use this
    /// to check whether a given author's content should be visible to the
    /// reader: if the author is in this map and their score meets their read
    /// threshold, the content is visible.
    ///
    /// NOTE: These scores do NOT include block propagation — they are an
    /// approximation. For exact block-penalized trust(author, reader), use
    /// `trust_between(author, reader)` which runs forward BFS from the author.
    #[cfg_attr(not(test), expect(dead_code))]
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

        let empty_blocks = HashSet::new();
        let blocked = self.block_sets.get(&source_id).unwrap_or(&empty_blocks);

        let mut paths = Vec::new();

        let source_neighbors = self.forward.neighbors(source_id);

        if source_neighbors.contains(&target_id) {
            paths.push(TrustPath::Direct);
        }

        for &mid in source_neighbors {
            if mid == source_id || mid == target_id || blocked.contains(&mid) {
                continue;
            }
            if self.forward.neighbors(mid).contains(&target_id) {
                paths.push(TrustPath::TwoHop {
                    via: self.index.get_uuid(mid),
                });
            }
        }

        for &mid1 in source_neighbors {
            if mid1 == source_id || mid1 == target_id || blocked.contains(&mid1) {
                continue;
            }
            for &mid2 in self.forward.neighbors(mid1) {
                if mid2 == source_id || mid2 == target_id || mid2 == mid1 || blocked.contains(&mid2)
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
        forward_bfs(source_id, &self.forward, &self.block_sets)
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

        for (node, score) in forward_bfs(source_id, &self.forward, &self.block_sets) {
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
}

// ---------------------------------------------------------------------------
// Periodic rebuild task
// ---------------------------------------------------------------------------

/// Rebuild the trust graph from the database and swap it into the shared Arc.
///
/// Called by the background task when the dirty flag is set. The new graph
/// replaces the old one atomically; in-flight queries using the old Arc
/// continue unaffected until they drop their reference.
pub async fn rebuild_trust_graph(
    db: &SqlitePool,
    graph: &std::sync::RwLock<std::sync::Arc<TrustGraph>>,
) -> Result<(), sqlx::Error> {
    let new_graph = TrustGraph::build(db).await?;
    let new_arc = std::sync::Arc::new(new_graph);
    *graph.write().unwrap() = new_arc;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        graph_from_edges_with_blocks(edges, &[])
    }

    /// Build a TrustGraph with both trust and block edges (no database).
    fn graph_from_edges_with_blocks(
        edges: &[(Uuid, Uuid)],
        block_edges: &[(Uuid, Uuid)],
    ) -> TrustGraph {
        let index = NodeIndex::from_edges(edges);
        let dense: Vec<(u32, u32)> = edges
            .iter()
            .map(|(s, t)| (index.get_id(s).unwrap(), index.get_id(t).unwrap()))
            .collect();
        let forward = CsrGraph::from_edges(index.num_nodes(), &dense);
        let reverse = forward.transpose();

        let mut block_sets: BlockSets = HashMap::new();
        for &(blocker, blocked) in block_edges {
            if let (Some(blocker_id), Some(blocked_id)) =
                (index.get_id(&blocker), index.get_id(&blocked))
            {
                block_sets.entry(blocker_id).or_default().insert(blocked_id);
            }
        }

        TrustGraph {
            forward,
            reverse,
            index,
            block_sets,
        }
    }

    // -- Score-to-distance tests --

    #[test]
    fn test_score_to_distance_direct_trust() {
        let d = score_to_distance(1.0);
        assert!((d - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_score_to_distance_two_hop() {
        let d = score_to_distance(DECAY);
        assert!((d - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_score_to_distance_three_hop() {
        let d = score_to_distance(DECAY * DECAY);
        assert!((d - 3.0).abs() < 0.01);
    }

    #[test]
    fn test_score_to_distance_zero() {
        assert!((score_to_distance(0.0) - 3.0).abs() < f64::EPSILON);
    }

    // -- PathGroups unit tests --

    #[test]
    fn test_path_groups_single() {
        let mut pg = PathGroups::new();
        pg.add(0, 0.49);
        assert!((pg.combined_score() - 0.49).abs() < f64::EPSILON);
    }

    #[test]
    fn test_path_groups_two_independent() {
        let mut pg = PathGroups::new();
        pg.add(0, 0.49);
        pg.add(1, 0.49);
        // 1 - (1-0.49)(1-0.49) = 0.7399
        assert!((pg.combined_score() - 0.7399).abs() < 0.001);
    }

    #[test]
    fn test_path_groups_same_group_takes_max() {
        let mut pg = PathGroups::new();
        pg.add(0, 0.49);
        pg.add(0, 0.343);
        assert!((pg.combined_score() - 0.49).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sybil_resistance_path_groups() {
        // All through same first hop — max = 0.49
        let mut pg = PathGroups::new();
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

    // -- Block propagation tests --

    #[test]
    fn test_block_single_target_penalizes_intermediary() {
        // A→B→C, B trusts E (blocked by A)
        let g = graph_from_edges_with_blocks(&[(A, B), (B, C), (B, E)], &[(A, E)]);
        let scores = g.forward_scores(A);
        let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

        // B trusts E (blocked) → reliability = 0.75
        assert!((map[&B] - 0.75).abs() < 0.001);
        // C = 0.75 * DECAY * 1.0 = 0.525
        assert!((map[&C] - 0.525).abs() < 0.001);
        // E is directly blocked → 0.0, filtered out by threshold
        assert!(!map.contains_key(&E));
    }

    #[test]
    fn test_block_multiple_targets_compound() {
        // A→B, B trusts C and D (both blocked by A)
        let g = graph_from_edges_with_blocks(&[(A, B), (B, C), (B, D)], &[(A, C), (A, D)]);
        let scores = g.forward_scores(A);
        let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

        // B trusts 2 blocked → reliability = 0.75^2 = 0.5625
        assert!((map[&B] - 0.5625).abs() < 0.001);
        // C and D are directly blocked → filtered out by threshold
        assert!(!map.contains_key(&C));
        assert!(!map.contains_key(&D));
    }

    #[test]
    fn test_block_no_penalty_clean_node() {
        // A→B→C, A→E. A blocks E. B doesn't trust E → no penalty.
        let g = graph_from_edges_with_blocks(&[(A, B), (B, C), (A, E)], &[(A, E)]);
        let scores = g.forward_scores(A);
        let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

        assert!((map[&B] - 1.0).abs() < 0.001);
        assert!((map[&C] - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_block_multipath_recovery() {
        // A→B→D, A→C→D. B trusts E (blocked by A), C is clean.
        let g = graph_from_edges_with_blocks(&[(A, B), (A, C), (B, D), (C, D), (B, E)], &[(A, E)]);
        let scores = g.forward_scores(A);
        let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

        // Group B: 0.75 * 0.7 = 0.525, Group C: 1.0 * 0.7 = 0.7
        // Combined: 1 - (1-0.525)(1-0.7) = 0.8575
        assert!((map[&D] - 0.8575).abs() < 0.001);
    }

    #[test]
    fn test_block_compounds_along_path() {
        // A→B→C→D, B trusts E (blocked), C trusts F (blocked)
        let g = graph_from_edges_with_blocks(
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
        // E, F blocked → filtered
        assert!(!map.contains_key(&E));
        assert!(!map.contains_key(&F));
    }

    #[test]
    fn test_block_sybil_resistance() {
        // A→H, H→M, H→S1→M, H→S2→M, H→E. A blocks E.
        let g = graph_from_edges_with_blocks(
            &[(A, H), (H, M), (H, S1), (H, S2), (S1, M), (S2, M), (H, E)],
            &[(A, E)],
        );
        let scores = g.forward_scores(A);
        let map: HashMap<Uuid, f64> = scores.iter().map(|s| (s.target_user, s.score)).collect();

        // All via first-hop H. H reliability = 0.75 (trusts E).
        // Best in group: H→M = 0.75 * 0.7 = 0.525
        assert!((map[&M] - 0.525).abs() < 0.001);
    }
}
