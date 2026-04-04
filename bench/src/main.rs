use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Per-hop decay constant for trust propagation (matches server/src/trust.rs).
const DECAY: f64 = 0.7;

/// Maximum BFS depth for trust traversal.
const MAX_DEPTH: u32 = 3;

// ---------------------------------------------------------------------------
// CSR graph representation
// ---------------------------------------------------------------------------

/// Compressed Sparse Row graph for cache-friendly BFS traversal.
///
/// Nodes are identified by dense u32 indices. Edge targets for node `i` are
/// stored in `targets[offsets[i]..offsets[i+1]]`. This is ~3-5x more memory
/// efficient than `HashMap<K, Vec<K>>` and yields sequential memory access
/// during BFS.
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
    ///
    /// `num_nodes` is the total number of nodes (indices 0..num_nodes).
    /// `edges` is a list of (source, target) pairs using dense indices.
    fn from_edges(num_nodes: u32, edges: &[(u32, u32)]) -> Self {
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

    /// Approximate memory usage in bytes.
    fn memory_bytes(&self) -> usize {
        self.offsets.len() * size_of::<u32>() + self.targets.len() * size_of::<u32>()
    }
}

/// Paired forward and reverse CSR graphs for dual BFS.
struct DualCsrGraph {
    forward: CsrGraph,
    reverse: CsrGraph,
    #[allow(dead_code)]
    num_nodes: u32,
}

impl DualCsrGraph {
    fn from_edges(num_nodes: u32, edges: &[(u32, u32)]) -> Self {
        let forward = CsrGraph::from_edges(num_nodes, edges);
        let reverse = forward.transpose();
        Self {
            forward,
            reverse,
            num_nodes,
        }
    }

    fn memory_bytes(&self) -> usize {
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
// Forward BFS: reader → authors (relevance)
// ---------------------------------------------------------------------------

/// Compute trust scores from a single source using bottleneck-grouped BFS
/// on the forward CSR graph.
///
/// Paths are grouped by the source's direct (first-hop) neighbor. Within each
/// group, only the max path score is kept. Across groups, scores combine via
/// probabilistic independence.
///
/// Returns a vec of (target_node, combined_score) for all reachable nodes.
fn forward_bfs(source: u32, graph: &CsrGraph) -> Vec<(u32, f64)> {
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
        queue.push_back((neighbor, 1, neighbor, 1.0));
        target_groups
            .entry(neighbor)
            .or_insert_with(PathGroupsU32::new)
            .add(neighbor, 1.0);
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

            let next_score = path_score * DECAY;

            target_groups
                .entry(next)
                .or_insert_with(PathGroupsU32::new)
                .add(first_hop, next_score);

            queue.push_back((next, depth + 1, first_hop, next_score));
        }
    }

    target_groups
        .into_iter()
        .map(|(target, groups)| (target, groups.combined_score()))
        .collect()
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
fn reverse_bfs(reader: u32, reverse_graph: &CsrGraph) -> Vec<(u32, f64)> {
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
// Synthetic graph generation
// ---------------------------------------------------------------------------

/// Configuration for synthetic federated graph generation.
struct GraphConfig {
    /// Number of local users (the "home instance").
    local_users: u32,
    /// Number of remote instances.
    remote_instances: u32,
    /// Average intra-instance vouches per user.
    avg_intra_vouches: u32,
    /// Number of cross-instance vouches from local users (one per remote
    /// instance for a well-connected instance).
    cross_instance_vouches: u32,
}

impl GraphConfig {
    fn single_instance() -> Self {
        Self {
            local_users: 10_000,
            remote_instances: 0,
            avg_intra_vouches: 10,
            cross_instance_vouches: 0,
        }
    }

    fn federation() -> Self {
        Self {
            local_users: 10_000,
            remote_instances: 10_000,
            avg_intra_vouches: 10,
            cross_instance_vouches: 10_000,
        }
    }
}

/// Generated graph with metadata about node ranges.
struct SyntheticGraph {
    edges: Vec<(u32, u32)>,
    num_nodes: u32,
    /// Range of local user node indices.
    local_range: std::ops::Range<u32>,
}

/// Generate a synthetic federated trust graph with clustered topology.
///
/// Creates a "home instance" with `local_users` densely connected users,
/// then `remote_instances` remote clusters each with a small number of
/// reachable users (following the 3-hop frontier model from
/// federation-bfs-analysis.md).
fn generate_graph(config: &GraphConfig, rng: &mut ChaCha8Rng) -> SyntheticGraph {
    let mut edges: Vec<(u32, u32)> = Vec::new();
    let mut next_node: u32 = 0;

    // --- Local instance ---
    let local_start = next_node;
    let local_end = local_start + config.local_users;
    next_node = local_end;

    // Intra-instance vouches: each local user vouches for `avg_intra_vouches`
    // random other local users.
    for user in local_start..local_end {
        let mut targets: HashSet<u32> = HashSet::new();
        while targets.len() < config.avg_intra_vouches as usize {
            let target = rng.gen_range(local_start..local_end);
            if target != user {
                targets.insert(target);
            }
        }
        for target in targets {
            edges.push((user, target));
        }
    }

    if config.remote_instances == 0 {
        return SyntheticGraph {
            num_nodes: next_node,
            edges,
            local_range: local_start..local_end,
        };
    }

    // --- Remote instances ---
    // For each remote instance, create a small cluster reachable from one
    // local user's cross-instance vouch. The cluster follows the 3-hop
    // frontier model:
    //   hop 1: 1 user (the cross-instance vouch target)
    //   hop 2: ~avg_intra_vouches users (hop-1's local neighbors)
    //   hop 3: ~avg_intra_vouches² users (hop-2's local neighbors)
    // Only edges from hops 1-2 are stored (hop-3 users are leaf nodes).
    let num_cross = config.cross_instance_vouches.min(config.remote_instances);
    let cross_sources: Vec<u32> = (0..num_cross)
        .map(|i| local_start + (i % config.local_users))
        .collect();

    for (i, &cross_src) in cross_sources.iter().enumerate() {
        let _instance_id = i;

        // Hop-1 user: the cross-instance vouch target.
        let hop1 = next_node;
        next_node += 1;
        edges.push((cross_src, hop1));

        // Hop-2 users: hop-1's local neighbors on the remote instance.
        let hop2_count = config.avg_intra_vouches;
        let hop2_start = next_node;
        let hop2_end = hop2_start + hop2_count;
        next_node = hop2_end;

        for h2 in hop2_start..hop2_end {
            edges.push((hop1, h2));
        }

        // Hop-3 users: each hop-2 user has ~avg_intra_vouches local neighbors.
        // These are leaf nodes — we store the edges from hop-2 to them but
        // don't store their outgoing edges.
        let hop3_per_h2 = config.avg_intra_vouches;
        for h2 in hop2_start..hop2_end {
            let hop3_start = next_node;
            let hop3_end = hop3_start + hop3_per_h2;
            next_node = hop3_end;

            for h3 in hop3_start..hop3_end {
                edges.push((h2, h3));
            }
        }
    }

    SyntheticGraph {
        num_nodes: next_node,
        edges,
        local_range: local_start..local_end,
    }
}

// ---------------------------------------------------------------------------
// Reference (HashMap) implementation for correctness verification
// ---------------------------------------------------------------------------

/// HashMap-based adjacency list (same as server/src/trust.rs, using u32).
struct HashMapGraph {
    adj: HashMap<u32, Vec<u32>>,
}

impl HashMapGraph {
    fn from_edges(edges: &[(u32, u32)]) -> Self {
        let mut adj: HashMap<u32, Vec<u32>> = HashMap::new();
        for &(src, tgt) in edges {
            adj.entry(src).or_default().push(tgt);
        }
        Self { adj }
    }
}

/// Reference forward BFS on HashMap graph (mirrors server/src/trust.rs logic).
fn reference_forward_bfs(source: u32, graph: &HashMapGraph) -> Vec<(u32, f64)> {
    let mut queue: VecDeque<(u32, u32, u32, f64)> = VecDeque::new();
    let mut target_groups: HashMap<u32, PathGroupsU32> = HashMap::new();
    let mut visited_per_group: HashMap<u32, HashSet<u32>> = HashMap::new();

    if let Some(neighbors) = graph.adj.get(&source) {
        for &neighbor in neighbors {
            if neighbor == source {
                continue;
            }
            queue.push_back((neighbor, 1, neighbor, 1.0));
            target_groups
                .entry(neighbor)
                .or_insert_with(PathGroupsU32::new)
                .add(neighbor, 1.0);
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

                let next_score = path_score * DECAY;
                target_groups
                    .entry(next)
                    .or_insert_with(PathGroupsU32::new)
                    .add(first_hop, next_score);
                queue.push_back((next, depth + 1, first_hop, next_score));
            }
        }
    }

    target_groups
        .into_iter()
        .map(|(target, groups)| (target, groups.combined_score()))
        .collect()
}

// ---------------------------------------------------------------------------
// Memory reporting (Linux /proc/self/status)
// ---------------------------------------------------------------------------

/// Read peak resident set size (VmHWM) from /proc/self/status on Linux.
/// Returns None on non-Linux or if the file is unreadable.
fn peak_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if line.starts_with("VmHWM:") {
            let kb_str = line
                .trim_start_matches("VmHWM:")
                .trim()
                .trim_end_matches("kB")
                .trim();
            return kb_str.parse().ok();
        }
    }
    None
}

/// Read current resident set size (VmRSS) from /proc/self/status.
fn current_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            let kb_str = line
                .trim_start_matches("VmRSS:")
                .trim()
                .trim_end_matches("kB")
                .trim();
            return kb_str.parse().ok();
        }
    }
    None
}

fn fmt_memory(kb: u64) -> String {
    if kb >= 1024 * 1024 {
        format!("{:.1} GB", kb as f64 / (1024.0 * 1024.0))
    } else if kb >= 1024 {
        format!("{:.1} MB", kb as f64 / 1024.0)
    } else {
        format!("{kb} KB")
    }
}

// ---------------------------------------------------------------------------
// Benchmark runner
// ---------------------------------------------------------------------------

fn run_benchmark(name: &str, config: &GraphConfig) {
    println!("\n{}", "=".repeat(60));
    println!("  Benchmark: {name}");
    println!("{}", "=".repeat(60));

    let rss_before = current_rss_kb();

    // --- Graph generation ---
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let t0 = Instant::now();
    let synth = generate_graph(config, &mut rng);
    let gen_time = t0.elapsed();
    println!(
        "\nGraph generation:  {:.1}ms",
        gen_time.as_secs_f64() * 1000.0
    );
    println!("  nodes: {}  edges: {}", synth.num_nodes, synth.edges.len());
    println!(
        "  local users: {}",
        synth.local_range.end - synth.local_range.start
    );

    // --- CSR build ---
    let t1 = Instant::now();
    let dual = DualCsrGraph::from_edges(synth.num_nodes, &synth.edges);
    let csr_build_time = t1.elapsed();
    println!(
        "\nCSR build:         {:.1}ms",
        csr_build_time.as_secs_f64() * 1000.0
    );
    println!(
        "  forward:  offsets={} targets={}",
        dual.forward.offsets.len(),
        dual.forward.targets.len()
    );
    println!(
        "  reverse:  offsets={} targets={}",
        dual.reverse.offsets.len(),
        dual.reverse.targets.len()
    );
    println!(
        "  memory:   {} (forward + reverse CSR, no index)",
        fmt_memory(dual.memory_bytes() as u64 / 1024)
    );

    let rss_after_build = current_rss_kb();
    if let (Some(before), Some(after)) = (rss_before, rss_after_build) {
        println!(
            "  RSS delta: {} → {} (+{})",
            fmt_memory(before),
            fmt_memory(after),
            fmt_memory(after.saturating_sub(before))
        );
    }

    // --- Forward BFS timing ---
    // Sample local users spread across the range for representative latency.
    let num_samples = 100.min((synth.local_range.end - synth.local_range.start) as usize);
    let step = ((synth.local_range.end - synth.local_range.start) as usize) / num_samples;
    let sample_sources: Vec<u32> = (0..num_samples)
        .map(|i| synth.local_range.start + (i * step) as u32)
        .collect();

    // Warm up (one run to populate caches).
    let _ = forward_bfs(sample_sources[0], &dual.forward);
    let _ = reverse_bfs(sample_sources[0], &dual.reverse);

    let mut forward_times = Vec::with_capacity(num_samples);
    let mut forward_result_counts = Vec::with_capacity(num_samples);
    for &src in &sample_sources {
        let t = Instant::now();
        let results = forward_bfs(src, &dual.forward);
        forward_times.push(t.elapsed().as_secs_f64() * 1000.0);
        forward_result_counts.push(results.len());
    }

    forward_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let fwd_p50 = forward_times[forward_times.len() / 2];
    let fwd_p99 = forward_times[(forward_times.len() as f64 * 0.99) as usize];
    let fwd_mean: f64 = forward_times.iter().sum::<f64>() / forward_times.len() as f64;
    let fwd_min = forward_times[0];
    let fwd_max = forward_times[forward_times.len() - 1];
    let avg_results: f64 =
        forward_result_counts.iter().sum::<usize>() as f64 / forward_result_counts.len() as f64;

    println!("\nForward BFS (relevance) — {num_samples} samples:");
    println!(
        "  min: {fwd_min:.3}ms  p50: {fwd_p50:.3}ms  p99: {fwd_p99:.3}ms  max: {fwd_max:.3}ms  mean: {fwd_mean:.3}ms"
    );
    println!("  avg reachable targets: {avg_results:.0}");

    // --- Reverse BFS timing ---
    let mut reverse_times = Vec::with_capacity(num_samples);
    let mut reverse_result_counts = Vec::with_capacity(num_samples);
    for &src in &sample_sources {
        let t = Instant::now();
        let results = reverse_bfs(src, &dual.reverse);
        reverse_times.push(t.elapsed().as_secs_f64() * 1000.0);
        reverse_result_counts.push(results.len());
    }

    reverse_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let rev_p50 = reverse_times[reverse_times.len() / 2];
    let rev_p99 = reverse_times[(reverse_times.len() as f64 * 0.99) as usize];
    let rev_mean: f64 = reverse_times.iter().sum::<f64>() / reverse_times.len() as f64;
    let rev_min = reverse_times[0];
    let rev_max = reverse_times[reverse_times.len() - 1];
    let avg_rev_results: f64 =
        reverse_result_counts.iter().sum::<usize>() as f64 / reverse_result_counts.len() as f64;

    println!("\nReverse BFS (visibility) — {num_samples} samples:");
    println!(
        "  min: {rev_min:.3}ms  p50: {rev_p50:.3}ms  p99: {rev_p99:.3}ms  max: {rev_max:.3}ms  mean: {rev_mean:.3}ms"
    );
    println!("  avg reachable sources: {avg_rev_results:.0}");

    // --- Combined dual-BFS (simulated page load) ---
    let mut dual_times = Vec::with_capacity(num_samples);
    for &src in &sample_sources {
        let t = Instant::now();
        let _fwd = forward_bfs(src, &dual.forward);
        let _rev = reverse_bfs(src, &dual.reverse);
        dual_times.push(t.elapsed().as_secs_f64() * 1000.0);
    }

    dual_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let dual_p50 = dual_times[dual_times.len() / 2];
    let dual_p99 = dual_times[(dual_times.len() as f64 * 0.99) as usize];
    let dual_mean: f64 = dual_times.iter().sum::<f64>() / dual_times.len() as f64;

    println!("\nDual BFS (simulated page load) — {num_samples} samples:");
    println!("  p50: {dual_p50:.3}ms  p99: {dual_p99:.3}ms  mean: {dual_mean:.3}ms");

    // --- Peak RSS ---
    if let Some(peak) = peak_rss_kb() {
        println!("\nPeak RSS: {}", fmt_memory(peak));
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("Prismoire Trust Graph Benchmark");
    println!("===============================");
    println!("Algorithm: Bottleneck-Grouped Probabilistic (DECAY={DECAY}, MAX_DEPTH={MAX_DEPTH})");

    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("all");

    match mode {
        "single" => {
            run_benchmark(
                "Single Instance (10K users)",
                &GraphConfig::single_instance(),
            );
        }
        "federation" => {
            run_benchmark("Federation (10K instances)", &GraphConfig::federation());
        }
        "test" => {
            run_tests();
        }
        _ => {
            run_benchmark(
                "Single Instance (10K users)",
                &GraphConfig::single_instance(),
            );
            run_benchmark("Federation (10K instances)", &GraphConfig::federation());
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn run_tests() {
    println!("\nRunning correctness tests...\n");
    let mut passed = 0;
    let mut failed = 0;

    macro_rules! assert_near {
        ($a:expr, $b:expr, $tol:expr, $msg:expr) => {
            if ($a - $b).abs() > $tol {
                eprintln!("  FAIL: {} — expected {}, got {}", $msg, $b, $a);
                failed += 1;
            } else {
                println!("  ok: {}", $msg);
                passed += 1;
            }
        };
    }

    macro_rules! assert_true {
        ($cond:expr, $msg:expr) => {
            if !$cond {
                eprintln!("  FAIL: {}", $msg);
                failed += 1;
            } else {
                println!("  ok: {}", $msg);
                passed += 1;
            }
        };
    }

    // Helper: build CSR + HashMap from edge list, run forward BFS on both,
    // return score maps.
    let to_map = |v: Vec<(u32, f64)>| -> HashMap<u32, f64> { v.into_iter().collect() };

    // --- Test 1: Linear chain A→B→C→D ---
    {
        let edges = vec![(0, 1), (1, 2), (2, 3)]; // A=0, B=1, C=2, D=3
        let csr = CsrGraph::from_edges(4, &edges);
        let href = HashMapGraph::from_edges(&edges);

        let csr_scores = to_map(forward_bfs(0, &csr));
        let ref_scores = to_map(reference_forward_bfs(0, &href));

        assert_near!(csr_scores[&1], 1.0, 0.001, "linear chain: B=1.0 (CSR)");
        assert_near!(csr_scores[&2], 0.7, 0.001, "linear chain: C=0.7 (CSR)");
        assert_near!(csr_scores[&3], 0.49, 0.001, "linear chain: D=0.49 (CSR)");
        assert_near!(
            csr_scores[&1],
            ref_scores[&1],
            f64::EPSILON,
            "linear chain: CSR matches reference for B"
        );
        assert_near!(
            csr_scores[&2],
            ref_scores[&2],
            f64::EPSILON,
            "linear chain: CSR matches reference for C"
        );
        assert_near!(
            csr_scores[&3],
            ref_scores[&3],
            f64::EPSILON,
            "linear chain: CSR matches reference for D"
        );
    }

    // --- Test 2: Two independent paths A→B→D, A→C→D ---
    {
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3)]; // A=0,B=1,C=2,D=3
        let csr = CsrGraph::from_edges(4, &edges);
        let href = HashMapGraph::from_edges(&edges);

        let csr_scores = to_map(forward_bfs(0, &csr));
        let ref_scores = to_map(reference_forward_bfs(0, &href));

        // 1-(1-0.7)(1-0.7) = 0.91
        assert_near!(csr_scores[&3], 0.91, 0.001, "two paths: D=0.91 (CSR)");
        assert_near!(
            csr_scores[&3],
            ref_scores[&3],
            f64::EPSILON,
            "two paths: CSR matches reference"
        );
    }

    // --- Test 3: Sybil attack through single first-hop ---
    {
        // A→H, H→M, H→S1, H→S2, S1→M, S2→M
        // A=0, H=1, M=2, S1=3, S2=4
        let edges = vec![(0, 1), (1, 2), (1, 3), (1, 4), (3, 2), (4, 2)];
        let csr = CsrGraph::from_edges(5, &edges);
        let csr_scores = to_map(forward_bfs(0, &csr));

        // All paths through H — max in group H is A→H→M = 0.7
        assert_near!(csr_scores[&2], 0.7, 0.001, "sybil: M=0.7 (collapsed)");
    }

    // --- Test 4: Depth limit ---
    {
        // A→B→C→D→E (4 hops, E unreachable)
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
        let csr = CsrGraph::from_edges(5, &edges);
        let csr_scores = to_map(forward_bfs(0, &csr));

        assert_true!(csr_scores.contains_key(&3), "depth limit: D reachable");
        assert_true!(!csr_scores.contains_key(&4), "depth limit: E unreachable");
    }

    // --- Test 5: No self-loop ---
    {
        // A→B→A
        let edges = vec![(0, 1), (1, 0)];
        let csr = CsrGraph::from_edges(2, &edges);
        let csr_scores = to_map(forward_bfs(0, &csr));

        assert_true!(
            !csr_scores.contains_key(&0),
            "no self-loop: A not in own scores"
        );
        assert_true!(csr_scores.contains_key(&1), "no self-loop: B reachable");
    }

    // --- Test 6: Reverse BFS matches forward BFS for linear chain ---
    {
        // A→B→C→D. Reverse BFS from D should produce trust(A,D), trust(B,D), trust(C,D).
        let edges = vec![(0, 1), (1, 2), (2, 3)];
        let dual = DualCsrGraph::from_edges(4, &edges);

        let rev_scores = to_map(reverse_bfs(3, &dual.reverse));

        // trust(C, D) = C directly vouches for D → 1.0
        assert_near!(rev_scores[&2], 1.0, 0.001, "reverse linear: trust(C,D)=1.0");
        // trust(B, D) = B→C→D → 0.7
        assert_near!(rev_scores[&1], 0.7, 0.001, "reverse linear: trust(B,D)=0.7");
        // trust(A, D) = A→B→C→D → 0.49
        assert_near!(
            rev_scores[&0],
            0.49,
            0.001,
            "reverse linear: trust(A,D)=0.49"
        );
    }

    // --- Test 7: Reverse BFS matches forward for two independent paths ---
    {
        // A→B→D, A→C→D. Forward trust(A,D)=0.91.
        // Reverse BFS from D should give same trust(A,D).
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3)];
        let dual = DualCsrGraph::from_edges(4, &edges);

        let fwd_scores = to_map(forward_bfs(0, &dual.forward));
        let rev_scores = to_map(reverse_bfs(3, &dual.reverse));

        assert_near!(
            rev_scores[&0],
            fwd_scores[&3],
            0.001,
            "reverse two-paths: trust(A,D) matches forward"
        );
    }

    // --- Test 8: Reverse BFS Sybil resistance ---
    {
        // A→H, H→R, H→S1, H→S2, S1→R, S2→R
        // A=0, H=1, R=2, S1=3, S2=4
        let edges = vec![(0, 1), (1, 2), (1, 3), (1, 4), (3, 2), (4, 2)];
        let dual = DualCsrGraph::from_edges(5, &edges);

        let fwd_scores = to_map(forward_bfs(0, &dual.forward));
        let rev_scores = to_map(reverse_bfs(2, &dual.reverse));

        // Forward trust(A, R) = group H only, max = A→H→R = 0.7
        assert_near!(fwd_scores[&2], 0.7, 0.001, "sybil fwd: trust(A,R)=0.7");
        // Reverse trust(A, R) should match.
        assert_near!(rev_scores[&0], 0.7, 0.001, "sybil rev: trust(A,R)=0.7");
    }

    // --- Test 9: Reverse BFS with mixed-depth paths ---
    {
        // A→X→R (2 hops) and A→Y→X→R (3 hops through different first-hop)
        // A=0, X=1, Y=2, R=3
        // Forward edges: A→X, A→Y, X→R, Y→X
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 1)];
        let dual = DualCsrGraph::from_edges(4, &edges);

        let fwd_scores = to_map(forward_bfs(0, &dual.forward));
        let rev_scores = to_map(reverse_bfs(3, &dual.reverse));

        // Forward: group X = 0.7 (A→X→R), group Y = 0.49 (A→Y→X→R)
        // Combined: 1-(1-0.7)(1-0.49) = 1-0.153 = 0.847
        assert_near!(
            fwd_scores[&3],
            0.847,
            0.001,
            "mixed-depth fwd: trust(A,R)=0.847"
        );
        assert_near!(
            rev_scores[&0],
            fwd_scores[&3],
            0.001,
            "mixed-depth: reverse matches forward"
        );
    }

    // --- Test 10: Forward/reverse agreement on random graph ---
    {
        // Generate a small random graph. For every (source, target) pair
        // reachable in both directions, verify forward_bfs and reverse_bfs
        // produce the same trust score.
        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let n = 50u32;
        let mut edges = Vec::new();
        for src in 0..n {
            let out_degree = rng.gen_range(2..6);
            let mut targets: HashSet<u32> = HashSet::new();
            while targets.len() < out_degree {
                let tgt = rng.gen_range(0..n);
                if tgt != src {
                    targets.insert(tgt);
                }
            }
            for tgt in targets {
                edges.push((src, tgt));
            }
        }

        let dual = DualCsrGraph::from_edges(n, &edges);

        // Pick a few source/target pairs and verify agreement.
        let mut mismatches = 0;
        let mut comparisons = 0;
        for src in 0..10u32 {
            let fwd = to_map(forward_bfs(src, &dual.forward));
            for tgt in 0..n {
                if tgt == src {
                    continue;
                }
                if let Some(&fwd_score) = fwd.get(&tgt) {
                    let rev = to_map(reverse_bfs(tgt, &dual.reverse));
                    if let Some(&rev_score) = rev.get(&src) {
                        comparisons += 1;
                        if (fwd_score - rev_score).abs() > 0.001 {
                            eprintln!(
                                "    mismatch: trust({src},{tgt}) fwd={fwd_score:.4} rev={rev_score:.4}"
                            );
                            mismatches += 1;
                        }
                    }
                }
            }
        }
        assert_true!(
            mismatches == 0,
            &format!(
                "random graph: {comparisons} forward/reverse comparisons, {mismatches} mismatches"
            )
        );
    }

    // --- Test 11: CSR forward matches HashMap reference on random graph ---
    {
        let mut rng = ChaCha8Rng::seed_from_u64(456);
        let n = 50u32;
        let mut edges = Vec::new();
        for src in 0..n {
            let out_degree = rng.gen_range(2..6);
            let mut targets: HashSet<u32> = HashSet::new();
            while targets.len() < out_degree {
                let tgt = rng.gen_range(0..n);
                if tgt != src {
                    targets.insert(tgt);
                }
            }
            for tgt in targets {
                edges.push((src, tgt));
            }
        }

        let csr = CsrGraph::from_edges(n, &edges);
        let href = HashMapGraph::from_edges(&edges);

        let mut mismatches = 0;
        let mut comparisons = 0;
        for src in 0..n {
            let csr_scores = to_map(forward_bfs(src, &csr));
            let ref_scores = to_map(reference_forward_bfs(src, &href));

            // Every target in either map should match.
            let all_targets: HashSet<u32> = csr_scores
                .keys()
                .chain(ref_scores.keys())
                .copied()
                .collect();
            for &tgt in &all_targets {
                comparisons += 1;
                let cs = csr_scores.get(&tgt).copied().unwrap_or(0.0);
                let rs = ref_scores.get(&tgt).copied().unwrap_or(0.0);
                if (cs - rs).abs() > 0.001 {
                    eprintln!("    mismatch: source={src} target={tgt} csr={cs:.4} ref={rs:.4}");
                    mismatches += 1;
                }
            }
        }
        assert_true!(
            mismatches == 0,
            &format!(
                "CSR vs HashMap: {comparisons} comparisons across all 50 sources, {mismatches} mismatches"
            )
        );
    }

    // --- Test 12: Reverse BFS no self-loop ---
    {
        // A→B→A. Reverse from A: trust(B,A)=1.0 (B vouches for A).
        // A should not appear in its own reverse results.
        let edges = vec![(0, 1), (1, 0)];
        let dual = DualCsrGraph::from_edges(2, &edges);
        let rev_scores = to_map(reverse_bfs(0, &dual.reverse));

        assert_true!(
            !rev_scores.contains_key(&0),
            "reverse no self-loop: reader not in own results"
        );
        assert_near!(
            rev_scores[&1],
            1.0,
            0.001,
            "reverse no self-loop: trust(B,A)=1.0"
        );
    }

    // --- Test 13: Reverse BFS depth limit ---
    {
        // A→B→C→D→E. Reverse from E: trust(D,E)=1, trust(C,E)=0.7,
        // trust(B,E)=0.49, trust(A,E) unreachable (4 hops).
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
        let dual = DualCsrGraph::from_edges(5, &edges);
        let rev_scores = to_map(reverse_bfs(4, &dual.reverse));

        assert_near!(rev_scores[&3], 1.0, 0.001, "reverse depth: trust(D,E)=1.0");
        assert_near!(rev_scores[&2], 0.7, 0.001, "reverse depth: trust(C,E)=0.7");
        assert_near!(
            rev_scores[&1],
            0.49,
            0.001,
            "reverse depth: trust(B,E)=0.49"
        );
        assert_true!(
            !rev_scores.contains_key(&0),
            "reverse depth: A unreachable (4 hops)"
        );
    }

    println!("\n{passed} passed, {failed} failed");
    if failed > 0 {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Cargo test integration
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn to_map(v: Vec<(u32, f64)>) -> HashMap<u32, f64> {
        v.into_iter().collect()
    }

    #[test]
    fn test_csr_linear_chain() {
        let edges = vec![(0, 1), (1, 2), (2, 3)];
        let csr = CsrGraph::from_edges(4, &edges);
        let scores = to_map(forward_bfs(0, &csr));

        assert!((scores[&1] - 1.0).abs() < 0.001);
        assert!((scores[&2] - 0.7).abs() < 0.001);
        assert!((scores[&3] - 0.49).abs() < 0.001);
    }

    #[test]
    fn test_csr_two_independent_paths() {
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3)];
        let csr = CsrGraph::from_edges(4, &edges);
        let scores = to_map(forward_bfs(0, &csr));

        assert!((scores[&3] - 0.91).abs() < 0.001);
    }

    #[test]
    fn test_csr_sybil_resistance() {
        let edges = vec![(0, 1), (1, 2), (1, 3), (1, 4), (3, 2), (4, 2)];
        let csr = CsrGraph::from_edges(5, &edges);
        let scores = to_map(forward_bfs(0, &csr));

        assert!((scores[&2] - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_csr_depth_limit() {
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
        let csr = CsrGraph::from_edges(5, &edges);
        let scores = to_map(forward_bfs(0, &csr));

        assert!(scores.contains_key(&3));
        assert!(!scores.contains_key(&4));
    }

    #[test]
    fn test_csr_no_self_loop() {
        let edges = vec![(0, 1), (1, 0)];
        let csr = CsrGraph::from_edges(2, &edges);
        let scores = to_map(forward_bfs(0, &csr));

        assert!(!scores.contains_key(&0));
        assert!(scores.contains_key(&1));
    }

    #[test]
    fn test_reverse_linear_chain() {
        let edges = vec![(0, 1), (1, 2), (2, 3)];
        let dual = DualCsrGraph::from_edges(4, &edges);
        let scores = to_map(reverse_bfs(3, &dual.reverse));

        assert!((scores[&2] - 1.0).abs() < 0.001);
        assert!((scores[&1] - 0.7).abs() < 0.001);
        assert!((scores[&0] - 0.49).abs() < 0.001);
    }

    #[test]
    fn test_reverse_two_paths_matches_forward() {
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3)];
        let dual = DualCsrGraph::from_edges(4, &edges);

        let fwd = to_map(forward_bfs(0, &dual.forward));
        let rev = to_map(reverse_bfs(3, &dual.reverse));

        assert!((fwd[&3] - rev[&0]).abs() < 0.001);
    }

    #[test]
    fn test_reverse_sybil_resistance() {
        let edges = vec![(0, 1), (1, 2), (1, 3), (1, 4), (3, 2), (4, 2)];
        let dual = DualCsrGraph::from_edges(5, &edges);

        let fwd = to_map(forward_bfs(0, &dual.forward));
        let rev = to_map(reverse_bfs(2, &dual.reverse));

        assert!((fwd[&2] - 0.7).abs() < 0.001);
        assert!((rev[&0] - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_reverse_mixed_depth() {
        // A→X→R and A→Y→X→R
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 1)];
        let dual = DualCsrGraph::from_edges(4, &edges);

        let fwd = to_map(forward_bfs(0, &dual.forward));
        let rev = to_map(reverse_bfs(3, &dual.reverse));

        assert!((fwd[&3] - 0.847).abs() < 0.001);
        assert!((rev[&0] - fwd[&3]).abs() < 0.001);
    }

    #[test]
    fn test_reverse_no_self_loop() {
        let edges = vec![(0, 1), (1, 0)];
        let dual = DualCsrGraph::from_edges(2, &edges);
        let scores = to_map(reverse_bfs(0, &dual.reverse));

        assert!(!scores.contains_key(&0));
        assert!((scores[&1] - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_reverse_depth_limit() {
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
        let dual = DualCsrGraph::from_edges(5, &edges);
        let scores = to_map(reverse_bfs(4, &dual.reverse));

        assert!((scores[&3] - 1.0).abs() < 0.001);
        assert!((scores[&2] - 0.7).abs() < 0.001);
        assert!((scores[&1] - 0.49).abs() < 0.001);
        assert!(!scores.contains_key(&0));
    }

    /// Exhaustive forward/reverse agreement on a random 50-node graph.
    #[test]
    fn test_forward_reverse_agreement_random() {
        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let n = 50u32;
        let mut edges = Vec::new();
        for src in 0..n {
            let out_degree = rng.gen_range(2..6);
            let mut targets: HashSet<u32> = HashSet::new();
            while targets.len() < out_degree {
                let tgt = rng.gen_range(0..n);
                if tgt != src {
                    targets.insert(tgt);
                }
            }
            for tgt in targets {
                edges.push((src, tgt));
            }
        }

        let dual = DualCsrGraph::from_edges(n, &edges);

        for src in 0..n {
            let fwd = to_map(forward_bfs(src, &dual.forward));
            for tgt in 0..n {
                if tgt == src {
                    continue;
                }
                if let Some(&fwd_score) = fwd.get(&tgt) {
                    let rev = to_map(reverse_bfs(tgt, &dual.reverse));
                    if let Some(&rev_score) = rev.get(&src) {
                        assert!(
                            (fwd_score - rev_score).abs() < 0.001,
                            "trust({src},{tgt}): fwd={fwd_score:.6} rev={rev_score:.6}"
                        );
                    }
                }
            }
        }
    }

    /// CSR forward BFS matches HashMap reference on a random graph.
    #[test]
    fn test_csr_matches_reference_random() {
        let mut rng = ChaCha8Rng::seed_from_u64(456);
        let n = 50u32;
        let mut edges = Vec::new();
        for src in 0..n {
            let out_degree = rng.gen_range(2..6);
            let mut targets: HashSet<u32> = HashSet::new();
            while targets.len() < out_degree {
                let tgt = rng.gen_range(0..n);
                if tgt != src {
                    targets.insert(tgt);
                }
            }
            for tgt in targets {
                edges.push((src, tgt));
            }
        }

        let csr = CsrGraph::from_edges(n, &edges);
        let href = HashMapGraph::from_edges(&edges);

        for src in 0..n {
            let csr_scores = to_map(forward_bfs(src, &csr));
            let ref_scores = to_map(reference_forward_bfs(src, &href));

            let all_targets: HashSet<u32> = csr_scores
                .keys()
                .chain(ref_scores.keys())
                .copied()
                .collect();
            for &tgt in &all_targets {
                let cs = csr_scores.get(&tgt).copied().unwrap_or(0.0);
                let rs = ref_scores.get(&tgt).copied().unwrap_or(0.0);
                assert!(
                    (cs - rs).abs() < 0.001,
                    "src={src} tgt={tgt}: csr={cs:.6} ref={rs:.6}"
                );
            }
        }
    }
}
