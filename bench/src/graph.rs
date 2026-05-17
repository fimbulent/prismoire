//! Synthetic graph generation for the bench.
//!
//! Two topology families:
//!
//! - [`generate_graph`] / [`GraphConfig`] — homogeneous: every user vouches
//!   for a fixed number of uniformly random others. Federation variant adds
//!   per-instance "remote clusters" reachable from local cross-instance
//!   vouches. Conservative model for performance bounds, matches the
//!   single-instance / federation modes in `bench/README.md`.
//!
//! - [`generate_power_law_graph`] / [`PowerLawConfig`] — heterogeneous: three
//!   out-degree tiers (lurker/active/power) mixed with Pareto-weighted target
//!   selection, producing a heavy-tailed in-degree distribution with hubs
//!   large enough to exercise hub dampening. Models the single-instance
//!   slice of the doc's power-law scenario
//!   (`docs/federation-bfs-analysis.md` §"Power-law Extension").

use std::collections::HashSet;

use rand::Rng;
use rand::distributions::{Distribution, WeightedIndex};
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;

// ---------------------------------------------------------------------------
// Common output type
// ---------------------------------------------------------------------------

/// Generated graph with metadata about node ranges.
pub struct SyntheticGraph {
    pub edges: Vec<(u32, u32)>,
    pub distrust_edges: Vec<(u32, u32)>,
    pub num_nodes: u32,
    /// Range of local user node indices (the "home instance" users — the
    /// only nodes sampled as BFS sources in the bench harness).
    pub local_range: std::ops::Range<u32>,
}

// ---------------------------------------------------------------------------
// Homogeneous topology (existing single-instance / federation bench)
// ---------------------------------------------------------------------------

/// Configuration for synthetic federated graph generation.
pub struct GraphConfig {
    /// Number of local users (the "home instance").
    pub local_users: u32,
    /// Number of remote instances; each contributes a small cluster.
    pub remote_instances: u32,
    /// Avg outgoing trust edges per local user.
    pub avg_intra_vouches: u32,
    /// Total cross-instance trust edges from local users to remote ones.
    pub cross_instance_vouches: u32,
}

impl GraphConfig {
    pub fn single_instance() -> Self {
        Self {
            local_users: 10_000,
            remote_instances: 0,
            avg_intra_vouches: 10,
            cross_instance_vouches: 0,
        }
    }

    pub fn federation() -> Self {
        Self {
            local_users: 10_000,
            remote_instances: 10_000,
            avg_intra_vouches: 10,
            cross_instance_vouches: 10_000,
        }
    }
}

/// Generate a synthetic federated trust graph with clustered topology.
///
/// Creates a "home instance" with `local_users` densely connected users,
/// then `remote_instances` remote clusters each with a small number of
/// reachable users (following the 3-hop frontier model from
/// federation-bfs-analysis.md).
pub fn generate_graph(config: &GraphConfig, rng: &mut ChaCha8Rng) -> SyntheticGraph {
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

    // --- Distrust edges ---
    // ~10% of local users distrust 1-2 random local users.
    let num_distrusters = (config.local_users / 10).max(1);
    let mut distrust_edges: Vec<(u32, u32)> = Vec::new();
    for i in 0..num_distrusters {
        let distruster = local_start + i;
        let num_distrusts = rng.gen_range(1..=2u32);
        for _ in 0..num_distrusts {
            let target = rng.gen_range(local_start..local_end);
            if target != distruster {
                distrust_edges.push((distruster, target));
            }
        }
    }

    if config.remote_instances == 0 {
        return SyntheticGraph {
            num_nodes: next_node,
            edges,
            distrust_edges,
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
        distrust_edges,
        local_range: local_start..local_end,
    }
}

// ---------------------------------------------------------------------------
// Power-law topology (heterogeneous single instance)
// ---------------------------------------------------------------------------

/// Configuration for power-law synthetic graph generation.
///
/// Models the heterogeneous federation scenario from
/// `docs/federation-bfs-analysis.md` §"Power-law Extension" as a single
/// densely-connected instance: three out-degree tiers (lurker/active/power)
/// for ~90/9/1% of users, with target selection biased toward high-rank
/// nodes to produce a heavy-tailed in-degree distribution.
///
/// At [`PowerLawConfig::medium_instance`] scale (50K users, α=0.8) the top
/// in-degree node lands around 8K–15K, comfortably above
/// [`crate::algo::HUB_DAMPEN_THRESHOLD`] so dampening is actually exercised.
pub struct PowerLawConfig {
    /// Total number of users in the instance.
    pub local_users: u32,
    /// Out-degree for "power user" tier (1% of users).
    pub power_out_degree: u32,
    /// Out-degree for "active" tier (9% of users).
    pub active_out_degree: u32,
    /// Out-degree for "lurker" tier (90% of users).
    pub lurker_out_degree: u32,
    /// Pareto exponent for in-degree attractiveness weight `1/(rank+1)^α`.
    /// Smaller α = heavier tail. 0.8 produces a top-1 in-degree share of
    /// ~1–2% at N=50K (~5K–15K inbound edges), enough to cross
    /// [`crate::algo::HUB_DAMPEN_THRESHOLD`].
    pub in_degree_alpha: f64,
}

impl PowerLawConfig {
    /// Medium-small instance: 50K users with the doc's standard tier shape.
    /// Sized so the top hubs cross the hub-dampening threshold.
    pub fn medium_instance() -> Self {
        Self {
            local_users: 50_000,
            power_out_degree: 200,
            active_out_degree: 50,
            lurker_out_degree: 5,
            in_degree_alpha: 0.8,
        }
    }
}

/// Generate a single-instance graph with power-law out-degree tiers and a
/// heavy-tailed in-degree distribution.
///
/// Algorithm:
///
/// 1. Assign each user an out-degree by tier (top 1% → `power_out_degree`,
///    next 9% → `active_out_degree`, rest → `lurker_out_degree`).
/// 2. Shuffle node IDs into a random in-degree rank order, decoupling the
///    out-degree tier from the in-degree rank (so a top celebrity is not
///    forced to also be a power-user).
/// 3. Assign attractiveness weight `w_i = 1/(rank_i+1)^α` and build a
///    [`WeightedIndex`] distribution for O(1) target sampling.
/// 4. For each user, sample its targets with rejection on self-loops and
///    duplicates (HashSet dedup).
/// 5. Add the same shape of distrust edges as [`generate_graph`].
pub fn generate_power_law_graph(config: &PowerLawConfig, rng: &mut ChaCha8Rng) -> SyntheticGraph {
    let n = config.local_users;
    let n_us = n as usize;

    // Step 1: out-degree tier assignment.
    // Indices 0..num_power → power tier; next num_active → active; rest lurker.
    let num_power = n_us.div_ceil(100); // 1%, rounded up to guarantee ≥1
    let num_active = (n_us * 9).div_ceil(100); // 9%, rounded up

    let mut out_degrees = vec![config.lurker_out_degree; n_us];
    for d in out_degrees.iter_mut().take(num_power) {
        *d = config.power_out_degree;
    }
    for d in out_degrees.iter_mut().skip(num_power).take(num_active) {
        *d = config.active_out_degree;
    }

    // Step 2: shuffle node IDs to assign in-degree ranks independent of
    // out-degree tier. Without this, "user 0" would be both a power user
    // AND the top celebrity, conflating two power-law axes.
    let mut rank_order: Vec<u32> = (0..n).collect();
    rank_order.shuffle(rng);

    // Step 3: attractiveness weight per node, then a WeightedIndex for
    // O(1) sampling. WeightedIndex builds an alias table once, then each
    // .sample() call is O(1) — appropriate when we'll sample hundreds of
    // thousands of times.
    let alpha = config.in_degree_alpha;
    let mut weight_of_node = vec![0.0_f64; n_us];
    for (rank, &node) in rank_order.iter().enumerate() {
        weight_of_node[node as usize] = 1.0 / ((rank + 1) as f64).powf(alpha);
    }
    let dist =
        WeightedIndex::new(&weight_of_node).expect("power-law weights are positive and finite");

    // Step 4: target sampling per user. Rejection rejects self-loops and
    // duplicates. With α=0.8 and N=50K the rejection rate is low because
    // the weight distribution is not too peaked at any single node.
    let total_edges_est: usize = out_degrees.iter().map(|&d| d as usize).sum();
    let mut edges = Vec::with_capacity(total_edges_est);
    for user in 0..n {
        let d = out_degrees[user as usize];
        let mut targets: HashSet<u32> = HashSet::with_capacity(d as usize);
        // Safety cap: if we've rejected an absurd number of times (e.g. a
        // user happens to be the top hub and keeps sampling itself), fall
        // back to uniform sampling so the generator can't hang.
        let cap = (d as usize).saturating_mul(20).max(64);
        let mut attempts = 0usize;
        while targets.len() < d as usize {
            attempts += 1;
            if attempts > cap {
                while targets.len() < d as usize {
                    let t = rng.gen_range(0..n);
                    if t != user {
                        targets.insert(t);
                    }
                }
                break;
            }
            let t = dist.sample(rng) as u32;
            if t != user {
                targets.insert(t);
            }
        }
        for t in targets {
            edges.push((user, t));
        }
    }

    // Step 5: distrust edges — same shape as the homogeneous bench.
    let num_distrusters = (n / 10).max(1);
    let mut distrust_edges: Vec<(u32, u32)> = Vec::new();
    for i in 0..num_distrusters {
        let num_distrusts = rng.gen_range(1..=2u32);
        for _ in 0..num_distrusts {
            let target = rng.gen_range(0..n);
            if target != i {
                distrust_edges.push((i, target));
            }
        }
    }

    SyntheticGraph {
        num_nodes: n,
        edges,
        distrust_edges,
        local_range: 0..n,
    }
}

// ---------------------------------------------------------------------------
// Federated power-law topology
// ---------------------------------------------------------------------------

/// What the admin controls — the home instance shape.
///
/// `local_users` is the headline parameter for sizing: how many local users
/// does the admin want to support on this hardware? Everything else is the
/// per-user behaviour shape (out-degree tiers, in-degree alpha) and the
/// federation exposure (`local_preference`).
pub struct HomeInstanceConfig {
    /// Number of users on the home instance.
    pub local_users: u32,
    /// Per-user shape: out-degree tiers and in-degree alpha. Reused as-is
    /// from the single-instance generator so the same per-user behaviour
    /// holds whether the instance is studied standalone or in federation.
    pub shape: PowerLawConfig,
    /// Fraction of each user's edges that target a *local* user. The rest
    /// target a remote user (instance-weighted, then rank-weighted within
    /// the chosen instance). 0.5 ≈ generalist instance; 0.7–0.9 ≈ niche.
    pub local_preference: f64,
}

impl HomeInstanceConfig {
    /// 50K local users with the standard tier shape and a balanced
    /// local/federation split. Same per-user behaviour as
    /// [`PowerLawConfig::medium_instance`].
    pub fn medium() -> Self {
        Self {
            local_users: 50_000,
            shape: PowerLawConfig::medium_instance(),
            local_preference: 0.5,
        }
    }
}

/// The federation the home instance is embedded in. Sensible defaults so
/// admins can sweep `local_users` without having to think about the
/// surrounding world.
pub struct FederationEnvironment {
    pub num_remote_instances: u32,
    /// Mean users per remote instance. Total federated population ≈ this ×
    /// `num_remote_instances`. Per-instance sizes are themselves drawn from
    /// a Pareto distribution; this is the *mean* of that distribution.
    pub mean_remote_instance_size: u32,
    /// Pareto exponent on per-instance size. `>1` means a few mega-instances
    /// dominate; 1.2 produces a realistic spread (most instances small, a
    /// handful 10–100× the median).
    pub instance_size_alpha: f64,
    /// Pareto exponent on hub-bias for remote target selection within an
    /// instance. Smaller = sharper concentration on hubs. 0.8 matches the
    /// single-instance generator.
    pub target_hub_alpha: f64,
}

impl FederationEnvironment {
    /// 10K instances × 10K mean users ≈ 100M conceptual users. Default
    /// federation environment for sizing studies.
    pub fn realistic_10k() -> Self {
        Self {
            num_remote_instances: 10_000,
            mean_remote_instance_size: 10_000,
            instance_size_alpha: 1.2,
            target_hub_alpha: 0.8,
        }
    }
}

/// Output of the analytical pre-flight estimator. All quantities are
/// approximate — see [`estimate_frontier`] for the model. Used to give
/// admins a rough "is this going to blow up?" answer before committing to
/// generation.
pub struct FrontierEstimate {
    pub cross_edges: u64,
    pub unique_remote_hubs: u64,
    pub frontier_nodes: u64,
    pub frontier_edges: u64,
    pub csr_memory_bytes: u64,
}

/// Analytical pre-flight: project frontier size and memory from
/// `(home, env)` without generating the graph.
///
/// Accuracy:
/// - `cross_edges`: exact (just `local_users × E[d_out] × (1-local_pref)`).
/// - `unique_remote_hubs`: occupancy formula evaluated over top ranks of
///   the federation pool, accurate to ~10–20% for our scales.
/// - `frontier_nodes`: combines `unique_remote_hubs × per-hub expansion`
///   with a calibrated dedup factor; expect ~30–50% error vs measurement.
/// - `csr_memory_bytes`: tight upper bound given `frontier_nodes` and
///   `frontier_edges`; working-set memory is somewhat higher.
pub fn estimate_frontier(
    home: &HomeInstanceConfig,
    env: &FederationEnvironment,
) -> FrontierEstimate {
    // Mean out-degree under tier distribution: 1% power + 9% active + 90% lurker.
    let mean_out = 0.01 * home.shape.power_out_degree as f64
        + 0.09 * home.shape.active_out_degree as f64
        + 0.90 * home.shape.lurker_out_degree as f64;

    let local_users = home.local_users as f64;
    let cross_edges = (local_users * mean_out * (1.0 - home.local_preference)).round() as u64;

    // Occupancy: E[unique items hit] = Σ_r [1 - (1-p_r)^N]. We approximate
    // (1-p_r)^N as exp(-p_r·N) (good for small p_r, which holds beyond the
    // top few ranks). The tail contributes negligibly once exp(-p_r·N) is
    // small relative to 1, so we stop iterating early.
    let m = env.num_remote_instances as f64 * env.mean_remote_instance_size as f64;
    let alpha = env.target_hub_alpha;
    // Z = Σ_{r=1..M} 1/r^α ≈ M^(1-α)/(1-α) for 0 < α < 1.
    let z = m.powf(1.0 - alpha) / (1.0 - alpha);
    let n = cross_edges as f64;
    let mut unique = 0.0_f64;
    let mut r = 1u64;
    let m_u = m as u64;
    while r < m_u {
        let p_r = (r as f64).powf(-alpha) / z;
        let expected_hit = 1.0 - (-p_r * n).exp();
        unique += expected_hit;
        if expected_hit < 1e-4 && r > 1000 {
            break;
        }
        r += 1;
    }
    let unique_remote_hubs = unique.round() as u64;

    // Per-hub expansion: 1 (the hub) + mean_out (hop-2) + mean_out² (hop-3).
    // Each hop-2/3 selection is itself rank-weighted within the same
    // instance, so they collide heavily across hubs in that instance —
    // empirically ≈2–3× compression. 2.5× is a calibrated guess; expect to
    // refine after seeing measurements.
    let naive_per_hub = 1.0 + mean_out + mean_out * mean_out;
    const DEDUP_FACTOR: f64 = 2.5;
    let frontier_nodes_remote =
        (unique_remote_hubs as f64 * naive_per_hub / DEDUP_FACTOR).round() as u64;

    let frontier_nodes = home.local_users as u64 + frontier_nodes_remote;

    // Edges: local intra + cross (= 1 edge per hub on average, summed) +
    // 2 levels of per-hub fan-out (mean_out at hop-2, mean_out² at hop-3).
    let local_intra_edges = (local_users * mean_out * home.local_preference).round() as u64;
    let per_hub_extra_edges = (mean_out + mean_out * mean_out).round() as u64;
    let frontier_edges = local_intra_edges + cross_edges + unique_remote_hubs * per_hub_extra_edges;

    // CSR memory: forward + reverse, each 8 bytes/offset × (N+1) + 4 bytes/target × E.
    let csr_memory_bytes = 2 * (8 * (frontier_nodes + 1) + 4 * frontier_edges);

    FrontierEstimate {
        cross_edges,
        unique_remote_hubs,
        frontier_nodes,
        frontier_edges,
        csr_memory_bytes,
    }
}

/// Sample a rank in `[1, n]` from `w(r) ∝ 1/r^α` using inverse-CDF
/// transform on the continuous approximation. O(1) per draw, no setup —
/// essential since instance sizes can be in the millions and we can't
/// afford a per-instance WeightedIndex.
///
/// Continuous CDF: F(r) = (r^(1-α) - 1) / (N^(1-α) - 1) for α < 1.
/// Inverse: r = (u · (N^(1-α) - 1) + 1)^(1/(1-α)) for u ~ U(0,1).
fn sample_rank_pareto(n: u32, alpha: f64, rng: &mut ChaCha8Rng) -> u32 {
    debug_assert!(alpha > 0.0 && alpha < 1.0);
    if n <= 1 {
        return 1;
    }
    let u: f64 = rng.gen_range(0.0..1.0);
    let one_minus_a = 1.0 - alpha;
    let n_f = n as f64;
    let r = (u * (n_f.powf(one_minus_a) - 1.0) + 1.0).powf(1.0 / one_minus_a);
    (r.floor() as u32).clamp(1, n)
}

/// Generate a federated power-law graph: a home instance embedded in a
/// 10K-instance federation, with cross-instance edges as a per-edge
/// fraction of every local user's out-degree (transparency model — every
/// edge has the same probability of crossing instances, not a separate
/// "federation-curious" user behaviour).
///
/// Algorithm:
///
/// 1. Draw per-remote-instance sizes from Pareto(`instance_size_alpha`)
///    with the mean set to `mean_remote_instance_size`.
/// 2. Generate the home instance's out-degrees and local in-degree
///    weights the same way as [`generate_power_law_graph`].
/// 3. For each home user's edge, roll `local_preference`: with that
///    probability pick a local target (rank-weighted), else pick a remote
///    instance (size-weighted) and a rank within it (hub-weighted).
/// 4. Each unique `(instance, rank)` cross-vouch target materialises a
///    new global node and gets queued for 2 more levels of BFS-reachable
///    expansion (hop-2 + hop-3).
/// 5. Drain the expansion queue: each queued node draws its own tier →
///    out-degree, samples that many targets within the same instance,
///    materialises any new targets, and queues them at one less depth.
/// 6. Same-shape distrust edges as the single-instance generators —
///    scales with local users, not federated population.
///
/// Node IDs `[0, local_users)` are home users; remote nodes get IDs
/// `[local_users, total)`. `local_range` covers only the home instance,
/// matching the harness convention of sampling BFS sources from local.
pub fn generate_federated_power_law_graph(
    home: &HomeInstanceConfig,
    env: &FederationEnvironment,
    rng: &mut ChaCha8Rng,
) -> SyntheticGraph {
    use std::collections::VecDeque;

    let n_local = home.local_users;
    let n_local_us = n_local as usize;

    // --- Step 1: per-instance sizes ---
    // Pareto with α > 1 has mean = α/(α-1) · x_min, so pick x_min to hit
    // the requested mean. Clamp to ≥1 to avoid empty instances.
    let num_inst = env.num_remote_instances as usize;
    let mean_size = env.mean_remote_instance_size as f64;
    let alpha_inst = env.instance_size_alpha;
    let x_min = mean_size * (alpha_inst - 1.0) / alpha_inst;
    let mut instance_sizes: Vec<u32> = Vec::with_capacity(num_inst);
    for _ in 0..num_inst {
        let u: f64 = rng.gen_range(0.0..1.0);
        // Inverse-CDF of Pareto: x = x_min / (1-u)^(1/α).
        let size = (x_min / (1.0 - u).powf(1.0 / alpha_inst)).round() as u32;
        instance_sizes.push(size.max(1));
    }
    let instance_sampler =
        WeightedIndex::new(&instance_sizes).expect("instance sizes are positive");

    // --- Step 2: home instance setup ---
    let shape = &home.shape;
    let num_power = n_local_us.div_ceil(100);
    let num_active = (n_local_us * 9).div_ceil(100);
    let mut out_degrees = vec![shape.lurker_out_degree; n_local_us];
    for d in out_degrees.iter_mut().take(num_power) {
        *d = shape.power_out_degree;
    }
    for d in out_degrees.iter_mut().skip(num_power).take(num_active) {
        *d = shape.active_out_degree;
    }

    let mut rank_order: Vec<u32> = (0..n_local).collect();
    rank_order.shuffle(rng);
    let alpha_local = shape.in_degree_alpha;
    let mut weight_of_node = vec![0.0_f64; n_local_us];
    for (rank, &node) in rank_order.iter().enumerate() {
        weight_of_node[node as usize] = 1.0 / ((rank + 1) as f64).powf(alpha_local);
    }
    let local_target_dist =
        WeightedIndex::new(&weight_of_node).expect("local weights are positive");

    // --- Generator state for remote materialisation ---
    let mut edges: Vec<(u32, u32)> = Vec::new();
    let mut next_node_id: u32 = n_local;
    let mut remote_node_map: std::collections::HashMap<(u32, u32), u32> =
        std::collections::HashMap::new();
    // Reverse lookup: which (instance, rank) is this node? Needed to sample
    // its outgoing edges within the same instance during expansion.
    let mut node_to_loc: std::collections::HashMap<u32, (u32, u32)> =
        std::collections::HashMap::new();
    // (node_id, depth_remaining) — depth_remaining counts how many more
    // levels of BFS-reachable out-edges we still need to materialise.
    let mut expansion_queue: VecDeque<(u32, u8)> = VecDeque::new();
    // Tracks max depth_remaining we've already expanded each node to, so a
    // node first seen as a deep leaf can be re-expanded if later reached
    // as a shallow hub.
    let mut expanded_to: std::collections::HashMap<u32, u8> = std::collections::HashMap::new();

    let target_alpha = env.target_hub_alpha;
    let local_pref = home.local_preference;

    // --- Step 3: home users' outgoing edges (local + cross-instance mix) ---
    for user in 0..n_local {
        let d = out_degrees[user as usize];
        let mut targets: HashSet<u32> = HashSet::with_capacity(d as usize);
        let cap = (d as usize).saturating_mul(20).max(64);
        let mut attempts = 0usize;
        while targets.len() < d as usize {
            attempts += 1;
            if attempts > cap {
                // Same uniform-fallback as the single-instance generator:
                // protects against pathological rejection loops.
                while targets.len() < d as usize {
                    let t = rng.gen_range(0..n_local);
                    if t != user {
                        targets.insert(t);
                    }
                }
                break;
            }
            let go_local: f64 = rng.gen_range(0.0..1.0);
            if go_local < local_pref {
                let t = local_target_dist.sample(rng) as u32;
                if t != user {
                    targets.insert(t);
                }
            } else {
                // Cross-instance: pick instance (size-weighted), then rank
                // within instance (hub-weighted). Materialise on first sight,
                // queue for 2 more levels of expansion (hop-2 + hop-3).
                let inst_id = instance_sampler.sample(rng) as u32;
                let inst_size = instance_sizes[inst_id as usize];
                let rank = sample_rank_pareto(inst_size, target_alpha, rng);
                let key = (inst_id, rank);
                let node_id = *remote_node_map.entry(key).or_insert_with(|| {
                    let id = next_node_id;
                    next_node_id += 1;
                    node_to_loc.insert(id, key);
                    expansion_queue.push_back((id, 2));
                    id
                });
                targets.insert(node_id);
            }
        }
        for t in targets {
            edges.push((user, t));
        }
    }

    // --- Step 4: drain expansion queue ---
    // Each queued node: independent tier roll → out-degree; sample that
    // many out-targets within the same instance; materialise new targets;
    // queue new targets at one less depth.
    while let Some((node, depth_remaining)) = expansion_queue.pop_front() {
        let already_at = expanded_to.get(&node).copied().unwrap_or(0);
        if already_at >= depth_remaining {
            continue;
        }
        expanded_to.insert(node, depth_remaining);

        let tier_roll: f64 = rng.gen_range(0.0..1.0);
        let d_out = if tier_roll < 0.01 {
            shape.power_out_degree
        } else if tier_roll < 0.10 {
            shape.active_out_degree
        } else {
            shape.lurker_out_degree
        };

        let (inst_id, this_rank) = node_to_loc[&node];
        let inst_size = instance_sizes[inst_id as usize];
        if inst_size <= 1 {
            continue;
        }

        let mut targets: HashSet<u32> = HashSet::with_capacity(d_out as usize);
        let cap = (d_out as usize).saturating_mul(20).max(64);
        let mut attempts = 0usize;
        while targets.len() < d_out as usize {
            attempts += 1;
            if attempts > cap {
                // Accept a partial fan-out — the instance may simply be
                // too small to support the drawn d_out unique targets.
                break;
            }
            let tgt_rank = sample_rank_pareto(inst_size, target_alpha, rng);
            if tgt_rank == this_rank {
                continue;
            }
            let key = (inst_id, tgt_rank);
            let target_node = *remote_node_map.entry(key).or_insert_with(|| {
                let id = next_node_id;
                next_node_id += 1;
                node_to_loc.insert(id, key);
                id
            });
            targets.insert(target_node);
        }

        for t in &targets {
            edges.push((node, *t));
            if depth_remaining > 1 {
                expansion_queue.push_back((*t, depth_remaining - 1));
            }
        }
    }

    // --- Step 5: distrust edges (local-scoped, same shape as elsewhere) ---
    let num_distrusters = (n_local / 10).max(1);
    let mut distrust_edges: Vec<(u32, u32)> = Vec::new();
    for i in 0..num_distrusters {
        let num_distrusts = rng.gen_range(1..=2u32);
        for _ in 0..num_distrusts {
            let target = rng.gen_range(0..n_local);
            if target != i {
                distrust_edges.push((i, target));
            }
        }
    }

    SyntheticGraph {
        num_nodes: next_node_id,
        edges,
        distrust_edges,
        local_range: 0..n_local,
    }
}
