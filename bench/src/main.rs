//! Prismoire trust-graph benchmark binary.
//!
//! The algorithm under test lives in [`algo`]; the synthetic graph
//! generators live in [`graph`]. This file owns the benchmark harness, the
//! verbose test runner, the cargo-test module, and the CLI dispatcher.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use uuid::Uuid;

mod algo;
mod graph;
mod mmap_csr;

use algo::{
    CsrAccess, DECAY, DistrustSets, DualCsrGraph, HashMapGraph, MAX_DEPTH, build_distrust_sets,
    forward_bfs, reference_forward_bfs, reverse_bfs,
};
use graph::{
    FederationEnvironment, GraphConfig, HomeInstanceConfig, PowerLawConfig, SyntheticGraph,
    estimate_frontier, generate_federated_power_law_graph, generate_graph,
    generate_power_law_graph,
};

// Re-import inside cargo-test scope works because tests `use super::*`.
// algo::CsrGraph is referenced by the inline test module.
use algo::CsrGraph;

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

// ---------------------------------------------------------------------------
// Rebuild-peak allocator probe
// ---------------------------------------------------------------------------

/// Allocations that mirror the production rebuild-peak shape so the
/// bench process's VmHWM matches what a real server would peak at
/// during a snapshot rebuild.
///
/// The bench builds a single [`DualCsrGraph`] and runs BFS on `u32`
/// directly, so without this probe its peak RSS misses three large
/// production components:
///
/// - The *old* DualCsrGraph kept resident while the new one is built
///   (simulated as a `Vec<u8>` of equivalent bytes — kernel doesn't
///   care about contents, only that pages are faulted in).
/// - The steady-state sorted-Vec NodeIndex (~40 B/entry: 24 B
///   `Vec<(Uuid, u32)>` slot + 16 B `Vec<Uuid>` slot).
/// - The transient HashMap-shape NodeIndex held during build
///   (~76 B/entry: 60 B HashMap bucket + 16 B `Vec<Uuid>` slot).
///
/// `synth.edges: Vec<(u32, u32)>` is already alive throughout the
/// existing bench flow (held by `SyntheticGraph`, borrowed into
/// `DualCsrGraph::from_edges`), so the 8 B/edge dense_edges
/// intermediate is already counted — no separate stand-in needed.
///
/// Hold this struct alive across the BFS measurement loop, then
/// drop it. Pages back actual RSS because every slot is written
/// during construction (sorted Vec via `collect+sort`, HashMap via
/// `insert`, byte Vec via `vec![byte; N]` which calls `write_bytes`
/// across the allocation).
struct RebuildPeakProbe {
    /// Stand-in for the *old* DualCsrGraph (2× CSR — forward + reverse)
    /// kept resident during rebuild. Same byte count as the live
    /// `DualCsrGraph`; contents don't matter to RSS accounting.
    _old_csr_standin: Vec<u8>,
    /// "Old" steady-state NodeIndex, sorted by Uuid for binary search.
    /// Production: `NodeIndex::by_uuid`.
    _old_nidx_by_uuid: Vec<(Uuid, u32)>,
    /// "Old" steady-state NodeIndex reverse lookup: id → Uuid.
    /// Production: `NodeIndex::id_to_uuid`.
    _old_nidx_id_to_uuid: Vec<Uuid>,
    /// "New" NodeIndex *during build*: the transient HashMap that
    /// `NodeIndexBuilder` holds until `freeze` runs. Heaviest
    /// allocation in the rebuild peak (~76 B/entry).
    _new_nidx_hashmap: HashMap<Uuid, u32>,
    /// "New" NodeIndex reverse lookup mid-build — `NodeIndexBuilder.id_to_uuid`.
    _new_nidx_id_to_uuid: Vec<Uuid>,
}

/// Allocate the rebuild-peak probe. `num_nodes` and `csr_bytes` should
/// match the live DualCsrGraph's `num_nodes` and `memory_bytes()`.
///
/// Synthesized Uuids are deterministic (`Uuid::from_u128(id as u128)`)
/// so successive runs allocate the same shape, but the actual bit
/// pattern doesn't matter — the production NodeIndex doesn't care
/// either, it just stores whatever the DB hands it.
fn allocate_rebuild_peak_probe(num_nodes: u32, csr_bytes: u64) -> RebuildPeakProbe {
    // Old CSR stand-in. `vec![byte; N]` writes the byte to every slot
    // via `write_bytes`, faulting the pages and putting them on RSS.
    // Without the write the pages would stay COW-mapped to the kernel
    // zero page on first read and not show up in RSS until first write.
    let old_csr_standin: Vec<u8> = vec![1u8; csr_bytes as usize];

    // Old sorted-Vec NodeIndex. Build in (uuid, id) order then sort
    // by uuid, matching `NodeIndexBuilder::freeze`. `shrink_to_fit`
    // matches production so per-entry overhead is the same.
    let mut old_nidx_by_uuid: Vec<(Uuid, u32)> = (0..num_nodes)
        .map(|id| (Uuid::from_u128(id as u128), id))
        .collect();
    old_nidx_by_uuid.sort_unstable_by_key(|(u, _)| *u);
    old_nidx_by_uuid.shrink_to_fit();
    let mut old_nidx_id_to_uuid: Vec<Uuid> = (0..num_nodes)
        .map(|id| Uuid::from_u128(id as u128))
        .collect();
    old_nidx_id_to_uuid.shrink_to_fit();

    // New mid-build NodeIndex. HashMap + Vec<Uuid> filled the same way
    // `NodeIndexBuilder::intern` would populate it during a streaming
    // rebuild — one insert per unique node.
    let mut new_nidx_hashmap: HashMap<Uuid, u32> = HashMap::with_capacity(num_nodes as usize);
    let mut new_nidx_id_to_uuid: Vec<Uuid> = Vec::with_capacity(num_nodes as usize);
    for id in 0..num_nodes {
        let u = Uuid::from_u128(id as u128);
        new_nidx_hashmap.insert(u, id);
        new_nidx_id_to_uuid.push(u);
    }

    RebuildPeakProbe {
        _old_csr_standin: old_csr_standin,
        _old_nidx_by_uuid: old_nidx_by_uuid,
        _old_nidx_id_to_uuid: old_nidx_id_to_uuid,
        _new_nidx_hashmap: new_nidx_hashmap,
        _new_nidx_id_to_uuid: new_nidx_id_to_uuid,
    }
}

/// Bytes the probe's allocations contribute, ignoring per-Vec/per-HashMap
/// header overhead (which is ~24 B each — rounding error vs. the
/// gigabyte-scale arrays). Matches the formula in
/// `graph::estimate_frontier::peak_rebuild_bytes` minus the live CSR
/// and the dense_edges intermediate that the bench already holds.
fn rebuild_peak_probe_bytes(num_nodes: u32, csr_bytes: u64) -> u64 {
    let n = num_nodes as u64;
    csr_bytes              // old CSR stand-in
        + n * 24           // old NodeIndex sorted Vec (16 B Uuid + 4 B id + 4 B pad)
        + n * 16           // old NodeIndex id_to_uuid Vec<Uuid>
        + n * 60           // new HashMap bucket (~60 B/entry for HashMap<Uuid, u32>)
        + n * 16 // new id_to_uuid Vec<Uuid>
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
// Shared timing helpers
// ---------------------------------------------------------------------------

/// Pick `num_samples` evenly-spaced source IDs from the local range.
fn pick_sample_sources(local: &std::ops::Range<u32>, num_samples: usize) -> Vec<u32> {
    let len = (local.end - local.start) as usize;
    let num = num_samples.min(len);
    let step = len / num.max(1);
    (0..num).map(|i| local.start + (i * step) as u32).collect()
}

/// Compute (min, p50, p99, max, mean) over a sorted-ascending timing vec.
fn timing_stats(sorted_times_ms: &[f64]) -> (f64, f64, f64, f64, f64) {
    let len = sorted_times_ms.len();
    let p50 = sorted_times_ms[len / 2];
    let p99 = sorted_times_ms[(len as f64 * 0.99) as usize];
    let min = sorted_times_ms[0];
    let max = sorted_times_ms[len - 1];
    let mean: f64 = sorted_times_ms.iter().sum::<f64>() / len as f64;
    (min, p50, p99, max, mean)
}

// ---------------------------------------------------------------------------
// Homogeneous benchmark runner
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

    let dual = build_csr_and_report(&synth, rss_before);
    let distrust_sets = build_distrust_sets(&synth.distrust_edges);
    println!(
        "  distrust edges: {}  distrusters: {}",
        synth.distrust_edges.len(),
        distrust_sets.len()
    );

    run_bfs_timings(&synth, &dual, &distrust_sets);

    if let Some(peak) = peak_rss_kb() {
        println!("\nPeak RSS: {}", fmt_memory(peak));
    }
}

/// Build the dual CSR and print build timing, edge counts, memory.
fn build_csr_and_report(synth: &SyntheticGraph, rss_before: Option<u64>) -> DualCsrGraph {
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

    dual
}

/// Standard BFS timing block: forward, reverse, dual.
fn run_bfs_timings(synth: &SyntheticGraph, dual: &DualCsrGraph, distrust_sets: &DistrustSets) {
    let sample_sources = pick_sample_sources(&synth.local_range, 100);
    let num_samples = sample_sources.len();

    // Warm up (one run to populate caches).
    let _ = forward_bfs(sample_sources[0], &dual.forward, distrust_sets);
    let _ = reverse_bfs(sample_sources[0], &dual.reverse);

    // --- Forward BFS ---
    let mut forward_times = Vec::with_capacity(num_samples);
    let mut forward_result_counts = Vec::with_capacity(num_samples);
    for &src in &sample_sources {
        let t = Instant::now();
        let results = forward_bfs(src, &dual.forward, distrust_sets);
        forward_times.push(t.elapsed().as_secs_f64() * 1000.0);
        forward_result_counts.push(results.len());
    }
    forward_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let (fwd_min, fwd_p50, fwd_p99, fwd_max, fwd_mean) = timing_stats(&forward_times);
    let avg_results: f64 =
        forward_result_counts.iter().sum::<usize>() as f64 / forward_result_counts.len() as f64;

    println!("\nForward BFS (relevance) — {num_samples} samples:");
    println!(
        "  min: {fwd_min:.3}ms  p50: {fwd_p50:.3}ms  p99: {fwd_p99:.3}ms  max: {fwd_max:.3}ms  mean: {fwd_mean:.3}ms"
    );
    println!("  avg reachable targets: {avg_results:.0}");

    // --- Reverse BFS ---
    let mut reverse_times = Vec::with_capacity(num_samples);
    let mut reverse_result_counts = Vec::with_capacity(num_samples);
    for &src in &sample_sources {
        let t = Instant::now();
        let results = reverse_bfs(src, &dual.reverse);
        reverse_times.push(t.elapsed().as_secs_f64() * 1000.0);
        reverse_result_counts.push(results.len());
    }
    reverse_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let (rev_min, rev_p50, rev_p99, rev_max, rev_mean) = timing_stats(&reverse_times);
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
        let _fwd = forward_bfs(src, &dual.forward, distrust_sets);
        let _rev = reverse_bfs(src, &dual.reverse);
        dual_times.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    dual_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let (_, dual_p50, dual_p99, _, dual_mean) = timing_stats(&dual_times);

    println!("\nDual BFS (simulated page load) — {num_samples} samples:");
    println!("  p50: {dual_p50:.3}ms  p99: {dual_p99:.3}ms  mean: {dual_mean:.3}ms");
}

// ---------------------------------------------------------------------------
// Power-law benchmark runner
// ---------------------------------------------------------------------------

/// Same as [`run_benchmark`] for setup/timing, plus three power-law-specific
/// measurements after CSR build:
///
/// 1. **Degree distribution.** Top-N + percentile dump of in/out degree.
///    Validates the generator produced the expected heavy tail.
/// 2. **Variance multiplier κ = E[d²] / E[d]².** Direct test of the doc's
///    "every `n·d²` formula understates by a factor of ~5×" claim.
/// 3. **Friendship-paradox effective branching.** `Σ d_in·d_out / Σ d_in`,
///    which is the expected out-degree of a node reached by a random hop.
///    Doc predicts ~59 vs ~11 for the modelled distribution.
fn run_power_law_benchmark(name: &str, config: &PowerLawConfig) {
    println!("\n{}", "=".repeat(60));
    println!("  Benchmark: {name}");
    println!("{}", "=".repeat(60));

    let rss_before = current_rss_kb();

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let t0 = Instant::now();
    let synth = generate_power_law_graph(config, &mut rng);
    let gen_time = t0.elapsed();
    println!(
        "\nGraph generation:  {:.1}ms",
        gen_time.as_secs_f64() * 1000.0
    );
    println!("  nodes: {}  edges: {}", synth.num_nodes, synth.edges.len());
    println!(
        "  topology: power-law (α={}, tiers: lurker={}/active={}/power={})",
        config.in_degree_alpha,
        config.lurker_out_degree,
        config.active_out_degree,
        config.power_out_degree,
    );

    let dual = build_csr_and_report(&synth, rss_before);
    let distrust_sets = build_distrust_sets(&synth.distrust_edges);
    println!(
        "  distrust edges: {}  distrusters: {}",
        synth.distrust_edges.len(),
        distrust_sets.len()
    );

    report_degree_distribution(&dual);
    report_variance_multiplier(&dual);
    report_effective_branching(&dual);

    run_bfs_timings(&synth, &dual, &distrust_sets);

    if let Some(peak) = peak_rss_kb() {
        println!("\nPeak RSS: {}", fmt_memory(peak));
    }
}

/// Measurement 1: in/out degree distribution top-10 + percentiles.
fn report_degree_distribution(dual: &DualCsrGraph) {
    let n = dual.num_nodes;
    let mut in_degrees: Vec<u32> = (0..n)
        .map(|node| dual.reverse.neighbors(node).len() as u32)
        .collect();
    let mut out_degrees: Vec<u32> = (0..n)
        .map(|node| dual.forward.neighbors(node).len() as u32)
        .collect();
    let total_in_edges: u64 = in_degrees.iter().map(|&d| d as u64).sum();

    in_degrees.sort_unstable_by(|a: &u32, b: &u32| b.cmp(a));
    out_degrees.sort_unstable_by(|a: &u32, b: &u32| b.cmp(a));

    // Percentile helper — input sorted DESCENDING, so p99 = index near 0.
    let pct =
        |sorted: &[u32], p: f64| -> u32 { sorted[((1.0 - p) * sorted.len() as f64) as usize] };

    println!("\nDegree distribution (power-law topology):");
    println!(
        "  in-degree:  max={}  p99={}  p90={}  p50={}",
        in_degrees[0],
        pct(&in_degrees, 0.99),
        pct(&in_degrees, 0.90),
        pct(&in_degrees, 0.50),
    );
    println!(
        "  out-degree: max={}  p99={}  p90={}  p50={}",
        out_degrees[0],
        pct(&out_degrees, 0.99),
        pct(&out_degrees, 0.90),
        pct(&out_degrees, 0.50),
    );

    let top_n = 10.min(in_degrees.len());
    let top_sum: u64 = in_degrees[..top_n].iter().map(|&d| d as u64).sum();
    println!(
        "  top-{top_n} in-degree share: {:.1}% ({} of {} total inbound edges)",
        100.0 * top_sum as f64 / total_in_edges as f64,
        top_sum,
        total_in_edges,
    );
}

/// Measurement 2: out-degree variance multiplier κ = E[d²] / E[d]².
///
/// The doc's claim is that every `n · d²` frontier formula understates by
/// this factor under power law. Homogeneous baseline = 1.0.
fn report_variance_multiplier(dual: &DualCsrGraph) {
    let n = dual.num_nodes;
    let mut sum_d = 0u64;
    let mut sum_d_sq = 0u128;
    for node in 0..n {
        let d = dual.forward.neighbors(node).len() as u64;
        sum_d += d;
        sum_d_sq += (d as u128) * (d as u128);
    }
    let mean_d = sum_d as f64 / n as f64;
    let mean_d_sq = sum_d_sq as f64 / n as f64;
    let kappa = mean_d_sq / (mean_d * mean_d);
    println!(
        "\nVariance multiplier κ = E[d²]/E[d]² = {kappa:.2}× (E[d]={mean_d:.1}, E[d²]={mean_d_sq:.0})"
    );
    println!("  homogeneous baseline κ = 1.0; doc predicts ≈5× for the modelled distribution");
}

/// Measurement 3: friendship-paradox effective branching factor.
///
/// `E[d_out | node reached by random hop] = Σ d_in·d_out / Σ d_in`. Doc
/// predicts ~59 vs mean out-degree of ~11 under the modelled distribution.
fn report_effective_branching(dual: &DualCsrGraph) {
    let n = dual.num_nodes;
    let mut sum_in_times_out: u128 = 0;
    let mut sum_in: u64 = 0;
    for node in 0..n {
        let d_in = dual.reverse.neighbors(node).len() as u64;
        let d_out = dual.forward.neighbors(node).len() as u64;
        sum_in_times_out += (d_in as u128) * (d_out as u128);
        sum_in += d_in;
    }
    let eff_branching = sum_in_times_out as f64 / sum_in.max(1) as f64;
    let mean_out = sum_in as f64 / n as f64; // Σ d_in = Σ d_out
    println!(
        "Friendship-paradox branching at hop 2/3: {eff_branching:.1} (mean out-degree = {mean_out:.1})"
    );
}

// ---------------------------------------------------------------------------
// Federated power-law benchmark runner
// ---------------------------------------------------------------------------

/// Format a byte count as `KB`/`MB`/`GB`.
fn fmt_bytes(b: u64) -> String {
    if b >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", b as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if b >= 1024 * 1024 {
        format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

/// Print the analytical pre-flight before generation so admins can ctrl-C
/// out of a config that would blow past their memory budget.
fn print_pre_flight(home: &HomeInstanceConfig, env: &FederationEnvironment) {
    let est = estimate_frontier(home, env);
    println!(
        "  federation env: {} instances × {} mean users ≈ {} conceptual users (α_size={}, α_target={})",
        env.num_remote_instances,
        env.mean_remote_instance_size,
        fmt_count(env.num_remote_instances as u64 * env.mean_remote_instance_size as u64),
        env.instance_size_alpha,
        env.target_hub_alpha,
    );
    println!(
        "  home: {} local users, local_preference={}",
        home.local_users, home.local_preference,
    );
    println!("\nProjected (analytical pre-flight):");
    println!("  cross-edges from home:   {}", fmt_count(est.cross_edges));
    println!(
        "  unique remote hubs hit:  {}",
        fmt_count(est.unique_remote_hubs)
    );
    println!(
        "  materialised frontier:   {} nodes ({:.1}× local)",
        fmt_count(est.frontier_nodes),
        est.frontier_nodes as f64 / home.local_users.max(1) as f64,
    );
    println!(
        "  total edges:             {}",
        fmt_count(est.frontier_edges)
    );
    println!(
        "  CSR memory (forward+reverse): {}",
        fmt_bytes(est.csr_memory_bytes)
    );
    println!(
        "  NodeIndex memory:        {}",
        fmt_bytes(est.nodeindex_bytes),
    );
    println!(
        "  Steady-state memory:     {}",
        fmt_bytes(est.csr_memory_bytes + est.nodeindex_bytes),
    );
    // Peak is the binding constraint for sizing — during snapshot
    // rebuild the old graph stays resident while the new one is built
    // (plus intermediate uuid_edges and dense_edges Vecs). Size
    // against this number, not the steady-state line above.
    println!(
        "  Rebuild peak memory:     {} (size against this)",
        fmt_bytes(est.peak_rebuild_bytes),
    );
}

/// Format an integer with thousands separators (`1,234,567`).
fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}

/// One-shot federated power-law benchmark. Mirrors
/// [`run_power_law_benchmark`] but with the federated generator and a
/// pre-flight estimate printed before generation.
fn run_federated_power_law_benchmark(
    name: &str,
    home: &HomeInstanceConfig,
    env: &FederationEnvironment,
    rebuild_peak_probe: bool,
) {
    println!("\n{}", "=".repeat(60));
    println!("  Benchmark: {name}");
    println!("{}", "=".repeat(60));

    print_pre_flight(home, env);

    let rss_before = current_rss_kb();

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let t0 = Instant::now();
    let synth = generate_federated_power_law_graph(home, env, &mut rng);
    let gen_time = t0.elapsed();
    println!(
        "\nGraph generation:  {:.1}ms",
        gen_time.as_secs_f64() * 1000.0
    );
    println!(
        "  nodes: {}  edges: {}",
        fmt_count(synth.num_nodes as u64),
        fmt_count(synth.edges.len() as u64),
    );
    let local_n = synth.local_range.end - synth.local_range.start;
    let remote_n = synth.num_nodes - local_n;
    println!(
        "  local users: {}   remote frontier: {} ({:.1}× local)",
        fmt_count(local_n as u64),
        fmt_count(remote_n as u64),
        remote_n as f64 / local_n.max(1) as f64,
    );

    let dual = build_csr_and_report(&synth, rss_before);
    let distrust_sets = build_distrust_sets(&synth.distrust_edges);
    println!(
        "  distrust edges: {}  distrusters: {}",
        synth.distrust_edges.len(),
        distrust_sets.len()
    );

    // Estimate-vs-measurement comparison so we can recalibrate the
    // estimator over time as we sweep more configs.
    let est = estimate_frontier(home, env);
    println!("\nEstimator vs measurement:");
    println!(
        "  frontier nodes:  est {}  actual {}  ratio {:.2}×",
        fmt_count(est.frontier_nodes),
        fmt_count(synth.num_nodes as u64),
        synth.num_nodes as f64 / est.frontier_nodes.max(1) as f64,
    );
    println!(
        "  total edges:     est {}  actual {}  ratio {:.2}×",
        fmt_count(est.frontier_edges),
        fmt_count(synth.edges.len() as u64),
        synth.edges.len() as f64 / est.frontier_edges.max(1) as f64,
    );
    println!(
        "  CSR bytes:       est {}  actual {}",
        fmt_bytes(est.csr_memory_bytes),
        fmt_bytes(dual.memory_bytes() as u64),
    );
    // NodeIndex isn't materialised in this scenario (the bench BFS runs
    // on u32 directly), so we only print the analytical projection here.
    println!(
        "  NodeIndex bytes: est {} (analytical — not materialised in this bench)",
        fmt_bytes(est.nodeindex_bytes),
    );
    println!(
        "  Rebuild peak:    est {} (production rebuild — uuid_edges + dense_edges + dual graphs)",
        fmt_bytes(est.peak_rebuild_bytes),
    );

    report_degree_distribution(&dual);
    report_variance_multiplier(&dual);
    report_effective_branching(&dual);

    // Rebuild-peak probe: hold production-shape NodeIndex allocations
    // (old sorted-Vec + new HashMap mid-build) and a stand-in for the
    // old DualCsrGraph alive across the BFS measurement loop. Without
    // this the bench's RSS undercounts production rebuild peak by 2–3×
    // (bench BFS runs on u32 directly and never builds a NodeIndex,
    // and only one DualCsrGraph is alive at a time).
    let probe = if rebuild_peak_probe {
        let bytes = rebuild_peak_probe_bytes(synth.num_nodes, dual.memory_bytes() as u64);
        println!(
            "\nRebuild-peak probe: allocating {} (old CSR stand-in + sorted-Vec NodeIndex + HashMap NodeIndex mid-build)",
            fmt_bytes(bytes)
        );
        Some(allocate_rebuild_peak_probe(
            synth.num_nodes,
            dual.memory_bytes() as u64,
        ))
    } else {
        println!(
            "\nRebuild-peak probe: DISABLED (--no-rebuild-peak). RSS reflects bench process only, not production rebuild peak."
        );
        None
    };

    run_bfs_timings(&synth, &dual, &distrust_sets);

    if let Some(peak) = peak_rss_kb() {
        println!("\nPeak RSS: {}", fmt_memory(peak));
    }
    // Keep the probe alive through peak RSS read above. Explicit drop
    // here both documents intent and silences "unused" warnings.
    drop(probe);
}

/// Scaling-sweep mode: run the federated benchmark across a range of
/// `local_users` values and emit a one-row-per-config table. Directly
/// answers the admin question "what userbase size fits this hardware /
/// stays under this latency SLO?"
///
/// Each row reports actual measured frontier, RSS delta, and BFS p99.
/// Generation per row is independent (fresh CSR, fresh RNG seed) so the
/// rows can't poison each other's allocator behaviour.
fn run_federated_power_law_sweep(env: &FederationEnvironment, sizes: &[u32]) {
    println!("\n{}", "=".repeat(60));
    println!("  Federated Power-Law Scaling Sweep");
    println!("{}", "=".repeat(60));
    println!(
        "  federation: {} instances × {} mean users ≈ {} conceptual users",
        env.num_remote_instances,
        env.mean_remote_instance_size,
        fmt_count(env.num_remote_instances as u64 * env.mean_remote_instance_size as u64),
    );
    println!("  shape: PowerLawConfig::medium_instance(), local_preference=0.5");

    // Memory columns:
    //
    // - CSR: forward + reverse compressed sparse row, measured.
    // - NIdx: production-shape `sorted Vec<(Uuid, u32)> + Vec<Uuid>`,
    //   analytical (this bench's BFS runs on u32 directly — the
    //   NodeIndex isn't materialised here). Sized at 40 B/entry.
    // - Peak: rebuild peak — `2 × CSR + NIdx + NIdx_build_HashMap + 40 B/edge`.
    //   The OLD graph stays resident while the NEW one is built (via a
    //   transient HashMap that's frozen to the sorted-Vec shape at the
    //   end). This is the binding constraint for sizing — steady-state
    //   (CSR + NIdx) underbudgets by 2–3×.
    println!();
    println!(
        "  {:>12}  {:>12}  {:>8}  {:>9}  {:>9}  {:>9}  {:>10}  {:>10}",
        "local_users", "frontier", "×local", "CSR", "NIdx", "Peak", "fwd_p99", "dual_p99",
    );
    println!("  {}", "─".repeat(95));

    for &n in sizes {
        let home = HomeInstanceConfig {
            local_users: n,
            shape: PowerLawConfig::medium_instance(),
            local_preference: 0.5,
            inbound_factor: 0.0,
        };
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let synth = generate_federated_power_law_graph(&home, env, &mut rng);
        let dual = DualCsrGraph::from_edges(synth.num_nodes, &synth.edges);
        let distrust_sets = build_distrust_sets(&synth.distrust_edges);

        let sample_sources = pick_sample_sources(&synth.local_range, 50);
        let _ = forward_bfs(sample_sources[0], &dual.forward, &distrust_sets);

        let mut fwd_times: Vec<f64> = Vec::with_capacity(sample_sources.len());
        let mut dual_times: Vec<f64> = Vec::with_capacity(sample_sources.len());
        for &src in &sample_sources {
            let t = Instant::now();
            let _ = forward_bfs(src, &dual.forward, &distrust_sets);
            fwd_times.push(t.elapsed().as_secs_f64() * 1000.0);

            let t = Instant::now();
            let _ = forward_bfs(src, &dual.forward, &distrust_sets);
            let _ = reverse_bfs(src, &dual.reverse);
            dual_times.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        fwd_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        dual_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p99 = |v: &[f64]| v[(v.len() as f64 * 0.99) as usize];

        // NodeIndex (sorted-Vec, production shape) projected from
        // frontier_nodes; analytical because this bench's BFS runs on
        // u32 directly and doesn't materialise the index. See
        // `estimate_frontier` for the per-entry constants.
        let nidx_bytes = synth.num_nodes as u64 * 40; // NODEINDEX_BYTES_PER_NODE
        let csr_bytes = dual.memory_bytes() as u64;
        // Rebuild peak: old graph stays resident while new one is built.
        // The new NodeIndex is built via a transient HashMap (~76 B/entry)
        // and frozen to the sorted-Vec shape at the end; the intermediate
        // `dense_edges` Vec (8 B/edge) also briefly co-exists. Matches
        // the closed-form `peak_rebuild_bytes` in `estimate_frontier`.
        let nidx_build_bytes = synth.num_nodes as u64 * 76;
        let peak_bytes =
            2 * csr_bytes + nidx_bytes + nidx_build_bytes + 8 * synth.edges.len() as u64;
        println!(
            "  {:>12}  {:>12}  {:>7.1}×  {:>9}  {:>9}  {:>9}  {:>8.2}ms  {:>8.2}ms",
            fmt_count(n as u64),
            fmt_count(synth.num_nodes as u64),
            synth.num_nodes as f64 / n.max(1) as f64,
            fmt_memory(csr_bytes / 1024),
            fmt_memory(nidx_bytes / 1024),
            fmt_memory(peak_bytes / 1024),
            p99(&fwd_times),
            p99(&dual_times),
        );
    }
    println!(
        "\n  Note: Peak is the binding sizing constraint — during snapshot\n  rebuild the old graph keeps serving reads while the new one is built\n  (≈ 2 × CSR + NIdx + NIdx_build_HashMap + 8 B/edge dense_edges).\n  Steady-state CSR + NIdx underbudgets by 2–3×. See\n  `docs/rebuild_peak_memory.md`."
    );
}

/// Bench mode: A/B BFS perf on a heap `CsrGraph` vs an `MmapCsrGraph` backed by a tmpfs file.
fn run_mmap_bench(
    home: &HomeInstanceConfig,
    env: &FederationEnvironment,
    rebuild_peak_probe: bool,
) {
    use std::time::Instant;

    use mmap_csr::{MmapCsrGraph, serialize_csr_to_file};

    println!("\n{}", "=".repeat(60));
    println!("  Mmap CSR Bench (Option C prototype)");
    println!("{}", "=".repeat(60));
    println!(
        "  home: {} local users, local_preference={}",
        fmt_count(home.local_users as u64),
        home.local_preference
    );
    println!(
        "  federation: {} instances × {} mean users ≈ {} conceptual users",
        env.num_remote_instances,
        env.mean_remote_instance_size,
        fmt_count(env.num_remote_instances as u64 * env.mean_remote_instance_size as u64),
    );

    // --- [1] Generate ---
    let rss_start = current_rss_kb().unwrap_or(0);
    print!("\n  [1] Generating graph... ");
    let t = Instant::now();
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let synth = generate_federated_power_law_graph(home, env, &mut rng);
    println!(
        "{:.1}s  nodes={}  edges={}",
        t.elapsed().as_secs_f64(),
        fmt_count(synth.num_nodes as u64),
        fmt_count(synth.edges.len() as u64),
    );

    // --- [2] Heap dual CSR ---
    print!("  [2] Building heap dual CSR... ");
    let t = Instant::now();
    let dual = DualCsrGraph::from_edges(synth.num_nodes, &synth.edges);
    let distrust_sets = build_distrust_sets(&synth.distrust_edges);
    let csr_bytes = dual.memory_bytes() as u64;
    let rss_heap = current_rss_kb().unwrap_or(0);
    println!(
        "{:.1}s  CSR={}  RSS {}→{} (+{})",
        t.elapsed().as_secs_f64(),
        fmt_memory(csr_bytes / 1024),
        fmt_memory(rss_start),
        fmt_memory(rss_heap),
        fmt_memory(rss_heap.saturating_sub(rss_start)),
    );

    // --- [2b] Rebuild-peak probe ---
    // Hold production-shape NodeIndex allocations + an old-CSR
    // stand-in alive through all subsequent measurements so the
    // mmap-vs-heap RSS comparison reflects realistic process state.
    // See `RebuildPeakProbe` for shape rationale.
    let _probe = if rebuild_peak_probe {
        let bytes = rebuild_peak_probe_bytes(synth.num_nodes, csr_bytes);
        println!(
            "  [2b] Rebuild-peak probe: allocating {} (old CSR stand-in + sorted-Vec NodeIndex + HashMap NodeIndex mid-build)",
            fmt_bytes(bytes)
        );
        Some(allocate_rebuild_peak_probe(synth.num_nodes, csr_bytes))
    } else {
        println!(
            "  [2b] Rebuild-peak probe: DISABLED (--no-rebuild-peak). RSS reflects bench process only."
        );
        None
    };

    // --- [3] Serialise to tmpfs ---
    // /dev/shm is tmpfs on Linux — backing store is RAM, page-cache-able,
    // and we don't pay any actual disk I/O. Matches the production
    // deployment model the doc suggests for Option C.
    let tmp_dir = std::env::temp_dir().join("prismoire-bench-mmap-csr");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).expect("mkdir tmp_dir");
    let fwd_path = tmp_dir.join("forward.csr");
    let rev_path = tmp_dir.join("reverse.csr");
    print!("  [3] Writing CSR files to {}... ", tmp_dir.display());
    let t = Instant::now();
    serialize_csr_to_file(&dual.forward, &fwd_path).expect("write forward csr");
    serialize_csr_to_file(&dual.reverse, &rev_path).expect("write reverse csr");
    let fwd_size = std::fs::metadata(&fwd_path).map(|m| m.len()).unwrap_or(0);
    let rev_size = std::fs::metadata(&rev_path).map(|m| m.len()).unwrap_or(0);
    println!(
        "{:.1}s  forward={}  reverse={}",
        t.elapsed().as_secs_f64(),
        fmt_memory(fwd_size / 1024),
        fmt_memory(rev_size / 1024),
    );

    // --- [4] Mmap back ---
    print!("  [4] Mmapping back... ");
    let t = Instant::now();
    let mmap_forward = MmapCsrGraph::open(&fwd_path).expect("open forward mmap");
    let mmap_reverse = MmapCsrGraph::open(&rev_path).expect("open reverse mmap");
    let rss_after_mmap = current_rss_kb().unwrap_or(0);
    println!(
        "{:.1}s  mapped={}  RSS now {} (+{} vs heap-only — mmap pages not yet touched)",
        t.elapsed().as_secs_f64(),
        fmt_memory((mmap_forward.mapped_bytes() + mmap_reverse.mapped_bytes()) as u64 / 1024),
        fmt_memory(rss_after_mmap),
        fmt_memory(rss_after_mmap.saturating_sub(rss_heap)),
    );

    // --- [5] Pick sample sources up front (same set for all phases) ---
    let sample_sources = pick_sample_sources(&synth.local_range, 100);

    // --- Correctness check: heap and mmap must produce identical BFS results
    // on the same source. Catches any silent corruption in the serialise →
    // mmap → slice path (wrong endianness, off-by-one, misaligned cast).
    let heap_sample = forward_bfs(sample_sources[0], &dual.forward, &distrust_sets);
    let mmap_sample = forward_bfs(sample_sources[0], &mmap_forward, &distrust_sets);
    {
        let mut h: Vec<(u32, f64)> = heap_sample.clone();
        let mut m: Vec<(u32, f64)> = mmap_sample.clone();
        h.sort_by_key(|&(n, _)| n);
        m.sort_by_key(|&(n, _)| n);
        assert_eq!(h.len(), m.len(), "heap/mmap BFS result size mismatch");
        for (a, b) in h.iter().zip(m.iter()) {
            assert_eq!(a.0, b.0, "heap/mmap node mismatch");
            assert!(
                (a.1 - b.1).abs() < 1e-9,
                "heap/mmap score mismatch at {}: {} vs {}",
                a.0,
                a.1,
                b.1
            );
        }
        println!(
            "  [5] Correctness: heap == mmap on {} reachable targets",
            fmt_count(h.len() as u64)
        );
    }

    // --- [6] Warm A/B: heap CSR vs mmap CSR (cache hot from build/serialize) ---
    // The warm case is the steady-state question: once pages are in the
    // cache, does mmap'd access match heap-resident access? Run one
    // warm-up iteration on each to fault any not-yet-touched pages
    // (heap was just built, mmap was just serialized — both should
    // already be hot, but the warm-up makes the comparison fair).
    let _ = forward_bfs(sample_sources[0], &dual.forward, &distrust_sets);
    let _ = forward_bfs(sample_sources[0], &mmap_forward, &distrust_sets);

    let mut heap_times: Vec<f64> = Vec::with_capacity(sample_sources.len());
    let mut mmap_warm_times: Vec<f64> = Vec::with_capacity(sample_sources.len());
    for &src in &sample_sources {
        let t = Instant::now();
        let _ = forward_bfs(src, &dual.forward, &distrust_sets);
        heap_times.push(t.elapsed().as_secs_f64() * 1000.0);

        let t = Instant::now();
        let _ = forward_bfs(src, &mmap_forward, &distrust_sets);
        mmap_warm_times.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    heap_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    mmap_warm_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |v: &[f64], q: f64| v[((v.len() as f64 - 1.0) * q) as usize];
    println!(
        "\n  [6] Warm forward BFS A/B ({} samples):",
        sample_sources.len()
    );
    println!(
        "      heap CSR  p50={:>6.3}ms  p90={:>6.3}ms  p99={:>6.3}ms",
        p(&heap_times, 0.50),
        p(&heap_times, 0.90),
        p(&heap_times, 0.99),
    );
    println!(
        "      mmap CSR  p50={:>6.3}ms  p90={:>6.3}ms  p99={:>6.3}ms  ({:>4.2}× / {:>4.2}× / {:>4.2}× vs heap)",
        p(&mmap_warm_times, 0.50),
        p(&mmap_warm_times, 0.90),
        p(&mmap_warm_times, 0.99),
        p(&mmap_warm_times, 0.50) / p(&heap_times, 0.50).max(1e-9),
        p(&mmap_warm_times, 0.90) / p(&heap_times, 0.90).max(1e-9),
        p(&mmap_warm_times, 0.99) / p(&heap_times, 0.99).max(1e-9),
    );

    // --- [7] Process-page-table eviction (TLB-cold, not cache-cold) ---
    //
    // `madvise(MADV_DONTNEED)` on a *shared file mapping* on Linux only
    // discards the process's page-table entries — the underlying file
    // pages stay in the OS page cache. The next access doesn't touch
    // disk; it just re-maps. So this measures *TLB / page-table*
    // warm-up cost, not the I/O cost of true cold start.
    //
    // For a real cold-start measurement on a disk-backed filesystem you
    // need `posix_fadvise(POSIX_FADV_DONTNEED)` on the fd to drop the
    // file from the page cache — but on tmpfs (the deployment model
    // the doc suggests) even that's a no-op, because tmpfs *is* the
    // page cache. Net: on tmpfs there is no cold-start penalty to
    // measure. The numbers below show the per-access overhead of
    // re-establishing process-side page-table entries only.
    print!("  [7] madvise(MADV_DONTNEED) on both mappings... ");
    mmap_forward
        .madvise_dontneed()
        .expect("madvise forward mmap");
    mmap_reverse
        .madvise_dontneed()
        .expect("madvise reverse mmap");
    let rss_after_madv = current_rss_kb().unwrap_or(0);
    println!(
        "RSS now {} ({:+} vs warm; tmpfs pages stay in page cache)",
        fmt_memory(rss_after_madv),
        rss_after_madv as i64 - rss_after_mmap as i64,
    );

    let mut mmap_unmapped_times: Vec<f64> = Vec::with_capacity(sample_sources.len());
    for &src in &sample_sources {
        let t = Instant::now();
        let _ = forward_bfs(src, &mmap_forward, &distrust_sets);
        mmap_unmapped_times.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    mmap_unmapped_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "  [8] Unmapped mmap forward BFS ({} samples — page-table rebuild only, no I/O):",
        sample_sources.len()
    );
    println!(
        "      mmap CSR  p50={:>6.3}ms  p90={:>6.3}ms  p99={:>6.3}ms  ({:>4.2}× / {:>4.2}× / {:>4.2}× vs warm mmap)",
        p(&mmap_unmapped_times, 0.50),
        p(&mmap_unmapped_times, 0.90),
        p(&mmap_unmapped_times, 0.99),
        p(&mmap_unmapped_times, 0.50) / p(&mmap_warm_times, 0.50).max(1e-9),
        p(&mmap_unmapped_times, 0.90) / p(&mmap_warm_times, 0.90).max(1e-9),
        p(&mmap_unmapped_times, 0.99) / p(&mmap_warm_times, 0.99).max(1e-9),
    );

    // --- [9] Cleanup ---
    drop(mmap_forward);
    drop(mmap_reverse);
    let _ = std::fs::remove_dir_all(&tmp_dir);

    println!(
        "\n  Read:\n  - Warm mmap ([6]) should match heap closely (same memory accesses,\n    same hot cache lines). A material gap here means the mmap\n    indirection has an inherent per-access cost.\n  - Unmapped mmap ([8]) measures process-page-table rebuild cost\n    only — on tmpfs there is no \"real\" cold start to measure\n    (tmpfs is the page cache).\n  - The Option C *RSS win* (cold pages eligible for eviction under\n    memory pressure) is not exercised by this bench, which runs alone\n    on the host with plenty of memory. The RSS line at [4] confirms\n    only that the mapping itself doesn't pre-fault."
    );
}

/// Sizing helper: pure analytical inversion of [`estimate_frontier`] to
/// find the largest `local_users` whose projected *rebuild peak* memory
/// fits the admin's budget. No generation — answers "can I host N users
/// on H hardware?" in milliseconds.
///
/// The budget is compared against rebuild peak (not steady-state)
/// because that's the binding constraint: during snapshot rebuild the
/// old graph keeps serving reads while the new one is built, so peak
/// runs 2–3× steady-state. Sizing against steady-state OOMs on the
/// first rebuild.
fn run_sizing_helper(max_memory_bytes: u64, env: &FederationEnvironment) {
    println!("\n{}", "=".repeat(60));
    println!("  Federated Power-Law Sizing Helper");
    println!("{}", "=".repeat(60));
    println!(
        "  target memory budget: {} (rebuild peak)",
        fmt_bytes(max_memory_bytes)
    );
    println!(
        "  federation: {} instances × {} mean users ≈ {} conceptual users",
        env.num_remote_instances,
        env.mean_remote_instance_size,
        fmt_count(env.num_remote_instances as u64 * env.mean_remote_instance_size as u64),
    );

    // Binary search on local_users — estimator is monotone-increasing in
    // local_users at fixed env, so this is well-defined.
    let probe = |n: u32| -> u64 {
        let home = HomeInstanceConfig {
            local_users: n,
            shape: PowerLawConfig::medium_instance(),
            local_preference: 0.5,
            inbound_factor: 0.0,
        };
        let est = estimate_frontier(&home, env);
        est.peak_rebuild_bytes
    };
    if probe(1_000) > max_memory_bytes {
        println!(
            "\n  Even 1K local users projects above budget ({} peak). \
             Reduce local_preference, simplify federation, or increase budget.",
            fmt_bytes(probe(1_000))
        );
        return;
    }
    let mut lo = 1_000u32;
    let mut hi = 10_000_000u32;
    while hi - lo > 1_000 {
        let mid = lo + (hi - lo) / 2;
        if probe(mid) > max_memory_bytes {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    let est = estimate_frontier(
        &HomeInstanceConfig {
            local_users: lo,
            shape: PowerLawConfig::medium_instance(),
            local_preference: 0.5,
            inbound_factor: 0.0,
        },
        env,
    );
    let steady = est.csr_memory_bytes + est.nodeindex_bytes;
    println!(
        "\n  Largest local_users fitting budget: ~{}",
        fmt_count(lo as u64)
    );
    println!(
        "  Projected frontier:   {} nodes ({:.1}× local)",
        fmt_count(est.frontier_nodes),
        est.frontier_nodes as f64 / lo.max(1) as f64,
    );
    println!(
        "  Projected CSR memory: {}",
        fmt_bytes(est.csr_memory_bytes),
    );
    println!("  Projected NodeIndex:  {}", fmt_bytes(est.nodeindex_bytes),);
    println!("  Steady-state total:   {}", fmt_bytes(steady),);
    println!(
        "  Rebuild peak:         {}   (budget {})",
        fmt_bytes(est.peak_rebuild_bytes),
        fmt_bytes(max_memory_bytes),
    );
    println!(
        "  Note: estimator is approximate (~30–50% error on frontier).\n  Run `bench fed-power-law --local-users {}` to measure for real.",
        lo
    );
}

// ---------------------------------------------------------------------------
// Reverse-frontier (inbound visibility) measurement
// ---------------------------------------------------------------------------

/// Visibility threshold — a post by author A is visible to reader R iff
/// trust(A, R) ≥ this (matches `MINIMUM_TRUST_THRESHOLD` in server/src/trust.rs).
const VISIBILITY_THRESHOLD: f64 = 0.45;

/// Visibility cap (proposed model): a reader's visible set is the authors who
/// trust them (reverse frontier ≥ threshold), capped at this many, ranked by
/// how much the reader trusts each author (forward score) descending, with
/// oldest-account-first (lower node id) as the tiebreak for the long tail that
/// shares forward score 0.0. For "normal" users the reverse set is far below
/// the cap so it is a no-op; it only bites the celebrities (high inbound),
/// bounding their visible set — and the per-author downstream work (fetch,
/// rank, render) — to a predictable N.
///
/// Under the root-advertisement model (docs/federation-root-advertisement.md
/// §6.2) the cap is not just an output filter but a **frontier-admission /
/// retention rule**: the home instance stores at most N inbound trusters per
/// local reader, evicting by the ranking. So the cap also bounds the *stored*
/// reverse frontier — the CSR + stub footprint the reverse BFS works over.
/// `measure_capped_union` / `induced_footprint` below model that stored
/// footprint (capped-induced subgraph) against the uncapped baseline.
const VISIBILITY_CAP: usize = 100_000;

/// Estimated bytes per retained remote frontier user ("stub"). Models the
/// lean `frontier_users` row of docs/federation-root-advertisement.md §8.1 /
/// §11.1: a 32-byte content public key + 32-byte home-instance key + a dense
/// u32 id and small per-row overhead ≈ 80 bytes. A full `users` row would be
/// several times larger — which is exactly why §11.1 flags a lighter stub
/// table as an open question. Stub bytes are reported separately from CSR
/// bytes so the two footprint drivers stay legible.
const STUB_ROW_BYTES: u64 = 80;

/// Stored BFS working-set footprint: the dual CSR (forward + reverse edge
/// arrays the reverse BFS traverses) plus the per-node stub rows. This is the
/// "memory taken by BFS in practice" the sizing question asks about.
struct StoredFootprint {
    /// Materialised graph nodes (local users + retained remote stubs).
    nodes: u64,
    /// Trust edges retained in the store (both endpoints materialised).
    edges: u64,
    /// Dual CSR bytes (forward + reverse offsets/targets arrays).
    csr_bytes: u64,
    /// Estimated stub-row bytes = `nodes × STUB_ROW_BYTES`.
    stub_bytes: u64,
}

impl StoredFootprint {
    fn total_bytes(&self) -> u64 {
        self.csr_bytes + self.stub_bytes
    }
}

/// Build the stored footprint of the cap-retained subgraph: the node-induced
/// subgraph on `retained` (a per-node keep bitset), compacted to dense ids and
/// rebuilt as a dual CSR. Models what the home instance actually keeps after
/// cap-at-N admission (§6.2) — every edge whose *both* endpoints survived
/// admission. Compacting to dense ids matters: a sparse offsets array over the
/// full node space would over-count, so the retained nodes are renumbered
/// `0..kept` before the CSR is built.
fn induced_footprint(edges: &[(u32, u32)], retained: &[bool]) -> StoredFootprint {
    // Dense remap: retained original id → compact id.
    let mut remap = vec![u32::MAX; retained.len()];
    let mut kept = 0u32;
    for (id, &keep) in retained.iter().enumerate() {
        if keep {
            remap[id] = kept;
            kept += 1;
        }
    }
    // Induced edge list: keep edges with both endpoints retained.
    let mut induced: Vec<(u32, u32)> = Vec::new();
    for &(s, t) in edges {
        let (rs, rt) = (remap[s as usize], remap[t as usize]);
        if rs != u32::MAX && rt != u32::MAX {
            induced.push((rs, rt));
        }
    }
    let dual = DualCsrGraph::from_edges(kept, &induced);
    StoredFootprint {
        nodes: kept as u64,
        edges: induced.len() as u64,
        csr_bytes: dual.memory_bytes() as u64,
        stub_bytes: kept as u64 * STUB_ROW_BYTES,
    }
}

/// Count remote nodes reachable within `max_depth` hops from the entire
/// local set over `graph`, ignoring scores. This is the *structural*
/// frontier — the routing/fetch upper bound the doc's frontier tables use.
///
/// Run over the forward graph it measures the forward frontier (authors a
/// local user could rank as relevant, the current federation `content_filter`
/// basis); run over the reverse graph it measures the reverse frontier
/// (authors whose posts are *visible* to local users — the inbound-trust
/// basis the visibility model actually gates on). "Remote" = node index
/// ≥ `local_end`; seed (local) nodes are not counted.
fn structural_frontier_remote<G: CsrAccess>(graph: &G, local_end: u32, max_depth: u32) -> u64 {
    let n = graph.num_nodes() as usize;
    let mut visited = vec![false; n];
    let mut queue: VecDeque<(u32, u32)> = VecDeque::new();
    for s in 0..local_end {
        visited[s as usize] = true;
        queue.push_back((s, 0));
    }
    let mut remote = 0u64;
    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        for &next in graph.neighbors(node) {
            if !visited[next as usize] {
                visited[next as usize] = true;
                if next >= local_end {
                    remote += 1;
                }
                queue.push_back((next, depth + 1));
            }
        }
    }
    remote
}

/// The top-`k` local nodes by in-degree (forward in-degree = reverse
/// out-degree). These are the "celebrities" — local users with the largest
/// inbound trust, the worst case for a reverse-frontier traversal. Evenly-
/// spaced sampling misses them (in-degree rank is shuffled vs node id), so
/// the reverse-frontier sample unions them in explicitly.
fn top_local_in_degree(dual: &DualCsrGraph, local_end: u32, k: usize) -> Vec<u32> {
    let mut v: Vec<(u32, u32)> = (0..local_end)
        .map(|node| (node, dual.reverse.neighbors(node).len() as u32))
        .collect();
    v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    v.into_iter().take(k).map(|(node, _)| node).collect()
}

/// Per-source reverse-frontier statistics at the visibility threshold.
struct ReverseFrontierStats {
    /// Structural forward frontier (remote nodes reachable in ≤3 forward hops
    /// from the local set). The current `content_filter` basis.
    fwd_remote: u64,
    /// Structural reverse frontier (remote nodes reachable in ≤3 reverse hops
    /// from the local set). The inbound-trust / visibility basis.
    rev_remote: u64,
    /// Largest local in-degree (the biggest celebrity).
    top_local_indeg: u32,
    /// Per-source reverse-reachable remote authors at ≥ threshold.
    reach_median: usize,
    reach_p99: usize,
    reach_max: usize,
    /// Worst-case reach after applying the visibility cap = min(cap, reach_max).
    /// This is the per-reader visible-set bound the proposed model guarantees.
    reach_capped_max: usize,
    /// How many sampled readers exceed the cap (the celebrities the cap bites).
    sample_over_cap: usize,
    /// Largest hop-1 *remote* in-degree across the sample (direct remote
    /// trusters of a single local user — the full-strength part of the frontier).
    direct_remote_max: usize,
    /// reverse_bfs latency over the sample.
    rev_p50_ms: f64,
    rev_p99_ms: f64,
    rev_max_ms: f64,
}

/// Measure the reverse frontier: structural size both directions, plus a
/// per-source reverse-BFS sweep (latency, direct-inbound) over
/// `sample_sources`. Counts only *remote* reachable authors ≥ threshold,
/// since those are the cross-instance content a reverse frontier would fetch.
fn measure_reverse_frontier(
    dual: &DualCsrGraph,
    local_end: u32,
    sample_sources: &[u32],
    cap: usize,
) -> ReverseFrontierStats {
    let fwd_remote = structural_frontier_remote(&dual.forward, local_end, MAX_DEPTH);
    let rev_remote = structural_frontier_remote(&dual.reverse, local_end, MAX_DEPTH);
    let top_local_indeg = (0..local_end)
        .map(|node| dual.reverse.neighbors(node).len() as u32)
        .max()
        .unwrap_or(0);

    let count_remote_visible = |v: &[(u32, f64)]| -> usize {
        v.iter()
            .filter(|&&(node, score)| score >= VISIBILITY_THRESHOLD && node >= local_end)
            .count()
    };

    let mut reach: Vec<usize> = Vec::with_capacity(sample_sources.len());
    let mut direct_remote: Vec<usize> = Vec::with_capacity(sample_sources.len());
    let mut times: Vec<f64> = Vec::with_capacity(sample_sources.len());

    // Warm-up to fault caches before timing.
    let _ = reverse_bfs(sample_sources[0], &dual.reverse);

    for &src in sample_sources {
        let t = Instant::now();
        let visible = reverse_bfs(src, &dual.reverse);
        times.push(t.elapsed().as_secs_f64() * 1000.0);

        reach.push(count_remote_visible(&visible));
        direct_remote.push(
            dual.reverse
                .neighbors(src)
                .iter()
                .filter(|&&x| x >= local_end)
                .count(),
        );
    }

    reach.sort_unstable();
    direct_remote.sort_unstable();
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let n = reach.len();
    let p = |v: &[f64], q: f64| v[((v.len() as f64 - 1.0) * q) as usize];

    let reach_max = *reach.last().unwrap();
    let sample_over_cap = reach.iter().filter(|&&r| r > cap).count();

    ReverseFrontierStats {
        fwd_remote,
        rev_remote,
        top_local_indeg,
        reach_median: reach[n / 2],
        reach_p99: reach[(n as f64 * 0.99) as usize % n],
        reach_max,
        reach_capped_max: reach_max.min(cap),
        sample_over_cap,
        direct_remote_max: *direct_remote.last().unwrap(),
        rev_p50_ms: p(&times, 0.50),
        rev_p99_ms: p(&times, 0.99),
        rev_max_ms: *times.last().unwrap(),
    }
}

/// Build the reverse-frontier sample: evenly-spaced local sources unioned
/// with the top-`top_k` celebrities so the worst case is always covered.
fn reverse_frontier_sample(
    dual: &DualCsrGraph,
    local_end: u32,
    spaced: usize,
    top_k: usize,
) -> Vec<u32> {
    let mut set: HashSet<u32> = pick_sample_sources(&(0..local_end), spaced)
        .into_iter()
        .collect();
    for n in top_local_in_degree(dual, local_end, top_k) {
        set.insert(n);
    }
    set.into_iter().collect()
}

/// Detailed single-config reverse-frontier benchmark. Generates a graph with
/// inbound bridges, then contrasts the forward (relevance / current
/// `content_filter`) frontier with the reverse (visibility) frontier the
/// system actually gates reads on.
fn run_reverse_frontier_bench(
    home: &HomeInstanceConfig,
    env: &FederationEnvironment,
    cap: usize,
    run_union: bool,
) {
    println!("\n{}", "=".repeat(60));
    println!("  Reverse-Frontier (inbound visibility) Bench");
    println!("{}", "=".repeat(60));
    println!(
        "  home: {} local users, local_preference={}, inbound_factor={}",
        fmt_count(home.local_users as u64),
        home.local_preference,
        home.inbound_factor,
    );
    println!("  visibility cap N = {}", fmt_count(cap as u64));
    println!(
        "  federation: {} instances × {} mean users ≈ {} conceptual users",
        env.num_remote_instances,
        env.mean_remote_instance_size,
        fmt_count(env.num_remote_instances as u64 * env.mean_remote_instance_size as u64),
    );

    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let t0 = Instant::now();
    let synth = generate_federated_power_law_graph(home, env, &mut rng);
    println!(
        "\nGraph generation: {:.1}s  nodes={}  edges={}",
        t0.elapsed().as_secs_f64(),
        fmt_count(synth.num_nodes as u64),
        fmt_count(synth.edges.len() as u64),
    );

    let dual = DualCsrGraph::from_edges(synth.num_nodes, &synth.edges);
    let local_end = synth.local_range.end;

    report_degree_distribution(&dual);

    let sample = reverse_frontier_sample(&dual, local_end, 100, 25);
    let stats = measure_reverse_frontier(&dual, local_end, &sample, cap);

    println!("\nStructural frontier (remote nodes within 3 hops of the local set):");
    println!(
        "  forward (relevance / current content_filter): {}",
        fmt_count(stats.fwd_remote)
    );
    println!(
        "  reverse (visibility / inbound-trust frontier): {}  ({:.2}× forward)",
        fmt_count(stats.rev_remote),
        stats.rev_remote as f64 / stats.fwd_remote.max(1) as f64,
    );
    println!(
        "  largest local in-degree (celebrity): {}",
        fmt_count(stats.top_local_indeg as u64)
    );

    println!(
        "\nPer-source reverse BFS at visibility threshold {VISIBILITY_THRESHOLD} ({} sampled local readers, incl. top-25 celebrities):",
        sample.len()
    );
    println!(
        "  remote authors visible:  median={}  p99={}  max={}",
        fmt_count(stats.reach_median as u64),
        fmt_count(stats.reach_p99 as u64),
        fmt_count(stats.reach_max as u64),
    );
    println!(
        "  visible set CAPPED at N={}: worst-case max={}  ({} of {} sampled readers clamped)",
        fmt_count(cap as u64),
        fmt_count(stats.reach_capped_max as u64),
        stats.sample_over_cap,
        sample.len(),
    );
    println!(
        "  largest hop-1 direct remote in-degree:  {} (direct trust is always full strength)",
        fmt_count(stats.direct_remote_max as u64),
    );
    println!(
        "  reverse BFS latency: p50={:.3}ms  p99={:.3}ms  max={:.3}ms",
        stats.rev_p50_ms, stats.rev_p99_ms, stats.rev_max_ms,
    );

    println!(
        "\n  Read: the reverse frontier is the set the visibility model actually\n  gates on (author-trusts-reader). Direct inbound trust (hop 1) is\n  full-strength by design — so a local celebrity's direct remote trusters\n  set a floor the frontier cannot fall below, while deeper transitive\n  trust decays multiplicatively with each hop."
    );

    if run_union {
        let distrust_sets = build_distrust_sets(&synth.distrust_edges);
        println!(
            "\nFederation union frontier (distinct remote authors visible across ALL {} local readers):",
            fmt_count(local_end as u64)
        );
        println!("  (full per-reader pass — this is O(local × BFS), give it a moment)");
        let t = Instant::now();
        let u = measure_capped_union(&dual, &synth.edges, local_end, &distrust_sets, cap);
        println!(
            "  uncapped union: {}   capped union (N={}): {}   ({:.1}% smaller)",
            fmt_count(u.uncapped_union_remote),
            fmt_count(cap as u64),
            fmt_count(u.capped_union_remote),
            100.0
                * (u.uncapped_union_remote
                    .saturating_sub(u.capped_union_remote)) as f64
                / u.uncapped_union_remote.max(1) as f64,
        );
        println!(
            "  readers over cap: {} of {}   (the cap only bites these celebrities)",
            fmt_count(u.readers_over_cap),
            fmt_count(local_end as u64),
        );
        println!("  union pass: {:.1}s", t.elapsed().as_secs_f64());

        let uf = &u.uncapped_footprint;
        let cf = &u.capped_footprint;
        let pct = |num: u64, den: u64| 100.0 * num as f64 / den.max(1) as f64;
        println!(
            "\n  Stored BFS working-set footprint (what the home instance keeps + traverses):"
        );
        println!(
            "    uncapped (full frontier):  nodes={}  edges={}  CSR={}  stubs@{}B={}  total={}",
            fmt_count(uf.nodes),
            fmt_count(uf.edges),
            fmt_bytes(uf.csr_bytes),
            STUB_ROW_BYTES,
            fmt_bytes(uf.stub_bytes),
            fmt_bytes(uf.total_bytes()),
        );
        println!(
            "    capped (cap-at-N admit):   nodes={}  edges={}  CSR={}  stubs@{}B={}  total={}",
            fmt_count(cf.nodes),
            fmt_count(cf.edges),
            fmt_bytes(cf.csr_bytes),
            STUB_ROW_BYTES,
            fmt_bytes(cf.stub_bytes),
            fmt_bytes(cf.total_bytes()),
        );
        println!(
            "    cap retains {:.1}% of nodes, {:.1}% of edges, {:.1}% of total bytes",
            pct(cf.nodes, uf.nodes),
            pct(cf.edges, uf.edges),
            pct(cf.total_bytes(), uf.total_bytes()),
        );
        println!(
            "\n  Read: capping bounds each *reader's* visible set, but it barely\n  shrinks the federation's distinct-content set — popular remote authors\n  are visible to many readers, not only celebrities, so trimming a\n  celebrity's long tail rarely removes an author no one else can see. The\n  cap's win is per-reader predictability (bounded fetch/rank/render); the\n  stored-footprint rows above show how little it reclaims here, because\n  the surviving stubs are shared across readers. Stub bytes (not CSR)\n  dominate the store — matching §8.1 / §11.1's lighter-stub-table point."
        );
    }
}

/// Per-reader visible-set cap applied across the whole local population, to see
/// whether bounding each celebrity's view also shrinks the federation's
/// *distinct* remote-author set (the global fetch/storage frontier).
struct CappedUnionStats {
    /// Distinct remote authors visible to at least one local reader (≥ threshold),
    /// with no cap applied.
    uncapped_union_remote: u64,
    /// Same, but readers over the cap contribute only their top-N authors
    /// (ranked by forward trust desc, oldest-account-first tiebreak).
    capped_union_remote: u64,
    /// Local readers whose uncapped visible set exceeds the cap.
    readers_over_cap: u64,
    /// Stored footprint with NO admission cap: the full materialised reverse
    /// frontier (every node/edge A received).
    uncapped_footprint: StoredFootprint,
    /// Stored footprint after cap-at-N admission: the node-induced subgraph on
    /// (local users ∪ each reader's capped visible set).
    capped_footprint: StoredFootprint,
}

/// Walk every local reader's reverse frontier once, accumulating two bitsets
/// of remote authors: the uncapped union and the capped union. Under-cap
/// readers contribute their whole visible set to both; over-cap readers
/// contribute their whole set to the uncapped union but only their top-`cap`
/// (ranked by forward trust, oldest-account-first tiebreak) to the capped one.
/// Forward scores are only computed for the (rare) over-cap readers.
fn measure_capped_union(
    dual: &DualCsrGraph,
    edges: &[(u32, u32)],
    local_end: u32,
    distrust_sets: &DistrustSets,
    cap: usize,
) -> CappedUnionStats {
    let n = dual.forward.num_nodes() as usize;
    let mut uncapped = vec![false; n];
    let mut capped = vec![false; n];
    let mut readers_over_cap = 0u64;

    for r in 0..local_end {
        let mut visible: Vec<(u32, f64)> = reverse_bfs(r, &dual.reverse)
            .into_iter()
            .filter(|&(node, score)| score >= VISIBILITY_THRESHOLD && node >= local_end)
            .collect();

        for &(node, _) in &visible {
            uncapped[node as usize] = true;
        }

        if visible.len() > cap {
            readers_over_cap += 1;
            // Rank by how much the reader trusts each author (forward score),
            // descending; oldest-account-first (lower node id) breaks ties —
            // including the long tail that all share forward score 0.0.
            let fwd: HashMap<u32, f64> = forward_bfs(r, &dual.forward, distrust_sets)
                .into_iter()
                .collect();
            visible.sort_unstable_by(|a, b| {
                let sa = fwd.get(&a.0).copied().unwrap_or(0.0);
                let sb = fwd.get(&b.0).copied().unwrap_or(0.0);
                sb.partial_cmp(&sa).unwrap().then(a.0.cmp(&b.0))
            });
            for &(node, _) in visible.iter().take(cap) {
                capped[node as usize] = true;
            }
        } else {
            for &(node, _) in &visible {
                capped[node as usize] = true;
            }
        }
    }

    // Local users are always materialised; mark them retained in both stores
    // so the induced subgraphs keep the local edges and the hop-1 bridges.
    for b in uncapped.iter_mut().take(local_end as usize) {
        *b = true;
    }
    for b in capped.iter_mut().take(local_end as usize) {
        *b = true;
    }

    CappedUnionStats {
        uncapped_union_remote: uncapped[local_end as usize..]
            .iter()
            .filter(|&&b| b)
            .count() as u64,
        capped_union_remote: capped[local_end as usize..].iter().filter(|&&b| b).count() as u64,
        readers_over_cap,
        uncapped_footprint: induced_footprint(edges, &uncapped),
        capped_footprint: induced_footprint(edges, &capped),
    }
}

/// Reverse-frontier scaling sweep: one row per `local_users`, contrasting the
/// forward and reverse structural frontiers and the per-reader reverse cost.
/// This is the table that feeds `docs/federation-bfs-analysis.md`.
fn run_reverse_frontier_sweep(
    env: &FederationEnvironment,
    sizes: &[u32],
    inbound_factor: f64,
    mem_capped: bool,
    cap: usize,
) {
    println!("\n{}", "=".repeat(60));
    println!("  Reverse-Frontier Scaling Sweep");
    println!("{}", "=".repeat(60));
    println!(
        "  federation: {} instances × {} mean users ≈ {} conceptual users",
        env.num_remote_instances,
        env.mean_remote_instance_size,
        fmt_count(env.num_remote_instances as u64 * env.mean_remote_instance_size as u64),
    );
    println!(
        "  shape: PowerLawConfig::medium_instance(), local_preference=0.5, inbound_factor={inbound_factor}"
    );
    println!(
        "\n  fwd_front  = structural forward frontier (relevance, current content_filter)\n  rev_front  = structural reverse frontier (visibility, inbound-trust)\n  reach_max  = worst-case per-reader remote authors visible (≥{VISIBILITY_THRESHOLD}), UNCAPPED\n  reach_cap  = worst-case after the N={cap} visibility cap = min(N, reach_max)\n  celeb      = largest local in-degree",
    );
    println!();
    println!(
        "  {:>11}  {:>11}  {:>11}  {:>6}  {:>9}  {:>11}  {:>11}  {:>9}",
        "local", "fwd_front", "rev_front", "r/f", "celeb", "reach_max", "reach_cap", "rev_p99",
    );
    println!("  {}", "─".repeat(92));

    // Buffer per-size stored-footprint rows; print the memory table after the
    // frontier table so the two concerns stay legible.
    let mut mem_rows: Vec<(u32, StoredFootprint, Option<StoredFootprint>)> = Vec::new();

    for &n in sizes {
        let home = HomeInstanceConfig {
            local_users: n,
            shape: PowerLawConfig::medium_instance(),
            local_preference: 0.5,
            inbound_factor,
        };
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let synth = generate_federated_power_law_graph(&home, env, &mut rng);
        let dual = DualCsrGraph::from_edges(synth.num_nodes, &synth.edges);
        let local_end = synth.local_range.end;
        let sample = reverse_frontier_sample(&dual, local_end, 50, 20);
        let s = measure_reverse_frontier(&dual, local_end, &sample, cap);
        println!(
            "  {:>11}  {:>11}  {:>11}  {:>5.2}×  {:>9}  {:>11}  {:>11}  {:>7.2}ms",
            fmt_count(n as u64),
            fmt_count(s.fwd_remote),
            fmt_count(s.rev_remote),
            s.rev_remote as f64 / s.fwd_remote.max(1) as f64,
            fmt_count(s.top_local_indeg as u64),
            fmt_count(s.reach_max as u64),
            fmt_count(s.reach_capped_max as u64),
            s.rev_p99_ms,
        );

        // Uncapped stored footprint is free (the full graph is already built).
        let uncapped = StoredFootprint {
            nodes: synth.num_nodes as u64,
            edges: synth.edges.len() as u64,
            csr_bytes: dual.memory_bytes() as u64,
            stub_bytes: synth.num_nodes as u64 * STUB_ROW_BYTES,
        };
        // Capped footprint needs the O(local × BFS) admission pass — opt-in.
        let capped = if mem_capped {
            let distrust_sets = build_distrust_sets(&synth.distrust_edges);
            Some(
                measure_capped_union(&dual, &synth.edges, local_end, &distrust_sets, cap)
                    .capped_footprint,
            )
        } else {
            None
        };
        mem_rows.push((n, uncapped, capped));
    }
    println!(
        "\n  Note: rev_front follows INBOUND edges (uncapped in-degree), fwd_front\n  follows OUTBOUND edges (capped at 200/user). reach_cap flattens the\n  worst-case visible set to N; once reach_max clears N, every celebrity\n  pins to the same bound regardless of how much bigger the network grows."
    );

    // Stored BFS working-set memory across userbase sizes.
    println!("\n  Stored BFS working-set memory (dual CSR + stub rows @ {STUB_ROW_BYTES}B/node):");
    if mem_capped {
        println!(
            "  {:>11}  {:>11}  {:>9}  {:>10}  {:>10}  {:>11}  {:>10}",
            "local", "nodes", "CSR", "stubs", "uncapped", "capped", "cap/uncap",
        );
    } else {
        println!(
            "  {:>11}  {:>11}  {:>11}  {:>9}  {:>10}  {:>10}",
            "local", "nodes", "edges", "CSR", "stubs", "total",
        );
    }
    println!("  {}", "─".repeat(if mem_capped { 80 } else { 70 }));
    for (n, uf, cf) in &mem_rows {
        if let Some(cf) = cf {
            println!(
                "  {:>11}  {:>11}  {:>9}  {:>10}  {:>10}  {:>11}  {:>9.1}%",
                fmt_count(*n as u64),
                fmt_count(uf.nodes),
                fmt_bytes(uf.csr_bytes),
                fmt_bytes(uf.stub_bytes),
                fmt_bytes(uf.total_bytes()),
                fmt_bytes(cf.total_bytes()),
                100.0 * cf.total_bytes() as f64 / uf.total_bytes().max(1) as f64,
            );
        } else {
            println!(
                "  {:>11}  {:>11}  {:>11}  {:>9}  {:>10}  {:>10}",
                fmt_count(*n as u64),
                fmt_count(uf.nodes),
                fmt_count(uf.edges),
                fmt_bytes(uf.csr_bytes),
                fmt_bytes(uf.stub_bytes),
                fmt_bytes(uf.total_bytes()),
            );
        }
    }
    println!(
        "\n  Read: 'uncapped' = every node in the generated graph, no admission.\n  'capped' = cap-at-N admission (§6.2): store only the union of each\n  reader's reverse-reachable visible top-N. The reduction (capped ≈ 55–62%\n  of uncapped here) is mostly the REVERSE-REACHABILITY restriction — only\n  nodes within a local reader's 3-hop reverse cone are kept; the ≥threshold\n  test prunes little, since a single 3-hop path already scores 1·0.7·0.7 =\n  0.49 ≥ 0.45, so MAX_DEPTH=3 is the real horizon. The top-N cap itself\n  also trims little, since few readers exceed N. Stub rows, not CSR edges,\n  dominate the footprint ~3–4×, so the lighter frontier_users table\n  (§11.1) is a bigger memory lever than the cap (pass --capped to quantify)."
    );
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

    // Global opt-out for the rebuild-peak probe. Default ON: the probe
    // makes bench-process RSS match production rebuild-peak RSS, which
    // is what the sizing helper budgets against. Disable for the old
    // "bench process only" RSS profile.
    let rebuild_peak_probe = !args.iter().any(|a| a == "--no-rebuild-peak");

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
        "power-law" | "powerlaw" => {
            run_power_law_benchmark(
                "Power-Law Single Instance (50K users)",
                &PowerLawConfig::medium_instance(),
            );
        }
        "fed-power-law" | "federated-power-law" => {
            // Optional `--local-users N` override; default = medium (50K).
            let mut home = HomeInstanceConfig::medium();
            if let Some(pos) = args.iter().position(|a| a == "--local-users")
                && let Some(n) = args.get(pos + 1).and_then(|s| s.parse::<u32>().ok())
            {
                home.local_users = n;
            }
            let env = FederationEnvironment::realistic_10k();
            let name = format!(
                "Federated Power-Law ({}K local users, ~100M conceptual)",
                home.local_users / 1000
            );
            run_federated_power_law_benchmark(&name, &home, &env, rebuild_peak_probe);
        }
        "inbound" | "reverse-frontier" => {
            // Reverse/visibility frontier study. Models inbound cross-instance
            // trust (remote → local) so local celebrities emerge; contrasts
            // the forward (relevance) frontier with the reverse (visibility)
            // one. `--local-users N` and `--inbound-factor F` overrides.
            let mut home = HomeInstanceConfig::medium();
            home.inbound_factor = 1.0;
            if let Some(pos) = args.iter().position(|a| a == "--local-users")
                && let Some(n) = args.get(pos + 1).and_then(|s| s.parse::<u32>().ok())
            {
                home.local_users = n;
            }
            if let Some(pos) = args.iter().position(|a| a == "--inbound-factor")
                && let Some(f) = args.get(pos + 1).and_then(|s| s.parse::<f64>().ok())
            {
                home.inbound_factor = f;
            }
            let mut cap = VISIBILITY_CAP;
            if let Some(pos) = args.iter().position(|a| a == "--cap")
                && let Some(c) = args.get(pos + 1).and_then(|s| s.parse::<usize>().ok())
            {
                cap = c;
            }
            let run_union = args.iter().any(|a| a == "--union");
            let env = FederationEnvironment::realistic_10k();
            run_reverse_frontier_bench(&home, &env, cap, run_union);
        }
        "inbound-sweep" | "rev-sweep" => {
            let default_sizes: &[u32] = &[10_000, 50_000, 100_000, 250_000, 500_000];
            let mut inbound_factor = 1.0f64;
            if let Some(pos) = args.iter().position(|a| a == "--inbound-factor")
                && let Some(f) = args.get(pos + 1).and_then(|s| s.parse::<f64>().ok())
            {
                inbound_factor = f;
            }
            // Positional sizes, skipping any token that is the value of a
            // `--flag value` pair (e.g. `--cap 5000`) so it isn't mistaken
            // for a userbase size.
            let value_flags = ["--cap", "--inbound-factor"];
            let mut sizes: Vec<u32> = Vec::new();
            let mut skip_next = false;
            for a in args.iter().skip(2) {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                if value_flags.contains(&a.as_str()) {
                    skip_next = true;
                    continue;
                }
                if let Ok(n) = a.parse::<u32>() {
                    sizes.push(n);
                }
            }
            let sizes = if sizes.is_empty() {
                default_sizes.to_vec()
            } else {
                sizes
            };
            // `--capped` adds the (expensive) per-size cap-at-N admission pass
            // so the memory table can contrast capped vs uncapped stored bytes.
            let mem_capped = args.iter().any(|a| a == "--capped");
            let mut cap = VISIBILITY_CAP;
            if let Some(pos) = args.iter().position(|a| a == "--cap")
                && let Some(c) = args.get(pos + 1).and_then(|s| s.parse::<usize>().ok())
            {
                cap = c;
            }
            let env = FederationEnvironment::realistic_10k();
            run_reverse_frontier_sweep(&env, &sizes, inbound_factor, mem_capped, cap);
        }
        "sweep" | "fed-sweep" => {
            // Default sweep grid; covers the SLO-relevant range. Override
            // by passing the desired sizes as positional args after `sweep`.
            let default_sizes: &[u32] = &[10_000, 50_000, 100_000, 250_000, 500_000];
            let sizes: Vec<u32> = args
                .iter()
                .skip(2)
                .filter_map(|s| s.parse::<u32>().ok())
                .collect();
            let sizes = if sizes.is_empty() {
                default_sizes.to_vec()
            } else {
                sizes
            };
            let env = FederationEnvironment::realistic_10k();
            run_federated_power_law_sweep(&env, &sizes);
        }
        "mmap" => {
            // Option C prototype. Same `--local-users N` override as
            // `fed-power-law`; defaults to `medium` (50K local users)
            // so a desktop dev box can run it in under a minute.
            let mut home = HomeInstanceConfig::medium();
            if let Some(pos) = args.iter().position(|a| a == "--local-users")
                && let Some(n) = args.get(pos + 1).and_then(|s| s.parse::<u32>().ok())
            {
                home.local_users = n;
            }
            let env = FederationEnvironment::realistic_10k();
            run_mmap_bench(&home, &env, rebuild_peak_probe);
        }
        "size" | "sizing" => {
            // `bench size 4GB` style. Accept a plain byte count or a
            // suffixed value (KB/MB/GB). Default budget: 4 GB.
            let default_budget = 4u64 * 1024 * 1024 * 1024;
            let budget = args
                .get(2)
                .and_then(|s| parse_memory_budget(s))
                .unwrap_or(default_budget);
            let env = FederationEnvironment::realistic_10k();
            run_sizing_helper(budget, &env);
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
            run_power_law_benchmark(
                "Power-Law Single Instance (50K users)",
                &PowerLawConfig::medium_instance(),
            );
            run_federated_power_law_benchmark(
                "Federated Power-Law (50K local users, ~100M conceptual)",
                &HomeInstanceConfig::medium(),
                &FederationEnvironment::realistic_10k(),
                rebuild_peak_probe,
            );
        }
    }
}

/// Parse `"4GB"` / `"512MB"` / `"1024"` (bare = bytes) into a byte count.
fn parse_memory_budget(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num_part, mult) = if let Some(n) = s.strip_suffix("GB").or_else(|| s.strip_suffix("gb")) {
        (n, 1024 * 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix("MB").or_else(|| s.strip_suffix("mb")) {
        (n, 1024 * 1024u64)
    } else if let Some(n) = s.strip_suffix("KB").or_else(|| s.strip_suffix("kb")) {
        (n, 1024u64)
    } else {
        (s, 1u64)
    };
    num_part.trim().parse::<u64>().ok().map(|n| n * mult)
}

// ---------------------------------------------------------------------------
// Verbose test runner ("cargo run -- test")
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
    let no_distrusts: DistrustSets = HashMap::new();

    // --- Test 1: Linear chain A→B→C→D ---
    {
        let edges = vec![(0, 1), (1, 2), (2, 3)]; // A=0, B=1, C=2, D=3
        let csr = CsrGraph::from_edges(4, &edges);
        let href = HashMapGraph::from_edges(&edges);

        let csr_scores = to_map(forward_bfs(0, &csr, &no_distrusts));
        let ref_scores = to_map(reference_forward_bfs(0, &href, &no_distrusts));

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

        let csr_scores = to_map(forward_bfs(0, &csr, &no_distrusts));
        let ref_scores = to_map(reference_forward_bfs(0, &href, &no_distrusts));

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
        let csr_scores = to_map(forward_bfs(0, &csr, &no_distrusts));

        // All paths through H — max in group H is A→H→M = 0.7
        assert_near!(csr_scores[&2], 0.7, 0.001, "sybil: M=0.7 (collapsed)");
    }

    // --- Test 4: Depth limit ---
    {
        // A→B→C→D→E (4 hops, E unreachable)
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
        let csr = CsrGraph::from_edges(5, &edges);
        let csr_scores = to_map(forward_bfs(0, &csr, &no_distrusts));

        assert_true!(csr_scores.contains_key(&3), "depth limit: D reachable");
        assert_true!(!csr_scores.contains_key(&4), "depth limit: E unreachable");
    }

    // --- Test 5: No self-loop ---
    {
        // A→B→A
        let edges = vec![(0, 1), (1, 0)];
        let csr = CsrGraph::from_edges(2, &edges);
        let csr_scores = to_map(forward_bfs(0, &csr, &no_distrusts));

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

        let fwd_scores = to_map(forward_bfs(0, &dual.forward, &no_distrusts));
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

        let fwd_scores = to_map(forward_bfs(0, &dual.forward, &no_distrusts));
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

        let fwd_scores = to_map(forward_bfs(0, &dual.forward, &no_distrusts));
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

    // --- Test 10: Forward/reverse agreement on random graph (no distrusts) ---
    {
        // Generate a small random graph. For every (source, target) pair
        // reachable in both directions, verify forward_bfs and reverse_bfs
        // produce the same trust score. Agreement is expected only without
        // distrusts — reverse BFS is an approximation that ignores distrust
        // penalties (see reverse_bfs docstring).
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
            let fwd = to_map(forward_bfs(src, &dual.forward, &no_distrusts));
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
            let csr_scores = to_map(forward_bfs(src, &csr, &no_distrusts));
            let ref_scores = to_map(reference_forward_bfs(src, &href, &no_distrusts));

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

    // --- Test 14: Single distrusted target penalizes intermediary ---
    {
        // V→A→B, A trusts E (distrusted by V)
        // V=0, A=1, B=2, E=3
        let edges = vec![(0, 1), (1, 2), (1, 3)];
        let blocks = HashMap::from([(0u32, HashSet::from([3u32]))]);
        let csr = CsrGraph::from_edges(4, &edges);
        let scores = to_map(forward_bfs(0, &csr, &blocks));

        // A trusts E (distrusted) → reliability = 0.75
        assert_near!(scores[&1], 0.75, 0.001, "distrust single: A=0.75");
        // B = 0.75 * DECAY * reliability(B) = 0.75 * 0.7 * 1.0 = 0.525
        assert_near!(scores[&2], 0.525, 0.001, "distrust single: B=0.525");
        // E is directly distrusted → 0.0
        assert_near!(
            scores[&3],
            0.0,
            0.001,
            "distrust single: E=0.0 (distrusted)"
        );
    }

    // --- Test 15: Multiple distrusted targets compound ---
    {
        // V→A, A trusts E1 and E2 (both distrusted by V)
        // V=0, A=1, E1=2, E2=3
        let edges = vec![(0, 1), (1, 2), (1, 3)];
        let blocks = HashMap::from([(0u32, HashSet::from([2u32, 3u32]))]);
        let csr = CsrGraph::from_edges(4, &edges);
        let scores = to_map(forward_bfs(0, &csr, &blocks));

        // A trusts 2 distrusted → reliability = 0.75^2 = 0.5625
        assert_near!(scores[&1], 0.5625, 0.001, "distrust multi: A=0.5625");
    }

    // --- Test 16: No penalty for clean node ---
    {
        // V→A→B, V distrusts E (not connected to A)
        // V=0, A=1, B=2, E=3
        let edges = vec![(0, 1), (1, 2), (0, 3)];
        let blocks = HashMap::from([(0u32, HashSet::from([3u32]))]);
        let csr = CsrGraph::from_edges(4, &edges);
        let scores = to_map(forward_bfs(0, &csr, &blocks));

        // A doesn't trust E → no penalty
        assert_near!(scores[&1], 1.0, 0.001, "distrust clean: A=1.0");
        assert_near!(scores[&2], 0.7, 0.001, "distrust clean: B=0.7");
    }

    // --- Test 17: Multi-path recovery with distrusts ---
    {
        // V→A→T, V→C→T. A trusts distrusted E, C is clean. T is clean.
        // V=0, A=1, C=2, T=3, E=4
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3), (1, 4)];
        let blocks = HashMap::from([(0u32, HashSet::from([4u32]))]);
        let csr = CsrGraph::from_edges(5, &edges);
        let scores = to_map(forward_bfs(0, &csr, &blocks));

        // Group A: A reliability=0.75, T via A = 0.75 * 0.7 = 0.525
        // Group C: C reliability=1.0, T via C = 1.0 * 0.7 = 0.7
        // Combined: 1 - (1-0.525)(1-0.7) = 1 - 0.1425 = 0.8575
        assert_near!(scores[&3], 0.8575, 0.001, "distrust multipath: T=0.8575");
    }

    // --- Test 18: Penalty compounds along path ---
    {
        // V→A→B→C, A trusts E1 (distrusted), B trusts E2 (distrusted)
        // V=0, A=1, B=2, C=3, E1=4, E2=5
        let edges = vec![(0, 1), (1, 2), (2, 3), (1, 4), (2, 5)];
        let blocks = HashMap::from([(0u32, HashSet::from([4u32, 5u32]))]);
        let csr = CsrGraph::from_edges(6, &edges);
        let scores = to_map(forward_bfs(0, &csr, &blocks));

        // A: reliability = 0.75 (trusts E1) → 0.75
        assert_near!(scores[&1], 0.75, 0.001, "distrust compound: A=0.75");
        // B: 0.75 * DECAY * reliability(B) = 0.75 * 0.7 * 0.75 = 0.39375
        assert_near!(scores[&2], 0.394, 0.001, "distrust compound: B≈0.394");
        // C: 0.394 * DECAY * 1.0 = 0.276
        assert_near!(scores[&3], 0.276, 0.01, "distrust compound: C≈0.276");
    }

    // --- Test 19: Distrust penalty + Sybil resistance ---
    {
        // V→H→M, V→H→S1→M, V→H→S2→M. H trusts E (distrusted by V).
        // V=0, H=1, M=2, S1=3, S2=4, E=5
        let edges = vec![(0, 1), (1, 2), (1, 3), (1, 4), (3, 2), (4, 2), (1, 5)];
        let blocks = HashMap::from([(0u32, HashSet::from([5u32]))]);
        let csr = CsrGraph::from_edges(6, &edges);
        let scores = to_map(forward_bfs(0, &csr, &blocks));

        // All paths through first-hop H. H reliability = 0.75 (trusts E).
        // H score = 0.75. Best path to M in group H: H→M = 0.75 * 0.7 * r(M)
        // M doesn't trust distrusted users → r(M)=1.0 → H→M = 0.525
        // Sybil paths: H→S1→M = 0.75*0.7*1.0*0.7*1.0 = 0.3675
        // Max in group H = 0.525. Sybils can't inflate.
        assert_near!(
            scores[&2],
            0.525,
            0.001,
            "distrust sybil: M=0.525 (sybils don't help)"
        );
    }

    // --- Test 20: CSR matches reference with distrusts ---
    {
        let edges = vec![(0, 1), (1, 2), (1, 3), (2, 4), (0, 5), (5, 4)];
        let blocks = HashMap::from([(0u32, HashSet::from([3u32]))]);
        let csr = CsrGraph::from_edges(6, &edges);
        let href = HashMapGraph::from_edges(&edges);

        let csr_scores = to_map(forward_bfs(0, &csr, &blocks));
        let ref_scores = to_map(reference_forward_bfs(0, &href, &blocks));

        for &tgt in csr_scores
            .keys()
            .chain(ref_scores.keys())
            .collect::<HashSet<_>>()
            .iter()
        {
            let cs = csr_scores.get(tgt).copied().unwrap_or(0.0);
            let rs = ref_scores.get(tgt).copied().unwrap_or(0.0);
            assert_near!(cs, rs, 0.001, &format!("distrust CSR vs ref: target {tgt}"));
        }
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

    fn empty_distrusts() -> DistrustSets {
        HashMap::new()
    }

    #[test]
    fn test_csr_linear_chain() {
        let edges = vec![(0, 1), (1, 2), (2, 3)];
        let csr = CsrGraph::from_edges(4, &edges);
        let scores = to_map(forward_bfs(0, &csr, &empty_distrusts()));

        assert!((scores[&1] - 1.0).abs() < 0.001);
        assert!((scores[&2] - 0.7).abs() < 0.001);
        assert!((scores[&3] - 0.49).abs() < 0.001);
    }

    #[test]
    fn test_csr_two_independent_paths() {
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3)];
        let csr = CsrGraph::from_edges(4, &edges);
        let scores = to_map(forward_bfs(0, &csr, &empty_distrusts()));

        assert!((scores[&3] - 0.91).abs() < 0.001);
    }

    #[test]
    fn test_csr_sybil_resistance() {
        let edges = vec![(0, 1), (1, 2), (1, 3), (1, 4), (3, 2), (4, 2)];
        let csr = CsrGraph::from_edges(5, &edges);
        let scores = to_map(forward_bfs(0, &csr, &empty_distrusts()));

        assert!((scores[&2] - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_csr_depth_limit() {
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
        let csr = CsrGraph::from_edges(5, &edges);
        let scores = to_map(forward_bfs(0, &csr, &empty_distrusts()));

        assert!(scores.contains_key(&3));
        assert!(!scores.contains_key(&4));
    }

    #[test]
    fn test_csr_no_self_loop() {
        let edges = vec![(0, 1), (1, 0)];
        let csr = CsrGraph::from_edges(2, &edges);
        let scores = to_map(forward_bfs(0, &csr, &empty_distrusts()));

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

        let fwd = to_map(forward_bfs(0, &dual.forward, &empty_distrusts()));
        let rev = to_map(reverse_bfs(3, &dual.reverse));

        assert!((fwd[&3] - rev[&0]).abs() < 0.001);
    }

    #[test]
    fn test_reverse_sybil_resistance() {
        let edges = vec![(0, 1), (1, 2), (1, 3), (1, 4), (3, 2), (4, 2)];
        let dual = DualCsrGraph::from_edges(5, &edges);

        let fwd = to_map(forward_bfs(0, &dual.forward, &empty_distrusts()));
        let rev = to_map(reverse_bfs(2, &dual.reverse));

        assert!((fwd[&2] - 0.7).abs() < 0.001);
        assert!((rev[&0] - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_reverse_mixed_depth() {
        // A→X→R and A→Y→X→R
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 1)];
        let dual = DualCsrGraph::from_edges(4, &edges);

        let fwd = to_map(forward_bfs(0, &dual.forward, &empty_distrusts()));
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
    /// Uses empty distrust sets — agreement is expected only without distrusts.
    /// Reverse BFS is an approximation that ignores distrust penalties (see
    /// reverse_bfs docstring).
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
            let fwd = to_map(forward_bfs(src, &dual.forward, &empty_distrusts()));
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
            let csr_scores = to_map(forward_bfs(src, &csr, &empty_distrusts()));
            let ref_scores = to_map(reference_forward_bfs(src, &href, &empty_distrusts()));

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

    // -- Distrust propagation tests --

    #[test]
    fn test_distrust_single_target() {
        // V→A→B, A trusts E (distrusted by V). V=0, A=1, B=2, E=3.
        let edges = vec![(0, 1), (1, 2), (1, 3)];
        let blocks = HashMap::from([(0u32, HashSet::from([3u32]))]);
        let csr = CsrGraph::from_edges(4, &edges);
        let scores = to_map(forward_bfs(0, &csr, &blocks));

        assert!((scores[&1] - 0.75).abs() < 0.001);
        assert!((scores[&2] - 0.525).abs() < 0.001);
        assert!((scores[&3] - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_distrust_multiple_targets() {
        // V→A, A trusts E1 and E2 (both distrusted). V=0, A=1, E1=2, E2=3.
        let edges = vec![(0, 1), (1, 2), (1, 3)];
        let blocks = HashMap::from([(0u32, HashSet::from([2u32, 3u32]))]);
        let csr = CsrGraph::from_edges(4, &edges);
        let scores = to_map(forward_bfs(0, &csr, &blocks));

        assert!((scores[&1] - 0.5625).abs() < 0.001);
    }

    #[test]
    fn test_distrust_no_penalty_clean_node() {
        // V→A→B, V distrusts E (not trusted by A). V=0, A=1, B=2, E=3.
        let edges = vec![(0, 1), (1, 2), (0, 3)];
        let blocks = HashMap::from([(0u32, HashSet::from([3u32]))]);
        let csr = CsrGraph::from_edges(4, &edges);
        let scores = to_map(forward_bfs(0, &csr, &blocks));

        assert!((scores[&1] - 1.0).abs() < 0.001);
        assert!((scores[&2] - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_distrust_multipath_recovery() {
        // V→A→T, V→C→T. A trusts E (distrusted), C clean. V=0, A=1, C=2, T=3, E=4.
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3), (1, 4)];
        let blocks = HashMap::from([(0u32, HashSet::from([4u32]))]);
        let csr = CsrGraph::from_edges(5, &edges);
        let scores = to_map(forward_bfs(0, &csr, &blocks));

        // Group A: 0.75*0.7=0.525, Group C: 1.0*0.7=0.7
        // Combined: 1-(0.475)(0.3)=0.8575
        assert!((scores[&3] - 0.8575).abs() < 0.001);
    }

    #[test]
    fn test_distrust_compounds_along_path() {
        // V→A→B→C, A trusts E1 (distrusted), B trusts E2 (distrusted).
        // V=0, A=1, B=2, C=3, E1=4, E2=5.
        let edges = vec![(0, 1), (1, 2), (2, 3), (1, 4), (2, 5)];
        let blocks = HashMap::from([(0u32, HashSet::from([4u32, 5u32]))]);
        let csr = CsrGraph::from_edges(6, &edges);
        let scores = to_map(forward_bfs(0, &csr, &blocks));

        assert!((scores[&1] - 0.75).abs() < 0.001);
        assert!((scores[&2] - 0.39375).abs() < 0.001);
        assert!((scores[&3] - 0.39375 * DECAY).abs() < 0.01);
    }

    #[test]
    fn test_distrust_sybil_resistance() {
        // V→H→M, V→H→S1→M, V→H→S2→M. H trusts E (distrusted).
        // V=0, H=1, M=2, S1=3, S2=4, E=5.
        let edges = vec![(0, 1), (1, 2), (1, 3), (1, 4), (3, 2), (4, 2), (1, 5)];
        let blocks = HashMap::from([(0u32, HashSet::from([5u32]))]);
        let csr = CsrGraph::from_edges(6, &edges);
        let scores = to_map(forward_bfs(0, &csr, &blocks));

        // All via first-hop H. H reliability=0.75.
        // Best in group: H→M = 0.75*0.7 = 0.525
        assert!((scores[&2] - 0.525).abs() < 0.001);
    }

    #[test]
    fn test_distrust_csr_matches_reference() {
        let edges = vec![(0, 1), (1, 2), (1, 3), (2, 4), (0, 5), (5, 4)];
        let blocks = HashMap::from([(0u32, HashSet::from([3u32]))]);
        let csr = CsrGraph::from_edges(6, &edges);
        let href = HashMapGraph::from_edges(&edges);

        let csr_scores = to_map(forward_bfs(0, &csr, &blocks));
        let ref_scores = to_map(reference_forward_bfs(0, &href, &blocks));

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
                "target {tgt}: csr={cs:.6} ref={rs:.6}"
            );
        }
    }

    // -- Power-law generator sanity --

    /// Variance multiplier κ on the power-law graph should be materially
    /// above 1.0 — otherwise the topology isn't actually heavy-tailed.
    /// Doc predicts ~5×; we assert a loose lower bound of 2× to allow for
    /// randomness while still catching a generator that has accidentally
    /// degenerated to uniform.
    #[test]
    fn test_power_law_variance_multiplier_above_one() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let synth = generate_power_law_graph(&PowerLawConfig::medium_instance(), &mut rng);
        let dual = DualCsrGraph::from_edges(synth.num_nodes, &synth.edges);
        let n = synth.num_nodes as f64;
        let mut sum_d = 0u64;
        let mut sum_d_sq = 0u128;
        for node in 0..synth.num_nodes {
            let d = dual.forward.neighbors(node).len() as u64;
            sum_d += d;
            sum_d_sq += (d as u128) * (d as u128);
        }
        let mean_d = sum_d as f64 / n;
        let mean_d_sq = sum_d_sq as f64 / n;
        let kappa = mean_d_sq / (mean_d * mean_d);
        assert!(
            kappa > 2.0,
            "κ = {kappa:.2} is too close to 1.0 — generator may have degenerated to uniform"
        );
    }
}
