//! Prismoire trust-graph benchmark binary.
//!
//! The algorithm under test lives in [`algo`]; the synthetic graph
//! generators live in [`graph`]. This file owns the benchmark harness, the
//! verbose test runner, the cargo-test module, and the CLI dispatcher.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

mod algo;
mod graph;

use algo::{
    DECAY, DistrustSets, DualCsrGraph, HUB_DAMPEN_THRESHOLD, HashMapGraph, MAX_DEPTH,
    build_distrust_sets, forward_bfs, forward_bfs_with_threshold, reference_forward_bfs,
    reverse_bfs,
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
    let _ = forward_bfs(
        sample_sources[0],
        &dual.forward,
        &dual.reverse,
        distrust_sets,
    );
    let _ = reverse_bfs(sample_sources[0], &dual.reverse);

    // --- Forward BFS ---
    let mut forward_times = Vec::with_capacity(num_samples);
    let mut forward_result_counts = Vec::with_capacity(num_samples);
    for &src in &sample_sources {
        let t = Instant::now();
        let results = forward_bfs(src, &dual.forward, &dual.reverse, distrust_sets);
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
        let _fwd = forward_bfs(src, &dual.forward, &dual.reverse, distrust_sets);
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

/// Same as [`run_benchmark`] for setup/timing, plus four power-law-specific
/// measurements after CSR build:
///
/// 1. **Degree distribution.** Top-N + percentile dump of in/out degree.
///    Validates the generator produced the expected heavy tail.
/// 2. **Variance multiplier κ = E[d²] / E[d]².** Direct test of the doc's
///    "every `n·d²` formula understates by a factor of ~5×" claim.
/// 3. **Friendship-paradox effective branching.** `Σ d_in·d_out / Σ d_in`,
///    which is the expected out-degree of a node reached by a random hop.
///    Doc predicts ~59 vs ~11 for the modelled distribution.
/// 4. **Hub-dampening A/B.** Runs forward BFS on each sample source with
///    dampening on (threshold=`HUB_DAMPEN_THRESHOLD`) and off
///    (threshold=`u32::MAX`); reports how many target-paths that would be
///    visible without dampening fall below the 0.45 visibility threshold
///    when dampening is on.
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

    let sample_sources = pick_sample_sources(&synth.local_range, 100);
    report_hub_dampening_impact(&dual, &sample_sources);

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

    let above_threshold = in_degrees
        .iter()
        .take_while(|&&d| d > HUB_DAMPEN_THRESHOLD)
        .count();
    println!(
        "  nodes above HUB_DAMPEN_THRESHOLD ({}): {}",
        HUB_DAMPEN_THRESHOLD, above_threshold,
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

/// Measurement 4: hub-dampening A/B vs visibility threshold.
///
/// For each sample source, runs forward BFS with dampening on
/// (threshold=`HUB_DAMPEN_THRESHOLD`) and off (threshold=`u32::MAX`). Counts
/// targets whose path crosses the 0.45 visibility threshold in each
/// configuration. The "attenuated" bucket is exactly the set of paths that
/// dampening cut off from the visible feed — its size answers the question
/// "how much frontier does dampening actually save on a realistic graph?".
fn report_hub_dampening_impact(dual: &DualCsrGraph, sample_sources: &[u32]) {
    const VISIBILITY_THRESHOLD: f64 = 0.45;
    let no_distrusts: DistrustSets = HashMap::new();

    let mut visible_with_damp = 0usize;
    let mut visible_without_damp = 0usize;
    let mut attenuated = 0usize;
    // Median/max per-source forward result counts under each config, to
    // give a frontier-size sense not just a yes/no on visibility.
    let mut frontier_with: Vec<usize> = Vec::with_capacity(sample_sources.len());
    let mut frontier_without: Vec<usize> = Vec::with_capacity(sample_sources.len());

    for &src in sample_sources {
        let with_damp: HashMap<u32, f64> = forward_bfs_with_threshold(
            src,
            &dual.forward,
            &dual.reverse,
            &no_distrusts,
            HUB_DAMPEN_THRESHOLD,
        )
        .into_iter()
        .collect();
        let no_damp: HashMap<u32, f64> =
            forward_bfs_with_threshold(src, &dual.forward, &dual.reverse, &no_distrusts, u32::MAX)
                .into_iter()
                .collect();

        frontier_with.push(with_damp.len());
        frontier_without.push(no_damp.len());

        for (target, &score_no) in &no_damp {
            if score_no >= VISIBILITY_THRESHOLD {
                visible_without_damp += 1;
                let score_with = with_damp.get(target).copied().unwrap_or(0.0);
                if score_with >= VISIBILITY_THRESHOLD {
                    visible_with_damp += 1;
                } else {
                    attenuated += 1;
                }
            }
        }
    }

    frontier_with.sort_unstable();
    frontier_without.sort_unstable();
    let median = |v: &[usize]| v[v.len() / 2];

    let attenuation_rate = if visible_without_damp == 0 {
        0.0
    } else {
        100.0 * attenuated as f64 / visible_without_damp as f64
    };

    println!(
        "\nHub-dampening A/B (visibility threshold = {VISIBILITY_THRESHOLD}, {} samples):",
        sample_sources.len()
    );
    println!(
        "  frontier (reachable targets)  with dampening: median={}  max={}",
        median(&frontier_with),
        frontier_with.last().copied().unwrap_or(0),
    );
    println!(
        "  frontier (reachable targets) without dampening: median={}  max={}",
        median(&frontier_without),
        frontier_without.last().copied().unwrap_or(0),
    );
    println!("  visible paths without dampening: {visible_without_damp}");
    println!("  visible paths with    dampening: {visible_with_damp}");
    println!(
        "  attenuated below threshold:      {attenuated}  ({attenuation_rate:.1}% of would-be-visible)"
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

    run_bfs_timings(&synth, &dual, &distrust_sets);

    let sample_sources = pick_sample_sources(&synth.local_range, 100);
    report_hub_dampening_impact(&dual, &sample_sources);

    if let Some(peak) = peak_rss_kb() {
        println!("\nPeak RSS: {}", fmt_memory(peak));
    }
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
        };
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let synth = generate_federated_power_law_graph(&home, env, &mut rng);
        let dual = DualCsrGraph::from_edges(synth.num_nodes, &synth.edges);
        let distrust_sets = build_distrust_sets(&synth.distrust_edges);

        let sample_sources = pick_sample_sources(&synth.local_range, 50);
        let _ = forward_bfs(
            sample_sources[0],
            &dual.forward,
            &dual.reverse,
            &distrust_sets,
        );

        let mut fwd_times: Vec<f64> = Vec::with_capacity(sample_sources.len());
        let mut dual_times: Vec<f64> = Vec::with_capacity(sample_sources.len());
        for &src in &sample_sources {
            let t = Instant::now();
            let _ = forward_bfs(src, &dual.forward, &dual.reverse, &distrust_sets);
            fwd_times.push(t.elapsed().as_secs_f64() * 1000.0);

            let t = Instant::now();
            let _ = forward_bfs(src, &dual.forward, &dual.reverse, &distrust_sets);
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
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("Prismoire Trust Graph Benchmark");
    println!("===============================");
    println!(
        "Algorithm: Bottleneck-Grouped Probabilistic (DECAY={DECAY}, MAX_DEPTH={MAX_DEPTH}, HUB_DAMPEN_THRESHOLD={HUB_DAMPEN_THRESHOLD})"
    );

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
            run_federated_power_law_benchmark(&name, &home, &env);
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
        let csr_rev = csr.transpose();
        let href = HashMapGraph::from_edges(&edges);

        let csr_scores = to_map(forward_bfs(0, &csr, &csr_rev, &no_distrusts));
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
        let csr_rev = csr.transpose();
        let href = HashMapGraph::from_edges(&edges);

        let csr_scores = to_map(forward_bfs(0, &csr, &csr_rev, &no_distrusts));
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
        let csr_rev = csr.transpose();
        let csr_scores = to_map(forward_bfs(0, &csr, &csr_rev, &no_distrusts));

        // All paths through H — max in group H is A→H→M = 0.7
        assert_near!(csr_scores[&2], 0.7, 0.001, "sybil: M=0.7 (collapsed)");
    }

    // --- Test 4: Depth limit ---
    {
        // A→B→C→D→E (4 hops, E unreachable)
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
        let csr = CsrGraph::from_edges(5, &edges);
        let csr_rev = csr.transpose();
        let csr_scores = to_map(forward_bfs(0, &csr, &csr_rev, &no_distrusts));

        assert_true!(csr_scores.contains_key(&3), "depth limit: D reachable");
        assert_true!(!csr_scores.contains_key(&4), "depth limit: E unreachable");
    }

    // --- Test 5: No self-loop ---
    {
        // A→B→A
        let edges = vec![(0, 1), (1, 0)];
        let csr = CsrGraph::from_edges(2, &edges);
        let csr_rev = csr.transpose();
        let csr_scores = to_map(forward_bfs(0, &csr, &csr_rev, &no_distrusts));

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

        let fwd_scores = to_map(forward_bfs(0, &dual.forward, &dual.reverse, &no_distrusts));
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

        let fwd_scores = to_map(forward_bfs(0, &dual.forward, &dual.reverse, &no_distrusts));
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

        let fwd_scores = to_map(forward_bfs(0, &dual.forward, &dual.reverse, &no_distrusts));
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
            let fwd = to_map(forward_bfs(
                src,
                &dual.forward,
                &dual.reverse,
                &no_distrusts,
            ));
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
        let csr_rev = csr.transpose();
        let href = HashMapGraph::from_edges(&edges);

        let mut mismatches = 0;
        let mut comparisons = 0;
        for src in 0..n {
            let csr_scores = to_map(forward_bfs(src, &csr, &csr_rev, &no_distrusts));
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
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));

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
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));

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
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));

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
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));

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
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));

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
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));

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
        let csr_rev = csr.transpose();
        let href = HashMapGraph::from_edges(&edges);

        let csr_scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));
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
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &empty_distrusts()));

        assert!((scores[&1] - 1.0).abs() < 0.001);
        assert!((scores[&2] - 0.7).abs() < 0.001);
        assert!((scores[&3] - 0.49).abs() < 0.001);
    }

    #[test]
    fn test_csr_two_independent_paths() {
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3)];
        let csr = CsrGraph::from_edges(4, &edges);
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &empty_distrusts()));

        assert!((scores[&3] - 0.91).abs() < 0.001);
    }

    #[test]
    fn test_csr_sybil_resistance() {
        let edges = vec![(0, 1), (1, 2), (1, 3), (1, 4), (3, 2), (4, 2)];
        let csr = CsrGraph::from_edges(5, &edges);
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &empty_distrusts()));

        assert!((scores[&2] - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_csr_depth_limit() {
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
        let csr = CsrGraph::from_edges(5, &edges);
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &empty_distrusts()));

        assert!(scores.contains_key(&3));
        assert!(!scores.contains_key(&4));
    }

    #[test]
    fn test_csr_no_self_loop() {
        let edges = vec![(0, 1), (1, 0)];
        let csr = CsrGraph::from_edges(2, &edges);
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &empty_distrusts()));

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

        let fwd = to_map(forward_bfs(
            0,
            &dual.forward,
            &dual.reverse,
            &empty_distrusts(),
        ));
        let rev = to_map(reverse_bfs(3, &dual.reverse));

        assert!((fwd[&3] - rev[&0]).abs() < 0.001);
    }

    #[test]
    fn test_reverse_sybil_resistance() {
        let edges = vec![(0, 1), (1, 2), (1, 3), (1, 4), (3, 2), (4, 2)];
        let dual = DualCsrGraph::from_edges(5, &edges);

        let fwd = to_map(forward_bfs(
            0,
            &dual.forward,
            &dual.reverse,
            &empty_distrusts(),
        ));
        let rev = to_map(reverse_bfs(2, &dual.reverse));

        assert!((fwd[&2] - 0.7).abs() < 0.001);
        assert!((rev[&0] - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_reverse_mixed_depth() {
        // A→X→R and A→Y→X→R
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 1)];
        let dual = DualCsrGraph::from_edges(4, &edges);

        let fwd = to_map(forward_bfs(
            0,
            &dual.forward,
            &dual.reverse,
            &empty_distrusts(),
        ));
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
            let fwd = to_map(forward_bfs(
                src,
                &dual.forward,
                &dual.reverse,
                &empty_distrusts(),
            ));
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
        let csr_rev = csr.transpose();
        let href = HashMapGraph::from_edges(&edges);

        for src in 0..n {
            let csr_scores = to_map(forward_bfs(src, &csr, &csr_rev, &empty_distrusts()));
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
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));

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
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));

        assert!((scores[&1] - 0.5625).abs() < 0.001);
    }

    #[test]
    fn test_distrust_no_penalty_clean_node() {
        // V→A→B, V distrusts E (not trusted by A). V=0, A=1, B=2, E=3.
        let edges = vec![(0, 1), (1, 2), (0, 3)];
        let blocks = HashMap::from([(0u32, HashSet::from([3u32]))]);
        let csr = CsrGraph::from_edges(4, &edges);
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));

        assert!((scores[&1] - 1.0).abs() < 0.001);
        assert!((scores[&2] - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_distrust_multipath_recovery() {
        // V→A→T, V→C→T. A trusts E (distrusted), C clean. V=0, A=1, C=2, T=3, E=4.
        let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3), (1, 4)];
        let blocks = HashMap::from([(0u32, HashSet::from([4u32]))]);
        let csr = CsrGraph::from_edges(5, &edges);
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));

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
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));

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
        let csr_rev = csr.transpose();
        let scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));

        // All via first-hop H. H reliability=0.75.
        // Best in group: H→M = 0.75*0.7 = 0.525
        assert!((scores[&2] - 0.525).abs() < 0.001);
    }

    #[test]
    fn test_distrust_csr_matches_reference() {
        let edges = vec![(0, 1), (1, 2), (1, 3), (2, 4), (0, 5), (5, 4)];
        let blocks = HashMap::from([(0u32, HashSet::from([3u32]))]);
        let csr = CsrGraph::from_edges(6, &edges);
        let csr_rev = csr.transpose();
        let href = HashMapGraph::from_edges(&edges);

        let csr_scores = to_map(forward_bfs(0, &csr, &csr_rev, &blocks));
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

    /// The power-law generator should produce a graph with at least one node
    /// whose in-degree exceeds HUB_DAMPEN_THRESHOLD (otherwise the dampening
    /// A/B in run_power_law_benchmark measures nothing).
    #[test]
    fn test_power_law_produces_hub_above_threshold() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let synth = generate_power_law_graph(&PowerLawConfig::medium_instance(), &mut rng);
        let dual = DualCsrGraph::from_edges(synth.num_nodes, &synth.edges);
        let max_in_degree = (0..synth.num_nodes)
            .map(|n| dual.reverse.neighbors(n).len() as u32)
            .max()
            .unwrap_or(0);
        assert!(
            max_in_degree > HUB_DAMPEN_THRESHOLD,
            "max in-degree {max_in_degree} did not exceed HUB_DAMPEN_THRESHOLD {HUB_DAMPEN_THRESHOLD} \
             — generator parameters may need adjustment"
        );
    }

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
