# Trust Graph Benchmark

Standalone benchmark for Prismoire's trust propagation algorithm (Bottleneck-Grouped Probabilistic) using CSR (Compressed Sparse Row) graph representation with forward and reverse BFS.

## Purpose

- Validate that CSR-based forward and reverse BFS produce identical trust scores
- Measure per-query latency (single-source forward, reverse, and dual BFS)
- Measure memory footprint at single-instance and federation scale
- Serve as a reference implementation for the production CSR + on-demand dual BFS architecture

## Architecture

The benchmark implements a dual BFS approach:

- **Forward BFS** (relevance): reader → authors. Groups paths by the reader's first-hop neighbor.
- **Reverse BFS** (visibility): authors → reader, computed via BFS on the transposed graph. Groups paths by the predecessor in the reverse traversal (= the discovered node's direct forward-graph neighbor toward the reader).

Both produce identical trust scores for any (source, target) pair — verified by exhaustive tests on random graphs.

## Usage

```sh
cargo run -p prismoire-bench --release                              # all four benchmarks
cargo run -p prismoire-bench --release -- single                    # single-instance (10K users, homogeneous)
cargo run -p prismoire-bench --release -- federation                # federation (10K instances, 1.1M nodes)
cargo run -p prismoire-bench --release -- power-law                 # single-instance (50K users, power-law)
cargo run -p prismoire-bench --release -- fed-power-law             # federated power-law (50K local, ~100M conceptual)
cargo run -p prismoire-bench --release -- fed-power-law --local-users 100000   # custom local user count
cargo run -p prismoire-bench --release -- sweep                     # scaling sweep across local_users
cargo run -p prismoire-bench --release -- sweep 10000 50000 250000  # custom sweep grid
cargo run -p prismoire-bench --release -- size 4GB                  # sizing helper: max local_users for memory budget
cargo run -p prismoire-bench --release -- test                      # verbose correctness tests
cargo test -p prismoire-bench                                       # cargo test suite (22 tests)
```

## Source layout

- `src/algo.rs` — the BFS algorithm itself (CSR, dual CSR, forward/reverse BFS, distrust handling, hub dampening, the `HashMapGraph` reference oracle). The `*_with_threshold` BFS variants accept a configurable hub-dampening threshold so the harness can A/B with dampening on vs off without forking the algorithm.
- `src/graph.rs` — synthetic graph generators: homogeneous (`generate_graph` / `GraphConfig`) and power-law (`generate_power_law_graph` / `PowerLawConfig`).
- `src/main.rs` — CLI, timing harness, measurement helpers (degree distribution, variance multiplier κ, friendship-paradox branching, hub-dampening A/B), and the verbose correctness test suite.

Cross-compile for Raspberry Pi via the flake:

```sh
nix build .#packages.aarch64-linux.bench
```

## Synthetic Graph Topology

Trust edges are binary (present or absent) and directional. The decay constant is 0.7 per hop, with a maximum traversal depth of 3 hops. Hub dampening kicks in for in-degrees above 5000 (`HUB_DAMPEN_THRESHOLD`).

The single-instance and federation scenarios assume **each user trusts 10 other users** on average; the power-law scenario uses a three-tier out-degree distribution described below.

### Single instance

- 10K users, each vouching for 10 random others → ~100K edges
- Represents one Prismoire instance, no federation
- Uniform random topology (no clustering) — a conservative model since real communities have tighter clusters, which would reduce BFS fan-out

### Federation

Models a well-connected home instance in a 10K-instance federation:

- **Local instance:** 10K users, ~10 vouches each (same as single instance)
- **Cross-instance edges:** 10K trust edges from local users to remote instances (one per instance, representing the "bridge" users who connect communities)
- **Remote clusters:** Each remote instance contributes a 3-hop frontier reachable from the cross-instance vouch:
  - Hop 1: 1 user (the vouch target on the remote instance)
  - Hop 2: 10 users (hop-1's local neighbors)
  - Hop 3: 100 users (hop-2's local neighbors, leaf nodes with no stored outgoing edges)
- **Totals:** ~1.1M nodes, ~1.2M edges

The federation model only stores edges needed for 3-hop traversal from local users. Hop-3 nodes are leaves — their outgoing edges are not included since they would only be relevant at hop 4+. This matches the production data model where the local instance only syncs trust edges within its reachability frontier.

This is a **pessimistic scenario for performance**: a 10K-user instance connected to all 10K federated instances maximizes the frontier size (1.1M nodes) that must be held in memory and potentially traversed. In practice, most instances would be connected to far fewer remote instances, with significant overlap in remote clusters, resulting in a smaller frontier and faster BFS.

### Power-law single instance

Instead of every user vouching for ~10 others, users fall into three out-degree tiers:

- **Power users** (top 1%): vouch for 200 others
- **Active users** (next 9%): vouch for 50 others
- **Lurkers** (remaining 90%): vouch for 5 others

Target selection is **preferentially attached**: each user's targets are sampled with weight `1/(rank+1)^α` where `α=0.8`. The in-degree rank order is shuffled independently of the out-degree tier, so being a "power user" does not force you to also be a "top celebrity" — the two power-law axes are decoupled. At 50K users this produces a top in-degree around 8K–15K, comfortably above `HUB_DAMPEN_THRESHOLD` (5000), so the dampening logic is actually exercised. The mean out-degree is ≈11 (matching the homogeneous scenarios), but the variance multiplier κ = E[d²]/E[d]² is ≈5× — matching the doc's prediction.

The power-law harness also emits a hub-dampening A/B (`with dampening` vs `threshold=u32::MAX`, holding everything else fixed) so you can see how many would-be-visible paths the dampening actually attenuates below the visibility threshold.

### Federated power-law

Embeds the power-law home instance in a 10K-instance federation (~100M conceptual users by default).

- **Home instance:** configurable `local_users` (50K default), same per-user shape as the standalone power-law scenario.
- **`local_preference`** (0.5 default): fraction of each user's edges that target a local user. The rest are cross-instance. 0.7+ for niche/topical instances, 0.3–0.5 for generalist.
- **Federation pool:** 10K instances × 10K mean users (Pareto-distributed sizes) ≈ 100M conceptual users. Only the 3-hop frontier reachable from local users is ever materialised — the conceptual 100M never hits memory.
- **Cross-instance target selection:** instance picked weighted by size; rank within instance picked weighted by `1/rank^0.8` (preferential attachment to known hubs).
- **Hub deduplication:** when N local users independently land on the same remote hub, the cluster is materialised once and edges from each local user point at the shared node. This is what keeps frontier growth sub-linear in `local_users`.

The bench prints an **analytical pre-flight estimate** (cross-edges, unique remote hubs, projected frontier nodes, CSR memory, sorted-Vec NodeIndex memory, steady-state total, and rebuild peak) before generation, and an **estimator-vs-measurement comparison** afterwards. The estimator is intended as a "will this blow up?" gut check; expect ~30–50% error on frontier size, ~exact on cross-edges, and a tight bound on the memory terms once frontier is fixed.

**Sweep mode** (`bench sweep`) runs the federated scenario across multiple `local_users` values and prints a one-row-per-config table with `CSR`, `NIdx`, and `Peak` columns. Directly answers "what userbase fits in N GB of rebuild headroom?" or "what userbase stays under M-ms p99?"

**Sizing helper** (`bench size 4GB`) inverts the estimator analytically: binary-searches `local_users` for the largest value whose projected **rebuild-peak** memory (not just steady-state CSR) fits the budget. Rebuild peak is what governs OOM risk on a tight host; see `docs/rebuild_peak_memory.md`. Pure math, no generation — runs in milliseconds.

> **Counter-intuitive finding:** at equal local-user count, the federated power-law has *less* hub concentration than the single-instance power-law. The 100M-user federation pool dilutes cross-vouches across many more potential targets than a 50K local pool concentrates intra-vouches. Single-instance power-law remains the more demanding stress test for `HUB_DAMPEN_THRESHOLD`.

## Example results

These results are from a test run on a Raspberry Pi 4. Even on modest hardware, forward and backwards trust computations for 100 users (simulated page load) in the "federation" scenario takes only 1ms:

```
Prismoire Trust Graph Benchmark
===============================
Algorithm: Bottleneck-Grouped Probabilistic (DECAY=0.7, MAX_DEPTH=3, HUB_DAMPEN_THRESHOLD=5000)

============================================================
  Benchmark: Single Instance (10K users)
============================================================

Graph generation:  19.9ms
  nodes: 10000  edges: 100000
  local users: 10000

CSR build:         6.8ms
  forward:  offsets=10001 targets=100000
  reverse:  offsets=10001 targets=100000
  memory:   859 KB (forward + reverse CSR, no index)
  RSS delta: 1.8 MB → 3.6 MB (+1.8 MB)
  distrust edges: 1532  distrusters: 1000

Forward BFS (relevance) — 100 samples:
  min: 0.474ms  p50: 0.488ms  p99: 1.124ms  max: 1.124ms  mean: 0.546ms
  avg reachable targets: 1046

Reverse BFS (visibility) — 100 samples:
  min: 0.101ms  p50: 0.416ms  p99: 0.911ms  max: 0.911ms  mean: 0.414ms
  avg reachable sources: 1082

Dual BFS (simulated page load) — 100 samples:
  p50: 0.930ms  p99: 1.451ms  mean: 0.946ms

Peak RSS: 4.2 MB

============================================================
  Benchmark: Federation (10K instances)
============================================================

Graph generation:  30.1ms
  nodes: 1120000  edges: 1210000
  local users: 10000

CSR build:         97.8ms
  forward:  offsets=1120001 targets=1210000
  reverse:  offsets=1120001 targets=1210000
  memory:   17.8 MB (forward + reverse CSR, no index)
  RSS delta: 2.6 MB → 37.8 MB (+35.2 MB)
  distrust edges: 1532  distrusters: 1000

Forward BFS (relevance) — 100 samples:
  min: 0.634ms  p50: 0.654ms  p99: 1.133ms  max: 1.133ms  mean: 0.702ms
  avg reachable targets: 1367

Reverse BFS (visibility) — 100 samples:
  min: 0.099ms  p50: 0.417ms  p99: 0.819ms  max: 0.819ms  mean: 0.406ms
  avg reachable sources: 1082

Dual BFS (simulated page load) — 100 samples:
  p50: 1.106ms  p99: 1.754ms  mean: 1.126ms

Peak RSS: 47.0 MB
```