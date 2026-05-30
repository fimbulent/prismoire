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
cargo run -p prismoire-bench --release -- mmap                      # A/B BFS perf: heap CSR vs mmap'd CSR (see below)
cargo run -p prismoire-bench --release -- test                      # verbose correctness tests
cargo test -p prismoire-bench                                       # cargo test suite (22 tests)
```

## Source layout

- `src/algo.rs` — the BFS algorithm itself (CSR, dual CSR, forward/reverse BFS, distrust handling, the `HashMapGraph` reference oracle). Defines the `CsrAccess` trait so BFS bodies work generically over heap-resident `CsrGraph` and mmap-backed `MmapCsrGraph`.
- `src/graph.rs` — synthetic graph generators: homogeneous (`generate_graph` / `GraphConfig`) and power-law (`generate_power_law_graph` / `PowerLawConfig`).
- `src/mmap_csr.rs` — alternative CSR backed by an mmap'd tmpfs file (see the `mmap` bench mode below).
- `src/main.rs` — CLI, timing harness, measurement helpers (degree distribution, variance multiplier κ, friendship-paradox branching), and the verbose correctness test suite.

Cross-compile for Raspberry Pi via the flake:

```sh
nix build .#packages.aarch64-linux.bench
```

## Synthetic Graph Topology

Trust edges are binary (present or absent) and directional. The decay constant is 0.7 per hop, with a maximum traversal depth of 3 hops.

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

Target selection is **preferentially attached**: each user's targets are sampled with weight `1/(rank+1)^α` where `α=0.8`. The in-degree rank order is shuffled independently of the out-degree tier, so being a "power user" does not force you to also be a "top celebrity" — the two power-law axes are decoupled. At 50K users this produces a top in-degree around 8K–15K. The mean out-degree is ≈11 (matching the homogeneous scenarios), but the variance multiplier κ = E[d²]/E[d]² is ≈5× — matching the doc's prediction.

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

> **Counter-intuitive finding:** at equal local-user count, the federated power-law has *less* hub concentration than the single-instance power-law. The 100M-user federation pool dilutes cross-vouches across many more potential targets than a 50K local pool concentrates intra-vouches. Single-instance power-law remains the more demanding hub-concentration stress test.

### mmap bench mode

`bench mmap` A/B-compares BFS perf on two CSR backings: the regular heap-resident `CsrGraph` and an `MmapCsrGraph` whose `offsets` / `targets` arrays live in a tmpfs file the process mmaps back. Builds a heap CSR, serialises it to `/dev/shm`, mmaps the file, runs the same BFS body against both backings on the same 100 sample sources, and reports p50/p90/p99 timings side by side. Also runs a correctness check (heap and mmap must return identical trust scores) and a `madvise(MADV_DONTNEED)` pass that demonstrates the mmap pages stay in the page cache on tmpfs (the next access doesn't re-read the file — it just re-establishes the process's page-table entries). Same `--local-users N` override as `fed-power-law`.

## Example results

These results are from a test run on a Raspberry Pi 4. Even on modest hardware, forward and backwards trust computations for 100 users (simulated page load) in the "federation power law" scenario takes 1ms on average, <20ms p99:

============================================================
Benchmark: Federated Power-Law (50K local users, ~100M conceptual)
============================================================
federation env: 10000 instances × 10000 mean users ≈ 100,000,000 conceptual users (α_size=1.2, α_target=0.8)
home: 50000 local users, local_preference=0.5

Projected (analytical pre-flight):
cross-edges from home:   275,000
unique remote hubs hit:  233,739
materialised frontier:   12,484,915 nodes (249.7× local)
total edges:             31,403,548
CSR memory (forward+reverse): 334.8 MB
NodeIndex memory:        476.3 MB
Steady-state memory:     811.1 MB
Rebuild peak memory:     2.2 GB (size against this)

Graph generation:  28319.2ms
nodes: 16,250,781  edges: 29,570,165
local users: 50,000   remote frontier: 16,200,781 (324.0× local)

CSR build:         3888.3ms
forward:  offsets=16250782 targets=29570165
reverse:  offsets=16250782 targets=29570165
memory:   349.6 MB (forward + reverse CSR, no index)
RSS delta: 16.4 MB → 587.9 MB (+571.4 MB)
distrust edges: 7511  distrusters: 5000

Estimator vs measurement:
frontier nodes:  est 12,484,915  actual 16,250,781  ratio 1.30×
total edges:     est 31,403,548  actual 29,570,165  ratio 0.94×
CSR bytes:       est 334.8 MB  actual 349.6 MB
NodeIndex bytes: est 476.3 MB (analytical — not materialised in this bench)
Rebuild peak:    est 2.2 GB (production rebuild — uuid_edges + dense_edges + dual graphs)

Degree distribution (power-law topology):
in-degree:  max=5432  p99=12  p90=3  p50=1
out-degree: max=200  p99=50  p90=5  p50=0
top-10 in-degree share: 0.1% (25936 of 29570165 total inbound edges)

Variance multiplier κ = E[d²]/E[d]² = 32.52× (E[d]=1.8, E[d²]=108)
homogeneous baseline κ = 1.0; doc predicts ≈5× for the modelled distribution
Friendship-paradox branching at hop 2/3: 4.0 (mean out-degree = 1.8)

Rebuild-peak probe: allocating 2.1 GB (old CSR stand-in + sorted-Vec NodeIndex + HashMap NodeIndex mid-build)

Forward BFS (relevance) — 100 samples:
min: 0.090ms  p50: 0.295ms  p99: 17.159ms  max: 17.159ms  mean: 1.034ms
avg reachable targets: 1337

Reverse BFS (visibility) — 100 samples:
min: 0.000ms  p50: 0.020ms  p99: 0.488ms  max: 0.488ms  mean: 0.041ms
avg reachable sources: 98

Dual BFS (simulated page load) — 100 samples:
p50: 0.348ms  p99: 17.259ms  mean: 1.084ms

Peak RSS: 2.4 GB
