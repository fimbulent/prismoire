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
cargo run -p prismoire-bench --release                # both benchmarks
cargo run -p prismoire-bench --release -- single      # single-instance (10K users)
cargo run -p prismoire-bench --release -- federation  # federation (10K instances, 1.1M nodes)
cargo run -p prismoire-bench --release -- test        # verbose correctness tests
cargo test -p prismoire-bench                         # cargo test suite (13 tests)
```

Cross-compile for Raspberry Pi via the flake:

```sh
nix build .#packages.aarch64-linux.bench
```

## Synthetic Graph Topology

Both scenarios assume **each user trusts 10 other users** on average. Trust edges are binary (present or absent) and directional. The decay constant is 0.7 per hop, with a maximum traversal depth of 3 hops.

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

## Example results

These results are from a test run on a Raspberry Pi 4. Even on modest hardware, forward and backwards trust computations for 100 users (simulated page load) in the "federation" scenario takes only 1ms:

```
Prismoire Trust Graph Benchmark
===============================
Algorithm: Bottleneck-Grouped Probabilistic (DECAY=0.7, MAX_DEPTH=3)

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