-- Phase 12 reverse-frontier wiring: record each frontier stub's
-- reverse-BFS hop distance so the §8.1 advertised filters can be
-- reconstructed from the store.
--
-- The reverse frontier is materialized by BFS outward from this
-- instance's local roots (hop 0). A stub is a non-root truster reached
-- at hop 1, 2, or 3 (never 0 — roots are local users and are never
-- stubbed; never >3 — MAX_DEPTH caps the BFS). The two advertised
-- filters are depth slices of this set (docs/federation-protocol.md
-- §8.1):
--
--   * visible_filter   — keys whose authored content we want: the full
--                        reverse frontier, hop 0..3.
--   * expansion_filter — keys whose inbound trust-edges we still want to
--                        discover deeper trusters: hop 0..2 only. We
--                        never expand past the hop-3 rim, so soliciting
--                        edges that target a hop-3 node wastes bandwidth.
--
-- `compute_local_frontier` reads this column to split the two filters;
-- without it both filters would have to carry the full frontier,
-- inflating the (≈10× larger) edge-interest filter.
--
-- Default 3 (visible-only, never expanded) is the conservative value
-- for any row written before this column existed: it keeps such a stub
-- in the content-interest filter but out of the edge-interest filter,
-- so a stale unknown-hop stub can never cause us to over-solicit edges.
ALTER TABLE frontier_users
    ADD COLUMN reverse_hop INTEGER NOT NULL DEFAULT 3
        CHECK (reverse_hop >= 1 AND reverse_hop <= 3);
