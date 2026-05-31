-- Phase 3 of root-advertisement federation: filter terminology rename
-- (docs/federation-protocol.md §8.1–§8.5).
--
-- The redesign renames the two advertised Bloom filters:
--   * content filter      → visible_filter   (reverse-hop 0..3, the
--                           reader's content-interest set, matched on
--                           an object's author/routing key)
--   * edge-origin filter  → expansion_filter (reverse-hop 0..2, the
--                           reader's edge-interest set, matched on a
--                           trust-edge's target)
-- with the invariant expansion_filter ⊆ visible_filter.
--
-- This migration renames only the storage columns to match; the
-- routing-logic inversion (match on edge target, reverse-BFS) is a
-- separate later slice. `ALTER TABLE ... RENAME COLUMN` propagates the
-- new names into the table's own CHECK constraints (e.g. the
-- `length(cf_bytes) = cf_m / 8` byte-length checks), so no table
-- rebuild is needed — which also avoids disturbing the
-- `peer_frontier_age_ceilings` child FK that now references this table.

ALTER TABLE peer_frontiers RENAME COLUMN cf_family     TO visible_family;
ALTER TABLE peer_frontiers RENAME COLUMN cf_k          TO visible_k;
ALTER TABLE peer_frontiers RENAME COLUMN cf_m          TO visible_m;
ALTER TABLE peer_frontiers RENAME COLUMN cf_n_est      TO visible_n_est;
ALTER TABLE peer_frontiers RENAME COLUMN cf_fpr_target TO visible_fpr_target;
ALTER TABLE peer_frontiers RENAME COLUMN cf_bytes      TO visible_bytes;

ALTER TABLE peer_frontiers RENAME COLUMN ef_family     TO expansion_family;
ALTER TABLE peer_frontiers RENAME COLUMN ef_k          TO expansion_k;
ALTER TABLE peer_frontiers RENAME COLUMN ef_m          TO expansion_m;
ALTER TABLE peer_frontiers RENAME COLUMN ef_n_est      TO expansion_n_est;
ALTER TABLE peer_frontiers RENAME COLUMN ef_fpr_target TO expansion_fpr_target;
ALTER TABLE peer_frontiers RENAME COLUMN ef_bytes      TO expansion_bytes;
