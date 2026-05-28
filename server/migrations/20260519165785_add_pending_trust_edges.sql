-- Phase 9.8: durable buffer for `deferred` trust-edges.
--
-- §9.1's `deferred` status promises that the receiver holds the
-- orphan and autonomously issues §9.3 chain backfill to recover the
-- missing predecessor. Through Phase 9.7 this promise was a no-op:
-- `apply_one_edge` returned `Deferred` without persisting the bytes
-- and relied on a re-push from the sender to close the gap. This
-- table is the durable side of the spec promise.
--
-- Key shape: `PRIMARY KEY (source_pubkey, prior_edge_hash)`. The
-- impl plan calls for keying by `(author, prior_edge_hash)` so
-- per-author cap enforcement is a covered index lookup. The
-- side-effect — pre-predecessor fork siblings collapse to one
-- buffered orphan — is acceptable: §9.4's "both stored as evidence,
-- neither active" rule fires only once one sibling has *applied*,
-- and the second sibling's evidence treatment will happen at
-- re-push time after the predecessor lands.
--
-- Auxiliary indexes:
--
-- - `idx_pending_trust_edges_prior` is the arrival-side hot path:
--   when a new edge projects, look up every pending row whose
--   `prior_edge_hash` equals the just-projected `canonical_hash`
--   and drain the chain (`drain_pending_orphans_after`).
-- - `idx_pending_trust_edges_received_at` covers the TTL sweep
--   (`evict_expired_pending_trust_edges`) which scans for rows
--   older than `DEFERRED_ORPHAN_TTL` (default 1h per spec §9.6).
--
-- Why not FK to `signed_objects.canonical_hash` for `prior_edge_hash`:
-- the predecessor is by definition not yet in `signed_objects` when
-- the orphan lands (that's why we deferred). An FK would either
-- block the insert or require us to have stored the predecessor
-- separately, which defeats the buffer's purpose.
CREATE TABLE IF NOT EXISTS pending_trust_edges (
    source_pubkey   BLOB NOT NULL,
    target_pubkey   BLOB NOT NULL,
    prior_edge_hash BLOB NOT NULL,
    canonical_hash  BLOB NOT NULL,
    payload         BLOB NOT NULL,
    signature       BLOB NOT NULL,
    received_at     INTEGER NOT NULL,
    PRIMARY KEY (source_pubkey, prior_edge_hash)
);

CREATE INDEX IF NOT EXISTS idx_pending_trust_edges_prior
    ON pending_trust_edges(prior_edge_hash);

CREATE INDEX IF NOT EXISTS idx_pending_trust_edges_received_at
    ON pending_trust_edges(received_at);
