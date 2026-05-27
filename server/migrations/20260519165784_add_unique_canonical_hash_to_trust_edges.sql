-- Add a partial UNIQUE index on `trust_edges.canonical_hash`.
--
-- Background: `canonical_hash` was added in 20260516174223 as a
-- nullable BLOB with no constraint, because legacy unsigned rows
-- (predating 20260516010149) carry NULL there. The Phase 9.6
-- federated-edge projection path (`try_project_trust_edge`) relies
-- on `canonical_hash` being unique for its idempotency
-- short-circuit:
--
--     SELECT 1 FROM trust_edges WHERE canonical_hash = ? LIMIT 1
--
-- If this returns a row the projection is treated as already done
-- and the INSERT is skipped. Without a schema-level UNIQUE, the
-- invariant was enforced only by SQLite's writer-serialization
-- (one writer at a time under WAL) plus BEGIN IMMEDIATE on the
-- receive path. That is safe in current code but fragile: a future
-- caller that omits BEGIN IMMEDIATE, or a future sweep that runs
-- outside a single transaction, could in principle double-insert.
--
-- The partial index makes the invariant schema-enforced for signed
-- rows while still permitting legacy NULL rows to coexist. The
-- explicit `WHERE canonical_hash IS NOT NULL` clause documents the
-- intent (signed rows are unique; unsigned rows are exempt) even
-- though SQLite already treats NULLs as distinct under a plain
-- UNIQUE.
CREATE UNIQUE INDEX IF NOT EXISTS idx_trust_edges_canonical_hash_unique
    ON trust_edges(canonical_hash)
    WHERE canonical_hash IS NOT NULL;
