-- Convert `trust_edges` from one-row-per-pair to append-only signed log
-- per docs/signed-payload-format.md §4.3 (Option C).
--
-- Changes:
-- 1. Drop UNIQUE(source_user, target_user) so multiple historical rows
--    can coexist for the same pair. Each PUT or DELETE handler call
--    appends a new signed row; the "current" stance is the latest
--    non-neutral row per pair.
-- 2. Relax the CHECK constraint to allow `trust_type = 'neutral'`. A
--    `neutral` row is a signed tombstone — federated for chain
--    continuity but contributes nothing to the trust graph.
-- 3. Add `current_trust_edges` view exposing the latest non-neutral
--    row per pair. All read sites switch to this view; the underlying
--    table is used only by writers and by code that needs full
--    history (`prior_edge_hash` lookup).
--
-- SQLite cannot DROP a UNIQUE constraint in place, so we rebuild the
-- table. Other tables don't FK to `trust_edges`, so the rebuild is
-- self-contained.

CREATE TABLE trust_edges_new (
    id TEXT PRIMARY KEY NOT NULL,
    source_user TEXT NOT NULL REFERENCES users(id),
    target_user TEXT NOT NULL REFERENCES users(id),
    trust_type TEXT NOT NULL CHECK (trust_type IN ('trust', 'distrust', 'neutral')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    reason TEXT,
    signature BLOB,
    prior_edge_hash BLOB,
    format_version INTEGER NOT NULL DEFAULT 1
);

INSERT INTO trust_edges_new
    (id, source_user, target_user, trust_type, created_at, reason, signature, prior_edge_hash, format_version)
SELECT id, source_user, target_user, trust_type, created_at, reason, signature, prior_edge_hash, format_version
FROM trust_edges;

DROP TABLE trust_edges;
ALTER TABLE trust_edges_new RENAME TO trust_edges;

-- Hot paths: lookup by (source, target) with the latest row needed.
-- DESC on created_at + id makes the latest-row scan a single index
-- step rather than a sort.
CREATE INDEX idx_trust_edges_source ON trust_edges(source_user);
CREATE INDEX idx_trust_edges_target ON trust_edges(target_user);
CREATE INDEX idx_trust_edges_pair_recent
    ON trust_edges(source_user, target_user, created_at DESC, id DESC);

-- The "current state" view. Every read site that previously hit
-- `trust_edges` directly switches to this view; writers still hit
-- the table.
--
-- TODO(perf): the view scales with the *total log size*, not the
-- number of active pairs — `ROW_NUMBER() OVER (PARTITION BY ...)`
-- walks every historical row to find the latest per pair. Admin
-- aggregates (`admin_overview.rs` count queries) and per-user
-- counts in `users.rs` will slow down as users accumulate
-- trust-edge mutation history. Mitigations to consider when this
-- bites: (1) periodic compaction that prunes superseded rows
-- outside a retention window; (2) a materialised current-state
-- table maintained by triggers on INSERT into `trust_edges`. Both
-- preserve the log shape externally while keeping reads O(active
-- pairs).
--
-- Row selection per `(source_user, target_user)`:
-- - `created_at DESC` — spec §4.3 "latest-wins by timestamp"
-- - `id DESC` — deterministic in-SQL tiebreaker on ties
--   (federation-correct tiebreak is bytewise comparison of
--   `canonical_hash`, which the SQL layer cannot do via ORDER BY in
--   a portable way; the Rust-side prior-hash lookup in
--   `signing::compute_prior_edge_hash` applies that comparison
--   when picking the chain predecessor)
-- - filter `trust_type != 'neutral'` — neutral rows are tombstones,
--   not edges
CREATE VIEW current_trust_edges AS
SELECT id, source_user, target_user, trust_type, created_at, reason,
       signature, prior_edge_hash, format_version
FROM (
    SELECT te.*, ROW_NUMBER() OVER (
        PARTITION BY source_user, target_user
        ORDER BY created_at DESC, id DESC
    ) AS rn
    FROM trust_edges te
) ranked
WHERE rn = 1 AND trust_type != 'neutral';
