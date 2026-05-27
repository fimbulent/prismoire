-- Phase 7 of federation: per-key move index for §12.3 backfill
-- (docs/federation-protocol.md §12.3 / §12.5; docs/federation-impl-plan.md
-- Phase 7).
--
-- `signed_objects` is keyed on `canonical_hash` and stores moves
-- intermixed with every other signed class. Serving §12.3
-- (`GET /federation/v1/moves/backfill?key=<hex>`) by scanning that
-- table and decoding each row to test the moving identity K would be
-- prohibitive — every move push would amplify into a full-table scan
-- on the next backfill request.
--
-- `user_moves` projects (canonical_hash, created_at) of every
-- accepted move per K so the chain-walk query becomes a keyset
-- pagination on `(user_key, created_at, canonical_hash)`, joined to
-- `signed_objects` for the payload bytes.
--
-- Population rules (see `apply_one_move` in `server/src/federation/moves.rs`):
--   * Every accepted move — both `applied` and `superseded` per §12.4
--     — gets a row. Both are chain evidence per §12.5; both must be
--     reachable via §12.3 so a peer rebuilding the chain sees both
--     branches of a §12.4 fork.
--   * `deferred` moves are NOT persisted (the canonical bytes never
--     entered `signed_objects` either), so they never insert here.
--   * `rejected` moves are NOT persisted.
--   * `duplicate` moves are NOT re-inserted — the row already exists.
--
-- Retention: indefinite, mirroring §12.5 retention of the underlying
-- `signed_objects` rows. There is no purge path; moves are tiny and
-- per-key counts stay in the single digits for any realistic identity
-- lifetime.

CREATE TABLE IF NOT EXISTS user_moves (
    -- Ed25519 public key of the moving identity K. Matches the
    -- `key` field of §5.1 `Move` payloads.
    user_key BLOB NOT NULL
            CHECK (length(user_key) = 32),

    -- SHA-256 (32 bytes) of the move's canonical payload bytes.
    -- Joins back to `signed_objects.canonical_hash` for the
    -- WireFormat payload + signature that §12.3 emits.
    canonical_hash BLOB NOT NULL
            CHECK (length(canonical_hash) = 32),

    -- Wire timestamp of the move (Unix milliseconds UTC), copied
    -- verbatim from the move payload. The §12.3 chain-walk orders
    -- ASC by this column with `canonical_hash` ASC as the
    -- deterministic tiebreaker so two moves with identical
    -- `created_at` (legal — `created_at` is per-millisecond) still
    -- produce a strict total order.
    created_at INTEGER NOT NULL,

    -- ISO-8601 timestamp of when this row was inserted. Operator-
    -- visible only — distinct from `created_at` (signer's wall clock).
    received_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    PRIMARY KEY (user_key, canonical_hash)
);

-- Covers the §12.3 chain-walk query
-- (`WHERE user_key = ? ORDER BY created_at, canonical_hash`).
-- The PK index is `(user_key, canonical_hash)` which serves point
-- lookups but not the ordered scan; this index makes the scan an
-- index range read.
CREATE INDEX IF NOT EXISTS idx_user_moves_chain_walk
    ON user_moves(user_key, created_at, canonical_hash);
