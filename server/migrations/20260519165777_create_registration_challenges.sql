-- Phase 7 of federation: registration-challenge nonce store
-- (docs/federation-protocol.md §13.1 / §13.2;
-- docs/federation-impl-plan.md Phase 7).
--
-- One row per `registration-challenge` (signed-payload-format.md §5.5)
-- this instance has issued. The row is written at issuance time and
-- consumed (`consumed_at` stamped) when the signed challenge is
-- successfully verified per §13.2. Replay of an already-consumed
-- nonce is rejected with `nonce_replay`; replay of an unknown nonce
-- is rejected with `invalid_signature` (the challenge bytes the
-- client signed don't match anything we issued).
--
-- §13.2 acceptance predicates that this table participates in:
--   * `nonce` has not been consumed by a prior verify
--     → SELECT consumed_at FROM registration_challenges WHERE nonce = ?
--   * `now - created_at ≤ REGISTRATION_CHALLENGE_TTL` (600 s default)
--     → comparison against the `created_at` column.
--
-- The §13 ceremony is mostly local (browser ↔ destination instance);
-- this table lives on the destination only. The source instance is
-- never contacted, so no cross-instance schema synchronization is
-- needed.
--
-- GC: a sweeper periodically deletes rows where
--   created_at < now - (TTL + skew_margin)
-- so unconsumed nonces don't accumulate. The CHECK constraint on
-- `nonce` length pairs with `REGISTRATION_NONCE_BYTES = 32`.

CREATE TABLE IF NOT EXISTS registration_challenges (
    -- Server-issued CSPRNG nonce, 32 bytes raw. PRIMARY KEY because
    -- §13.2 enforces global single-use semantics: a given nonce
    -- never participates in more than one accepted verify.
    nonce BLOB PRIMARY KEY NOT NULL
            CHECK (length(nonce) = 32),

    -- Ed25519 public key of the user the challenge was issued for
    -- (raw 32 bytes). Recorded so a `nonce_replay` rejection can
    -- log which key tried to re-use the nonce without re-decoding
    -- the signed payload bytes.
    user_key BLOB NOT NULL
            CHECK (length(user_key) = 32),

    -- Wire timestamp of the challenge payload (Unix milliseconds
    -- UTC), copied verbatim. §13.2's TTL check compares this
    -- against the server's wall clock.
    created_at INTEGER NOT NULL,

    -- ISO-8601 timestamp the nonce was redeemed, or NULL if the
    -- nonce has not yet been consumed. `IS NULL` means "issued
    -- but not yet redeemed"; a value means "single-use budget
    -- spent — any further verify against this nonce returns
    -- `nonce_replay`."
    consumed_at TEXT NULL
);

-- GC sweep scans by issuance age (DELETE WHERE created_at < ?). The
-- PK index on `nonce` covers verify-time lookups; a secondary index
-- on `created_at` keeps the sweep linear in expired rows rather than
-- full-table.
CREATE INDEX IF NOT EXISTS idx_registration_challenges_created_at
    ON registration_challenges (created_at);
