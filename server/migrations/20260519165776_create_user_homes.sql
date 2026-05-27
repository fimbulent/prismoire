-- Phase 7 of federation: resolved-current-home projection table
-- (docs/federation-protocol.md §12.1 / §12.4 latest-wins resolution;
-- docs/federation-impl-plan.md Phase 7).
--
-- One row per user public key for which this instance has *ever*
-- successfully applied (or superseded) a §5.1 move declaration. The
-- row carries the chain-grounded current home as resolved by §12.4
-- (latest-wins-by-timestamp, ties broken by canonical_hash bytewise
-- compare), plus the canonical_hash + created_at of the winning move
-- so subsequent inbound moves can apply the same rule in O(1).
--
-- Receive-time consultation points (Phase 7):
--   * `apply_admin_rm` (`content.rs`) — replaces the
--     `users.public_key`-only "are we the home of target_author?"
--     heuristic with a resolved-home lookup. Authoritative admin-rms
--     from any peer other than the resolved current home flip to
--     `wrong_route`; this closes the trust-on-first-claim window.
--   * Per-class routing-key resolution for any read path that needs
--     to know where to redirect a request for a moved user.
--
-- Population rules:
--   * On `applied` (current home flips to the move's `to_instance`):
--     UPSERT current_home_domain = move.to_instance,
--             current_move_hash  = canonical_hash,
--             current_created_at = move.created_at.
--   * On `superseded` (move loses §12.4 tiebreak): no UPSERT. The
--     row continues to reflect the §12.4 winner.
--   * The very first move for a key MAY arrive `superseded` only if
--     the receiver already has a later move for the same key; in
--     that case the row was already created by the later move and
--     the no-op is correct.
--
-- All-zero invariant: `current_home_domain` is never empty / NULL —
-- a row exists iff at least one chain-grounded move has applied.
-- Absence of a row means "no resolved home yet known" and callers
-- fall back to the local `users.public_key` lookup (which is the
-- receiver's authoritative answer for users it locally hosts and
-- has not yet seen migrate).

CREATE TABLE IF NOT EXISTS user_homes (
    -- Ed25519 public key of the moving identity (raw 32 bytes).
    -- Matches the `key` field of §5.1 `Move` payloads and the
    -- `users.public_key` column for local users.
    user_key BLOB PRIMARY KEY NOT NULL
            CHECK (length(user_key) = 32),

    -- Ed25519 `instance_pubkey` (raw 32 bytes) of the user's
    -- currently-resolved home instance. Copied verbatim from the
    -- winning move's `to_instance_key` field
    -- (signed-payload-format.md §5.1 + protocol §12). Per §3 of
    -- the protocol this is the *trust anchor* for "is the sender
    -- authoritative for K?" comparisons; `current_home_domain`
    -- below is mutable metadata kept alongside.
    current_home_key BLOB NOT NULL
            CHECK (length(current_home_key) = 32),

    -- Bare canonical domain of the user's currently-resolved home
    -- instance. Copied verbatim from the winning move's
    -- `to_instance` field; never empty.
    current_home_domain TEXT NOT NULL
            CHECK (length(current_home_domain) > 0),

    -- SHA-256 (32 bytes) of the canonical payload bytes of the
    -- winning `move` object. Joins back to
    -- `signed_objects.canonical_hash`; used by §12.3 backfill to
    -- serve the resolution chain without scanning every stored
    -- move.
    current_move_hash BLOB NOT NULL
            CHECK (length(current_move_hash) = 32),

    -- Wire timestamp of the winning move (Unix milliseconds UTC),
    -- copied verbatim from the move payload. The §12.4 latest-wins
    -- comparison reads this column directly; receivers MUST NOT
    -- re-derive it from a local clock.
    current_created_at INTEGER NOT NULL,

    -- ISO-8601 timestamp of the most recent UPSERT against this
    -- row. Operator-visible only — distinct from
    -- `current_created_at` (signer's wall clock) because we want
    -- to know when *we* learned of the latest resolution.
    updated_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Lookups in admin-rm receive-time validation and move-routed reads
-- are all by PK (user_key); the PK index covers them. No secondary
-- index is needed for the resolve-by-key hot path.
