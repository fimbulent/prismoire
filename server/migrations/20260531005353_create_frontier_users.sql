-- Phase 2 of root-advertisement federation: lean local materialization
-- of remote frontier nodes (docs/federation-protocol.md §8.11).
--
-- The reverse frontier reachable from this instance's local roots
-- contains pubkey-identified users hosted on *other* instances. We do
-- not (and must not) create full `users` rows for them — they have no
-- local account, no credential, no profile we own. §8.11 specifies a
-- separate lean stub table whose memory footprint scales O(U^β),
-- β≈0.54, so a single instance can materialize the frontier of a
-- multi-million-user federation without paying per-node `users` cost.
--
-- One row per remote user key that currently appears as a node in any
-- of our gossiped reverse frontiers. The row carries only what the
-- routing / rendering paths need:
--   * the home instance the key currently advertises from (so a read
--     that surfaces a frontier author can be routed/backfilled), and
--   * an optional human-facing display name carried opportunistically
--     in gossip (NULL until/unless a peer supplies one — §8.11 keeps
--     this best-effort and non-authoritative).
--
-- The `generation` column drives the §8.12 mark-sweep GC: each rebuild
-- cadence stamps live stubs with the current generation; stubs older
-- than K generations (default K=3) are swept. This is the local
-- counterpart of the edge eviction that the same GC pass applies to
-- the (Phase 3) frontier edge store.
--
-- This table holds only keys learned from gossip about *remote*
-- identities; it is not user-owned PII of any local account, so it is
-- outside the GDPR export/delete surface in `server/src/privacy.rs`
-- (which covers data owned by *this instance's* users). A local user
-- who also appears in some peer's frontier is represented in their
-- home instance's `users` table, not here.

CREATE TABLE IF NOT EXISTS frontier_users (
    -- Ed25519 public key of the remote frontier identity (raw 32
    -- bytes). Matches the `key` field of §5.1 payloads and the
    -- routing key used by reverse-BFS frontier traversal. This is the
    -- stub's identity; there is at most one stub per key.
    user_key BLOB PRIMARY KEY NOT NULL
            CHECK (length(user_key) = 32),

    -- Ed25519 `instance_pubkey` (raw 32 bytes) of the instance this
    -- key currently advertises its home from, as last learned through
    -- gossip. Used to route/backfill content authored by the frontier
    -- node. Distinct from `user_homes.current_home_key`, which is the
    -- chain-grounded resolution for keys we have applied a §5.1 move
    -- for; a frontier stub may exist for a key we have never seen a
    -- move chain for.
    home_instance_key BLOB NOT NULL
            CHECK (length(home_instance_key) = 32),

    -- Bare canonical domain of the home instance, carried alongside
    -- the key for operator-facing rendering and backfill URL
    -- construction. Never empty.
    home_instance_domain TEXT NOT NULL
            CHECK (length(home_instance_domain) > 0),

    -- Opportunistic, non-authoritative display name carried in gossip
    -- (§8.11). NULL until a peer supplies one. Renderers MUST treat a
    -- NULL as "unknown" and fall back to a key-derived handle rather
    -- than assuming a name is always present.
    display_name TEXT,

    -- §8.12 generational GC tag. Stamped with the current rebuild
    -- generation whenever this stub is observed live during a frontier
    -- rebuild. The sweep phase deletes stubs whose `generation` is
    -- more than K generations behind the current one (default K=3).
    generation INTEGER NOT NULL DEFAULT 0
            CHECK (generation >= 0),

    -- ISO-8601 timestamp of the most recent UPSERT against this row.
    -- Operator-visible only; the GC sweep keys off `generation`, not
    -- this column.
    updated_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- The §8.12 sweep deletes by generation watermark
-- (`WHERE generation < current_generation - K`). Without an index this
-- is a full-table scan every rebuild cadence; the index makes it a
-- range read over the stubs actually due for eviction.
CREATE INDEX IF NOT EXISTS idx_frontier_users_generation
    ON frontier_users(generation);
