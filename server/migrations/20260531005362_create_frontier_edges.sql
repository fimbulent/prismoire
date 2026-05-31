-- Phase 3 of root-advertisement federation: the reverse-frontier edge
-- store (docs/federation-protocol.md §8.9, §8.12).
--
-- The multi-source reverse BFS that grows this instance's frontier
-- traverses directed trust edges between pubkey-identified users. Those
-- users are overwhelmingly *remote* (their identity stubs live in
-- `frontier_users`, not `users`), so their edges cannot live in the
-- local-account `trust_edges` table (UUID-keyed, FK'd to `users.id`).
-- This table is the pubkey-keyed counterpart: one row per signed
-- `trust-edge` object learned through gossip, identified by source and
-- target Ed25519 keys.
--
-- Reverse traversal expands by *target*: to grow "who trusts X" the BFS
-- reads every edge whose `target_pubkey = X`. That is the hot path, so
-- `target_pubkey` is indexed. The edge `source` becomes a new frontier
-- node only as a consequence of its target being expanded (§9), so the
-- target gates relevance and drives the index.
--
-- The store is **append-mostly** (§8.12): a row is written once on
-- first receipt (deduped on `canonical_hash`) and never mutated except
-- to restamp its `generation` GC tag. Nothing reaps an edge eagerly
-- when the last reader needing it drops; instead the generational
-- mark-sweep (§8.12, default K=3) sweeps edges whose `generation` falls
-- more than K behind the current rebuild generation. The reverse-BFS
-- rebuild is itself the mark phase.
--
-- All stances federate identically and are stored identically: `trust`,
-- `distrust`, and `neutral` (revocation tombstone) all append here. The
-- active graph is derived at read time by resolving each
-- `(source, target)` chain to its latest stance and dropping `neutral`
-- tombstones, mirroring the local `current_trust_edges` view — this
-- table is the log, not the resolved graph.
--
-- Like `frontier_users`, this holds only edges between keys learned
-- through gossip about *remote* identities; it is not user-owned PII of
-- any local account and stays outside the GDPR export/delete surface in
-- `server/src/privacy.rs`. A local user's own outbound edges live in
-- `trust_edges`.

CREATE TABLE IF NOT EXISTS frontier_edges (
    -- Canonical hash of the signed `trust-edge` object
    -- (signed-payload-format.md §4.3). The dedup key: a redelivered
    -- edge collides here and is a no-op (§9 idempotency). Raw 32 bytes.
    canonical_hash BLOB PRIMARY KEY NOT NULL
            CHECK (length(canonical_hash) = 32),

    -- Ed25519 public key of the truster (raw 32 bytes). Becomes a new
    -- frontier node when its target is expanded.
    source_pubkey BLOB NOT NULL
            CHECK (length(source_pubkey) = 32),

    -- Ed25519 public key of the trustee (raw 32 bytes). The reverse BFS
    -- expands "who trusts this key" by reading all rows with this
    -- target; this is the traversal key.
    target_pubkey BLOB NOT NULL
            CHECK (length(target_pubkey) = 32),

    -- Canonical hash of the previous signed row for the same
    -- `(source, target)` pair, linking the per-pair chain (§9 chain
    -- continuity). NULL for the genesis edge of a pair. A non-NULL value
    -- whose predecessor is absent indicates a gap to backfill; that
    -- buffering happens in `pending_trust_edges`, not here.
    prior_edge_hash BLOB
            CHECK (prior_edge_hash IS NULL OR length(prior_edge_hash) = 32),

    -- Resolved stance carried by this signed object, denormalised out
    -- of `payload` so chain resolution and the active-graph derivation
    -- do not re-parse the CBOR. CHECK mirrors the local edge stances.
    stance TEXT NOT NULL
            CHECK (stance IN ('trust', 'distrust', 'neutral')),

    -- Unix milliseconds UTC from the signed object's `created_at`. Used
    -- to order the per-pair chain when resolving the active stance.
    created_at INTEGER NOT NULL,

    -- The full signed `trust-edge` WireFormat object (signed-payload-
    -- format.md §3), retained for re-forwarding (§7.5) and backfill
    -- responses (§9 chain continuity) without reconstructing the bytes.
    payload BLOB NOT NULL,

    -- Ed25519 signature over the payload (raw 64 bytes). Retained so a
    -- re-forwarded edge carries its original author signature.
    signature BLOB NOT NULL
            CHECK (length(signature) = 64),

    -- §8.12 generational GC tag. Restamped with the current rebuild
    -- generation whenever the reverse BFS marks this edge live. The
    -- sweep deletes edges whose `generation` is more than K generations
    -- behind the current one (default K=3).
    generation INTEGER NOT NULL DEFAULT 0
            CHECK (generation >= 0),

    -- ISO-8601 timestamp of the most recent write touching this row
    -- (initial insert or generation restamp). Operator-visible only;
    -- the sweep keys off `generation`, not this column.
    updated_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Reverse-BFS expansion hot path: "who trusts X" reads every edge whose
-- target is X. Without this index each expansion hop is a full-table
-- scan over the whole frontier edge set.
CREATE INDEX IF NOT EXISTS idx_frontier_edges_target
    ON frontier_edges(target_pubkey);

-- Per-pair chain resolution (latest stance per `(source, target)`) and
-- predecessor lookup during backfill walk the pair together.
CREATE INDEX IF NOT EXISTS idx_frontier_edges_pair
    ON frontier_edges(source_pubkey, target_pubkey);

-- The §8.12 sweep deletes by generation watermark
-- (`WHERE generation < current_generation - K`); the index turns the
-- full-table scan into a range read over edges actually due for
-- eviction.
CREATE INDEX IF NOT EXISTS idx_frontier_edges_generation
    ON frontier_edges(generation);
