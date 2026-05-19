-- Canonical store for all signed-object classes.
--
-- Part of Phase A of the federation schema refactor (see
-- `docs/federation_planning.md` §1.9 (1)). Federation requires a clear
-- split between the canonical signed-bytes layer (the protocol form,
-- frozen by canonicalization rules) and the projection layer (the
-- local rows handlers actually read from). This table is the canonical
-- side: the verbatim CBOR bytes that were signed, addressed by the
-- SHA-256 of those bytes, paired with the Ed25519 signature.
--
-- Phase A introduces the table empty. Backfill from existing
-- `trust_edges` and `post_revisions` rows, and the dual-write path
-- from handlers, both land in Phase B. The corresponding projection
-- tables continue to carry their own `signature` / `canonical_hash`
-- columns for join-free verification on hot read paths
-- (federation_planning.md §1.9 (1) trade-off table).
--
-- The `inner_class` allowlist mirrors federation_planning.md §1.9 (1):
-- every signed class that persists beyond a single request and is
-- eligible to surface through generic federation-tier operations
-- (`/by-hash` backfill, by-author backfill, recovery export, gossip
-- replication, audit tooling). Ephemeral signed classes (envelope,
-- attest, registration/recovery challenge-response) are *not* stored
-- here. `report` is also excluded by design — the spec explicitly
-- forbids it from generic backfill — and gets its own dedicated
-- projection table in a later phase.
CREATE TABLE signed_objects (
    canonical_hash BLOB PRIMARY KEY NOT NULL,
    inner_class    TEXT NOT NULL CHECK (inner_class IN (
                       'post-rev', 'retract', 'admin-rm',
                       'trust-edge', 'profile', 'thread-create',
                       'thread-status', 'deactivate', 'move',
                       'user-status'
                   )),
    payload        BLOB NOT NULL,
    signature      BLOB NOT NULL,
    received_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX idx_signed_objects_class ON signed_objects(inner_class);
