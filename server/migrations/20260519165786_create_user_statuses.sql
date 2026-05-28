-- Phase 11 of federation: current user-status projection table
-- (docs/federation-protocol.md §16; docs/federation-impl-plan.md
-- Phase 11).
--
-- One row per user public key for which this instance has applied (or
-- superseded into) a §5.10 `user-status` object. The row carries the
-- §16.3 latest-wins-by-`created_at` resolution (ties broken by
-- canonical_hash bytewise compare), plus the winning object's
-- canonical_hash so subsequent inbound statuses can apply the same
-- rule in O(1) without re-walking the chain.
--
-- The signed bytes themselves live in `signed_objects`
-- (inner_class = 'user-status'); this table is only the resolved
-- current view + the §16.3 latest-wins anchor. By-hash chain backfill
-- (§16.3) serves from `signed_objects` directly, so no separate chain
-- index lives here.
CREATE TABLE IF NOT EXISTS user_statuses (
    -- Ed25519 public key of the subject user (raw 32 bytes). Matches
    -- the `subject` field of §5.10 `user-status` payloads and the
    -- `users.public_key` column for local users.
    subject BLOB PRIMARY KEY NOT NULL
            CHECK (length(subject) = 32),

    -- Resolved current status kind. CHECK mirrors `UserStatusKind`.
    status TEXT NOT NULL
            CHECK (status IN ('active', 'suspended', 'banned')),

    -- Unix milliseconds UTC. Present iff `status = 'suspended'` AND
    -- the suspension has a fixed end time; NULL otherwise. Copied
    -- verbatim from the winning object's `suspended_until` field.
    suspended_until INTEGER,

    -- Bare canonical domain of the issuing instance (the subject's
    -- home at the object's `created_at`). Copied verbatim from the
    -- winning object's `signing_instance`.
    signing_instance TEXT NOT NULL
            CHECK (length(signing_instance) > 0),

    -- Optional human-readable reason, copied verbatim from the
    -- winning object. NULL when the issuer omitted it.
    reason TEXT,

    -- Wire timestamp of the winning object (Unix milliseconds UTC),
    -- copied verbatim. The §16.3 latest-wins comparison reads this
    -- column directly; receivers MUST NOT re-derive it from a local
    -- clock.
    current_created_at INTEGER NOT NULL,

    -- SHA-256 (32 bytes) of the winning object's canonical payload
    -- bytes. Joins back to `signed_objects.canonical_hash`.
    current_status_hash BLOB NOT NULL
            CHECK (length(current_status_hash) = 32),

    -- ISO-8601 timestamp of the most recent UPSERT against this row.
    -- Operator-visible only — distinct from `current_created_at`
    -- (signer's wall clock).
    updated_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
