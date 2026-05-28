-- Phase 11 of federation: current thread-status (lock state)
-- projection table (docs/federation-protocol.md §17;
-- docs/federation-impl-plan.md Phase 11).
--
-- One row per thread UUID for which this instance has applied (or
-- superseded into) a §5.12 `thread-status` object. The row carries the
-- §17.3 latest-wins-by-`created_at` resolution (ties broken by
-- canonical_hash bytewise compare).
--
-- The local enforcement column is `threads.locked`; the §17.1 handler
-- mirrors the resolved lock state there when the thread is known
-- locally so the existing reply-rejection path (`create_reply.rs`)
-- honours federated locks. This table additionally records federated
-- locks for threads not (yet) projected into `threads`, and carries
-- the §17.3 latest-wins anchor.
--
-- Signed bytes live in `signed_objects` (inner_class =
-- 'thread-status'); by-hash chain backfill (§17.3) serves from there.
CREATE TABLE IF NOT EXISTS thread_statuses (
    -- Target thread UUID (raw 16 bytes). Matches the `thread_id`
    -- field of §5.12 `thread-status` payloads.
    thread_id BLOB PRIMARY KEY NOT NULL
            CHECK (length(thread_id) = 16),

    -- Resolved current lock state. CHECK mirrors `ThreadStatusKind`.
    status TEXT NOT NULL
            CHECK (status IN ('open', 'locked')),

    -- Bare canonical domain of the thread's home instance (the
    -- issuer). Copied verbatim from the winning object's
    -- `signing_instance`.
    signing_instance TEXT NOT NULL
            CHECK (length(signing_instance) > 0),

    -- Optional human-readable reason, copied verbatim. NULL when the
    -- issuer omitted it.
    reason TEXT,

    -- Wire timestamp of the winning object (Unix milliseconds UTC),
    -- copied verbatim. The §17.3 latest-wins comparison reads this
    -- column directly.
    current_created_at INTEGER NOT NULL,

    -- SHA-256 (32 bytes) of the winning object's canonical payload
    -- bytes. Joins back to `signed_objects.canonical_hash`.
    current_status_hash BLOB NOT NULL
            CHECK (length(current_status_hash) = 32),

    -- ISO-8601 timestamp of the most recent UPSERT against this row.
    updated_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
