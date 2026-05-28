-- Phase 11 of federation: federated report queue
-- (docs/federation-protocol.md §18; docs/federation-impl-plan.md
-- Phase 11).
--
-- Reports are a private channel from the reporter's home to the target
-- post's home (§18). They never gossip, never backfill, and are never
-- exposed on any user-facing API (§18.3). They land here purely to
-- feed the operator moderation queue.
--
-- Unlike user-status / thread-status, reports do NOT chain and are NOT
-- stored in `signed_objects` ('report' is not a `signed_objects`
-- inner_class). The §18.1 dedup key is `(post_id, reporter)`; we keep
-- the canonical_hash for audit ("show me the original signature")
-- without retaining the full WireFormat, since §18.2 guarantees no
-- backfill that would need to re-serve the bytes.
CREATE TABLE IF NOT EXISTS federated_reports (
    -- Stable row identity for log references and a future "dismiss
    -- this report" admin action. Text UUID matches the convention
    -- used by `admin_log.id` and `admin_rm_reports.id`.
    id TEXT PRIMARY KEY NOT NULL,

    -- Target post UUID (raw 16 bytes), from the signed report payload.
    post_id BLOB NOT NULL
            CHECK (length(post_id) = 16),

    -- Ed25519 pubkey of the target post's author (raw 32 bytes). By
    -- construction the local instance is this user's current home —
    -- the §18.1 handler rejects `wrong_recipient` before inserting.
    target_author BLOB NOT NULL
            CHECK (length(target_author) = 32),

    -- Ed25519 pubkey of the reporter (raw 32 bytes; the report
    -- signer). Identified per §18.3 for sybil/spam defense. Part of
    -- the §18.1 `(post_id, reporter)` dedup key.
    reporter BLOB NOT NULL
            CHECK (length(reporter) = 32),

    -- Bounded reason enum, copied verbatim from the report payload.
    -- CHECK mirrors `ReportReason`.
    reason TEXT NOT NULL
            CHECK (reason IN ('spam', 'rules_violation', 'illegal_content', 'other')),

    -- Optional reporter-supplied free-form detail. Length-bounded at
    -- sign time by `MAX_REPORT_DETAIL_LEN`; treated as untrusted input
    -- on the admin UI per §18.3. NULL when omitted.
    detail TEXT,

    -- SHA-256 (32 bytes) of the report's canonical payload bytes. The
    -- bytes themselves are not retained (no backfill); the hash lets
    -- an operator join an action back to the originating signature if
    -- the reporter's home re-supplies it.
    canonical_hash BLOB NOT NULL
            CHECK (length(canonical_hash) = 32),

    -- Report time, Unix milliseconds UTC, copied verbatim from the
    -- payload.
    created_at INTEGER NOT NULL,

    -- ISO-8601 timestamp of the row write. Drives admin queue display
    -- order ("oldest pending first").
    received_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    -- §18.1 idempotency: one stored report per (post_id, reporter).
    UNIQUE (post_id, reporter)
);
