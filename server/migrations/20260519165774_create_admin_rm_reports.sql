-- Phase 6 of federation: advisory admin-rm report queue
-- (docs/federation-protocol.md §10.4;
-- docs/federation-impl-plan.md Phase 6).
--
-- Stores advisory admin-rm objects received via
-- `POST /federation/v1/admin-rm-report` — signed by a moderator on a
-- non-home instance and addressed to the author's home so the home's
-- operators can review and decide whether to escalate to a local
-- authoritative admin-rm. Local-only state; never federated and
-- never erases payloads.
--
-- Dedup is per-target-post per §10.4: a second advisory for a post
-- that already has a row here returns `status: "duplicate"` and is
-- NOT re-enqueued. The first-reporter-wins rule keeps the admin
-- review queue bounded under abusive re-reporting from coordinated
-- non-home moderators.
--
-- No operator-facing route consumes this table in Phase 6; the queue
-- is populated for future admin UX (deferred per Phase 6 plan).

CREATE TABLE admin_rm_reports (
    -- Stable row identity for log references and a future "dismiss
    -- this report" admin action. Text UUID matches the convention
    -- used by `admin_log.id` and the rest of the moderation tables.
    id TEXT PRIMARY KEY NOT NULL,

    -- Target post UUID (raw 16 bytes), matching the `post_id` field
    -- of the signed admin-rm payload. Also the per-post dedup key —
    -- enforced via UNIQUE rather than PK so the surrogate `id` can
    -- be used for foreign-key references from future admin tables.
    post_id BLOB NOT NULL UNIQUE
            CHECK (length(post_id) = 16),

    -- Ed25519 pubkey of the post's author (raw 32 bytes). The home
    -- of this user is, by construction, the local instance — the
    -- handler rejects advisories where the receiver isn't the
    -- author's current home with `not_authoritative_home` before
    -- inserting here.
    target_author BLOB NOT NULL
            CHECK (length(target_author) = 32),

    -- Bare canonical domain of the moderator's instance (the
    -- envelope sender and the admin-rm signer; the §10.4 handler
    -- verifies both equal this string before insert). Per-source
    -- rate limiting groups rows by this field, so it gets an index.
    signing_instance TEXT NOT NULL,

    -- Optional human-readable justification, copied verbatim from
    -- the admin-rm payload's `reason` field. NULL when the signer
    -- omitted it. Length-bounded at write time by the same per-field
    -- cap that gates local admin-rm origination.
    reason TEXT,

    -- SHA-256 of the admin-rm's canonical payload bytes (32 bytes).
    -- The bytes themselves live in `signed_objects`; we keep the
    -- hash here so an operator action like "see the original
    -- signature" can join back without scanning by signer pubkey.
    canonical_hash BLOB NOT NULL
            CHECK (length(canonical_hash) = 32),

    -- ISO-8601 timestamp of the row write. Drives the
    -- per-source-instance rate-limit window
    -- (MAX_ADVISORY_REPORTS_PER_HOUR per §10.6) and the admin queue
    -- display order ("oldest pending first").
    received_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Hot path: the per-source-instance rate-limit query counts
-- `WHERE signing_instance = ? AND received_at >= ?` over the past
-- hour for every inbound advisory. Index `(signing_instance,
-- received_at)` makes that count an indexed-range scan instead of a
-- table scan.
CREATE INDEX idx_admin_rm_reports_source_received
    ON admin_rm_reports(signing_instance, received_at);
