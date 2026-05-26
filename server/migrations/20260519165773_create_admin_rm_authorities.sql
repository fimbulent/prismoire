-- Phase 6 of federation: authoritative admin-rm projection table
-- (docs/federation-protocol.md §10.4 receive-time precedence;
-- docs/federation-impl-plan.md Phase 6).
--
-- Indexed lookup target for the §10.4 receive-time precedence check:
-- when an inbound `post-rev` or `retract` is ingested via §10.1,
-- between signature verification and the consumption-store write the
-- receiver consults this table by `post_id`. A hit means the post
-- has been authoritatively admin-removed; the inbound object is
-- rejected with `admin_removed` and is NOT re-forwarded. This avoids
-- storage churn on the GC → re-accept → GC cycle that would
-- otherwise happen for stale gossip replays of admin-removed content.
--
-- Authoritative-only: per §10.4 only an admin-rm whose signing
-- instance equals the target post author's home instance is
-- authoritative. Advisory admin-rms (signer ≠ home) route to
-- `admin_rm_reports` via `POST /federation/v1/admin-rm-report`
-- instead and are never inserted here.
--
-- PRIMARY KEY (post_id) enforces "first-and-only" semantics:
-- admin-removal is terminal, so the first authoritative admin-rm
-- wins and any subsequent admin-rm targeting the same post resolves
-- to `duplicate` via the dedup check in `signed_objects`.

CREATE TABLE admin_rm_authorities (
    -- Target post UUID (raw 16 bytes), matching the `post_id` field
    -- of the signed admin-rm payload (signed-payload-format.md §5.2).
    -- Same identity used by `posts.id` (stored as text-uuid in that
    -- table; this table uses the raw 16-byte form because §10.4
    -- receive-time lookups compare against the wire payload).
    post_id BLOB PRIMARY KEY NOT NULL
            CHECK (length(post_id) = 16),

    -- Ed25519 pubkey of the targeted post's author (raw 32 bytes).
    -- Persisted so an operator dashboard can render the affected
    -- user without a JOIN through `posts`/`users`, and so
    -- receive-time checks can short-circuit when the post itself
    -- isn't locally known (only the authority matters).
    target_author BLOB NOT NULL
            CHECK (length(target_author) = 32),

    -- Bare canonical domain of the issuing (signing) instance — must
    -- equal the home instance of `target_author` at the time the
    -- admin-rm was signed. Persisted for operator audit; the
    -- authoritative-vs-advisory routing decision happens at ingest
    -- time, so this field is informational here.
    signing_instance TEXT NOT NULL,

    -- Removal time, Unix milliseconds UTC, copied verbatim from the
    -- admin-rm payload. Lets the dashboard sort by recency without
    -- re-parsing canonical bytes.
    created_at INTEGER NOT NULL,

    -- SHA-256 of the admin-rm's canonical payload bytes (32 bytes).
    -- Joins back to `signed_objects.canonical_hash` so a §10.5
    -- backfill request for an admin-removed post can serve the
    -- admin-rm bytes as the `410 Gone` body without a content scan.
    canonical_hash BLOB NOT NULL
            CHECK (length(canonical_hash) = 32),

    -- ISO-8601 timestamp of the row write. Operator-visible only;
    -- distinct from `created_at` (wire timestamp from the signer)
    -- because clock skew between instances is real and we want to
    -- know when *we* learned about the removal.
    received_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Receive-time precedence is the hot path; the PK index covers all
-- `WHERE post_id = ?` lookups, so no secondary index is needed.
