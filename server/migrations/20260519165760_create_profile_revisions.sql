-- Append-only signed log of user profile revisions per
-- docs/signed-payload-format.md §5.8.
--
-- Shape mirrors `trust_edges` (Option C log) deliberately — same
-- prior_*_hash chaining semantics, same canonical_hash on each signed
-- row, same "latest-wins by created_at" view contract. Every change
-- to a user's display_name / bio / avatar appends a new row; nothing
-- ever updates or deletes a row except payload erasure (account
-- deletion, see `privacy.rs::soft_delete_user`).
--
-- Why a new table and not a JSON column on `users`:
--   docs/tmp_schema_refactor.md §1.3 — display_name and bio currently
--   exist outside the signed-object model, which conflates server-side
--   user state with federated content. This migration moves them into
--   the signed-object world so they can be propagated to peers using
--   the same machinery as posts and trust-edges (federation-protocol.md
--   §10.1 inner-class routing).
--
-- Backfill: see `prismoire admin migrate profile-revisions-backfill`.
-- The backfill synthesizes a created_at = NOW() signed event per
-- local user with a stored signing key, using the user's current
-- display_name / bio as the payload. Documented in the refactor doc
-- as a one-time, deliberate compromise: the alternative (no backfill,
-- profiles start empty) leaves existing names outside the signed-
-- object model and the user-visible profile would flip to a
-- pubkey-hex placeholder until the user edits.

CREATE TABLE profile_revisions (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    -- Canonical bytes are the source of truth. These projection
    -- columns exist so reads (and FTS triggers if we add them later)
    -- don't have to round-trip through CBOR parsing.
    display_name TEXT NOT NULL,
    bio TEXT NOT NULL,
    -- 32-byte SHA-256 of the avatar attachment, or NULL.
    avatar_attachment_hash BLOB,
    -- Authored time in Unix milliseconds (the same value that lives in
    -- the canonical payload's `created_at`). Stored as INTEGER, not
    -- ISO-8601 text, so latest-wins ordering is a direct numeric
    -- comparison and ties never depend on string-format quirks.
    created_at INTEGER NOT NULL,
    -- 64-byte Ed25519 signature over the canonical CBOR payload.
    signature BLOB NOT NULL,
    -- SHA-256 of the canonical bytes of the prior profile object for
    -- the same user, or NULL when this is the user's first revision.
    prior_profile_hash BLOB,
    -- SHA-256 of this row's canonical bytes. Persisted (rather than
    -- recomputed on lookup) for the same reason as
    -- `trust_edges.canonical_hash`: post-rotation key changes must not
    -- silently rebind the chain.
    canonical_hash BLOB NOT NULL,
    format_version INTEGER NOT NULL DEFAULT 1
);

-- Lookups by user_id with the latest row needed. DESC on (created_at,
-- id) makes the latest-row scan a single index step, mirroring
-- `idx_trust_edges_pair_recent`.
CREATE INDEX idx_profile_revisions_user ON profile_revisions(user_id);
CREATE INDEX idx_profile_revisions_user_recent
    ON profile_revisions(user_id, created_at DESC, id DESC);

-- Current-state view: latest revision per user. Read sites that want
-- "the user's profile" hit this view; writers and prior-hash lookups
-- hit the table.
--
-- Row selection per `user_id`:
-- - `created_at DESC` — spec §5.8 "latest-wins by created_at"
-- - `id DESC` — deterministic in-SQL tiebreaker (federation-correct
--   tiebreak is bytewise comparison of canonical_hash; the Rust-side
--   `compute_prior_profile_hash` applies that comparison when picking
--   the chain predecessor)
--
-- No `trust_type != 'neutral'` analog — profiles have no tombstone
-- variant; an "erased" profile is one whose `signed_objects.payload`
-- has been NULLed by `privacy.rs::soft_delete_user`.
CREATE VIEW current_profile_revisions AS
SELECT id, user_id, display_name, bio, avatar_attachment_hash,
       created_at, signature, prior_profile_hash, canonical_hash,
       format_version
FROM (
    SELECT pr.*, ROW_NUMBER() OVER (
        PARTITION BY user_id
        ORDER BY created_at DESC, id DESC
    ) AS rn
    FROM profile_revisions pr
) ranked
WHERE rn = 1;
