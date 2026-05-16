-- Step 7 of docs/signed-payload-format.md §9.3: expose the signed
-- payload's format version as a column on every table that stores a
-- signature, so a verifier can dispatch by version without parsing
-- the canonical CBOR payload.
--
-- `trust_edges.format_version` was added alongside the signature
-- columns in 20260516010149. This migration completes step 7 by
-- doing the same for the two remaining signed-row tables:
-- `post_revisions` (per-revision signature) and `posts`
-- (retraction signature, when the post is retracted).
--
-- Defaults to 1 because V1 is the only format currently emitted by
-- producers. Future schema migrations re-signing rows under V2+ will
-- bump this column for the affected rows.
ALTER TABLE post_revisions ADD COLUMN format_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE posts ADD COLUMN retraction_format_version INTEGER NOT NULL DEFAULT 1;
