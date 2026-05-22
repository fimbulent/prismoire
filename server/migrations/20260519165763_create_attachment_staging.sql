-- Tracks uploaded blobs that aren't yet bound to a post
-- (docs/attachments.md §1, §3).
--
-- The two-step upload flow ("POST /api/attachments" first, then
-- "POST /api/threads" with the hash) needs to track "this hash isn't
-- bound to any post yet — sweep me if I expire" without the blob row
-- itself being GC-eligible (it could be deduped against a bound
-- blob). Staging is that separate ledger.
--
-- Keyed on content_hash (matches attachment_blobs.content_hash) so
-- staging an identical-bytes upload by a second user is a constraint
-- violation rather than two competing rows — the design defers
-- multi-user staging by collapsing to single-owner. The first
-- uploader's row stands; a second upload of the same hash on a fresh
-- staging row would race with the §5 GC. If this becomes a real
-- collision in practice (federation will not produce collisions here
-- per §3's encoder-non-determinism note), promote the PK to
-- (content_hash, uploader).
--
-- expires_at is the sweep target. The hourly sweeper deletes rows
-- past expiry; orphan blobs (refcount = 0 AND no staging row) get
-- dropped in the same pass. Budget is NOT refunded on staging sweep
-- (matches the spec: deletion doesn't reclaim allowance).
CREATE TABLE IF NOT EXISTS attachment_staging (
    content_hash BLOB NOT NULL PRIMARY KEY,
    uploader TEXT NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- §7.a sweeps a deleted user's staged-but-unbound uploads by uploader.
-- The hourly TTL sweep uses expires_at — both deserve their own
-- indexes since neither scan should require a full table walk.
CREATE INDEX IF NOT EXISTS idx_attachment_staging_uploader
    ON attachment_staging(uploader);
CREATE INDEX IF NOT EXISTS idx_attachment_staging_expires_at
    ON attachment_staging(expires_at);
