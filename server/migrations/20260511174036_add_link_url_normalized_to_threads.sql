-- Add `link_url_normalized` column to `threads` and backfill from
-- existing `link_url` values. The normalized form strips the scheme
-- (`http://` / `https://`) and a leading `www.`, so those near-universal
-- tokens never enter `threads_fts` once the URL column is folded into
-- the index in the next migration. Without this, a search for "https"
-- or "www" would match every link-bearing thread, filling the
-- candidate pool with noise.
--
-- The raw `link_url` is kept for display and click-through; only this
-- normalized form is indexed. New rows populate both columns from the
-- application layer (see `normalize_url_for_fts` in
-- `server/src/threads/common.rs`); this migration backfills the
-- existing rows.

ALTER TABLE threads ADD COLUMN link_url_normalized TEXT;

-- Backfill: case-insensitive prefix strip on scheme + leading `www.`.
-- Order matters — longer prefixes must come first so e.g.
-- `https://www.foo` matches the 12-char arm before the 8-char arm.
-- Inner occurrences of `https://` or `www.` are intentionally left
-- alone (archive-style URLs may embed another URL in the path).
UPDATE threads
SET link_url_normalized = CASE
    WHEN lower(substr(link_url, 1, 12)) = 'https://www.' THEN substr(link_url, 13)
    WHEN lower(substr(link_url, 1, 11)) = 'http://www.'  THEN substr(link_url, 12)
    WHEN lower(substr(link_url, 1, 8))  = 'https://'     THEN substr(link_url, 9)
    WHEN lower(substr(link_url, 1, 7))  = 'http://'      THEN substr(link_url, 8)
    WHEN lower(substr(link_url, 1, 4))  = 'www.'         THEN substr(link_url, 5)
    ELSE link_url
END
WHERE link_url IS NOT NULL;
