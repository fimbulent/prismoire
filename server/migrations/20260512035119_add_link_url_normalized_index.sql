-- Partial index supporting exact-equality lookups on
-- `threads.link_url_normalized` for the "suggest existing threads with
-- this same link" feature on the new-thread page.
--
-- The column is nullable (text threads have no link), and only
-- link-bearing rows will ever satisfy the lookup, so a partial index
-- on `WHERE link_url_normalized IS NOT NULL` is both smaller and the
-- only set of rows the query plan needs.

CREATE INDEX IF NOT EXISTS threads_link_url_normalized_idx
    ON threads(link_url_normalized)
    WHERE link_url_normalized IS NOT NULL;
