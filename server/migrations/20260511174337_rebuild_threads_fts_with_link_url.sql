-- Rebuild `threads_fts` with a third indexed column: `link_url`.
--
-- FTS5 virtual tables can't be `ALTER`ed to add a column, so the only
-- path is drop-and-recreate. Triggers depending on the old shape are
-- dropped first, the table is recreated with the new column, the
-- triggers are recreated to maintain it, and the table is backfilled
-- from `threads`.
--
-- Why `link_url` here instead of a separate FTS table: it lets the
-- existing FTS5 column-filter syntax (`title:foo`, `link_url:bar`,
-- `{title link_url}:baz`) work natively across all three columns, and
-- collapses the previous URL-substring LIKE pool in
-- `search_threads_core` into a single index-bound MATCH query.
--
-- Why `unicode61` and not `trigram`: the tokenizer is table-wide in
-- FTS5, and switching `title` / `op_body` to `trigram` would degrade
-- BM25 ranking on natural-language content. `unicode61` already splits
-- URLs into word tokens (`.`, `/`, `:`, `?`, `&`, `#` are all token
-- boundaries by default), so URL fragments index as
-- `["github", "com", "anthropics", ...]` — searching by domain or path
-- segment works without trigram's tradeoffs.
--
-- The indexed form comes from `threads.link_url_normalized` (populated
-- by `normalize_url_for_fts` on insert; backfilled in the previous
-- migration). That strips `http(s)://` and a leading `www.` so those
-- near-universal tokens never enter the index.

-- ---------------------------------------------------------------------------
-- Drop the old `threads_fts` and its maintenance triggers
-- ---------------------------------------------------------------------------

DROP TRIGGER IF EXISTS threads_fts_after_insert;
DROP TRIGGER IF EXISTS threads_fts_after_delete;
DROP TRIGGER IF EXISTS threads_fts_after_update_title;
DROP TRIGGER IF EXISTS threads_fts_op_body_after_revision;
DROP TRIGGER IF EXISTS threads_fts_op_after_retract;
DROP TABLE IF EXISTS threads_fts;

-- ---------------------------------------------------------------------------
-- Recreate `threads_fts` with `link_url` as a third column
-- ---------------------------------------------------------------------------

CREATE VIRTUAL TABLE threads_fts USING fts5(
    title,
    op_body,
    link_url,
    content='',
    tokenize = "unicode61 remove_diacritics 2"
);

-- ---------------------------------------------------------------------------
-- Triggers: threads_fts maintenance (parallels the original migration)
-- ---------------------------------------------------------------------------

-- New thread → insert FTS row with empty op_body (filled in by the
-- post_revisions trigger when the OP's first revision lands) and the
-- normalized link_url (NULL becomes the empty string so FTS5 has a
-- defined cell).
CREATE TRIGGER threads_fts_after_insert
AFTER INSERT ON threads
BEGIN
    INSERT INTO threads_fts (rowid, title, op_body, link_url)
    VALUES (NEW.rowid, NEW.title, '', COALESCE(NEW.link_url_normalized, ''));
END;

-- Thread deleted → drop FTS row.
CREATE TRIGGER threads_fts_after_delete
AFTER DELETE ON threads
BEGIN
    DELETE FROM threads_fts WHERE rowid = OLD.rowid;
END;

-- Title edited → rewrite FTS title cell.
CREATE TRIGGER threads_fts_after_update_title
AFTER UPDATE OF title ON threads
BEGIN
    UPDATE threads_fts
    SET title = NEW.title
    WHERE rowid = NEW.rowid;
END;

-- `link_url_normalized` is populated once at INSERT time and is
-- otherwise immutable (the URL itself is immutable post-creation;
-- see threads/create_thread.rs). No update trigger needed today; if
-- a future feature ever lets a user edit the URL of an existing
-- link post, mirror this with an
-- `AFTER UPDATE OF link_url_normalized` trigger.

-- New OP revision (parent IS NULL) → rewrite threads_fts.op_body.
-- The MAX(revision) guard prevents an out-of-order insert from
-- overwriting a newer body with an older one.
CREATE TRIGGER threads_fts_op_body_after_revision
AFTER INSERT ON post_revisions
WHEN (SELECT parent FROM posts WHERE id = NEW.post_id) IS NULL
 AND NEW.revision = (SELECT MAX(revision) FROM post_revisions WHERE post_id = NEW.post_id)
BEGIN
    UPDATE threads_fts
    SET op_body = NEW.body
    WHERE rowid = (
        SELECT t.rowid FROM threads t
        WHERE t.id = (SELECT thread FROM posts WHERE id = NEW.post_id)
    );
END;

-- OP retracted → blank out op_body so the thread's title (and URL) is
-- still searchable but the retracted body isn't.
CREATE TRIGGER threads_fts_op_after_retract
AFTER UPDATE OF retracted_at ON posts
WHEN OLD.retracted_at IS NULL
 AND NEW.retracted_at IS NOT NULL
 AND NEW.parent IS NULL
BEGIN
    UPDATE threads_fts
    SET op_body = ''
    WHERE rowid = (SELECT rowid FROM threads WHERE id = NEW.thread);
END;

-- ---------------------------------------------------------------------------
-- Backfill
-- ---------------------------------------------------------------------------

INSERT INTO threads_fts (rowid, title, op_body, link_url)
SELECT t.rowid,
       t.title,
       COALESCE(
           (
               SELECT pr.body
               FROM post_revisions pr
               JOIN posts p ON p.id = pr.post_id
               WHERE p.thread = t.id
                 AND p.parent IS NULL
                 AND p.retracted_at IS NULL
               ORDER BY pr.revision DESC
               LIMIT 1
           ),
           ''
       ),
       COALESCE(t.link_url_normalized, '')
FROM threads t;

-- ---------------------------------------------------------------------------
-- Optimize after backfill
-- ---------------------------------------------------------------------------

INSERT INTO threads_fts (threads_fts) VALUES ('optimize');
