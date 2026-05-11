-- Fix `threads_fts` maintenance triggers: contentless FTS5 tables
-- (`content=''`) don't support UPDATE. The original `create_fts_tables`
-- migration (2026-05-06) and its rebuild in
-- `rebuild_threads_fts_with_link_url` both shipped UPDATE-shaped triggers
-- by inheritance. They never fired during backfill (backfill uses
-- INSERT) and `posts_fts` happened to use DELETE+INSERT correctly, so
-- the bug only surfaces the first time a thread is created post-FTS:
--
--   1. `INSERT INTO threads` → `threads_fts_after_insert` inserts a row
--      with `op_body=''` (works fine).
--   2. `INSERT INTO posts` (the OP) → no FTS trigger.
--   3. `INSERT INTO post_revisions` (OP body) →
--      `threads_fts_op_body_after_revision` tries to
--      `UPDATE threads_fts SET op_body = NEW.body` → SQLite errors
--      "cannot UPDATE contentless fts5 table: threads_fts" and the
--      whole `create_thread` transaction aborts.
--
-- Fix: convert the three UPDATE triggers to DELETE+INSERT, matching the
-- pattern `posts_fts_after_revision` already uses. Because the FTS row
-- has to be reconstructed in full (contentless = no read-back), the new
-- triggers query the source tables for whichever column the trigger
-- isn't changing itself.
--
-- Verified against SQLite 3.51 (libsqlite3-sys ships 3.46 in this repo):
--   sqlite> CREATE VIRTUAL TABLE t USING fts5(a, content='');
--   sqlite> INSERT INTO t (rowid, a) VALUES (1, 'x');
--   sqlite> UPDATE t SET a = 'y' WHERE rowid = 1;
--   Runtime error: cannot UPDATE contentless fts5 table: t

DROP TRIGGER IF EXISTS threads_fts_after_update_title;
DROP TRIGGER IF EXISTS threads_fts_op_body_after_revision;
DROP TRIGGER IF EXISTS threads_fts_op_after_retract;

-- Title edited → rebuild FTS row. Pulls the current op_body from the
-- latest non-retracted OP revision (mirrors the backfill in the
-- previous migration) and the current link_url_normalized from the
-- thread row itself.
CREATE TRIGGER threads_fts_after_update_title
AFTER UPDATE OF title ON threads
BEGIN
    DELETE FROM threads_fts WHERE rowid = NEW.rowid;
    INSERT INTO threads_fts (rowid, title, op_body, link_url)
    VALUES (
        NEW.rowid,
        NEW.title,
        COALESCE(
            (
                SELECT pr.body
                FROM post_revisions pr
                JOIN posts p ON p.id = pr.post_id
                WHERE p.thread = NEW.id
                  AND p.parent IS NULL
                  AND p.retracted_at IS NULL
                ORDER BY pr.revision DESC
                LIMIT 1
            ),
            ''
        ),
        COALESCE(NEW.link_url_normalized, '')
    );
END;

-- New OP revision (parent IS NULL) → rebuild FTS row with NEW.body as
-- op_body. The MAX(revision) guard still prevents an out-of-order
-- revision from clobbering a newer body. Title and link_url come from
-- the threads row.
CREATE TRIGGER threads_fts_op_body_after_revision
AFTER INSERT ON post_revisions
WHEN (SELECT parent FROM posts WHERE id = NEW.post_id) IS NULL
 AND NEW.revision = (SELECT MAX(revision) FROM post_revisions WHERE post_id = NEW.post_id)
BEGIN
    DELETE FROM threads_fts WHERE rowid = (
        SELECT t.rowid FROM threads t
        WHERE t.id = (SELECT thread FROM posts WHERE id = NEW.post_id)
    );
    INSERT INTO threads_fts (rowid, title, op_body, link_url)
    SELECT t.rowid, t.title, NEW.body, COALESCE(t.link_url_normalized, '')
    FROM threads t
    WHERE t.id = (SELECT thread FROM posts WHERE id = NEW.post_id);
END;

-- OP retracted → rebuild FTS row with op_body=''. Title and link_url
-- stay searchable.
CREATE TRIGGER threads_fts_op_after_retract
AFTER UPDATE OF retracted_at ON posts
WHEN OLD.retracted_at IS NULL
 AND NEW.retracted_at IS NOT NULL
 AND NEW.parent IS NULL
BEGIN
    DELETE FROM threads_fts WHERE rowid = (
        SELECT rowid FROM threads WHERE id = NEW.thread
    );
    INSERT INTO threads_fts (rowid, title, op_body, link_url)
    SELECT t.rowid, t.title, '', COALESCE(t.link_url_normalized, '')
    FROM threads t
    WHERE t.id = NEW.thread;
END;
