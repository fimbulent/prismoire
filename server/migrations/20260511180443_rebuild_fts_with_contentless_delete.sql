-- Rebuild all three FTS5 virtual tables with `contentless_delete=1`.
--
-- Background: plain contentless FTS5 tables (`content=''`) support
-- INSERT only — DELETE and UPDATE both raise errors. The previous
-- migration (`fix_threads_fts_update_triggers`) tried to work around
-- the UPDATE restriction with a DELETE+INSERT pattern, which fails on
-- the DELETE step for the same reason.
--
-- SQLite 3.45 (Jan 2024) added the `contentless_delete=1` option,
-- which removes both restrictions:
--
--   - DELETE works directly.
--   - INSERT OR REPLACE INTO works (used here as the upsert primitive
--     for triggers that need to write a new full-row state).
--   - UPDATE works too, but only if every user-defined column is set
--     in the same statement — which is awkward for triggers that
--     only know a subset of the new column values. INSERT OR REPLACE
--     is cleaner.
--
-- libsqlite3-sys 0.30 bundles SQLite 3.46, so `contentless_delete=1`
-- is available. Verified:
--
--   sqlite> CREATE VIRTUAL TABLE t USING fts5(a, content='');
--   sqlite> INSERT INTO t (rowid, a) VALUES (1, 'x');
--   sqlite> DELETE FROM t WHERE rowid = 1;
--   Runtime error: cannot DELETE from contentless fts5 table: t
--
--   sqlite> CREATE VIRTUAL TABLE t USING fts5(a, content='', contentless_delete=1);
--   sqlite> INSERT INTO t (rowid, a) VALUES (1, 'x');
--   sqlite> DELETE FROM t WHERE rowid = 1;       -- ok
--   sqlite> INSERT OR REPLACE INTO t VALUES (...); -- ok
--
-- All three FTS tables in this schema need the flag:
--
--   - `threads_fts` — title/op_body/link_url upserts on title edit,
--     OP revision, and OP retract.
--   - `posts_fts` — body upsert on every revision; row may not exist
--     yet for a freshly-inserted post, so INSERT OR REPLACE handles
--     both cases in one statement.
--   - `rooms_fts` — slug edit (theoretical; slugs are nominally
--     immutable) plus soft-delete, merge, and hard-delete DELETEs.
--
-- FTS5 virtual tables can't be ALTERed, so this is a drop-and-recreate
-- with full trigger reinstall and a backfill from the source tables.

-- ---------------------------------------------------------------------------
-- Drop existing FTS tables and all their triggers
-- ---------------------------------------------------------------------------

DROP TRIGGER IF EXISTS threads_fts_after_insert;
DROP TRIGGER IF EXISTS threads_fts_after_delete;
DROP TRIGGER IF EXISTS threads_fts_after_update_title;
DROP TRIGGER IF EXISTS threads_fts_op_body_after_revision;
DROP TRIGGER IF EXISTS threads_fts_op_after_retract;

DROP TRIGGER IF EXISTS posts_fts_after_revision;
DROP TRIGGER IF EXISTS posts_fts_after_retract;
DROP TRIGGER IF EXISTS posts_fts_after_delete;

DROP TRIGGER IF EXISTS rooms_fts_after_insert;
DROP TRIGGER IF EXISTS rooms_fts_after_update_slug;
DROP TRIGGER IF EXISTS rooms_fts_after_soft_delete;
DROP TRIGGER IF EXISTS rooms_fts_after_merge;
DROP TRIGGER IF EXISTS rooms_fts_after_delete;

DROP TABLE IF EXISTS threads_fts;
DROP TABLE IF EXISTS posts_fts;
DROP TABLE IF EXISTS rooms_fts;

-- ---------------------------------------------------------------------------
-- threads_fts
-- ---------------------------------------------------------------------------

CREATE VIRTUAL TABLE threads_fts USING fts5(
    title,
    op_body,
    link_url,
    content='',
    contentless_delete=1,
    tokenize = "unicode61 remove_diacritics 2"
);

-- New thread → insert FTS row with empty op_body. The OP's first
-- revision arrives via threads_fts_op_body_after_revision and replaces
-- this row with the body filled in.
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

-- Title edited → INSERT OR REPLACE with new title, current op_body
-- (re-derived from the latest non-retracted OP revision), and current
-- link_url_normalized.
CREATE TRIGGER threads_fts_after_update_title
AFTER UPDATE OF title ON threads
BEGIN
    INSERT OR REPLACE INTO threads_fts (rowid, title, op_body, link_url)
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

-- New OP revision (parent IS NULL) → INSERT OR REPLACE the thread's
-- FTS row with NEW.body as op_body. The MAX(revision) guard prevents
-- an out-of-order revision from clobbering a newer body.
CREATE TRIGGER threads_fts_op_body_after_revision
AFTER INSERT ON post_revisions
WHEN (SELECT parent FROM posts WHERE id = NEW.post_id) IS NULL
 AND NEW.revision = (SELECT MAX(revision) FROM post_revisions WHERE post_id = NEW.post_id)
BEGIN
    INSERT OR REPLACE INTO threads_fts (rowid, title, op_body, link_url)
    SELECT t.rowid, t.title, NEW.body, COALESCE(t.link_url_normalized, '')
    FROM threads t
    WHERE t.id = (SELECT thread FROM posts WHERE id = NEW.post_id);
END;

-- OP retracted → INSERT OR REPLACE with op_body=''. Title and link_url
-- stay searchable.
CREATE TRIGGER threads_fts_op_after_retract
AFTER UPDATE OF retracted_at ON posts
WHEN OLD.retracted_at IS NULL
 AND NEW.retracted_at IS NOT NULL
 AND NEW.parent IS NULL
BEGIN
    INSERT OR REPLACE INTO threads_fts (rowid, title, op_body, link_url)
    SELECT t.rowid, t.title, '', COALESCE(t.link_url_normalized, '')
    FROM threads t
    WHERE t.id = NEW.thread;
END;

-- ---------------------------------------------------------------------------
-- posts_fts
-- ---------------------------------------------------------------------------

CREATE VIRTUAL TABLE posts_fts USING fts5(
    body,
    content='',
    contentless_delete=1,
    tokenize = "unicode61 remove_diacritics 2"
);

-- New post revision → INSERT OR REPLACE the post's body. Handles both
-- "first revision of a new post" (no row yet → INSERT) and "edit of an
-- existing post" (row exists → REPLACE) in one statement.
CREATE TRIGGER posts_fts_after_revision
AFTER INSERT ON post_revisions
WHEN (SELECT retracted_at FROM posts WHERE id = NEW.post_id) IS NULL
 AND NEW.revision = (SELECT MAX(revision) FROM post_revisions WHERE post_id = NEW.post_id)
BEGIN
    INSERT OR REPLACE INTO posts_fts (rowid, body)
    VALUES (
        (SELECT rowid FROM posts WHERE id = NEW.post_id),
        NEW.body
    );
END;

-- Post retracted → drop from posts_fts.
CREATE TRIGGER posts_fts_after_retract
AFTER UPDATE OF retracted_at ON posts
WHEN OLD.retracted_at IS NULL
 AND NEW.retracted_at IS NOT NULL
BEGIN
    DELETE FROM posts_fts WHERE rowid = OLD.rowid;
END;

-- Post hard-deleted → drop from posts_fts. (Thread-side cleanup is
-- handled by threads_fts_after_delete.)
CREATE TRIGGER posts_fts_after_delete
AFTER DELETE ON posts
BEGIN
    DELETE FROM posts_fts WHERE rowid = OLD.rowid;
END;

-- ---------------------------------------------------------------------------
-- rooms_fts
-- ---------------------------------------------------------------------------

CREATE VIRTUAL TABLE rooms_fts USING fts5(
    slug,
    content='',
    contentless_delete=1,
    tokenize='trigram'
);

-- New room → insert into FTS, guarded against pre-deleted/pre-merged
-- rows on the off chance a future code path creates one.
CREATE TRIGGER rooms_fts_after_insert
AFTER INSERT ON rooms
WHEN NEW.deleted_at IS NULL AND NEW.merged_into IS NULL
BEGIN
    INSERT INTO rooms_fts (rowid, slug) VALUES (NEW.rowid, NEW.slug);
END;

-- Slug edit → INSERT OR REPLACE. Slugs are nominally immutable; this
-- trigger is defensive against future features.
CREATE TRIGGER rooms_fts_after_update_slug
AFTER UPDATE OF slug ON rooms
WHEN NEW.deleted_at IS NULL AND NEW.merged_into IS NULL
BEGIN
    INSERT OR REPLACE INTO rooms_fts (rowid, slug) VALUES (NEW.rowid, NEW.slug);
END;

-- Soft-delete transition.
CREATE TRIGGER rooms_fts_after_soft_delete
AFTER UPDATE OF deleted_at ON rooms
WHEN OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL
BEGIN
    DELETE FROM rooms_fts WHERE rowid = NEW.rowid;
END;

-- Merge transition.
CREATE TRIGGER rooms_fts_after_merge
AFTER UPDATE OF merged_into ON rooms
WHEN OLD.merged_into IS NULL AND NEW.merged_into IS NOT NULL
BEGIN
    DELETE FROM rooms_fts WHERE rowid = NEW.rowid;
END;

-- Hard delete.
CREATE TRIGGER rooms_fts_after_delete
AFTER DELETE ON rooms
BEGIN
    DELETE FROM rooms_fts WHERE rowid = OLD.rowid;
END;

-- ---------------------------------------------------------------------------
-- Backfill
-- ---------------------------------------------------------------------------

-- threads_fts: title + latest non-retracted OP body + normalized URL.
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

-- posts_fts: latest revision body, excluding retracted posts.
INSERT INTO posts_fts (rowid, body)
SELECT p.rowid,
       (
           SELECT pr.body
           FROM post_revisions pr
           WHERE pr.post_id = p.id
           ORDER BY pr.revision DESC
           LIMIT 1
       )
FROM posts p
WHERE p.retracted_at IS NULL;

-- rooms_fts: active rooms only.
INSERT INTO rooms_fts (rowid, slug)
SELECT rowid, slug FROM rooms
WHERE deleted_at IS NULL AND merged_into IS NULL;

-- ---------------------------------------------------------------------------
-- Optimize
-- ---------------------------------------------------------------------------

INSERT INTO threads_fts (threads_fts) VALUES ('optimize');
INSERT INTO posts_fts   (posts_fts)   VALUES ('optimize');
INSERT INTO rooms_fts   (rooms_fts)   VALUES ('optimize');
