-- Full-text search infrastructure for threads and posts.
--
-- Two contentless FTS5 virtual tables, indexed by the underlying
-- table's implicit rowid. `threads_fts` indexes thread titles plus
-- the OP body (denormalised from post_revisions); `posts_fts` indexes
-- the latest revision body per non-retracted post.
--
-- Visibility filtering happens in Rust against the trust graph after
-- FTS returns candidates; nothing in this schema enforces it.
--
-- See docs/search.md for the design rationale.

-- ---------------------------------------------------------------------------
-- threads_fts: title + OP body (BM25 weighting applied at query time)
-- ---------------------------------------------------------------------------

CREATE VIRTUAL TABLE IF NOT EXISTS threads_fts USING fts5(
    title,
    op_body,
    content='',
    tokenize = "unicode61 remove_diacritics 2"
);

-- ---------------------------------------------------------------------------
-- posts_fts: latest non-retracted body per post
-- ---------------------------------------------------------------------------

CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts USING fts5(
    body,
    content='',
    tokenize = "unicode61 remove_diacritics 2"
);

-- ---------------------------------------------------------------------------
-- Triggers: threads_fts maintenance
-- ---------------------------------------------------------------------------

-- New thread → insert FTS row with empty op_body (the body arrives
-- via the OP's first post_revisions insert and is filled in by the
-- post_revisions trigger below).
CREATE TRIGGER IF NOT EXISTS threads_fts_after_insert
AFTER INSERT ON threads
BEGIN
    INSERT INTO threads_fts (rowid, title, op_body)
    VALUES (NEW.rowid, NEW.title, '');
END;

-- Thread deleted → drop FTS row.
CREATE TRIGGER IF NOT EXISTS threads_fts_after_delete
AFTER DELETE ON threads
BEGIN
    DELETE FROM threads_fts WHERE rowid = OLD.rowid;
END;

-- Title edited → rewrite FTS title cell.
CREATE TRIGGER IF NOT EXISTS threads_fts_after_update_title
AFTER UPDATE OF title ON threads
BEGIN
    UPDATE threads_fts
    SET title = NEW.title
    WHERE rowid = NEW.rowid;
END;

-- ---------------------------------------------------------------------------
-- Triggers: op_body maintenance from post_revisions
-- ---------------------------------------------------------------------------

-- New OP revision (parent IS NULL) → rewrite threads_fts.op_body.
-- The MAX(revision) guard prevents an out-of-order insert from
-- overwriting a newer body with an older one.
CREATE TRIGGER IF NOT EXISTS threads_fts_op_body_after_revision
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

-- OP retracted → blank out op_body so the thread's title is still
-- searchable but the retracted body isn't.
CREATE TRIGGER IF NOT EXISTS threads_fts_op_after_retract
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
-- Triggers: posts_fts maintenance
-- ---------------------------------------------------------------------------

-- New post revision → ensure posts_fts has the latest body for the
-- post, unless the post is retracted. Delete-then-insert because
-- contentless FTS5 doesn't support UPSERT cleanly.
CREATE TRIGGER IF NOT EXISTS posts_fts_after_revision
AFTER INSERT ON post_revisions
WHEN (SELECT retracted_at FROM posts WHERE id = NEW.post_id) IS NULL
 AND NEW.revision = (SELECT MAX(revision) FROM post_revisions WHERE post_id = NEW.post_id)
BEGIN
    DELETE FROM posts_fts
    WHERE rowid = (SELECT rowid FROM posts WHERE id = NEW.post_id);

    INSERT INTO posts_fts (rowid, body)
    VALUES (
        (SELECT rowid FROM posts WHERE id = NEW.post_id),
        NEW.body
    );
END;

-- Post retracted → drop from posts_fts.
CREATE TRIGGER IF NOT EXISTS posts_fts_after_retract
AFTER UPDATE OF retracted_at ON posts
WHEN OLD.retracted_at IS NULL
 AND NEW.retracted_at IS NOT NULL
BEGIN
    DELETE FROM posts_fts WHERE rowid = OLD.rowid;
END;

-- Post hard-deleted (e.g. GDPR erasure path drops the row) → drop
-- from posts_fts. The threads_fts cleanup is handled by the
-- threads_fts_after_delete trigger when the corresponding thread
-- row is removed.
CREATE TRIGGER IF NOT EXISTS posts_fts_after_delete
AFTER DELETE ON posts
BEGIN
    DELETE FROM posts_fts WHERE rowid = OLD.rowid;
END;

-- ---------------------------------------------------------------------------
-- Backfill
-- ---------------------------------------------------------------------------

-- Threads: title + (latest non-retracted OP revision body, or '').
INSERT INTO threads_fts (rowid, title, op_body)
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
       )
FROM threads t;

-- Posts: latest revision body, excluding retracted posts.
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

-- ---------------------------------------------------------------------------
-- Initial optimize after backfill
-- ---------------------------------------------------------------------------

INSERT INTO threads_fts (threads_fts) VALUES ('optimize');
INSERT INTO posts_fts   (posts_fts)   VALUES ('optimize');
