-- Add `canonical_hash` to `post_revisions` so erasure can navigate
-- from a post_id to its signed_objects rows (and null their payloads).
--
-- NOT NULL because no instance is live: every existing row is dev
-- data that gets wiped on `just db-reset`, and every new INSERT via
-- the dual-write handlers populates the column. Keeping it NOT NULL
-- frees the erasure helpers from a `canonical_hash IS NOT NULL`
-- guard.
--
-- SQLite can't add a NOT NULL column to an existing table without a
-- DEFAULT, so we rebuild `post_revisions`. No table FK-references
-- `post_revisions`, so this is a contained single-table rebuild — no
-- need for the dependency-chain dance in `server/migrations/CLAUDE.md`.
-- See docs/signed-payload-format.md §3.1 for the erasure model.

-- Drop the third trigger that references `post_revisions` in its
-- body (the other two fire AFTER INSERT ON post_revisions and get
-- dropped automatically with the table). SQLite revalidates trigger
-- bodies during the RENAME below, and a body referencing a
-- non-existent table fails the rename. Recreate after the rebuild.
DROP TRIGGER threads_fts_after_update_title;

CREATE TABLE post_revisions_new (
    post_id        TEXT NOT NULL REFERENCES posts(id),
    revision       INTEGER NOT NULL DEFAULT 0,
    body           TEXT NOT NULL,
    signature      BLOB NOT NULL,
    canonical_hash BLOB NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    epoch          INTEGER NOT NULL DEFAULT 0,
    format_version INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (post_id, revision)
);

DROP TABLE post_revisions;
ALTER TABLE post_revisions_new RENAME TO post_revisions;

-- Re-install the FTS triggers verbatim. The two AFTER-INSERT
-- triggers were dropped by the DROP TABLE above; the
-- threads-side title trigger by the explicit DROP TRIGGER. Definitions
-- mirror 20260511180443_rebuild_fts_with_contentless_delete.sql.

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
