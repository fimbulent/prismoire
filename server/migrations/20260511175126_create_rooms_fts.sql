-- Full-text search infrastructure for room slugs.
--
-- Background: `search_rooms_core` and the dropdown's room section
-- both do `LOWER(slug) LIKE '%<q>%'` substring filtering. A leading
-- `%` LIKE can't use a standard btree, so SQLite was scanning every
-- active room on every keystroke. That was fine when rooms were
-- admin-curated and bounded, but Prismoire auto-creates a room
-- whenever someone posts to a new slug, so room count grows with
-- topic diversity × user activity. This migration adds a trigram
-- FTS5 index over `slug` so substring LIKE queries become
-- index-bound regardless of room count.
--
-- Why trigram (not unicode61): unicode61 tokenizes on
-- non-alphanumeric, so a query for "rust" wouldn't substring-match
-- a slug like "rust-lang" (it would only match the whole token
-- "rust"). Trigram supports true substring search via LIKE/GLOB
-- against the indexed column — exactly the existing semantic.
-- See `docs/search_efficiency.md` for context.
--
-- Required SQLite >= 3.34 for the trigram tokenizer; the bundled
-- libsqlite3-sys ships 3.46.

-- ---------------------------------------------------------------------------
-- rooms_fts: trigram-indexed slug
-- ---------------------------------------------------------------------------

CREATE VIRTUAL TABLE IF NOT EXISTS rooms_fts USING fts5(
    slug,
    content='',
    tokenize='trigram'
);

-- ---------------------------------------------------------------------------
-- Triggers
-- ---------------------------------------------------------------------------
--
-- The FTS index holds active rooms only: rooms whose `deleted_at`
-- and `merged_into` are both NULL. Soft-delete or merge transitions
-- remove the row from the FTS index; hard delete does the same.
-- Filtering still happens defensively in the query JOIN so a missed
-- transition can't leak a stale row into results.

-- New room → insert into FTS (auto-creation in `create_thread.rs`
-- always creates rooms with `deleted_at IS NULL` and
-- `merged_into IS NULL`, but the WHEN guard makes the trigger safe
-- for any future code path that inserts pre-deleted or pre-merged
-- rows).
CREATE TRIGGER IF NOT EXISTS rooms_fts_after_insert
AFTER INSERT ON rooms
WHEN NEW.deleted_at IS NULL AND NEW.merged_into IS NULL
BEGIN
    INSERT INTO rooms_fts (rowid, slug) VALUES (NEW.rowid, NEW.slug);
END;

-- Slug edit → update FTS row (slugs are nominally immutable
-- post-creation; this trigger is defensive against future features).
CREATE TRIGGER IF NOT EXISTS rooms_fts_after_update_slug
AFTER UPDATE OF slug ON rooms
WHEN NEW.deleted_at IS NULL AND NEW.merged_into IS NULL
BEGIN
    UPDATE rooms_fts SET slug = NEW.slug WHERE rowid = NEW.rowid;
END;

-- Soft-delete transition: deleted_at goes NULL → non-NULL.
-- (There's no un-soft-delete path today; if one is added, mirror
-- this with an INSERT trigger for the reverse transition.)
CREATE TRIGGER IF NOT EXISTS rooms_fts_after_soft_delete
AFTER UPDATE OF deleted_at ON rooms
WHEN OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL
BEGIN
    DELETE FROM rooms_fts WHERE rowid = NEW.rowid;
END;

-- Merge transition: merged_into goes NULL → non-NULL.
-- (No merge endpoint exists in the codebase yet, but the column is
-- schema-defined and an admin merge feature is on the roadmap. This
-- trigger ensures the FTS stays correct the moment that lands.)
CREATE TRIGGER IF NOT EXISTS rooms_fts_after_merge
AFTER UPDATE OF merged_into ON rooms
WHEN OLD.merged_into IS NULL AND NEW.merged_into IS NOT NULL
BEGIN
    DELETE FROM rooms_fts WHERE rowid = NEW.rowid;
END;

-- Hard delete → drop FTS row. Rooms aren't normally hard-deleted
-- (soft-delete is the standard admin action), but the trigger keeps
-- the index consistent if a future path bypasses the soft-delete.
CREATE TRIGGER IF NOT EXISTS rooms_fts_after_delete
AFTER DELETE ON rooms
BEGIN
    DELETE FROM rooms_fts WHERE rowid = OLD.rowid;
END;

-- ---------------------------------------------------------------------------
-- Backfill: active rooms only
-- ---------------------------------------------------------------------------

INSERT INTO rooms_fts (rowid, slug)
SELECT rowid, slug FROM rooms
WHERE deleted_at IS NULL AND merged_into IS NULL;

-- ---------------------------------------------------------------------------
-- Optimize after backfill
-- ---------------------------------------------------------------------------

INSERT INTO rooms_fts (rooms_fts) VALUES ('optimize');
