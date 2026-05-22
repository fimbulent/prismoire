-- Per-revision attachment bindings (docs/attachments.md §1).
--
-- One row per (post_revision, position) — i.e. each revision lists its
-- own attachment set independently. This makes §6 edit semantics
-- (an edit can add/remove/reorder the attachment array) a clean
-- per-revision projection of the signed `attachments[]` CBOR array
-- without rewriting prior rows.
--
-- The signed array carries no position field; array index *is* the
-- position. The local `position` column is the projection of that
-- index, written as a contiguous 0..N-1 sequence per revision so
-- removal from the middle doesn't leave gaps (§6.1 step 5).
--
-- Column rationale:
--   post_id, revision   — composite reference into post_revisions.
--                         CASCADE delete is intentional: erasing the
--                         post_revisions row (via payload erasure on
--                         retract) drops the projection too. Refcount
--                         decrement on each cascaded delete is handled
--                         by the AFTER DELETE trigger below.
--   position            — 0..2 stable display order, contiguous per
--                         revision. CHECK pins the §10.1 invariant
--                         MAX_ATTACHMENTS_PER_OP = 3.
--   content_hash        — FK to attachment_blobs. NO ON DELETE CASCADE
--                         on the blob side: bindings are dropped
--                         explicitly first (via post_revisions cascade,
--                         retract handler, or edit handler), then the
--                         blob row is GC'd when refcount reaches zero.
--                         A blob with live bindings must never be
--                         deletable.
--   filename            — Author-supplied display name, post-§2.2
--                         sanitization. Per-binding so an edit can
--                         rename without re-uploading.
--   display_mode        — 'inline' (images only) or 'download'. The
--                         image-MIME constraint is enforced at the
--                         handler layer (it requires joining to
--                         attachment_blobs.content_type); a CHECK here
--                         on text alone can't see the MIME.
CREATE TABLE IF NOT EXISTS post_attachments (
    post_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 2),
    content_hash BLOB NOT NULL REFERENCES attachment_blobs(content_hash),
    filename TEXT NOT NULL,
    display_mode TEXT NOT NULL CHECK (display_mode IN ('inline', 'download')),
    PRIMARY KEY (post_id, revision, position),
    UNIQUE (post_id, revision, content_hash),
    FOREIGN KEY (post_id, revision)
        REFERENCES post_revisions(post_id, revision)
        ON DELETE CASCADE
);

-- Orphan-GC predicate joins post_attachments by content_hash to find
-- "are there any bindings left for this blob?". Without this index
-- the GC sweep is a table scan per candidate blob.
CREATE INDEX IF NOT EXISTS idx_post_attachments_content_hash
    ON post_attachments(content_hash);

-- Refcount maintenance lives in triggers so every binding-mutation
-- path (local OP create, local edit, local retract cascade, federation
-- receive when wired in §11) accounts uniformly without each call
-- site having to remember.
--
-- AFTER INSERT bumps refcount when a binding row appears. AFTER DELETE
-- decrements when a binding goes away, whether via direct DELETE
-- (retract / edit-remove) or via the post_revisions CASCADE.
--
-- The CHECK (refcount >= 0) constraint on attachment_blobs is the
-- backstop: if a double-decrement bug ever sneaks through, the
-- constraint violates loudly rather than letting refcount go silently
-- negative and breaking the §5 GC predicate.
CREATE TRIGGER IF NOT EXISTS trg_post_attachments_refcount_inc
AFTER INSERT ON post_attachments
BEGIN
    UPDATE attachment_blobs
       SET refcount = refcount + 1
     WHERE content_hash = NEW.content_hash;
END;

CREATE TRIGGER IF NOT EXISTS trg_post_attachments_refcount_dec
AFTER DELETE ON post_attachments
BEGIN
    UPDATE attachment_blobs
       SET refcount = refcount - 1
     WHERE content_hash = OLD.content_hash;
END;
