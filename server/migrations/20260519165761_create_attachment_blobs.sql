-- Content-addressed blob storage for post attachments
-- (docs/attachments.md §1).
--
-- Bytes are decoupled from posts: a blob row exists once per unique
-- SHA-256 hash, and any number of `post_attachments` bindings can
-- point at it. This mirrors the federation §11 wire shape (the signed
-- post carries a hash + size + mime ref, blobs flow separately) and
-- gives automatic dedup across staged uploads, posts, and federation
-- receives.
--
-- Column rationale:
--   content_hash   — SHA-256 of stored bytes (PK). Content-addressed,
--                    so dedup is automatic.
--   blob           — Nullable. Three legitimate NULL states:
--                    (1) the row was created by a federation receive
--                        that has bound the hash but not yet fetched
--                        the bytes (§11.6 fetch-pending),
--                    (2) cache eviction freed the bytes but bindings
--                        still reference the row (§11.4),
--                    (3) transient state during the upload tx between
--                        row insert and blob write (not held at rest).
--                    `content_type` and `size` stay populated so the
--                    §4 placeholder UX can render
--                    "Image (200 KiB, JPEG) — unavailable" without
--                    hitting the bytes.
--   content_type   — Allowlisted MIME (PNG/JPEG/WebP/text/plain/PDF).
--                    See §10.1 ALLOWED_MIMES. Not constrained by CHECK
--                    here because the allowlist may evolve in code
--                    faster than the schema; the upload + federation
--                    receive paths gate by `ALLOWED_MIMES` constant.
--   size           — Stored byte length. Wire invariant: must equal
--                    `attachments[].size` in the signed post-rev.
--   uploader       — Local user_id of the first uploader, or NULL.
--                    Three NULL paths:
--                    (1) federation-received blob with no local uploader
--                        identity (§11.2),
--                    (2) original uploader's account was deleted and
--                        the blob survived via another user's binding
--                        (§7.b — anonymizes residual personal data),
--                    (3) intentional choice for blobs whose origin we
--                        do not assert.
--   refcount       — Number of live `post_attachments` bindings.
--                    Maintained by triggers on `post_attachments` so
--                    every binding-mutation path (local handlers,
--                    federation receives) accounts uniformly. CHECK
--                    constraint is a backstop against double-decrement
--                    bugs surfacing as silent negatives that would
--                    defeat the §5 GC predicate.
CREATE TABLE IF NOT EXISTS attachment_blobs (
    content_hash BLOB NOT NULL PRIMARY KEY,
    blob BLOB,
    content_type TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    uploader TEXT REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    refcount INTEGER NOT NULL DEFAULT 0 CHECK (refcount >= 0)
);

-- §7.b account-delete sweeps blobs by uploader; the periodic GC sweep
-- can also use this index when looking for orphaned blobs uploaded by
-- a given user. Without it both paths fall back to a table scan.
CREATE INDEX IF NOT EXISTS idx_attachment_blobs_uploader
    ON attachment_blobs(uploader);
