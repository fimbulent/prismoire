-- §10.5.1: record the canonical hash of each thread's paired
-- `thread-create` signed object so the by-author backfill surface can
-- serve it. Without a queryable thread-create -> author mapping, a
-- freshly-trusted author's pre-existing threads can never surface on a
-- newly-interested instance (the §11.9.5 unknown-source bootstrap).
-- Nullable: pre-existing local rows have no recorded hash, and remote
-- thread rows projected before this migration stay NULL until re-pushed.
ALTER TABLE threads ADD COLUMN thread_create_hash BLOB;
