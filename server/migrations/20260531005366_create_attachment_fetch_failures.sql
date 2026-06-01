-- §11.4 durable attachment-fetch failure state.
--
-- The §11.3 receiver fetch client (`federation/attachment_fetch.rs`)
-- discovers two kinds of failure when pulling absent attachment bytes;
-- this table persists them across restarts so the synchronous serve
-- trigger (`attachments/serve.rs`) does not hammer the origin on every
-- render of an attachment it cannot obtain:
--
--   - 'mismatch' — a candidate served bytes whose SHA-256 did not equal
--     the requested content hash. Per §11.4 this is a terminal,
--     no-further-fetches-without-operator-intervention failure: the
--     reference itself is broken or someone is serving corrupt bytes.
--   - 'transient' — every candidate 404'd / timed out. The bytes may
--     appear later, so the serve trigger re-attempts once
--     `last_attempt_at` is older than the retry backoff.
--
-- Keyed by `content_hash` (not by peer): the fetch client tries the
-- origin and several fallback peers and returns a single verdict per
-- hash, so the durable state is per-hash. ON DELETE CASCADE ties a
-- failure row's lifetime to its `attachment_blobs` row — once the blob
-- record is gone the hash is meaningless and so is its failure state.
--
-- `last_attempt_at` is unix epoch milliseconds (integer) so the backoff
-- comparison is plain arithmetic rather than ISO-8601 string parsing.
CREATE TABLE IF NOT EXISTS attachment_fetch_failures (
    content_hash    BLOB PRIMARY KEY NOT NULL
                    REFERENCES attachment_blobs(content_hash) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('mismatch', 'transient')),
    last_attempt_at INTEGER NOT NULL
);
