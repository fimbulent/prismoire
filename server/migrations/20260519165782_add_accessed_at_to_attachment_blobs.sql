-- §11.5 receiver-local attachment cache: per-blob last-access timestamp
-- driving the sloppy-LRU eviction sweep.
--
-- The cache lives in `attachment_blobs.blob`: any row with non-NULL
-- bytes is either an origin-authored blob (locally-bound to a current
-- post revision) or a federation-fetched cache entry. Origin-authored
-- bytes are immune to eviction — the §11 wire contract obliges us to
-- keep them — so the cache sweep walks rows with NULL bindings only.
-- The partial index keys on `accessed_at` over exactly that population
-- (`blob IS NOT NULL`) so the sweep's "32 oldest eligible" probe is an
-- index-only scan rather than a table scan.
--
-- Default expression matches the pattern used elsewhere in the schema
-- (`created_at`, `attachment_staging.created_at`): wall-clock UTC in
-- the canonical ISO-8601 `Z` form. New rows inserted by the upload
-- handler or by future federation fetches automatically stamp the
-- current time without any application-side write.
ALTER TABLE attachment_blobs
    ADD COLUMN accessed_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));

CREATE INDEX IF NOT EXISTS idx_attachment_blobs_accessed_at
    ON attachment_blobs(accessed_at)
    WHERE blob IS NOT NULL;
