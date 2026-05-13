-- Single-row table holding instance-level runtime configuration that
-- admins can edit from the Config tab in the admin dashboard.
--
-- Why a single-row table (id = 1 sentinel) rather than a key-value
-- table: the field set here is small and heterogeneous (durations,
-- byte counts, URL) and benefits from explicit typed columns plus
-- inline CHECK constraints. The single-row pattern (with the CHECK to
-- pin id to 1) makes "the row exists" a load-bearing invariant rather
-- than an implicit one, so handlers can assume `WHERE id = 1` always
-- hits exactly one row.
--
-- A row is seeded immediately with the application's compiled-in
-- defaults; the application reads from this row at startup and on
-- every admin config change.
--
-- Fields:
--   rebuild_debounce_ms       — quiet time after the last mutation
--                               before the trust-graph rebuild loop
--                               fires (coalesces bursts).
--   rebuild_min_interval_ms   — minimum time between rebuilds.
--   rebuild_max_interval_ms   — maximum staleness; rebuild fires
--                               even under sustained mutation.
--   rebuild_bfs_cache_bytes   — total BFS cache budget split between
--                               forward / reverse / delta caches.
--                               Takes effect on the next rebuild.
--   source_repo_url           — public URL to this instance's source
--                               code. Required for AGPL compliance;
--                               linked in the page footer. NULL only
--                               before initial setup completes.

CREATE TABLE IF NOT EXISTS instance_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    rebuild_debounce_ms INTEGER NOT NULL CHECK (rebuild_debounce_ms BETWEEN 1000 AND 60000),
    rebuild_min_interval_ms INTEGER NOT NULL CHECK (rebuild_min_interval_ms BETWEEN 1000 AND 3600000),
    rebuild_max_interval_ms INTEGER NOT NULL CHECK (rebuild_max_interval_ms BETWEEN 1000 AND 3600000),
    rebuild_bfs_cache_bytes INTEGER NOT NULL CHECK (rebuild_bfs_cache_bytes BETWEEN 1048576 AND 4294967296),
    source_repo_url TEXT,
    CHECK (rebuild_debounce_ms <= rebuild_min_interval_ms),
    CHECK (rebuild_min_interval_ms <= rebuild_max_interval_ms)
);

-- Seed the row with the application's compile-time defaults. Values
-- here must match `RebuildSchedule::default()` in `server/src/trust.rs`
-- and the `DEFAULT_BFS_CACHE_BYTES` constant. If those defaults change,
-- update them here too — but existing deployments will keep whatever
-- the operator has already configured because INSERT OR IGNORE is a
-- no-op once the row exists.
INSERT OR IGNORE INTO instance_config (
    id,
    rebuild_debounce_ms,
    rebuild_min_interval_ms,
    rebuild_max_interval_ms,
    rebuild_bfs_cache_bytes,
    source_repo_url
) VALUES (
    1,
    5000,
    30000,
    300000,
    67108864,
    NULL
);
