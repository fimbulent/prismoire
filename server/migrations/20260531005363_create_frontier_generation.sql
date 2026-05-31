-- Phase 3 of root-advertisement federation: the persisted generation
-- counter that drives §8.12 generational mark-sweep GC of the reverse
-- frontier (docs/federation-protocol.md §8.12).
--
-- The reverse-BFS rebuild (D2/D3) IS the mark phase: every edge and stub
-- it touches is restamped with the *current* generation. The sweep then
-- deletes any `frontier_edges` / `frontier_users` row whose `generation`
-- has fallen more than K behind (default K=3) — i.e. rows untouched by
-- the last K rebuilds, presumed no longer reachable from any local
-- reader's cap.
--
-- That window arithmetic only works if the counter is *monotonic across
-- restarts*: if it reset to 0 on every boot, the sweep's `current - K`
-- watermark would lurch backwards and either spare dead rows forever or
-- wrongly reap live ones. So the counter is durable, not in-memory.
--
-- This is deliberately NOT in `instance_config`: that table is the
-- operator-editable admin surface (debounce/interval knobs, repo URL).
-- The generation is internal bookkeeping the rebuild loop owns and an
-- operator must never hand-edit, so it gets its own single-row table.
--
-- It holds no user data of any kind (just a counter) and stays outside
-- the GDPR export/delete surface in `server/src/privacy.rs`.

CREATE TABLE IF NOT EXISTS frontier_generation (
    -- Single-row guard: the table holds exactly one row, id = 1. Any
    -- second insert violates the CHECK + PK, keeping the counter global.
    id INTEGER PRIMARY KEY NOT NULL
            CHECK (id = 1),

    -- The current rebuild generation. Monotonically increasing; advanced
    -- once per reverse-frontier rebuild immediately before the mark
    -- phase, so every edge/stub the rebuild touches is stamped with this
    -- value. The sweep evicts rows whose stamp is < this - K.
    generation INTEGER NOT NULL DEFAULT 0
            CHECK (generation >= 0),

    -- ISO-8601 timestamp of the most recent advance. Operator-visible
    -- only; the GC window keys off `generation`, not this column.
    updated_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Seed the singleton row so `advance_generation` is a plain UPDATE and
-- never has to branch on first-run insertion. Idempotent: a re-run of
-- this migration (or a fresh DB that already has the row) is a no-op.
INSERT OR IGNORE INTO frontier_generation (id, generation) VALUES (1, 0);
