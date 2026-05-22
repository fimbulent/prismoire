-- Per-user storage token bucket (docs/attachments.md §1, §3).
--
-- Lazy-refill model: a row is created on first upload with
-- `available_bytes = cap` (or whatever the operator's current cap
-- is — admin-dynamic per §10.3), and on each subsequent upload the
-- refill is recomputed against `last_refill_at` before the debit.
--
-- Formula (in handler code, not SQL):
--   available = min(BUDGET_CAP,
--                   available + REFILL_RATE * (now - last_refill_at))
--   require   available >= bytes_to_spend
--   debit     available -= bytes_to_spend
--   set       last_refill_at = now
--
-- Deletion never refunds (per spec: "deleting a post or attachment
-- does not reclaim allowance" — prevents upload-replicate-delete
-- gaming). `lifetime_spent` is monotonic for audit only.
--
-- A user with no row yet has implicit full budget — the row is
-- created on first attempt. Soft-delete (§7.c) drops the row.
CREATE TABLE IF NOT EXISTS user_storage_budgets (
    user_id TEXT NOT NULL PRIMARY KEY REFERENCES users(id),
    available_bytes INTEGER NOT NULL CHECK (available_bytes >= 0),
    last_refill_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    lifetime_spent INTEGER NOT NULL DEFAULT 0 CHECK (lifetime_spent >= 0)
);
