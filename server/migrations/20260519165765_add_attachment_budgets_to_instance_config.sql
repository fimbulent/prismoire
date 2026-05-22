-- Admin-dynamic attachment-budget knobs (docs/attachments.md §10.3).
--
-- Per-user upload allowance, live-tunable from the admin Config tab
-- like the existing trust-rebuild knobs in this table. No wire
-- effect — budget is purely a local upload-rate policy, so per-instance
-- drift is harmless (the §10.1 wire constants are hardcoded in code).
--
-- Defaults match the §10.3 starting values:
--   ATTACHMENT_BUDGET_CAP    = 10 MiB = 10 * 1024 * 1024 = 10485760
--   ATTACHMENT_BUDGET_REFILL = 1 MiB / day  = 1048576 bytes per day
--
-- ALTER TABLE ADD COLUMN with a constant DEFAULT is safe inside the
-- migration's transaction (SQLite doesn't rewrite existing rows; the
-- DEFAULT is materialized on read for the legacy single-row).
ALTER TABLE instance_config
    ADD COLUMN attachment_budget_cap_bytes INTEGER NOT NULL DEFAULT 10485760
    CHECK (attachment_budget_cap_bytes BETWEEN 0 AND 10737418240);

ALTER TABLE instance_config
    ADD COLUMN attachment_budget_refill_bytes_per_day INTEGER NOT NULL DEFAULT 1048576
    CHECK (attachment_budget_refill_bytes_per_day BETWEEN 0 AND 10737418240);
