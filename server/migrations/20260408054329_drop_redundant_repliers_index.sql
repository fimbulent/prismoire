-- The PK (thread_id, reply_rank) already covers lookups by thread_id,
-- making this single-column index redundant.
DROP INDEX IF EXISTS idx_thread_recent_repliers_thread;
