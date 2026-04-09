-- Replace single-column thread index with composite (thread, created_at)
-- to eliminate filesort in the two-pass metadata query.
-- The composite index serves as a prefix index for existing WHERE thread = ? queries.
DROP INDEX IF EXISTS idx_posts_thread;
CREATE INDEX IF NOT EXISTS idx_posts_thread_created ON posts(thread, created_at);
