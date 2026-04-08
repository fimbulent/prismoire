-- Denormalize last_activity and reply_count onto the threads table.
-- last_activity: timestamp of the most recent reply (global, not viewer-specific).
-- reply_count: total number of replies (global, not viewer-specific).
-- These are maintained on reply insert and used for candidate ordering and
-- the "recently active" sort. The warm sort uses viewer-specific values
-- computed at read time from thread_recent_repliers.

ALTER TABLE threads ADD COLUMN last_activity TEXT;
ALTER TABLE threads ADD COLUMN reply_count INTEGER NOT NULL DEFAULT 0;

-- Backfill from existing posts.
UPDATE threads SET
    reply_count = (
        SELECT COUNT(*) FROM posts p
        WHERE p.thread = threads.id AND p.parent IS NOT NULL
    ),
    last_activity = (
        SELECT MAX(p.created_at) FROM posts p
        WHERE p.thread = threads.id
    );

CREATE INDEX idx_threads_last_activity ON threads(last_activity);
CREATE INDEX idx_threads_created_at ON threads(created_at);
