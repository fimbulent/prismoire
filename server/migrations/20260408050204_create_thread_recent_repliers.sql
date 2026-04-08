-- Stores the N most recent repliers per thread for warm sort scoring.
-- reply_rank 0 = most recent reply, ascending. Maintained on each reply insert.
-- At read time, filtered by the viewer's reverse trust set to compute
-- viewer-specific last_activity and trust_signal.

CREATE TABLE IF NOT EXISTS thread_recent_repliers (
    thread_id TEXT NOT NULL REFERENCES threads(id),
    reply_rank INTEGER NOT NULL,
    replier_id TEXT NOT NULL REFERENCES users(id),
    replied_at TEXT NOT NULL,
    PRIMARY KEY (thread_id, reply_rank)
);

CREATE INDEX idx_thread_recent_repliers_thread ON thread_recent_repliers(thread_id);

-- Backfill from existing posts (up to 50 most recent repliers per thread).
INSERT INTO thread_recent_repliers (thread_id, reply_rank, replier_id, replied_at)
SELECT thread_id, reply_rank, author, created_at
FROM (
    SELECT
        p.thread AS thread_id,
        p.author,
        p.created_at,
        ROW_NUMBER() OVER (PARTITION BY p.thread ORDER BY p.created_at DESC) - 1 AS reply_rank
    FROM posts p
    WHERE p.parent IS NOT NULL
)
WHERE reply_rank < 50;
