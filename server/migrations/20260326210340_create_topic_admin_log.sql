CREATE TABLE IF NOT EXISTS topic_admin_log (
    id TEXT PRIMARY KEY NOT NULL,
    admin TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL CHECK (action IN ('merge', 'delete')),
    topic_id TEXT NOT NULL REFERENCES topics(id),
    merged_into TEXT REFERENCES topics(id),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_topic_admin_log_topic ON topic_admin_log(topic_id);
