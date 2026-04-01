CREATE TABLE IF NOT EXISTS post_revisions (
    post_id TEXT NOT NULL REFERENCES posts(id),
    revision INTEGER NOT NULL DEFAULT 0,
    body TEXT NOT NULL,
    signature BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    epoch INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (post_id, revision)
);
