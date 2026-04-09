-- SQLite doesn't support DROP COLUMN on older versions, so recreate the table.
CREATE TABLE trust_edges_new (
    id TEXT PRIMARY KEY NOT NULL,
    source_user TEXT NOT NULL REFERENCES users(id),
    target_user TEXT NOT NULL REFERENCES users(id),
    trust_type TEXT NOT NULL CHECK (trust_type IN ('trust', 'distrust')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    reason TEXT,
    UNIQUE(source_user, target_user)
);

INSERT INTO trust_edges_new (id, source_user, target_user, trust_type, created_at, reason)
SELECT id, source_user, target_user, trust_type, created_at, reason FROM trust_edges;

DROP TABLE trust_edges;
ALTER TABLE trust_edges_new RENAME TO trust_edges;

CREATE INDEX idx_trust_edges_source ON trust_edges(source_user);
CREATE INDEX idx_trust_edges_target ON trust_edges(target_user);
