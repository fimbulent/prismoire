-- Rename trust_type value 'block' to 'distrust' in trust_edges.
-- SQLite cannot alter CHECK constraints, so recreate the table.

CREATE TABLE trust_edges_new (
    id TEXT PRIMARY KEY NOT NULL,
    source_user TEXT NOT NULL REFERENCES users(id),
    target_user TEXT NOT NULL REFERENCES users(id),
    trust_type TEXT NOT NULL CHECK (trust_type IN ('trust', 'distrust')),
    weight REAL NOT NULL DEFAULT 1.0 CHECK (weight >= 0.0 AND weight <= 1.0),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at TEXT,
    reason TEXT,
    UNIQUE(source_user, target_user)
);

INSERT INTO trust_edges_new (id, source_user, target_user, trust_type, weight, created_at, expires_at, reason)
SELECT id, source_user, target_user,
       CASE trust_type WHEN 'block' THEN 'distrust' ELSE trust_type END,
       weight, created_at, expires_at, reason
FROM trust_edges;

DROP TABLE trust_edges;
ALTER TABLE trust_edges_new RENAME TO trust_edges;

CREATE INDEX IF NOT EXISTS idx_trust_edges_source ON trust_edges(source_user);
CREATE INDEX IF NOT EXISTS idx_trust_edges_target ON trust_edges(target_user);
