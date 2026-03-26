CREATE TABLE IF NOT EXISTS trust_edges (
    id TEXT PRIMARY KEY NOT NULL,
    source_user TEXT NOT NULL REFERENCES users(id),
    target_user TEXT NOT NULL REFERENCES users(id),
    trust_type TEXT NOT NULL CHECK (trust_type IN ('vouch', 'block')),
    weight REAL NOT NULL DEFAULT 1.0 CHECK (weight >= 0.0 AND weight <= 1.0),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at TEXT,
    reason TEXT,
    UNIQUE(source_user, target_user)
);

CREATE INDEX IF NOT EXISTS idx_trust_edges_source ON trust_edges(source_user);
CREATE INDEX IF NOT EXISTS idx_trust_edges_target ON trust_edges(target_user);
