CREATE TABLE IF NOT EXISTS signing_keys (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    active INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_signing_keys_user_id ON signing_keys(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_keys_active ON signing_keys(user_id) WHERE active = 1;
