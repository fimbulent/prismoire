CREATE TABLE IF NOT EXISTS user_settings (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id),
    theme TEXT NOT NULL DEFAULT 'rose-pine'
);
