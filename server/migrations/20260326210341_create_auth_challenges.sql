-- Temporary storage for WebAuthn ceremony state (registration and authentication).
-- Rows are short-lived: created at ceremony start, consumed at ceremony completion.
CREATE TABLE IF NOT EXISTS auth_challenges (
    id TEXT PRIMARY KEY NOT NULL,
    challenge_type TEXT NOT NULL CHECK (challenge_type IN ('registration', 'authentication')),
    state BLOB NOT NULL,
    display_name TEXT,
    invite_code TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
