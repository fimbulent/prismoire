-- Widen the challenge_type CHECK constraint to include 'discoverable' for
-- WebAuthn conditional UI (passkey autofill) ceremonies.
-- SQLite cannot alter CHECK constraints in place, so we recreate the table.

CREATE TABLE auth_challenges_new (
    id TEXT PRIMARY KEY NOT NULL,
    challenge_type TEXT NOT NULL CHECK (challenge_type IN ('registration', 'authentication', 'discoverable')),
    state BLOB NOT NULL,
    display_name TEXT,
    invite_code TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO auth_challenges_new (id, challenge_type, state, display_name, invite_code, created_at)
    SELECT id, challenge_type, state, display_name, invite_code, created_at
    FROM auth_challenges;

DROP TABLE auth_challenges;

ALTER TABLE auth_challenges_new RENAME TO auth_challenges;
