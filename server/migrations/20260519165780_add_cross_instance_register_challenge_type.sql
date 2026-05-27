-- Phase 7 of federation: widen `auth_challenges.challenge_type` CHECK
-- to include `'cross_instance_register'`
-- (docs/federation-protocol.md §13; docs/federation-impl-plan.md
-- Phase 7).
--
-- The §13 cross-instance registration ceremony pairs a §5.5
-- `registration-challenge` (server-issued, signed by the user's
-- existing private key — single-use bookkeeping lives in the
-- separate `registration_challenges` table) with a fresh WebAuthn
-- passkey registration on the destination instance. The WebAuthn
-- state for the inline passkey-add ride-along reuses the existing
-- `auth_challenges` row infrastructure under the new
-- `'cross_instance_register'` discriminator; pairing the two rows
-- happens via the §5.5 challenge bytes the browser carries from
-- begin to complete.
--
-- SQLite can't `ALTER TABLE ... ALTER CHECK`, so the table is
-- recreated. No other table FK-references `auth_challenges`, so this
-- is a contained single-table rebuild — no FK-chain dance needed
-- (mirrors the precedent in
-- `20260326210343_add_discoverable_challenge_type.sql`).

CREATE TABLE auth_challenges_new (
    id TEXT PRIMARY KEY NOT NULL,
    challenge_type TEXT NOT NULL CHECK (challenge_type IN (
        'registration',
        'authentication',
        'discoverable',
        'cross_instance_register'
    )),
    state BLOB NOT NULL,
    display_name TEXT,
    invite_code TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    user_id TEXT
);

INSERT INTO auth_challenges_new (id, challenge_type, state, display_name, invite_code, created_at, user_id)
    SELECT id, challenge_type, state, display_name, invite_code, created_at, user_id
    FROM auth_challenges;

DROP TABLE auth_challenges;

ALTER TABLE auth_challenges_new RENAME TO auth_challenges;
