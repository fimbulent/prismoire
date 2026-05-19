-- Phase D of the federation schema refactor
-- (docs/tmp_schema_refactor.md item 13): drop
-- `signing_keys.public_key`. Since Phase C, `users.public_key` is the
-- canonical federation identity column (NOT NULL UNIQUE); the same
-- bytes were also being dual-written into `signing_keys` for
-- backwards compatibility, but nothing reads them from there anymore.
--
-- `signing_keys` becomes a pure server-side private-key vault
-- (`docs/signed-payload-format.md §1.9 (3)`).
--
-- SQLite can't `ALTER TABLE DROP COLUMN` on a column that's
-- referenced by an index, and we don't want to leave behind a
-- vestigial index either. No other table FK-references
-- `signing_keys`, so this is a contained single-table rebuild — no
-- need for the FK-chain dance from
-- `20260519165758_federation_user_identity_constraints.sql`.

CREATE TABLE signing_keys_new (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    private_key BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    active INTEGER NOT NULL DEFAULT 1
);

INSERT INTO signing_keys_new (id, user_id, private_key, created_at, active)
SELECT id, user_id, private_key, created_at, active
FROM signing_keys;

DROP TABLE signing_keys;
ALTER TABLE signing_keys_new RENAME TO signing_keys;

CREATE INDEX idx_signing_keys_user_id ON signing_keys(user_id);
CREATE UNIQUE INDEX idx_signing_keys_active ON signing_keys(user_id) WHERE active = 1;
