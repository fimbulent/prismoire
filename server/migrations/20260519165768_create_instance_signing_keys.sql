-- Per-instance Ed25519 signing key for federation envelopes (§6.2).
--
-- The instance key is server-level operational state, not a user
-- credential: loaded at startup, kept in memory, used to sign every
-- outbound `X-Prismoire-Federation-Auth` envelope and verified
-- against the recorded `peers.instance_pubkey` on the way back in.
-- Mirrors the shape of `signing_keys` (the per-user signing-key
-- vault) but is single-active: there is one and only one in-use
-- instance key per server. §6.6 rotation will overlap two rows
-- (old + new both valid for a window) once that lifecycle lands;
-- modelling `active` as a column rather than collapsing into the
-- primary key keeps that path open without a future table rebuild.
--
-- The private key sits next to the database and shares its
-- operational handling (file permissions, backup, restore). It is
-- treated as a server secret: never logged, never exposed in any
-- API surface.
CREATE TABLE instance_signing_keys (
    public_key  BLOB    PRIMARY KEY NOT NULL
                        CHECK (length(public_key) = 32),
    -- Ed25519 secret seed (`ed25519_dalek::SigningKey::from_bytes`
    -- takes a 32-byte seed). Treated as a server secret — never
    -- logged, never exposed in any API surface.
    private_key BLOB    NOT NULL CHECK (length(private_key) = 32),
    active      INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Partial unique index: at most one row may be `active = 1` at any
-- given time during V1. Once §6.6 rotation overlap ships, replace
-- with a constraint sized to the documented rotation window.
CREATE UNIQUE INDEX idx_instance_signing_keys_active
    ON instance_signing_keys(active) WHERE active = 1;
