-- Relax user_homes so a home can be recorded without a move object.
--
-- user_homes was originally a pure §12.4 move-resolution projection:
-- every row corresponded to a winning `move` declaration, so
-- current_move_hash / current_created_at were NOT NULL. Phase 11.9.5
-- (cross-instance trust bootstrap via "trust codes") introduces a
-- second writer: pasting a trust code seeds a remote user's home
-- pointer (current_home_key + current_home_domain) with no move object
-- behind it. NULL move state now means "home learned via trust-code
-- seed, no move chain yet". A later real move UPSERTs over the NULLs
-- (§12.4 latest-wins treats NULL created_at as the epoch, so any real
-- move supersedes); §12.3 move-chain backfill serves from stored move
-- objects, so a NULL move_hash simply yields `unknown_chain`.
--
-- current_home_key stays NOT NULL — it is the §3 trust anchor and the
-- only column the home-resolution readers consult. No table references
-- user_homes by FK and it has no indexes, so this is a plain rebuild.

CREATE TABLE user_homes_new (
    -- Ed25519 public key of the moving identity (raw 32 bytes).
    user_key BLOB PRIMARY KEY NOT NULL
            CHECK (length(user_key) = 32),

    -- Ed25519 instance_pubkey (raw 32 bytes) of the user's
    -- currently-resolved home instance. The §3 trust anchor. Always set:
    -- a move copies it from the winning move's to_instance_key; a
    -- trust-code seed copies it from the code's instance pubkey.
    current_home_key BLOB NOT NULL
            CHECK (length(current_home_key) = 32),

    -- Bare canonical domain of the user's currently-resolved home
    -- instance. From the winning move's to_instance, or the trust
    -- code's home_domain. Never empty.
    current_home_domain TEXT NOT NULL
            CHECK (length(current_home_domain) > 0),

    -- SHA-256 (32 bytes) of the winning move's canonical payload bytes,
    -- joining back to signed_objects.canonical_hash for §12.3 backfill.
    -- NULL when the row was seeded by a trust code (no move object).
    current_move_hash BLOB
            CHECK (current_move_hash IS NULL OR length(current_move_hash) = 32),

    -- Wire timestamp of the winning move (Unix milliseconds UTC),
    -- copied verbatim; the §12.4 latest-wins comparison reads it
    -- directly. NULL when seeded by a trust code (treated as the epoch,
    -- so any real move supersedes).
    current_created_at INTEGER,

    -- ISO-8601 timestamp of the most recent UPSERT against this row.
    -- Operator-visible only.
    updated_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO user_homes_new
    (user_key, current_home_key, current_home_domain,
     current_move_hash, current_created_at, updated_at)
SELECT user_key, current_home_key, current_home_domain,
       current_move_hash, current_created_at, updated_at
FROM user_homes;

DROP TABLE user_homes;

ALTER TABLE user_homes_new RENAME TO user_homes;
