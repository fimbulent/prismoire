-- Allow `signed_objects.payload` to be NULL (erased), and add an
-- `erased_at` timestamp so we can distinguish "never had bytes"
-- (impossible by the CHECK) from "had bytes, then erased on receipt".
--
-- Backing rationale: GDPR Article 17 right-to-erasure. When a user
-- retracts a post, neutralises a trust edge, deactivates, or an
-- authoritative admin-rm fires, peers MUST drop the payload bytes of
-- the targeted prior signed objects while retaining the canonical hash
-- + signature + class + receipt timestamp so chain continuity and
-- audit verification still work. See docs/signed-payload-format.md
-- §3.1 ("Payload erasure") and docs/federation-protocol.md §10.5.3.
--
-- SQLite can't ALTER a column's nullability in place, so we rebuild
-- the table. No other table FK-references signed_objects, so this is
-- a contained single-table rebuild — no need for the full dependency
-- chain dance described in `server/migrations/CLAUDE.md`.

CREATE TABLE signed_objects_new (
    canonical_hash BLOB PRIMARY KEY NOT NULL,
    inner_class    TEXT NOT NULL CHECK (inner_class IN (
                       'post-rev', 'retract', 'admin-rm',
                       'trust-edge', 'profile', 'thread-create',
                       'thread-status', 'deactivate', 'move',
                       'user-status'
                   )),
    payload        BLOB,
    signature      BLOB NOT NULL,
    received_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    erased_at      TEXT,
    CHECK (payload IS NOT NULL OR erased_at IS NOT NULL)
);

INSERT INTO signed_objects_new (canonical_hash, inner_class, payload, signature, received_at)
SELECT canonical_hash, inner_class, payload, signature, received_at FROM signed_objects;

DROP TABLE signed_objects;
ALTER TABLE signed_objects_new RENAME TO signed_objects;

CREATE INDEX idx_signed_objects_class ON signed_objects(inner_class);
