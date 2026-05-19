-- Federation peer registry.
--
-- Part of Phase A of the federation schema refactor (see
-- `docs/federation_planning.md` §1.9 (7) and `federation-protocol.md`
-- §5.4). Peers are keyed on the instance's Ed25519 admin pubkey —
-- the trust anchor — while `instance_domain` is mutable routing
-- metadata that can change without disturbing peering. This is the
-- structural difference from ActivityPub-style identity: a domain
-- rename here updates one column, instead of orphaning every prior
-- relationship.
--
-- Phase A introduces the table empty. It is populated by the
-- federation handshake flow (capability negotiation, pubkey exchange),
-- which lands after the schema refactor completes. Until then, every
-- `home_instance` BLOB on `users`, `posts`, and `threads` is NULL
-- (local-authored) and never needs a `peers` join.
--
-- Rotation state per `federation-protocol.md` §6.6 is intentionally
-- not modeled yet — the columns needed to express it will be added
-- alongside the handshake handlers, when their shape is concrete.
CREATE TABLE peers (
    instance_pubkey BLOB PRIMARY KEY NOT NULL,
    instance_domain TEXT NOT NULL UNIQUE,
    status          TEXT NOT NULL CHECK (status IN ('pending', 'active', 'severed')),
    capabilities    BLOB,
    first_seen      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_handshake  TEXT
);

CREATE INDEX idx_peers_status ON peers(status);
