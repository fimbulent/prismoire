-- Phase 2 of root-advertisement federation: inbound age-ceiling map
-- received from each peer (docs/federation-protocol.md §8.3 / §8.4).
--
-- §8.3 adds an optional `age_ceilings` field to a frontier announce: a
-- sparse map {root_key → cutoff} where `cutoff` is a `genesis_at`
-- watermark. A peer publishes a ceiling for one of its roots when the
-- group-2 age-ranked tail under that root (the §8.10 celebrity cleave)
-- has grown past what it wants to keep flooding; the ceiling tells us
-- "for this root, do not expand frontier edges whose target's
-- `genesis_at` is newer than `cutoff`." §8.4 deltas MAY carry an
-- updated `age_ceilings` that *tightens* (lowers a cutoff / adds a
-- root); enforcement is opportunistic and monotonic-tighten fail-open.
--
-- The map is sparse — most roots carry no ceiling — so it is stored as
-- child rows rather than a column on `peer_frontiers`. One row per
-- (peer, root) pair for which the peer currently advertises a ceiling.
-- Absence of a row for a root means "no ceiling" (expand without an
-- age cutoff for that root). Applying a fresh §8.3 announce replaces
-- this peer's whole map; a §8.4 delta upserts the carried entries.
--
-- Holds only ceilings learned from remote peers about remote roots; no
-- local user PII, so outside the GDPR surface in privacy.rs.

CREATE TABLE IF NOT EXISTS peer_frontier_age_ceilings (
    -- Sender's instance signing pubkey (raw 32 bytes). Joins to the
    -- parent `peer_frontiers` row; ON DELETE CASCADE drops a peer's
    -- ceilings when its frontier (and the peering) is dropped.
    peer_pubkey BLOB NOT NULL
            CHECK (length(peer_pubkey) = 32),

    -- Ed25519 public key (raw 32 bytes) of the peer's root that this
    -- ceiling applies to. The §8.3 map key.
    root_key BLOB NOT NULL
            CHECK (length(root_key) = 32),

    -- `genesis_at` cutoff (Unix milliseconds UTC) for this root.
    -- Frontier targets whose `genesis_at` (see `user_genesis`) is
    -- strictly newer than this value are not expanded under `root_key`.
    -- Carried on the wire as u64; stored as i64 (fits any realistic
    -- timestamp). Tightening lowers this value; §8.4 enforces the
    -- monotonic-tighten rule in application code.
    cutoff INTEGER NOT NULL,

    -- ISO-8601 timestamp of the last upsert of this ceiling.
    -- Operator-visible only.
    updated_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    PRIMARY KEY (peer_pubkey, root_key),

    FOREIGN KEY (peer_pubkey) REFERENCES peer_frontiers(peer_pubkey)
        ON DELETE CASCADE
);
