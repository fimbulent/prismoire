-- Phase 4 of federation: per-peer frontier filter state
-- (docs/federation-protocol.md §8 + docs/federation-impl-plan.md Phase 4).
--
-- Holds the latest §8.3-style frontier announce we have received from
-- each peer: both Bloom filter pairs (content + edge-origin), the
-- monotonic `applied_version` we use to reject stale §8.3/§8.4
-- bodies, and the opaque cursor we hand back to the §8.5 GET caller
-- so they can issue conditional refreshes.
--
-- One row per peer. The §6 envelope auth gates writes (only an
-- envelope-verified §8.3/§8.4 handler can insert/update), so we don't
-- need an FK to `peers` to enforce who is allowed to populate this
-- table; we do still FK to it for the operator-facing referential
-- integrity (a terminated peering should also drop its cached
-- frontier rather than holding stale state that no longer matches
-- a live peer pubkey). ON DELETE CASCADE keeps that invariant cheap.

CREATE TABLE peer_frontiers (
    -- Sender's instance signing pubkey (raw 32 bytes). One row per
    -- peer; the PK is identical to `peers.instance_pubkey`.
    peer_pubkey BLOB PRIMARY KEY NOT NULL
                CHECK (length(peer_pubkey) = 32),

    -- Highest §8.3 `version` we have applied from this sender. The
    -- §8.3/§8.4 handlers reject any inbound body with
    -- `version <= applied_version` per the spec's monotonic-cursor
    -- rule.
    applied_version INTEGER NOT NULL,

    -- §8.3 `epoch_start` (unix ms). Informational on the wire; we
    -- persist it because §8.5 GET callers see it in the snapshot
    -- they fetch.
    epoch_start INTEGER NOT NULL,

    -- §8.3 `active_horizon_days`. 0 means "no trimming applied."
    -- Informational; we persist for §20 dashboards and for the
    -- §8.5 GET round-trip.
    active_horizon_days INTEGER NOT NULL DEFAULT 0
                CHECK (active_horizon_days >= 0),

    -- Content filter (3-hop closure per §7.4). The family-name
    -- field is the future-compat dispatch hook from §8.2; we accept
    -- only `prismoire-bloom-v1` today but persist what the sender
    -- declared so a future build that supports an additional family
    -- can read existing rows without re-syncing.
    cf_family TEXT NOT NULL,
    cf_k INTEGER NOT NULL
                CHECK (cf_k BETWEEN 1 AND 32),
    cf_m INTEGER NOT NULL
                CHECK (cf_m >= 64 AND (cf_m % 64) = 0),
    cf_n_est INTEGER NOT NULL
                CHECK (cf_n_est >= 0),
    cf_fpr_target REAL NOT NULL,
    -- Exactly cf_m / 8 bytes; CHECK enforces it locally so a row
    -- inserted out of band still satisfies the §8.2 invariant.
    cf_bytes BLOB NOT NULL
                CHECK (length(cf_bytes) = cf_m / 8),

    -- Edge-origin filter (2-hop closure per §7.4). Same field shape
    -- as the content filter; receivers must validate both
    -- independently per §8.3.
    ef_family TEXT NOT NULL,
    ef_k INTEGER NOT NULL
                CHECK (ef_k BETWEEN 1 AND 32),
    ef_m INTEGER NOT NULL
                CHECK (ef_m >= 64 AND (ef_m % 64) = 0),
    ef_n_est INTEGER NOT NULL
                CHECK (ef_n_est >= 0),
    ef_fpr_target REAL NOT NULL,
    ef_bytes BLOB NOT NULL
                CHECK (length(ef_bytes) = ef_m / 8),

    -- Opaque §8.5 cursor we return to GET callers (≤ 64 bytes per
    -- the spec table). We mint this server-side on each apply and
    -- return it from /announce and /delta success responses too,
    -- so the caller has a fresh cursor without a follow-up GET.
    cursor BLOB NOT NULL
                CHECK (length(cursor) <= 64),

    -- ISO-8601 timestamp of the last apply. Operator-visible only;
    -- not consulted by the routing path.
    updated_at TEXT NOT NULL
                DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    FOREIGN KEY (peer_pubkey) REFERENCES peers(instance_pubkey)
        ON DELETE CASCADE
);
