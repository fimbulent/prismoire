-- Phase 2 of root-advertisement federation: outbound age-ceiling map
-- this instance advertises for its own local roots
-- (docs/federation-protocol.md §8.3 / §8.10).
--
-- The source-side counterpart of `peer_frontier_age_ceilings`. When a
-- local root accrues a group-2 age-ranked tail large enough that
-- continuing to flood it is wasteful (§8.10 celebrity cleave), this
-- instance sets a `genesis_at` ceiling for that root and emits it in
-- the optional `age_ceilings` map of every §8.3 announce and §8.4
-- delta it sends. Peers then stop expanding frontier edges whose
-- target is newer than the cutoff, shedding the flood at the source.
--
-- One row per local root for which we currently advertise a ceiling.
-- The map is sparse — the common case is no row (no ceiling, flood
-- the whole tail). The §8.3/§8.4 producer serializes every row here
-- into the outbound `age_ceilings` field. Tightening (lowering a
-- cutoff) is just an UPDATE that the next delta/announce carries; the
-- §8.10 backpressure controller owns when to set/tighten these.
--
-- `root_key` is one of *this instance's* local user keys, but the
-- ceiling itself is operator backpressure policy, not user-owned data;
-- it is reconstructible from frontier sizing and carries no PII, so it
-- is outside the GDPR export/delete surface in privacy.rs.

CREATE TABLE IF NOT EXISTS local_frontier_age_ceilings (
    -- Ed25519 public key (raw 32 bytes) of the local root this ceiling
    -- applies to. One ceiling per root; the PK enforces it.
    root_key BLOB PRIMARY KEY NOT NULL
            CHECK (length(root_key) = 32),

    -- `genesis_at` cutoff (Unix milliseconds UTC) we advertise for
    -- this root. Peers do not expand frontier targets newer than this
    -- under `root_key`. Emitted on the wire as u64; stored as i64.
    -- Lowering it tightens the ceiling (sheds more of the tail).
    cutoff INTEGER NOT NULL,

    -- ISO-8601 timestamp of the last time we set or tightened this
    -- ceiling. Operator-visible; also a useful audit trail for the
    -- §8.10 controller's decisions.
    updated_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
