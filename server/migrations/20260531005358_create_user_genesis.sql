-- Phase 2 of root-advertisement federation: genesis attestation store
-- (docs/federation-protocol.md §12.8 / §5.1;
-- docs/signed-payload-format.md §5.1 GenesisAttestation).
--
-- §12.8 generalizes the §5.1 move payload into a home *declaration*: a
-- declaration with no `from_*` fields is a genesis (account birth),
-- and every declaration carries an immutable `genesis_at` (the account
-- age anchor) plus a birth-instance counter-signed `genesis_attestation`
-- {key, genesis_at, birth_instance_key, sig}. Carrying genesis_at
-- forward, re-signed on every chain link, and pinning it to a
-- birth-instance signature closes the tail-spam vector: a newly minted
-- key cannot forge an old account age to evade the §8.9 cap-at-N
-- age-ranking or the §8.3 age_ceilings cutoffs.
--
-- This table is the resolved projection of the genesis attestation for
-- each key we have applied a declaration for. One row per user key,
-- written on the *first* genesis/move declaration we accept for that
-- key and thereafter immutable (genesis_at and the attestation are
-- forward-carried unchanged — a later declaration for the same key
-- MUST present the identical attestation, so the row is an UPSERT that
-- never changes the genesis fields). Receivers read `genesis_at` here
-- directly for age comparisons rather than re-deriving it from a local
-- clock or re-walking the move chain.
--
-- GDPR: for a *local* user, the genesis_at anchor is account-birth
-- metadata about that user. `server/src/privacy.rs` covers it in the
-- right-to-access export. Right-to-erasure deletes the local account
-- but the genesis attestation is signed chain evidence that peers also
-- hold; the local row is dropped on erasure of a locally-hosted key
-- so this instance retains no birth metadata for an erased local user.

CREATE TABLE IF NOT EXISTS user_genesis (
    -- Ed25519 public key of the identity K whose genesis this is (raw
    -- 32 bytes). Matches the `key` field of §5.1 declarations and the
    -- `attestation.key` field; the two MUST agree (enforced in
    -- application verification, not here).
    user_key BLOB PRIMARY KEY NOT NULL
            CHECK (length(user_key) = 32),

    -- Immutable account-age anchor (Unix milliseconds UTC), copied
    -- verbatim from the declaration's `genesis_at` field. Forward-
    -- carried unchanged across every move in the chain. The §8.9
    -- cap-at-N age ranking and the §8.3 age_ceilings cutoffs compare
    -- against this value; receivers MUST NOT re-derive it locally.
    genesis_at INTEGER NOT NULL,

    -- Ed25519 `instance_pubkey` (raw 32 bytes) of the instance that
    -- minted the identity and counter-signed the genesis attestation
    -- (`attestation.birth_instance_key`). This is the signing key the
    -- `attestation_sig` below verifies against.
    birth_instance_key BLOB NOT NULL
            CHECK (length(birth_instance_key) = 32),

    -- Ed25519 signature (raw 64 bytes) by `birth_instance_key` over
    -- the canonical GenesisAttestation {key, genesis_at,
    -- birth_instance_key} (signed-payload-format.md §5.1). Persisted
    -- so this instance can re-serve and re-verify the attestation when
    -- forwarding the key's declarations to peers, without re-fetching
    -- it from the birth instance.
    attestation_sig BLOB NOT NULL
            CHECK (length(attestation_sig) = 64),

    -- ISO-8601 timestamp of when this row was first inserted.
    -- Operator-visible only — distinct from `genesis_at` (the signer-
    -- attested account-birth wall clock).
    received_at TEXT NOT NULL
            DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
