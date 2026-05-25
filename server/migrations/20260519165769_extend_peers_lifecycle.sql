-- Expand the `peers` table to track the §5.4 handshake lifecycle.
--
-- The original `peers` shape (migration `20260519165753_create_peers`)
-- modelled status as `('pending', 'active', 'severed')` — sufficient
-- for the structural skeleton it landed under but too coarse for the
-- handshake state machine documented in `federation-protocol.md`
-- §5.1, which needs to distinguish:
--
--   - `pending_outbound`  — we sent a peer-request, awaiting their
--                           operator's accept/reject callback.
--   - `pending_inbound`   — they sent us a peer-request, awaiting
--                           our operator's accept/reject decision.
--   - `active`            — handshake complete on both sides; the
--                           §6 envelope verifier will accept their
--                           sender key on inbound requests.
--   - `key_rotating`      — placeholder for §6.6 rotation overlap;
--                           no transitions yet (Phase 3+).
--   - `rejected`          — terminal: peer's operator rejected our
--                           outbound peer-request (or ours rejected
--                           theirs). Archive-only; inbound traffic
--                           rejects per §5.4.
--   - `terminated`        — terminal: a previously-active peering
--                           was ended by operator action on either
--                           side. Placeholder; the transition lands
--                           with the Phase 3+ termination route.
--   - `closed`            — generic terminal fallback retained for
--                           forward-compat. Producers prefer the
--                           specific `rejected` / `terminated`
--                           variants; this value is reserved for
--                           cases neither covers.
--
-- We also need to remember the `request_id` UUID that ties a
-- peer-request to its later peer-response callback (so the responder
-- can quote it back and the initiator can correlate), and to store
-- the `agreed_capabilities` set the responder committed to on
-- accept. The existing `capabilities` column (advertised set from
-- /identity) is preserved as a separate field — the two are
-- different facts and merging them would lose information once
-- capability negotiation gets richer.
--
-- The previous `peers` rows (if any) are dropped along with the
-- table: the table was introduced empty by the original Phase A
-- migration and no production peerings exist to preserve. If a
-- future deployment ever finds itself with rows here at this
-- migration's run-time, the rebuild loses them — which is the
-- correct behaviour because the new schema's required `direction`
-- field has no sensible default for a row whose origin is unknown.
DROP INDEX IF EXISTS idx_peers_status;
DROP TABLE IF EXISTS peers;

CREATE TABLE peers (
    instance_pubkey     BLOB    PRIMARY KEY NOT NULL
                                CHECK (length(instance_pubkey) = 32),
    instance_domain     TEXT    NOT NULL UNIQUE,
    status              TEXT    NOT NULL CHECK (status IN (
                            'pending_outbound',
                            'pending_inbound',
                            'active',
                            'key_rotating',
                            'rejected',
                            'terminated',
                            'closed'
                        )),
    -- Whether the current relationship was initiated by us
    -- (`outbound`) or by them (`inbound`). Locked at the
    -- pending_* → active transition; preserved through the rest of
    -- the lifecycle for audit / operator-UI display.
    direction           TEXT    NOT NULL CHECK (direction IN ('outbound', 'inbound')),
    -- UUID (bstr 16) of the peer-request that initiated the current
    -- relationship phase. Outbound: minted by us, echoed by peer in
    -- the peer-response callback. Inbound: minted by them, quoted
    -- back in our peer-response.
    request_id          BLOB    NOT NULL CHECK (length(request_id) = 16),
    -- Capabilities the peer advertised in their /identity payload
    -- (or peer-request body for inbound, peer-response body for
    -- outbound accept). Canonical CBOR array of tstr. May lag the
    -- peer's live /identity until next handshake step.
    capabilities        BLOB,
    -- Capabilities both sides agreed to use in this peering — the
    -- intersection of advertised sets at handshake time. CBOR array
    -- of tstr. NULL while the row is in any `pending_*` state.
    agreed_capabilities BLOB,
    -- Operator-set message from the most recent peer-response
    -- (welcome note on accept, rejection reason on reject). Surfaced
    -- in the admin UI alongside the row. NULL when no message was
    -- supplied or when the row is still in `pending_*`.
    decision_message    TEXT,
    first_seen          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    -- Wall-clock of the most recent successful handshake message
    -- exchanged with this peer (peer-request sent/received,
    -- peer-response received). NULL until the first such event.
    last_handshake      TEXT
);

CREATE INDEX idx_peers_status ON peers(status);

-- Correlation queries (peer-response handler, operator accept) look
-- up the in-flight handshake by `request_id`. UNIQUE: each
-- request_id ties exactly one peer row, so a duplicate would be a
-- protocol-level confusion the verifier should surface as an INSERT
-- failure rather than silently returning an arbitrary `fetch_one`
-- result.
CREATE UNIQUE INDEX idx_peers_request_id ON peers(request_id);
