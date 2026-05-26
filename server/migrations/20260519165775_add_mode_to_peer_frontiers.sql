-- Phase 6.5 of federation: per-peer routing mode columns
-- (docs/federation-protocol.md §7.2; docs/federation-impl-plan.md Phase 6.5).
--
-- Two TEXT columns, one per direction:
--
--   inbound_mode  — the mode the peer says they use when sending to us;
--                   piggybacked on the peer's frontier announce/delta
--                   body and stored verbatim on receive.
--                   *** UNTRUSTED SELF-CLAIM. *** Never gate a security
--                   decision (rate limit, accept/drop, trust scoring)
--                   on this value — a peer can write whatever they want
--                   into it. It exists for observability and for the
--                   §7.2 wire round-trip; the only routing decision
--                   that ever consults a peer's "mode" is the receiver
--                   side reading their *own* outbound_mode below.
--   outbound_mode — the mode we use when sending to the peer; classified
--                   locally from coverage of the peer's content_filter
--                   against our local-user pubkeys (§7.2 detection rule),
--                   recomputed on every announce/delta receive.
--
-- Defaults to 'filtered' per §7.2 ("fresh peering never starts in
-- all-mode"): both the first row inserted for a peer (before any
-- announce has been received) and any pre-existing row from an older
-- build land in `filtered` and only flip once coverage crosses the
-- HIGH/LOW thresholds.
--
-- CHECK constraint enforces the §7.2 value domain at the DB so a stray
-- write outside the application path can't corrupt the routing state.

ALTER TABLE peer_frontiers
    ADD COLUMN inbound_mode TEXT NOT NULL DEFAULT 'filtered'
        CHECK (inbound_mode IN ('filtered', 'all'));

ALTER TABLE peer_frontiers
    ADD COLUMN outbound_mode TEXT NOT NULL DEFAULT 'filtered'
        CHECK (outbound_mode IN ('filtered', 'all'));
