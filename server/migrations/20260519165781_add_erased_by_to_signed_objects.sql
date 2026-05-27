-- Add `erased_by` forward-link from an erased signed object to the
-- canonical_hash of the *authority* that triggered the erasure (the
-- retraction, deactivate, or admin-rm signed object). This makes the
-- §10.5 "410 Gone" backfill response path O(1): when a peer pulls an
-- object whose payload has been dropped, we need to attach the signed
-- authority that justified the erasure so the requester can verify the
-- justification and erase the object themselves.
--
-- Without this column, finding the authority requires class-specific
-- scans of projection tables (admin_rm_authorities works O(1) for
-- admin-rm via post_id, but retraction/deactivate cascades would need
-- per-payload parsing of every candidate). A nullable forward-link
-- column keeps the lookup uniform and cheap.
--
-- NULL `erased_by` is permitted: it means "erased but the authority is
-- not locally known" (e.g. backfilled-erased state from another peer
-- where we never received the authority object). The 410-Gone handler
-- treats those as "erased without bytes to return".
--
-- See docs/federation-protocol.md §10.5.3 ("410 Gone shape") and
-- §3.1 ("Payload erasure") in docs/signed-payload-format.md.

ALTER TABLE signed_objects ADD COLUMN erased_by BLOB
    REFERENCES signed_objects(canonical_hash) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_signed_objects_erased_by
    ON signed_objects(erased_by)
    WHERE erased_by IS NOT NULL;
