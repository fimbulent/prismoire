-- Add canonical-CBOR signing columns to trust_edges per
-- docs/signed-payload-format.md §9.3 step 5.
--
-- `signature` and `prior_edge_hash` are nullable so this migration
-- can land before the backfill populates `signature`. A startup pass
-- (see main.rs) signs every existing row using the source user's V1
-- server-side signing key. New mutations (step 6, when handlers cut
-- over to producing trust-edge signed objects) will write `signature`
-- on every INSERT.
--
-- `prior_edge_hash` stays nullable indefinitely: per §4.3 it is
-- absent for the first mutation of any `(from_key, to_key)` pair,
-- which under the current UNIQUE(source_user, target_user) constraint
-- is every row.
--
-- `format_version` lets the verifier dispatch by version without
-- parsing the payload. Defaults to 1; bumped by future migrations
-- that re-sign under a new schema (V2+).
ALTER TABLE trust_edges ADD COLUMN signature BLOB;
ALTER TABLE trust_edges ADD COLUMN prior_edge_hash BLOB;
ALTER TABLE trust_edges ADD COLUMN format_version INTEGER NOT NULL DEFAULT 1;
