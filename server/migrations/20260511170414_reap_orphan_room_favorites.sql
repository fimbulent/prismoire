-- Reap orphan `room_favorites` rows pointing at soft-deleted or merged
-- rooms.
--
-- Background: `room_favorites.room_id` has `ON DELETE CASCADE`, so
-- *hard* deletes have always reaped favorites automatically. But soft
-- deletes (`rooms.deleted_at`) and merges (`rooms.merged_into`) leave
-- the favorite row in place, which causes a divergence between
-- `GET /api/me/favorites` (which silently skips invisible rooms) and
-- `PUT /api/me/favorites` (which validates the submitted set against
-- the raw table). Users with at least one orphan favorite could never
-- successfully reorder.
--
-- Going forward, `admin::delete_room` reaps favorites in the same
-- transaction that stamps `deleted_at`, so new orphans can't accrue.
-- This one-shot backfill clears the orphans that existed before that
-- handler change.
DELETE FROM room_favorites
WHERE room_id IN (
    SELECT id FROM rooms
    WHERE deleted_at IS NOT NULL OR merged_into IS NOT NULL
);
