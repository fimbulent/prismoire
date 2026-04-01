-- Rename "area" concept to "room" throughout the schema.

-- Rename the areas table to rooms.
ALTER TABLE areas RENAME TO rooms;

-- Rename area column in threads to room.
ALTER TABLE threads RENAME COLUMN area TO room;

-- Rename area_admin_log table and its area_id column.
ALTER TABLE area_admin_log RENAME TO room_admin_log;
ALTER TABLE room_admin_log RENAME COLUMN area_id TO room_id;

-- Recreate indexes with new names.
-- (Old indexes on renamed tables still work but have stale names.)
DROP INDEX IF EXISTS idx_threads_area;
CREATE INDEX IF NOT EXISTS idx_threads_room ON threads(room);

DROP INDEX IF EXISTS idx_area_admin_log_area;
CREATE INDEX IF NOT EXISTS idx_room_admin_log_room ON room_admin_log(room_id);

DROP INDEX IF EXISTS idx_areas_slug;
CREATE UNIQUE INDEX IF NOT EXISTS idx_rooms_slug ON rooms(slug);
