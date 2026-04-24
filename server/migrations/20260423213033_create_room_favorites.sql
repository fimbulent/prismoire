-- Per-user pinned/favorited rooms for tab-bar and /rooms listing.
--
-- `position` is a dense 0-based ordinal; reorder mutations rewrite the full
-- range for the user in a single transaction. No fractional indexing since
-- per-user favorite counts are small (soft-capped at 50 in the handler).
--
-- ON DELETE CASCADE on both FKs cleans up when a user or room disappears,
-- so the handler and privacy.rs don't need to do it explicitly — they still
-- do, for the user-delete case, because the FK cascade depends on
-- `PRAGMA foreign_keys = ON` (set at connection time in application code).

CREATE TABLE room_favorites (
    user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    room_id    TEXT    NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    position   INTEGER NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (user_id, room_id)
);

CREATE INDEX idx_room_favorites_user_pos ON room_favorites(user_id, position);
