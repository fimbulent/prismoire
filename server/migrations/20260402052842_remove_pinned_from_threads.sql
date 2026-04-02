-- Remove the pinned column from threads and pin/unpin actions from admin_log.

-- 1. Drop pinned column (SQLite 3.35.0+)
ALTER TABLE threads DROP COLUMN pinned;

-- 2. Recreate admin_log without pin_thread/unpin_thread actions
-- (must recreate because CHECK constraint change)
PRAGMA defer_foreign_keys = ON;

CREATE TABLE admin_log_new (
    id TEXT PRIMARY KEY NOT NULL,
    admin TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL CHECK (action IN (
        'lock_thread', 'unlock_thread',
        'remove_post',
        'merge_room', 'delete_room'
    )),
    thread_id TEXT REFERENCES threads(id),
    post_id TEXT REFERENCES posts(id),
    room_id TEXT REFERENCES rooms(id),
    merged_into TEXT REFERENCES rooms(id),
    reason TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO admin_log_new (id, admin, action, thread_id, post_id, room_id, merged_into, reason, created_at)
    SELECT id, admin, action, thread_id, post_id, room_id, merged_into, reason, created_at
    FROM admin_log
    WHERE action NOT IN ('pin_thread', 'unpin_thread');

DROP TABLE admin_log;
ALTER TABLE admin_log_new RENAME TO admin_log;

CREATE INDEX idx_admin_log_created_at ON admin_log(created_at);