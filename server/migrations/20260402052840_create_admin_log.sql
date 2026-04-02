CREATE TABLE IF NOT EXISTS admin_log (
    id TEXT PRIMARY KEY NOT NULL,
    admin TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL CHECK (action IN (
        'pin_thread', 'unpin_thread',
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

CREATE INDEX IF NOT EXISTS idx_admin_log_created_at ON admin_log(created_at);
