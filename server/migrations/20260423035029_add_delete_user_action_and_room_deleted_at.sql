-- Support for admin-initiated room and user deletion (the "Actions" tab on
-- the admin dashboard).
--
-- 1. Add a `deleted_at` tombstone column to `rooms`, mirroring the one we
--    already use on `users`. When an admin deletes a room we hard-delete
--    all of its threads / posts / revisions / recent-replier rows (so the
--    content disappears for everyone) but keep the `rooms` row itself so
--    admin_log entries that reference it stay FK-valid and renderable in
--    the log UI. The tombstone is what hides the room from public listings
--    (`list_rooms`, `top_rooms`, `get_room`).
--
-- 2. Extend the `admin_log.action` CHECK constraint to accept `delete_user`
--    so the admin-initiated soft-delete can write a log entry. The
--    existing `delete_room` action already covers room deletion. SQLite
--    can't alter a CHECK constraint in place, so the table is rebuilt. The
--    only child table with an FK to `admin_log.id` is
--    `ban_trust_snapshots`; both are rebuilt together (leaves-to-root
--    drop, root-to-leaves recreate) per the migrations/CLAUDE.md
--    rebuild-chain pattern.

-- 1. Room tombstone.
ALTER TABLE rooms ADD COLUMN deleted_at TEXT;
CREATE INDEX idx_rooms_deleted_at ON rooms(deleted_at);

-- 2. Rebuild admin_log + ban_trust_snapshots to widen the action CHECK.
CREATE TEMP TABLE _admin_log_backup AS SELECT * FROM admin_log;
CREATE TEMP TABLE _ban_trust_snapshots_backup AS SELECT * FROM ban_trust_snapshots;

DROP TABLE ban_trust_snapshots;
DROP TABLE admin_log;

CREATE TABLE admin_log (
    id TEXT PRIMARY KEY NOT NULL,
    admin TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL CHECK (action IN (
        'lock_thread', 'unlock_thread',
        'remove_post',
        'merge_room', 'delete_room',
        'ban_user', 'unban_user',
        'suspend_user', 'unsuspend_user',
        'revoke_invites', 'grant_invites',
        'delete_user'
    )),
    target_user TEXT REFERENCES users(id),
    thread_id TEXT REFERENCES threads(id),
    post_id TEXT REFERENCES posts(id),
    room_id TEXT REFERENCES rooms(id),
    merged_into TEXT REFERENCES rooms(id),
    reason TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE ban_trust_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    admin_log_id TEXT NOT NULL REFERENCES admin_log(id),
    target_user TEXT NOT NULL REFERENCES users(id),
    trusting_user TEXT NOT NULL REFERENCES users(id),
    edge_created_at TEXT NOT NULL,
    snapshot_at TEXT NOT NULL,
    action_type TEXT NOT NULL CHECK (action_type IN ('ban', 'suspend'))
);

INSERT INTO admin_log SELECT * FROM _admin_log_backup;
INSERT INTO ban_trust_snapshots SELECT * FROM _ban_trust_snapshots_backup;

DROP TABLE _admin_log_backup;
DROP TABLE _ban_trust_snapshots_backup;

CREATE INDEX idx_admin_log_created_at ON admin_log(created_at);
CREATE INDEX idx_admin_log_target_user ON admin_log(target_user);
CREATE INDEX idx_ban_trust_snapshots_target ON ban_trust_snapshots(target_user);
CREATE INDEX idx_ban_trust_snapshots_trusting ON ban_trust_snapshots(trusting_user);
CREATE INDEX idx_ban_trust_snapshots_admin_log ON ban_trust_snapshots(admin_log_id);