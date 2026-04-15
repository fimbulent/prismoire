-- Ban/suspend system: add user fields, rebuild admin_log with new actions
-- and target_user, create ban_trust_snapshots table.

-- 1. Add suspended_until and can_invite to users
ALTER TABLE users ADD COLUMN suspended_until TEXT;
ALTER TABLE users ADD COLUMN can_invite INTEGER NOT NULL DEFAULT 1;

-- 2. Rebuild admin_log to add target_user column and extend action CHECK.
--    Nothing references admin_log via FK, so a simple rebuild suffices.

CREATE TEMP TABLE _admin_log_backup AS SELECT * FROM admin_log;
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
        'revoke_invites', 'grant_invites'
    )),
    target_user TEXT REFERENCES users(id),
    thread_id TEXT REFERENCES threads(id),
    post_id TEXT REFERENCES posts(id),
    room_id TEXT REFERENCES rooms(id),
    merged_into TEXT REFERENCES rooms(id),
    reason TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO admin_log (id, admin, action, thread_id, post_id, room_id, merged_into, reason, created_at)
    SELECT id, admin, action, thread_id, post_id, room_id, merged_into, reason, created_at
    FROM _admin_log_backup;

DROP TABLE _admin_log_backup;

CREATE INDEX idx_admin_log_created_at ON admin_log(created_at);
CREATE INDEX idx_admin_log_target_user ON admin_log(target_user);

-- 3. Create ban_trust_snapshots table
CREATE TABLE IF NOT EXISTS ban_trust_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    admin_log_id TEXT NOT NULL REFERENCES admin_log(id),
    target_user TEXT NOT NULL REFERENCES users(id),
    trusting_user TEXT NOT NULL REFERENCES users(id),
    edge_created_at TEXT NOT NULL,
    snapshot_at TEXT NOT NULL,
    action_type TEXT NOT NULL CHECK (action_type IN ('ban', 'suspend'))
);

CREATE INDEX idx_ban_trust_snapshots_target ON ban_trust_snapshots(target_user);
CREATE INDEX idx_ban_trust_snapshots_trusting ON ban_trust_snapshots(trusting_user);
CREATE INDEX idx_ban_trust_snapshots_admin_log ON ban_trust_snapshots(admin_log_id);
