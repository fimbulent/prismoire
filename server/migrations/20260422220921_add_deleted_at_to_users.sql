-- Account self-deletion support. When a user deletes their own account we
-- keep the row for FK integrity (rooms, threads, posts, reports, admin_log
-- all reference users.id) but null out personal data and set deleted_at.
--
-- `deleted_at` doubles as a tombstone marker:
--   * the UI can show "[deleted]" instead of a display name,
--   * login flows refuse credentials for deleted users,
--   * admin moderation skips deleted users.
ALTER TABLE users ADD COLUMN deleted_at TEXT;

CREATE INDEX idx_users_deleted_at ON users(deleted_at);
