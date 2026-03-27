-- Add a UTS #39 confusable skeleton column for lookalike display name detection.
-- Two names with identical skeletons are visually confusable (e.g. "alice" vs "aIice").
-- The unique index prevents registration of names that look like existing ones.
ALTER TABLE users ADD COLUMN display_name_skeleton TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_display_name_skeleton ON users(display_name_skeleton);