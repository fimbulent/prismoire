-- Per-viewer private tags attached to other users.
--
-- ON DELETE CASCADE on both FKs cleans up automatically when either
-- the viewer or the target user is hard-deleted. The soft-delete path
-- (`privacy.rs::soft_delete_user`) only anonymises the users row, so
-- the FK cascade does not fire there — the soft-delete handler
-- explicitly deletes user_tags rows for both directions to match.

CREATE TABLE user_tags (
    viewer_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag        TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (viewer_id, target_id),
    CHECK (viewer_id <> target_id),
    CHECK (length(tag) > 0)
);

CREATE INDEX idx_user_tags_viewer ON user_tags(viewer_id);
