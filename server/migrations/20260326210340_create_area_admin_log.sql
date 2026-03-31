CREATE TABLE IF NOT EXISTS area_admin_log (
    id TEXT PRIMARY KEY NOT NULL,
    admin TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL CHECK (action IN ('merge', 'delete')),
    area_id TEXT NOT NULL REFERENCES areas(id),
    merged_into TEXT REFERENCES areas(id),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_area_admin_log_area ON area_admin_log(area_id);
