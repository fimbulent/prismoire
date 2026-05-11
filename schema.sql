CREATE TABLE _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    checksum BLOB NOT NULL,
    execution_time BIGINT NOT NULL
);
CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    display_name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    signup_method TEXT NOT NULL CHECK (signup_method IN ('steam_key', 'invite', 'admin')),
    steam_verified INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'banned')),
    bio TEXT
, display_name_skeleton TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')), invite_id TEXT REFERENCES invites(id), suspended_until TEXT, can_invite INTEGER NOT NULL DEFAULT 1, deleted_at TEXT);
CREATE TABLE credentials (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    credential_id BLOB NOT NULL UNIQUE,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_used TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    label TEXT
);
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE TABLE sessions (
    token TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE TABLE invites (
    id TEXT PRIMARY KEY NOT NULL,
    code TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    revoked_at TEXT,
    max_uses INTEGER,
    expires_at TEXT
);
CREATE INDEX idx_invites_code ON invites(code);
CREATE UNIQUE INDEX idx_users_display_name_skeleton ON users(display_name_skeleton);
CREATE TABLE IF NOT EXISTS "auth_challenges" (
    id TEXT PRIMARY KEY NOT NULL,
    challenge_type TEXT NOT NULL CHECK (challenge_type IN ('registration', 'authentication', 'discoverable')),
    state BLOB NOT NULL,
    display_name TEXT,
    invite_code TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
, user_id TEXT);
CREATE TABLE signing_keys (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_signing_keys_user_id ON signing_keys(user_id);
CREATE UNIQUE INDEX idx_signing_keys_active ON signing_keys(user_id) WHERE active = 1;
CREATE INDEX idx_users_invite_id ON users(invite_id);
CREATE TABLE user_settings (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id),
    theme TEXT NOT NULL DEFAULT 'rose-pine'
, font TEXT NOT NULL DEFAULT 'inter');
CREATE TABLE IF NOT EXISTS "trust_edges" (
    id TEXT PRIMARY KEY NOT NULL,
    source_user TEXT NOT NULL REFERENCES users(id),
    target_user TEXT NOT NULL REFERENCES users(id),
    trust_type TEXT NOT NULL CHECK (trust_type IN ('trust', 'distrust')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    reason TEXT,
    UNIQUE(source_user, target_user)
);
CREATE INDEX idx_trust_edges_source ON trust_edges(source_user);
CREATE INDEX idx_trust_edges_target ON trust_edges(target_user);
CREATE TABLE csp_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    document_uri TEXT,
    referrer TEXT,
    violated_directive TEXT,
    effective_directive TEXT,
    original_policy TEXT,
    blocked_uri TEXT,
    source_file TEXT,
    line_number INTEGER,
    column_number INTEGER,
    status_code INTEGER,
    script_sample TEXT
);
CREATE TABLE sqlite_sequence(name,seq);
CREATE INDEX idx_csp_reports_received_at ON csp_reports(received_at);
CREATE TABLE rooms (
    id TEXT PRIMARY KEY NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    merged_into TEXT REFERENCES rooms(id)
, deleted_at TEXT);
CREATE TABLE threads (
    id TEXT PRIMARY KEY NOT NULL,
    title TEXT NOT NULL,
    author TEXT NOT NULL REFERENCES users(id),
    room TEXT NOT NULL REFERENCES rooms(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    locked INTEGER NOT NULL DEFAULT 0,
    last_activity TEXT,
    reply_count INTEGER NOT NULL DEFAULT 0
, link_url TEXT, link_url_normalized TEXT);
CREATE TABLE posts (
    id TEXT PRIMARY KEY NOT NULL,
    author TEXT NOT NULL REFERENCES users(id),
    thread TEXT NOT NULL REFERENCES threads(id),
    parent TEXT REFERENCES posts(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    retracted_at TEXT,
    retraction_signature BLOB,
    revision_count INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE post_revisions (
    post_id TEXT NOT NULL REFERENCES posts(id),
    revision INTEGER NOT NULL DEFAULT 0,
    body TEXT NOT NULL,
    signature BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    epoch INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (post_id, revision)
);
CREATE TABLE thread_recent_repliers (
    thread_id TEXT NOT NULL REFERENCES threads(id),
    reply_rank INTEGER NOT NULL,
    replier_id TEXT NOT NULL REFERENCES users(id),
    replied_at TEXT NOT NULL,
    PRIMARY KEY (thread_id, reply_rank)
);
CREATE TABLE room_admin_log (
    id TEXT PRIMARY KEY NOT NULL,
    admin TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL CHECK (action IN ('merge', 'delete')),
    room_id TEXT NOT NULL REFERENCES rooms(id),
    merged_into TEXT REFERENCES rooms(id),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE UNIQUE INDEX idx_rooms_slug ON rooms(slug);
CREATE INDEX idx_threads_author ON threads(author);
CREATE INDEX idx_threads_room ON threads(room);
CREATE INDEX idx_threads_last_activity ON threads(last_activity);
CREATE INDEX idx_threads_created_at ON threads(created_at);
CREATE INDEX idx_posts_author ON posts(author);
CREATE INDEX idx_posts_parent ON posts(parent);
CREATE INDEX idx_posts_thread_created ON posts(thread, created_at);
CREATE INDEX idx_room_admin_log_room ON room_admin_log(room_id);
CREATE TABLE reports (
    id TEXT PRIMARY KEY NOT NULL,
    post_id TEXT NOT NULL REFERENCES posts(id),
    reporter TEXT NOT NULL REFERENCES users(id),
    reason TEXT NOT NULL CHECK (reason IN ('spam', 'rules_violation', 'illegal_content', 'other')),
    detail TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'dismissed', 'actioned')),
    resolved_by TEXT REFERENCES users(id),
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(post_id, reporter)
);
CREATE INDEX idx_reports_post_id ON reports(post_id);
CREATE INDEX idx_reports_reporter ON reports(reporter);
CREATE INDEX idx_reports_status ON reports(status);
CREATE INDEX idx_reports_created_at ON reports(created_at);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
CREATE INDEX idx_rooms_deleted_at ON rooms(deleted_at);
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
        'delete_user',
        'remove_bio'
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
CREATE INDEX idx_admin_log_created_at ON admin_log(created_at);
CREATE INDEX idx_admin_log_target_user ON admin_log(target_user);
CREATE INDEX idx_ban_trust_snapshots_target ON ban_trust_snapshots(target_user);
CREATE INDEX idx_ban_trust_snapshots_trusting ON ban_trust_snapshots(trusting_user);
CREATE INDEX idx_ban_trust_snapshots_admin_log ON ban_trust_snapshots(admin_log_id);
CREATE TABLE room_favorites (
    user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    room_id    TEXT    NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    position   INTEGER NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (user_id, room_id)
);
CREATE INDEX idx_room_favorites_user_pos ON room_favorites(user_id, position);
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
CREATE VIRTUAL TABLE threads_fts USING fts5(
    title,
    op_body,
    link_url,
    content='',
    contentless_delete=1,
    tokenize = "unicode61 remove_diacritics 2"
)
/* threads_fts(title,op_body,link_url) */;
CREATE TABLE IF NOT EXISTS 'threads_fts_data'(id INTEGER PRIMARY KEY, block BLOB);
CREATE TABLE IF NOT EXISTS 'threads_fts_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS 'threads_fts_docsize'(id INTEGER PRIMARY KEY, sz BLOB, origin INTEGER);
CREATE TABLE IF NOT EXISTS 'threads_fts_config'(k PRIMARY KEY, v) WITHOUT ROWID;
CREATE TRIGGER threads_fts_after_insert
AFTER INSERT ON threads
BEGIN
    INSERT INTO threads_fts (rowid, title, op_body, link_url)
    VALUES (NEW.rowid, NEW.title, '', COALESCE(NEW.link_url_normalized, ''));
END;
CREATE TRIGGER threads_fts_after_delete
AFTER DELETE ON threads
BEGIN
    DELETE FROM threads_fts WHERE rowid = OLD.rowid;
END;
CREATE TRIGGER threads_fts_after_update_title
AFTER UPDATE OF title ON threads
BEGIN
    INSERT OR REPLACE INTO threads_fts (rowid, title, op_body, link_url)
    VALUES (
        NEW.rowid,
        NEW.title,
        COALESCE(
            (
                SELECT pr.body
                FROM post_revisions pr
                JOIN posts p ON p.id = pr.post_id
                WHERE p.thread = NEW.id
                  AND p.parent IS NULL
                  AND p.retracted_at IS NULL
                ORDER BY pr.revision DESC
                LIMIT 1
            ),
            ''
        ),
        COALESCE(NEW.link_url_normalized, '')
    );
END;
CREATE TRIGGER threads_fts_op_body_after_revision
AFTER INSERT ON post_revisions
WHEN (SELECT parent FROM posts WHERE id = NEW.post_id) IS NULL
 AND NEW.revision = (SELECT MAX(revision) FROM post_revisions WHERE post_id = NEW.post_id)
BEGIN
    INSERT OR REPLACE INTO threads_fts (rowid, title, op_body, link_url)
    SELECT t.rowid, t.title, NEW.body, COALESCE(t.link_url_normalized, '')
    FROM threads t
    WHERE t.id = (SELECT thread FROM posts WHERE id = NEW.post_id);
END;
CREATE TRIGGER threads_fts_op_after_retract
AFTER UPDATE OF retracted_at ON posts
WHEN OLD.retracted_at IS NULL
 AND NEW.retracted_at IS NOT NULL
 AND NEW.parent IS NULL
BEGIN
    INSERT OR REPLACE INTO threads_fts (rowid, title, op_body, link_url)
    SELECT t.rowid, t.title, '', COALESCE(t.link_url_normalized, '')
    FROM threads t
    WHERE t.id = NEW.thread;
END;
CREATE VIRTUAL TABLE posts_fts USING fts5(
    body,
    content='',
    contentless_delete=1,
    tokenize = "unicode61 remove_diacritics 2"
)
/* posts_fts(body) */;
CREATE TABLE IF NOT EXISTS 'posts_fts_data'(id INTEGER PRIMARY KEY, block BLOB);
CREATE TABLE IF NOT EXISTS 'posts_fts_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS 'posts_fts_docsize'(id INTEGER PRIMARY KEY, sz BLOB, origin INTEGER);
CREATE TABLE IF NOT EXISTS 'posts_fts_config'(k PRIMARY KEY, v) WITHOUT ROWID;
CREATE TRIGGER posts_fts_after_revision
AFTER INSERT ON post_revisions
WHEN (SELECT retracted_at FROM posts WHERE id = NEW.post_id) IS NULL
 AND NEW.revision = (SELECT MAX(revision) FROM post_revisions WHERE post_id = NEW.post_id)
BEGIN
    INSERT OR REPLACE INTO posts_fts (rowid, body)
    VALUES (
        (SELECT rowid FROM posts WHERE id = NEW.post_id),
        NEW.body
    );
END;
CREATE TRIGGER posts_fts_after_retract
AFTER UPDATE OF retracted_at ON posts
WHEN OLD.retracted_at IS NULL
 AND NEW.retracted_at IS NOT NULL
BEGIN
    DELETE FROM posts_fts WHERE rowid = OLD.rowid;
END;
CREATE TRIGGER posts_fts_after_delete
AFTER DELETE ON posts
BEGIN
    DELETE FROM posts_fts WHERE rowid = OLD.rowid;
END;
CREATE VIRTUAL TABLE rooms_fts USING fts5(
    slug,
    content='',
    contentless_delete=1,
    tokenize='trigram'
)
/* rooms_fts(slug) */;
CREATE TABLE IF NOT EXISTS 'rooms_fts_data'(id INTEGER PRIMARY KEY, block BLOB);
CREATE TABLE IF NOT EXISTS 'rooms_fts_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS 'rooms_fts_docsize'(id INTEGER PRIMARY KEY, sz BLOB, origin INTEGER);
CREATE TABLE IF NOT EXISTS 'rooms_fts_config'(k PRIMARY KEY, v) WITHOUT ROWID;
CREATE TRIGGER rooms_fts_after_insert
AFTER INSERT ON rooms
WHEN NEW.deleted_at IS NULL AND NEW.merged_into IS NULL
BEGIN
    INSERT INTO rooms_fts (rowid, slug) VALUES (NEW.rowid, NEW.slug);
END;
CREATE TRIGGER rooms_fts_after_update_slug
AFTER UPDATE OF slug ON rooms
WHEN NEW.deleted_at IS NULL AND NEW.merged_into IS NULL
BEGIN
    INSERT OR REPLACE INTO rooms_fts (rowid, slug) VALUES (NEW.rowid, NEW.slug);
END;
CREATE TRIGGER rooms_fts_after_soft_delete
AFTER UPDATE OF deleted_at ON rooms
WHEN OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL
BEGIN
    DELETE FROM rooms_fts WHERE rowid = NEW.rowid;
END;
CREATE TRIGGER rooms_fts_after_merge
AFTER UPDATE OF merged_into ON rooms
WHEN OLD.merged_into IS NULL AND NEW.merged_into IS NOT NULL
BEGIN
    DELETE FROM rooms_fts WHERE rowid = NEW.rowid;
END;
CREATE TRIGGER rooms_fts_after_delete
AFTER DELETE ON rooms
BEGIN
    DELETE FROM rooms_fts WHERE rowid = OLD.rowid;
END;
