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
);
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
);
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
CREATE INDEX idx_admin_log_created_at ON admin_log(created_at);
CREATE INDEX idx_admin_log_target_user ON admin_log(target_user);
CREATE INDEX idx_ban_trust_snapshots_target ON ban_trust_snapshots(target_user);
CREATE INDEX idx_ban_trust_snapshots_trusting ON ban_trust_snapshots(trusting_user);
CREATE INDEX idx_ban_trust_snapshots_admin_log ON ban_trust_snapshots(admin_log_id);
