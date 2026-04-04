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
, display_name_skeleton TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')), invite_id TEXT REFERENCES invites(id));
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
CREATE TABLE trust_edges (
    id TEXT PRIMARY KEY NOT NULL,
    source_user TEXT NOT NULL REFERENCES users(id),
    target_user TEXT NOT NULL REFERENCES users(id),
    trust_type TEXT NOT NULL CHECK (trust_type IN ('vouch', 'block')),
    weight REAL NOT NULL DEFAULT 1.0 CHECK (weight >= 0.0 AND weight <= 1.0),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at TEXT,
    reason TEXT,
    UNIQUE(source_user, target_user)
);
CREATE INDEX idx_trust_edges_source ON trust_edges(source_user);
CREATE INDEX idx_trust_edges_target ON trust_edges(target_user);
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
CREATE TABLE IF NOT EXISTS "rooms" (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    merged_into TEXT REFERENCES "rooms"(id)
, slug TEXT NOT NULL DEFAULT '', public INTEGER NOT NULL DEFAULT 0);
CREATE TABLE threads (
    id TEXT PRIMARY KEY NOT NULL,
    title TEXT NOT NULL,
    author TEXT NOT NULL REFERENCES users(id),
    room TEXT NOT NULL REFERENCES "rooms"(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    locked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_threads_author ON threads(author);
CREATE TABLE IF NOT EXISTS "room_admin_log" (
    id TEXT PRIMARY KEY NOT NULL,
    admin TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL CHECK (action IN ('merge', 'delete')),
    room_id TEXT NOT NULL REFERENCES "rooms"(id),
    merged_into TEXT REFERENCES "rooms"(id),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
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
CREATE INDEX idx_posts_thread ON posts(thread);
CREATE INDEX idx_posts_author ON posts(author);
CREATE INDEX idx_posts_parent ON posts(parent);
CREATE TABLE post_revisions (
    post_id TEXT NOT NULL REFERENCES posts(id),
    revision INTEGER NOT NULL DEFAULT 0,
    body TEXT NOT NULL,
    signature BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    epoch INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (post_id, revision)
);
CREATE INDEX idx_threads_room ON threads(room);
CREATE INDEX idx_room_admin_log_room ON room_admin_log(room_id);
CREATE UNIQUE INDEX idx_rooms_slug ON rooms(slug);
CREATE TABLE IF NOT EXISTS "admin_log" (
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
CREATE INDEX idx_admin_log_created_at ON admin_log(created_at);
CREATE INDEX idx_users_invite_id ON users(invite_id);
CREATE TABLE trust_scores (
    source_user TEXT NOT NULL REFERENCES users(id),
    target_user TEXT NOT NULL REFERENCES users(id),
    score REAL NOT NULL,
    distance REAL NOT NULL,
    PRIMARY KEY (source_user, target_user)
);
CREATE INDEX idx_trust_scores_target ON trust_scores(target_user);
