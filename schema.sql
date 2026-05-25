CREATE TABLE _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    checksum BLOB NOT NULL,
    execution_time BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS "auth_challenges" (
    id TEXT PRIMARY KEY NOT NULL,
    challenge_type TEXT NOT NULL CHECK (challenge_type IN ('registration', 'authentication', 'discoverable')),
    state BLOB NOT NULL,
    display_name TEXT,
    invite_code TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
, user_id TEXT);
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
CREATE TABLE instance_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    rebuild_debounce_ms INTEGER NOT NULL CHECK (rebuild_debounce_ms BETWEEN 1000 AND 60000),
    rebuild_min_interval_ms INTEGER NOT NULL CHECK (rebuild_min_interval_ms BETWEEN 1000 AND 3600000),
    rebuild_max_interval_ms INTEGER NOT NULL CHECK (rebuild_max_interval_ms BETWEEN 1000 AND 3600000),
    rebuild_bfs_cache_bytes INTEGER NOT NULL CHECK (rebuild_bfs_cache_bytes BETWEEN 1048576 AND 4294967296),
    source_repo_url TEXT, attachment_budget_cap_bytes INTEGER NOT NULL DEFAULT 10485760
    CHECK (attachment_budget_cap_bytes BETWEEN 0 AND 10737418240), attachment_budget_refill_bytes_per_day INTEGER NOT NULL DEFAULT 1048576
    CHECK (attachment_budget_refill_bytes_per_day BETWEEN 0 AND 10737418240),
    CHECK (rebuild_debounce_ms <= rebuild_min_interval_ms),
    CHECK (rebuild_min_interval_ms <= rebuild_max_interval_ms)
);
CREATE TABLE IF NOT EXISTS "signed_objects" (
    canonical_hash BLOB PRIMARY KEY NOT NULL,
    inner_class    TEXT NOT NULL CHECK (inner_class IN (
                       'post-rev', 'retract', 'admin-rm',
                       'trust-edge', 'profile', 'thread-create',
                       'thread-status', 'deactivate', 'move',
                       'user-status'
                   )),
    payload        BLOB,
    signature      BLOB NOT NULL,
    received_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    erased_at      TEXT,
    CHECK (payload IS NOT NULL OR erased_at IS NOT NULL)
);
CREATE INDEX idx_signed_objects_class ON signed_objects(inner_class);
CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    signup_method TEXT NOT NULL CHECK (signup_method IN ('steam_key', 'invite', 'admin')),
    steam_verified INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'banned')),
    bio TEXT,
    display_name_skeleton TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    invite_id TEXT REFERENCES invites(id),
    suspended_until TEXT,
    can_invite INTEGER NOT NULL DEFAULT 1,
    deleted_at TEXT,
    public_key BLOB NOT NULL,
    home_instance BLOB
);
CREATE TABLE invites (
    id TEXT PRIMARY KEY NOT NULL,
    code TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    revoked_at TEXT,
    max_uses INTEGER,
    expires_at TEXT
);
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
CREATE TABLE sessions (
    token TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at TEXT NOT NULL
);
CREATE TABLE rooms (
    id TEXT PRIMARY KEY NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    merged_into TEXT REFERENCES rooms(id),
    deleted_at TEXT
);
CREATE TABLE threads (
    id TEXT PRIMARY KEY NOT NULL,
    title TEXT NOT NULL,
    author TEXT NOT NULL REFERENCES users(id),
    room TEXT NOT NULL REFERENCES rooms(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    locked INTEGER NOT NULL DEFAULT 0,
    last_activity TEXT,
    reply_count INTEGER NOT NULL DEFAULT 0,
    link_url TEXT,
    link_url_normalized TEXT,
    home_instance BLOB
);
CREATE TABLE posts (
    id TEXT PRIMARY KEY NOT NULL,
    author TEXT NOT NULL REFERENCES users(id),
    thread TEXT NOT NULL REFERENCES threads(id),
    parent TEXT REFERENCES posts(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    retracted_at TEXT,
    retraction_signature BLOB,
    revision_count INTEGER NOT NULL DEFAULT 1,
    retraction_format_version INTEGER NOT NULL DEFAULT 1,
    home_instance BLOB
);
CREATE TABLE post_revisions (
    post_id        TEXT NOT NULL REFERENCES posts(id),
    revision       INTEGER NOT NULL DEFAULT 0,
    body           TEXT NOT NULL,
    signature      BLOB NOT NULL,
    canonical_hash BLOB NOT NULL,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    epoch          INTEGER NOT NULL DEFAULT 0,
    format_version INTEGER NOT NULL DEFAULT 1,
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
CREATE TABLE room_favorites (
    user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    room_id    TEXT    NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    position   INTEGER NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (user_id, room_id)
);
CREATE TABLE user_tags (
    viewer_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tag        TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (viewer_id, target_id),
    CHECK (viewer_id <> target_id),
    CHECK (length(tag) > 0)
);
CREATE TABLE trust_edges (
    id TEXT PRIMARY KEY NOT NULL,
    source_user TEXT NOT NULL REFERENCES users(id),
    target_user TEXT NOT NULL REFERENCES users(id),
    trust_type TEXT NOT NULL CHECK (trust_type IN ('trust', 'distrust', 'neutral')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    reason TEXT,
    signature BLOB,
    prior_edge_hash BLOB,
    format_version INTEGER NOT NULL DEFAULT 1,
    canonical_hash BLOB
);
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
        'remove_bio',
        'edit_config'
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
CREATE UNIQUE INDEX idx_users_public_key ON users(public_key);
CREATE INDEX idx_users_home_instance ON users(home_instance) WHERE home_instance IS NOT NULL;
CREATE UNIQUE INDEX idx_users_display_name_local ON users(display_name) WHERE home_instance IS NULL;
CREATE UNIQUE INDEX idx_users_display_name_skeleton_local ON users(display_name_skeleton) WHERE home_instance IS NULL;
CREATE INDEX idx_users_invite_id ON users(invite_id);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_invites_code ON invites(code);
CREATE UNIQUE INDEX idx_rooms_slug ON rooms(slug);
CREATE INDEX idx_rooms_deleted_at ON rooms(deleted_at);
CREATE INDEX idx_threads_author ON threads(author);
CREATE INDEX idx_threads_room ON threads(room);
CREATE INDEX idx_threads_last_activity ON threads(last_activity);
CREATE INDEX idx_threads_created_at ON threads(created_at);
CREATE INDEX threads_link_url_normalized_idx
    ON threads(link_url_normalized)
    WHERE link_url_normalized IS NOT NULL;
CREATE INDEX idx_posts_author ON posts(author);
CREATE INDEX idx_posts_parent ON posts(parent);
CREATE INDEX idx_posts_thread_created ON posts(thread, created_at);
CREATE INDEX idx_room_admin_log_room ON room_admin_log(room_id);
CREATE INDEX idx_reports_post_id ON reports(post_id);
CREATE INDEX idx_reports_reporter ON reports(reporter);
CREATE INDEX idx_reports_status ON reports(status);
CREATE INDEX idx_reports_created_at ON reports(created_at);
CREATE INDEX idx_room_favorites_user_pos ON room_favorites(user_id, position);
CREATE INDEX idx_user_tags_viewer ON user_tags(viewer_id);
CREATE INDEX idx_trust_edges_source ON trust_edges(source_user);
CREATE INDEX idx_trust_edges_target ON trust_edges(target_user);
CREATE INDEX idx_trust_edges_pair_recent
    ON trust_edges(source_user, target_user, created_at DESC, id DESC);
CREATE INDEX idx_admin_log_created_at ON admin_log(created_at);
CREATE INDEX idx_admin_log_target_user ON admin_log(target_user);
CREATE INDEX idx_ban_trust_snapshots_target ON ban_trust_snapshots(target_user);
CREATE INDEX idx_ban_trust_snapshots_trusting ON ban_trust_snapshots(trusting_user);
CREATE INDEX idx_ban_trust_snapshots_admin_log ON ban_trust_snapshots(admin_log_id);
CREATE VIEW current_trust_edges AS
SELECT id, source_user, target_user, trust_type, created_at, reason,
       signature, prior_edge_hash, format_version
FROM (
    SELECT te.*, ROW_NUMBER() OVER (
        PARTITION BY source_user, target_user
        ORDER BY created_at DESC, id DESC
    ) AS rn
    FROM trust_edges te
) ranked
WHERE rn = 1 AND trust_type != 'neutral'
/* current_trust_edges(id,source_user,target_user,trust_type,created_at,reason,signature,prior_edge_hash,format_version) */;
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
CREATE TABLE IF NOT EXISTS "signing_keys" (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    private_key BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_signing_keys_user_id ON signing_keys(user_id);
CREATE UNIQUE INDEX idx_signing_keys_active ON signing_keys(user_id) WHERE active = 1;
CREATE TABLE profile_revisions (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    -- Canonical bytes are the source of truth. These projection
    -- columns exist so reads (and FTS triggers if we add them later)
    -- don't have to round-trip through CBOR parsing.
    display_name TEXT NOT NULL,
    bio TEXT NOT NULL,
    -- 32-byte SHA-256 of the avatar attachment, or NULL.
    avatar_attachment_hash BLOB,
    -- Authored time in Unix milliseconds (the same value that lives in
    -- the canonical payload's `created_at`). Stored as INTEGER, not
    -- ISO-8601 text, so latest-wins ordering is a direct numeric
    -- comparison and ties never depend on string-format quirks.
    created_at INTEGER NOT NULL,
    -- 64-byte Ed25519 signature over the canonical CBOR payload.
    signature BLOB NOT NULL,
    -- SHA-256 of the canonical bytes of the prior profile object for
    -- the same user, or NULL when this is the user's first revision.
    prior_profile_hash BLOB,
    -- SHA-256 of this row's canonical bytes. Persisted (rather than
    -- recomputed on lookup) for the same reason as
    -- `trust_edges.canonical_hash`: post-rotation key changes must not
    -- silently rebind the chain.
    canonical_hash BLOB NOT NULL,
    format_version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_profile_revisions_user ON profile_revisions(user_id);
CREATE INDEX idx_profile_revisions_user_recent
    ON profile_revisions(user_id, created_at DESC, id DESC);
CREATE VIEW current_profile_revisions AS
SELECT id, user_id, display_name, bio, avatar_attachment_hash,
       created_at, signature, prior_profile_hash, canonical_hash,
       format_version
FROM (
    SELECT pr.*, ROW_NUMBER() OVER (
        PARTITION BY user_id
        ORDER BY created_at DESC, id DESC
    ) AS rn
    FROM profile_revisions pr
) ranked
WHERE rn = 1
/* current_profile_revisions(id,user_id,display_name,bio,avatar_attachment_hash,created_at,signature,prior_profile_hash,canonical_hash,format_version) */;
CREATE TABLE attachment_blobs (
    content_hash BLOB NOT NULL PRIMARY KEY,
    blob BLOB,
    content_type TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    uploader TEXT REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    refcount INTEGER NOT NULL DEFAULT 0 CHECK (refcount >= 0)
);
CREATE INDEX idx_attachment_blobs_uploader
    ON attachment_blobs(uploader);
CREATE TABLE post_attachments (
    post_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 2),
    content_hash BLOB NOT NULL REFERENCES attachment_blobs(content_hash),
    filename TEXT NOT NULL,
    PRIMARY KEY (post_id, revision, position),
    UNIQUE (post_id, revision, content_hash),
    FOREIGN KEY (post_id, revision)
        REFERENCES post_revisions(post_id, revision)
        ON DELETE CASCADE
);
CREATE INDEX idx_post_attachments_content_hash
    ON post_attachments(content_hash);
CREATE TRIGGER trg_post_attachments_refcount_inc
AFTER INSERT ON post_attachments
BEGIN
    UPDATE attachment_blobs
       SET refcount = refcount + 1
     WHERE content_hash = NEW.content_hash;
END;
CREATE TRIGGER trg_post_attachments_refcount_dec
AFTER DELETE ON post_attachments
BEGIN
    UPDATE attachment_blobs
       SET refcount = refcount - 1
     WHERE content_hash = OLD.content_hash;
END;
CREATE TABLE attachment_staging (
    content_hash BLOB NOT NULL PRIMARY KEY,
    uploader TEXT NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_attachment_staging_uploader
    ON attachment_staging(uploader);
CREATE INDEX idx_attachment_staging_expires_at
    ON attachment_staging(expires_at);
CREATE TABLE user_storage_budgets (
    user_id TEXT NOT NULL PRIMARY KEY REFERENCES users(id),
    available_bytes INTEGER NOT NULL CHECK (available_bytes >= 0),
    last_refill_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    lifetime_spent INTEGER NOT NULL DEFAULT 0 CHECK (lifetime_spent >= 0)
);
CREATE TABLE IF NOT EXISTS "user_settings" (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id),
    theme TEXT NOT NULL DEFAULT 'rose-pine',
    font TEXT NOT NULL DEFAULT 'literata'
);
CREATE TABLE instance_signing_keys (
    public_key  BLOB    PRIMARY KEY NOT NULL
                        CHECK (length(public_key) = 32),
    -- Ed25519 secret seed (`ed25519_dalek::SigningKey::from_bytes`
    -- takes a 32-byte seed). Treated as a server secret — never
    -- logged, never exposed in any API surface.
    private_key BLOB    NOT NULL CHECK (length(private_key) = 32),
    active      INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE UNIQUE INDEX idx_instance_signing_keys_active
    ON instance_signing_keys(active) WHERE active = 1;
CREATE TABLE peers (
    instance_pubkey     BLOB    PRIMARY KEY NOT NULL
                                CHECK (length(instance_pubkey) = 32),
    instance_domain     TEXT    NOT NULL UNIQUE,
    status              TEXT    NOT NULL CHECK (status IN (
                            'pending_outbound',
                            'pending_inbound',
                            'active',
                            'key_rotating',
                            'rejected',
                            'terminated',
                            'closed'
                        )),
    -- Whether the current relationship was initiated by us
    -- (`outbound`) or by them (`inbound`). Locked at the
    -- pending_* → active transition; preserved through the rest of
    -- the lifecycle for audit / operator-UI display.
    direction           TEXT    NOT NULL CHECK (direction IN ('outbound', 'inbound')),
    -- UUID (bstr 16) of the peer-request that initiated the current
    -- relationship phase. Outbound: minted by us, echoed by peer in
    -- the peer-response callback. Inbound: minted by them, quoted
    -- back in our peer-response.
    request_id          BLOB    NOT NULL CHECK (length(request_id) = 16),
    -- Capabilities the peer advertised in their /identity payload
    -- (or peer-request body for inbound, peer-response body for
    -- outbound accept). Canonical CBOR array of tstr. May lag the
    -- peer's live /identity until next handshake step.
    capabilities        BLOB,
    -- Capabilities both sides agreed to use in this peering — the
    -- intersection of advertised sets at handshake time. CBOR array
    -- of tstr. NULL while the row is in any `pending_*` state.
    agreed_capabilities BLOB,
    -- Operator-set message from the most recent peer-response
    -- (welcome note on accept, rejection reason on reject). Surfaced
    -- in the admin UI alongside the row. NULL when no message was
    -- supplied or when the row is still in `pending_*`.
    decision_message    TEXT,
    first_seen          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    -- Wall-clock of the most recent successful handshake message
    -- exchanged with this peer (peer-request sent/received,
    -- peer-response received). NULL until the first such event.
    last_handshake      TEXT
, termination_reason TEXT);
CREATE INDEX idx_peers_status ON peers(status);
CREATE UNIQUE INDEX idx_peers_request_id ON peers(request_id);
