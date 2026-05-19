-- Phase C of the federation schema refactor (docs/tmp_schema_refactor.md
-- items 9–10): tighten `users.public_key` to UNIQUE NOT NULL and relax
-- the `display_name` / `display_name_skeleton` uniqueness to a partial
-- index `WHERE home_instance IS NULL`. After this migration,
-- `users.public_key` is the canonical identity column (see
-- docs/signed-payload-format.md §1.8); `signing_keys.public_key` is
-- still dual-written but no longer read. Phase D will drop it.
--
-- Why a full FK-chain rebuild
--
--   * The original `users` definition has `display_name TEXT NOT NULL
--     UNIQUE` inline. SQLite's `ALTER TABLE DROP COLUMN` cannot remove
--     a column that participates in UNIQUE, and `ALTER TABLE` cannot
--     remove a column-level UNIQUE constraint in place — so the table
--     must be rebuilt.
--   * Once `users` is rebuilt, every table that FK-references
--     `users(id)` must be rebuilt too (the FK-chain dance documented
--     in `server/migrations/CLAUDE.md`). `PRAGMA foreign_keys = OFF`
--     is a no-op inside a transaction, and `DROP TABLE` does an
--     immediate FK-child check even with `defer_foreign_keys`.
--
-- This migration follows the precedent in
-- `20260413053001_simplify_rooms.sql`; it is just larger because
-- 16 tables (and the FTS triggers they own) sit under `users`.
--
-- Phase 0 — backfill `users.public_key` from `signing_keys.public_key`
-- Phase 1 — save data into temp tables
-- Phase 2 — drop the view, then tables leaves-to-root
-- Phase 3 — recreate root-to-leaves with new constraints
-- Phase 4 — restore data + indexes + view + FTS triggers
-- Phase 5 — drop the temp tables

-------------------------------------------------------------------
-- Phase 0: backfill `users.public_key`
-------------------------------------------------------------------
-- Every local user has an active signing_key (created during signup),
-- and the dual-write in signing.rs::create_signing_key has been
-- populating `users.public_key` for every new signup since Phase B.
-- This UPDATE catches any rows that predate the dual-write.
-- After it runs, every existing user must have a public_key — the
-- subsequent NOT NULL rebuild will fail loudly if any row is still
-- NULL, which is the right outcome for bad test data.
UPDATE users
SET public_key = (
    SELECT sk.public_key
    FROM signing_keys sk
    WHERE sk.user_id = users.id AND sk.active = 1
)
WHERE public_key IS NULL;

-------------------------------------------------------------------
-- Phase 1: save data into temp tables
-------------------------------------------------------------------
CREATE TEMP TABLE _users AS SELECT * FROM users;
CREATE TEMP TABLE _credentials AS SELECT * FROM credentials;
CREATE TEMP TABLE _sessions AS SELECT * FROM sessions;
CREATE TEMP TABLE _invites AS SELECT * FROM invites;
CREATE TEMP TABLE _signing_keys AS SELECT * FROM signing_keys;
CREATE TEMP TABLE _rooms AS SELECT * FROM rooms;
CREATE TEMP TABLE _threads AS SELECT * FROM threads;
CREATE TEMP TABLE _posts AS SELECT * FROM posts;
CREATE TEMP TABLE _post_revisions AS SELECT * FROM post_revisions;
CREATE TEMP TABLE _thread_recent_repliers AS SELECT * FROM thread_recent_repliers;
CREATE TEMP TABLE _room_admin_log AS SELECT * FROM room_admin_log;
CREATE TEMP TABLE _reports AS SELECT * FROM reports;
CREATE TEMP TABLE _room_favorites AS SELECT * FROM room_favorites;
CREATE TEMP TABLE _user_tags AS SELECT * FROM user_tags;
CREATE TEMP TABLE _user_settings AS SELECT * FROM user_settings;
CREATE TEMP TABLE _trust_edges AS SELECT * FROM trust_edges;
CREATE TEMP TABLE _admin_log AS SELECT * FROM admin_log;
CREATE TEMP TABLE _ban_trust_snapshots AS SELECT * FROM ban_trust_snapshots;

-------------------------------------------------------------------
-- Phase 2: drop view + tables leaves-to-root
-------------------------------------------------------------------
-- The view references trust_edges; drop it first so dropping trust_edges
-- doesn't trip "view depends on table" revalidation.
DROP VIEW current_trust_edges;

-- ban_trust_snapshots → admin_log, users
DROP TABLE ban_trust_snapshots;
-- admin_log → users, threads, posts, rooms
DROP TABLE admin_log;
-- trust_edges → users x2
DROP TABLE trust_edges;
-- user_settings → users
DROP TABLE user_settings;
-- user_tags → users x2
DROP TABLE user_tags;
-- room_favorites → users, rooms
DROP TABLE room_favorites;
-- reports → users x2, posts
DROP TABLE reports;
-- room_admin_log → users, rooms
DROP TABLE room_admin_log;
-- thread_recent_repliers → users, threads
DROP TABLE thread_recent_repliers;
-- post_revisions → posts (also owns posts_fts_after_revision +
-- threads_fts_op_body_after_revision triggers, dropped automatically)
DROP TABLE post_revisions;
-- posts → users, threads, posts (also owns threads_fts_op_after_retract,
-- posts_fts_after_retract, posts_fts_after_delete triggers)
DROP TABLE posts;
-- threads → users, rooms (also owns threads_fts_after_insert,
-- threads_fts_after_delete, threads_fts_after_update_title triggers)
DROP TABLE threads;
-- rooms → users (also owns rooms_fts_after_* triggers)
DROP TABLE rooms;
-- signing_keys → users
DROP TABLE signing_keys;
-- sessions → users (CASCADE)
DROP TABLE sessions;
-- credentials → users
DROP TABLE credentials;
-- invites → users (and users.invite_id → invites: circular pair)
DROP TABLE invites;
-- users — root
DROP TABLE users;

-------------------------------------------------------------------
-- Phase 3: recreate root-to-leaves with new constraints
-------------------------------------------------------------------

-- New `users` definition:
--   * `public_key BLOB NOT NULL` — tightened from nullable (Phase A).
--     Uniqueness comes from the separate `idx_users_public_key` index
--     created below.
--   * `display_name` is no longer inline-UNIQUE; uniqueness is enforced
--     by partial indexes `WHERE home_instance IS NULL` (local users
--     only). Federated users keep whatever display name their home
--     instance signs into a profile revision (see Phase E).
--   * `home_instance` stays nullable; NULL means local.
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

CREATE TABLE signing_keys (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id),
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    active INTEGER NOT NULL DEFAULT 1
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

CREATE TABLE user_settings (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id),
    theme TEXT NOT NULL DEFAULT 'rose-pine-moon',
    font TEXT NOT NULL DEFAULT 'literata'
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

-------------------------------------------------------------------
-- Phase 4: restore data + indexes + view + FTS triggers
-------------------------------------------------------------------

-- Restore root-to-leaves so FK checks succeed.
INSERT INTO users SELECT * FROM _users;
INSERT INTO invites SELECT * FROM _invites;
INSERT INTO credentials SELECT * FROM _credentials;
INSERT INTO sessions SELECT * FROM _sessions;
INSERT INTO signing_keys SELECT * FROM _signing_keys;
INSERT INTO rooms SELECT * FROM _rooms;
INSERT INTO threads SELECT * FROM _threads;
INSERT INTO posts SELECT * FROM _posts;
INSERT INTO post_revisions SELECT * FROM _post_revisions;
INSERT INTO thread_recent_repliers SELECT * FROM _thread_recent_repliers;
INSERT INTO room_admin_log SELECT * FROM _room_admin_log;
INSERT INTO reports SELECT * FROM _reports;
INSERT INTO room_favorites SELECT * FROM _room_favorites;
INSERT INTO user_tags SELECT * FROM _user_tags;
INSERT INTO user_settings SELECT * FROM _user_settings;
INSERT INTO trust_edges SELECT * FROM _trust_edges;
INSERT INTO admin_log SELECT * FROM _admin_log;
INSERT INTO ban_trust_snapshots SELECT * FROM _ban_trust_snapshots;

-- Indexes on `users`. The display_name + display_name_skeleton
-- uniqueness is now scoped to local users (`home_instance IS NULL`);
-- federated users carry their identity via `public_key` and may
-- collide on display name across instances without breaking anything.
CREATE UNIQUE INDEX idx_users_public_key ON users(public_key);
CREATE INDEX idx_users_home_instance ON users(home_instance) WHERE home_instance IS NOT NULL;
CREATE UNIQUE INDEX idx_users_display_name_local ON users(display_name) WHERE home_instance IS NULL;
CREATE UNIQUE INDEX idx_users_display_name_skeleton_local ON users(display_name_skeleton) WHERE home_instance IS NULL;
CREATE INDEX idx_users_invite_id ON users(invite_id);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);

-- Re-create the rest of the indexes that lived on the dropped
-- tables. Order matches the original schema for grep-ability.
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_invites_code ON invites(code);
CREATE INDEX idx_signing_keys_user_id ON signing_keys(user_id);
CREATE UNIQUE INDEX idx_signing_keys_active ON signing_keys(user_id) WHERE active = 1;
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

-- Recreate the latest-edge-per-pair view that the trust handlers read.
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
WHERE rn = 1 AND trust_type != 'neutral';

-- Re-install FTS triggers on threads / posts / post_revisions / rooms.
-- Definitions mirror the latest migrations:
--   * threads_fts_*           — 20260511180443_rebuild_fts_with_contentless_delete.sql
--   * posts_fts_*             — 20260511180443
--   * rooms_fts_*             — 20260511175126_create_rooms_fts.sql
--   * post_revisions triggers — 20260519165756_add_canonical_hash_to_post_revisions.sql

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

-------------------------------------------------------------------
-- Phase 5: drop temp tables
-------------------------------------------------------------------
DROP TABLE _users;
DROP TABLE _credentials;
DROP TABLE _sessions;
DROP TABLE _invites;
DROP TABLE _signing_keys;
DROP TABLE _rooms;
DROP TABLE _threads;
DROP TABLE _posts;
DROP TABLE _post_revisions;
DROP TABLE _thread_recent_repliers;
DROP TABLE _room_admin_log;
DROP TABLE _reports;
DROP TABLE _room_favorites;
DROP TABLE _user_tags;
DROP TABLE _user_settings;
DROP TABLE _trust_edges;
DROP TABLE _admin_log;
DROP TABLE _ban_trust_snapshots;
