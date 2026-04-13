-- Simplify rooms: drop name, description, and public columns.
-- Slug becomes the sole human-readable identifier. The "announcements"
-- room is identified by slug check in application code rather than
-- a `public` column.
--
-- SQLite can't DROP COLUMN on UNIQUE columns (`name`), and
-- PRAGMA foreign_keys = OFF is a no-op inside a transaction (sqlx wraps
-- migrations in one). DROP TABLE with foreign_keys = ON checks child FKs
-- immediately even with defer_foreign_keys. So we must rebuild the
-- entire FK dependency chain.
--
-- Phase 1 — save data to temp tables
-- Phase 2 — drop everything leaves-to-root
-- Phase 3 — recreate everything root-to-leaves (with full FK constraints)
-- Phase 4 — restore data and indexes

-------------------------------------------------------------------
-- Phase 1: save data
-------------------------------------------------------------------
CREATE TEMP TABLE _rooms AS SELECT id, slug, created_by, created_at, merged_into FROM rooms;
CREATE TEMP TABLE _threads AS SELECT * FROM threads;
CREATE TEMP TABLE _posts AS SELECT * FROM posts;
CREATE TEMP TABLE _post_revisions AS SELECT * FROM post_revisions;
CREATE TEMP TABLE _thread_recent_repliers AS SELECT * FROM thread_recent_repliers;
CREATE TEMP TABLE _admin_log AS SELECT * FROM admin_log;
CREATE TEMP TABLE _room_admin_log AS SELECT * FROM room_admin_log;

-------------------------------------------------------------------
-- Phase 2: drop leaves-to-root
-------------------------------------------------------------------
DROP TABLE post_revisions;
DROP TABLE admin_log;
DROP TABLE room_admin_log;
DROP TABLE thread_recent_repliers;
DROP TABLE posts;
DROP TABLE threads;
DROP TABLE rooms;

-------------------------------------------------------------------
-- Phase 3: recreate root-to-leaves with full FK constraints
-------------------------------------------------------------------

CREATE TABLE rooms (
    id TEXT PRIMARY KEY NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    merged_into TEXT REFERENCES rooms(id)
);

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

CREATE TABLE admin_log (
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

-------------------------------------------------------------------
-- Phase 4: restore data and indexes (root-to-leaves)
-------------------------------------------------------------------
INSERT INTO rooms SELECT * FROM _rooms;
INSERT INTO threads SELECT * FROM _threads;
INSERT INTO posts SELECT * FROM _posts;
INSERT INTO post_revisions SELECT * FROM _post_revisions;
INSERT INTO thread_recent_repliers SELECT * FROM _thread_recent_repliers;
INSERT INTO room_admin_log SELECT * FROM _room_admin_log;
INSERT INTO admin_log SELECT * FROM _admin_log;

CREATE UNIQUE INDEX idx_rooms_slug ON rooms(slug);
CREATE INDEX idx_threads_author ON threads(author);
CREATE INDEX idx_threads_room ON threads(room);
CREATE INDEX idx_threads_last_activity ON threads(last_activity);
CREATE INDEX idx_threads_created_at ON threads(created_at);
CREATE INDEX idx_posts_author ON posts(author);
CREATE INDEX idx_posts_parent ON posts(parent);
CREATE INDEX idx_posts_thread_created ON posts(thread, created_at);
CREATE INDEX idx_room_admin_log_room ON room_admin_log(room_id);
CREATE INDEX idx_admin_log_created_at ON admin_log(created_at);

DROP TABLE _rooms;
DROP TABLE _threads;
DROP TABLE _posts;
DROP TABLE _post_revisions;
DROP TABLE _thread_recent_repliers;
DROP TABLE _admin_log;
DROP TABLE _room_admin_log;
