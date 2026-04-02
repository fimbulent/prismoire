use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::session::AuthUser;
use crate::signing;
use crate::state::AppState;

const MIN_TITLE_LEN: usize = 5;
const MAX_TITLE_LEN: usize = 150;
const MAX_BODY_LEN: usize = 50_000;
const PAGE_SIZE: usize = 20;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ThreadSummary {
    pub id: String,
    pub title: String,
    pub author_id: String,
    pub author_name: String,
    pub room_id: String,
    pub room_name: String,
    pub room_slug: String,
    pub created_at: String,
    pub locked: bool,
    pub room_public: bool,
    pub reply_count: i64,
    pub last_activity: Option<String>,
}

#[derive(Serialize)]
pub struct ThreadListResponse {
    pub threads: Vec<ThreadSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct PaginationParams {
    pub cursor: Option<String>,
}

#[derive(Serialize)]
pub struct PostResponse {
    pub id: String,
    pub parent_id: Option<String>,
    pub author_id: String,
    pub author_name: String,
    pub body: String,
    pub created_at: String,
    pub edited_at: Option<String>,
    pub revision: i64,
    pub is_op: bool,
    pub retracted_at: Option<String>,
    pub children: Vec<PostResponse>,
}

#[derive(Serialize)]
pub struct ThreadDetailResponse {
    pub id: String,
    pub title: String,
    pub author_id: String,
    pub author_name: String,
    pub room_id: String,
    pub room_name: String,
    pub room_slug: String,
    pub created_at: String,
    pub locked: bool,
    pub room_public: bool,
    pub post: PostResponse,
    pub reply_count: i64,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateThreadRequest {
    pub title: String,
    pub body: String,
}

#[derive(Deserialize)]
pub struct CreateReplyRequest {
    pub parent_id: String,
    pub body: String,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_title(title: &str) -> Result<String, String> {
    let trimmed = title.trim().to_string();
    if trimmed.len() < MIN_TITLE_LEN {
        return Err(format!("title must be at least {MIN_TITLE_LEN} characters"));
    }
    if trimmed.len() > MAX_TITLE_LEN {
        return Err(format!("title must be at most {MAX_TITLE_LEN} characters"));
    }
    Ok(trimmed)
}

pub fn validate_body(body: &str) -> Result<String, String> {
    let trimmed = body.trim().to_string();
    if trimmed.is_empty() {
        return Err("body cannot be empty".into());
    }
    if trimmed.len() > MAX_BODY_LEN {
        return Err(format!("body must be at most {MAX_BODY_LEN} characters"));
    }
    Ok(trimmed)
}

// ---------------------------------------------------------------------------
// POST /api/rooms/:id/threads — create a new thread
// ---------------------------------------------------------------------------

/// Create a new thread in a room.
///
/// Inserts a `threads` row, a `posts` row (the OP with parent=NULL), and a
/// `post_revisions` row (revision 0) with the body signed by the author's
/// Ed25519 signing key.
pub async fn create_thread(
    State(state): State<Arc<AppState>>,
    Path(room_id_or_slug): Path<String>,
    user: AuthUser,
    Json(req): Json<CreateThreadRequest>,
) -> Result<impl IntoResponse, AppError> {
    let title = validate_title(&req.title).map_err(AppError::BadRequest)?;
    let body = validate_body(&req.body).map_err(AppError::BadRequest)?;

    let room: Option<(String, bool)> = sqlx::query_as(
        "SELECT id, public FROM rooms WHERE (id = ? OR slug = ?) AND merged_into IS NULL",
    )
    .bind(&room_id_or_slug)
    .bind(&room_id_or_slug)
    .fetch_optional(&state.db)
    .await?;

    let (room_id, room_public) = room.ok_or_else(|| AppError::NotFound("room not found".into()))?;

    if room_public && !user.is_admin() {
        return Err(AppError::Unauthorized(
            "only admins can post in public rooms".into(),
        ));
    }

    let signature = signing::sign_message(&state.db, &user.user_id, body.as_bytes()).await?;

    let thread_id = Uuid::new_v4().to_string();
    let post_id = Uuid::new_v4().to_string();

    sqlx::query("INSERT INTO threads (id, title, author, room) VALUES (?, ?, ?, ?)")
        .bind(&thread_id)
        .bind(&title)
        .bind(&user.user_id)
        .bind(&room_id)
        .execute(&state.db)
        .await?;

    sqlx::query("INSERT INTO posts (id, author, thread) VALUES (?, ?, ?)")
        .bind(&post_id)
        .bind(&user.user_id)
        .bind(&thread_id)
        .execute(&state.db)
        .await?;

    sqlx::query(
        "INSERT INTO post_revisions (post_id, revision, body, signature) VALUES (?, 0, ?, ?)",
    )
    .bind(&post_id)
    .bind(&body)
    .bind(&signature)
    .execute(&state.db)
    .await?;

    let (created_at, fetched_room_name): (String, String) = sqlx::query_as(
        "SELECT t.created_at, r.name FROM threads t JOIN rooms r ON r.id = t.room WHERE t.id = ?",
    )
    .bind(&thread_id)
    .fetch_one(&state.db)
    .await?;

    let (post_created_at,): (String,) =
        sqlx::query_as("SELECT created_at FROM post_revisions WHERE post_id = ? AND revision = 0")
            .bind(&post_id)
            .fetch_one(&state.db)
            .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(ThreadDetailResponse {
            id: thread_id,
            title,
            author_id: user.user_id.clone(),
            author_name: user.display_name.clone(),
            room_id,
            room_name: fetched_room_name,
            room_slug: room_id_or_slug,
            created_at,
            locked: false,
            room_public,
            post: PostResponse {
                id: post_id,
                parent_id: None,
                author_id: user.user_id,
                author_name: user.display_name,
                body,
                created_at: post_created_at,
                revision: 0,
                edited_at: None,
                is_op: true,
                retracted_at: None,
                children: vec![],
            },
            reply_count: 0,
        }),
    ))
}

/// Parse a cursor string into (timestamp, id).
///
/// Cursors encode the last-seen sort key so the next page starts after it.
/// Format: `<ISO timestamp>|<UUID>`.
pub fn parse_cursor(cursor: &str) -> Result<(String, String), AppError> {
    let (ts, id) = cursor
        .split_once('|')
        .ok_or_else(|| AppError::BadRequest("invalid cursor".into()))?;
    let _: chrono::NaiveDateTime = ts
        .parse()
        .map_err(|_| AppError::BadRequest("invalid cursor".into()))?;
    let _: uuid::Uuid = id
        .parse()
        .map_err(|_| AppError::BadRequest("invalid cursor".into()))?;
    Ok((ts.to_string(), id.to_string()))
}

/// Build a cursor string from a thread summary.
fn make_cursor(thread: &ThreadSummary) -> String {
    let ts = thread
        .last_activity
        .as_deref()
        .unwrap_or(&thread.created_at);
    format!("{}|{}", ts, thread.id)
}

// ---------------------------------------------------------------------------
// GET /api/threads/public — list threads in public rooms (no auth required)
// ---------------------------------------------------------------------------

/// List threads from public rooms only, ordered by last activity, with cursor pagination.
/// This endpoint does not require authentication and is used for the logged-out landing page.
pub async fn list_public_threads(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, AppError> {
    let rows = if let Some(ref cursor) = params.cursor {
        let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
        sqlx::query_as::<_, (String, String, String, String, String, String, String, String, bool, bool, i64, Option<String>)>(
            "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
             r.id, r.name, r.slug, t.locked, r.public, \
             (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
             (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
             FROM threads t \
             JOIN users u ON u.id = t.author \
             JOIN rooms r ON r.id = t.room \
             WHERE r.merged_into IS NULL \
               AND r.public = 1 \
               AND NOT (reply_count = 0 \
                    AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
               AND (COALESCE(last_activity, t.created_at) < ? \
                    OR (COALESCE(last_activity, t.created_at) = ? AND t.id < ?)) \
             ORDER BY last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC \
             LIMIT ?",
        )
        .bind(&cursor_ts)
        .bind(&cursor_ts)
        .bind(&cursor_id)
        .bind(PAGE_SIZE as i64 + 1)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, (String, String, String, String, String, String, String, String, bool, bool, i64, Option<String>)>(
            "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
             r.id, r.name, r.slug, t.locked, r.public, \
             (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
             (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
             FROM threads t \
             JOIN users u ON u.id = t.author \
             JOIN rooms r ON r.id = t.room \
             WHERE r.merged_into IS NULL \
               AND r.public = 1 \
               AND NOT (reply_count = 0 \
                    AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
             ORDER BY last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC \
             LIMIT ?",
        )
        .bind(PAGE_SIZE as i64 + 1)
        .fetch_all(&state.db)
        .await?
    };

    let has_more = rows.len() > PAGE_SIZE;
    let threads: Vec<ThreadSummary> = rows
        .into_iter()
        .take(PAGE_SIZE)
        .map(
            |(
                id,
                title,
                author_id,
                author_name,
                created_at,
                room_id,
                room_name,
                room_slug,
                locked,
                room_public,
                reply_count,
                last_activity,
            )| {
                ThreadSummary {
                    id,
                    title,
                    author_id,
                    author_name,
                    room_id,
                    room_name,
                    room_slug,
                    created_at,
                    locked,
                    room_public,
                    reply_count,
                    last_activity,
                }
            },
        )
        .collect();

    let next_cursor = if has_more {
        threads.last().map(make_cursor)
    } else {
        None
    };

    Ok(Json(ThreadListResponse {
        threads,
        next_cursor,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/threads — list threads across all rooms
// ---------------------------------------------------------------------------
// TODO: The "hide retracted OP with no replies" condition is duplicated across
// list_all_threads, list_threads, and list_public_threads. Deduplicate when
// migrating to sqlx::query!().

/// List threads across all rooms, ordered by last activity, with cursor pagination.
pub async fn list_all_threads(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, AppError> {
    let rows = if let Some(ref cursor) = params.cursor {
        let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
        sqlx::query_as::<_, (String, String, String, String, String, String, String, String, bool, bool, i64, Option<String>)>(
            "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
             r.id, r.name, r.slug, t.locked, r.public, \
             (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
             (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
             FROM threads t \
             JOIN users u ON u.id = t.author \
             JOIN rooms r ON r.id = t.room \
             WHERE r.merged_into IS NULL \
               AND NOT (reply_count = 0 \
                    AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
               AND (COALESCE(last_activity, t.created_at) < ? \
                    OR (COALESCE(last_activity, t.created_at) = ? AND t.id < ?)) \
             ORDER BY last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC \
             LIMIT ?",
        )
        .bind(&cursor_ts)
        .bind(&cursor_ts)
        .bind(&cursor_id)
        .bind(PAGE_SIZE as i64 + 1)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, (String, String, String, String, String, String, String, String, bool, bool, i64, Option<String>)>(
            "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
             r.id, r.name, r.slug, t.locked, r.public, \
             (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
             (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
             FROM threads t \
             JOIN users u ON u.id = t.author \
             JOIN rooms r ON r.id = t.room \
             WHERE r.merged_into IS NULL \
               AND NOT (reply_count = 0 \
                    AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
             ORDER BY last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC \
             LIMIT ?",
        )
        .bind(PAGE_SIZE as i64 + 1)
        .fetch_all(&state.db)
        .await?
    };

    let has_more = rows.len() > PAGE_SIZE;
    let threads: Vec<ThreadSummary> = rows
        .into_iter()
        .take(PAGE_SIZE)
        .map(
            |(
                id,
                title,
                author_id,
                author_name,
                created_at,
                room_id,
                room_name,
                room_slug,
                locked,
                room_public,
                reply_count,
                last_activity,
            )| {
                ThreadSummary {
                    id,
                    title,
                    author_id,
                    author_name,
                    room_id,
                    room_name,
                    room_slug,
                    created_at,
                    locked,
                    room_public,
                    reply_count,
                    last_activity,
                }
            },
        )
        .collect();

    let next_cursor = if has_more {
        threads.last().map(make_cursor)
    } else {
        None
    };

    Ok(Json(ThreadListResponse {
        threads,
        next_cursor,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/rooms/:id/threads — list threads in a room
// ---------------------------------------------------------------------------

/// List threads in a room, ordered by last activity, with cursor pagination.
pub async fn list_threads(
    State(state): State<Arc<AppState>>,
    Path(room_id_or_slug): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, AppError> {
    let room: Option<(String, String, String, bool)> = sqlx::query_as(
        "SELECT id, name, slug, public FROM rooms WHERE (id = ? OR slug = ?) AND merged_into IS NULL",
    )
    .bind(&room_id_or_slug)
    .bind(&room_id_or_slug)
    .fetch_optional(&state.db)
    .await?;

    let (room_id, room_name, room_slug, room_public) =
        room.ok_or_else(|| AppError::NotFound("room not found".into()))?;

    let rows = if let Some(ref cursor) = params.cursor {
        let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
        sqlx::query_as::<_, (String, String, String, String, String, bool, i64, Option<String>)>(
            "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
             t.locked, \
             (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
             (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
             FROM threads t \
             JOIN users u ON u.id = t.author \
             WHERE t.room = ? \
               AND NOT (reply_count = 0 \
                    AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
               AND (COALESCE(last_activity, t.created_at) < ? \
                    OR (COALESCE(last_activity, t.created_at) = ? AND t.id < ?)) \
             ORDER BY last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC \
             LIMIT ?",
        )
        .bind(&room_id)
        .bind(&cursor_ts)
        .bind(&cursor_ts)
        .bind(&cursor_id)
        .bind(PAGE_SIZE as i64 + 1)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, (String, String, String, String, String, bool, i64, Option<String>)>(
            "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
             t.locked, \
             (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
             (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
             FROM threads t \
             JOIN users u ON u.id = t.author \
             WHERE t.room = ? \
               AND NOT (reply_count = 0 \
                    AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
             ORDER BY last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC \
             LIMIT ?",
        )
        .bind(&room_id)
        .bind(PAGE_SIZE as i64 + 1)
        .fetch_all(&state.db)
        .await?
    };

    let has_more = rows.len() > PAGE_SIZE;
    let threads: Vec<ThreadSummary> = rows
        .into_iter()
        .take(PAGE_SIZE)
        .map(
            |(
                id,
                title,
                author_id,
                author_name,
                created_at,
                locked,
                reply_count,
                last_activity,
            )| {
                ThreadSummary {
                    id,
                    title,
                    author_id,
                    author_name,
                    room_id: room_id.clone(),
                    room_name: room_name.clone(),
                    room_slug: room_slug.clone(),
                    created_at,
                    locked,
                    room_public,
                    reply_count,
                    last_activity,
                }
            },
        )
        .collect();

    let next_cursor = if has_more {
        threads.last().map(make_cursor)
    } else {
        None
    };

    Ok(Json(ThreadListResponse {
        threads,
        next_cursor,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/threads/:id — thread detail with nested reply tree
// ---------------------------------------------------------------------------

/// Get thread detail including all posts as a nested reply tree.
///
/// Fetches every post in the thread with its latest revision, then
/// reconstructs the parent-child tree in memory. The OP (parent IS NULL)
/// is returned as `post`, with its `children` populated recursively.
pub async fn get_thread(
    State(state): State<Arc<AppState>>,
    Path(thread_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let thread = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            bool,
            bool,
        ),
    >(
        "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
         r.id, r.name, r.slug, t.locked, r.public \
         FROM threads t \
         JOIN users u ON u.id = t.author \
         JOIN rooms r ON r.id = t.room \
         WHERE t.id = ?",
    )
    .bind(&thread_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("thread not found".into()))?;

    let (
        id,
        title,
        thread_author_id,
        thread_author_name,
        created_at,
        room_id,
        room_name,
        room_slug,
        locked,
        room_public,
    ) = thread;

    let rows = sqlx::query_as::<_, (String, Option<String>, String, String, String, String, i64, Option<String>, String)>(
        "SELECT p.id, p.parent, p.author, u.display_name, pr.body, pr.created_at, pr.revision, \
         p.retracted_at, \
         (SELECT pr0.created_at FROM post_revisions pr0 WHERE pr0.post_id = p.id AND pr0.revision = 0) AS original_at \
         FROM posts p \
         JOIN users u ON u.id = p.author \
         JOIN post_revisions pr ON pr.post_id = p.id AND pr.revision = ( \
             SELECT MAX(pr2.revision) FROM post_revisions pr2 WHERE pr2.post_id = p.id \
         ) \
         WHERE p.thread = ? \
         ORDER BY p.created_at ASC",
    )
    .bind(&thread_id)
    .fetch_all(&state.db)
    .await?;

    let op_author_id = thread_author_id.clone();

    use std::collections::{HashMap, HashSet};
    let mut posts: Vec<Option<PostResponse>> = Vec::with_capacity(rows.len());
    let mut id_to_index: HashMap<String, usize> = HashMap::new();
    let mut retracted: HashSet<usize> = HashSet::new();

    for (
        post_id,
        parent_id,
        author_id,
        author_name,
        body,
        latest_revision_at,
        revision,
        retracted_at,
        original_at,
    ) in &rows
    {
        let edited_at = if *revision > 0 {
            Some(latest_revision_at.clone())
        } else {
            None
        };
        let idx = posts.len();
        id_to_index.insert(post_id.clone(), idx);
        if retracted_at.is_some() {
            retracted.insert(idx);
        }
        posts.push(Some(PostResponse {
            id: post_id.clone(),
            parent_id: parent_id.clone(),
            author_id: author_id.clone(),
            author_name: author_name.clone(),
            body: body.clone(),
            created_at: original_at.clone(),
            edited_at,
            revision: *revision,
            is_op: author_id == &op_author_id,
            retracted_at: retracted_at.clone(),
            children: vec![],
        }));
    }

    let mut children_map: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut root_idx: Option<usize> = None;

    for (i, post) in posts.iter().enumerate() {
        let post = post.as_ref().expect("post not yet taken");
        if let Some(ref pid) = post.parent_id {
            if let Some(&parent_idx) = id_to_index.get(pid) {
                children_map.entry(parent_idx).or_default().push(i);
            }
        } else {
            root_idx = Some(i);
        }
    }

    fn build_tree(
        idx: usize,
        posts: &mut Vec<Option<PostResponse>>,
        children_map: &HashMap<usize, Vec<usize>>,
        retracted: &HashSet<usize>,
    ) -> PostResponse {
        let child_indices: Vec<usize> = children_map.get(&idx).cloned().unwrap_or_default();
        let children: Vec<PostResponse> = child_indices
            .into_iter()
            .filter_map(|ci| {
                if retracted.contains(&ci) && !children_map.contains_key(&ci) {
                    return None;
                }
                Some(build_tree(ci, posts, children_map, retracted))
            })
            .collect();
        let mut post = posts[idx].take().expect("post already taken from tree");
        post.children = children;
        post
    }

    let root_idx =
        root_idx.ok_or_else(|| AppError::Internal("thread has no opening post".into()))?;
    let reply_count = posts.len() as i64 - 1;
    let op = build_tree(root_idx, &mut posts, &children_map, &retracted);

    Ok(Json(ThreadDetailResponse {
        id,
        title,
        author_id: thread_author_id,
        author_name: thread_author_name,
        room_id,
        room_name,
        room_slug,
        created_at,
        locked,
        room_public,
        post: op,
        reply_count,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/threads/:id/posts — reply to a thread
// ---------------------------------------------------------------------------

/// Create a reply to a post within a thread.
///
/// The `parent_id` is required — every reply must have a parent. The OP
/// is the only post with parent=NULL, created at thread creation time.
/// Rejects replies to retracted posts and replies in locked threads.
///
/// Returns the new post with `children` always empty — mutation endpoints
/// return flat posts; only `get_thread` populates the nested tree.
pub async fn create_reply(
    State(state): State<Arc<AppState>>,
    Path(thread_id): Path<String>,
    user: AuthUser,
    Json(req): Json<CreateReplyRequest>,
) -> Result<impl IntoResponse, AppError> {
    let body = validate_body(&req.body).map_err(AppError::BadRequest)?;

    let thread = sqlx::query_as::<_, (String, bool, String)>(
        "SELECT id, locked, author FROM threads WHERE id = ?",
    )
    .bind(&thread_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("thread not found".into()))?;

    let (_tid, locked, thread_author) = thread;
    if locked {
        return Err(AppError::BadRequest("thread is locked".into()));
    }

    let parent = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT id, thread, retracted_at FROM posts WHERE id = ?",
    )
    .bind(&req.parent_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("parent post not found".into()))?;

    let (parent_id, parent_thread, parent_retracted) = parent;
    if parent_thread != thread_id {
        return Err(AppError::BadRequest(
            "parent post does not belong to this thread".into(),
        ));
    }
    if parent_retracted.is_some() {
        return Err(AppError::BadRequest(
            "cannot reply to a retracted post".into(),
        ));
    }

    let signature = signing::sign_message(&state.db, &user.user_id, body.as_bytes()).await?;

    let post_id = Uuid::new_v4().to_string();

    sqlx::query("INSERT INTO posts (id, author, thread, parent) VALUES (?, ?, ?, ?)")
        .bind(&post_id)
        .bind(&user.user_id)
        .bind(&thread_id)
        .bind(&parent_id)
        .execute(&state.db)
        .await?;

    sqlx::query(
        "INSERT INTO post_revisions (post_id, revision, body, signature) VALUES (?, 0, ?, ?)",
    )
    .bind(&post_id)
    .bind(&body)
    .bind(&signature)
    .execute(&state.db)
    .await?;

    let (post_created_at,): (String,) =
        sqlx::query_as("SELECT created_at FROM post_revisions WHERE post_id = ? AND revision = 0")
            .bind(&post_id)
            .fetch_one(&state.db)
            .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(PostResponse {
            id: post_id,
            parent_id: Some(parent_id),
            author_id: user.user_id.clone(),
            author_name: user.display_name.clone(),
            body,
            created_at: post_created_at,
            edited_at: None,
            revision: 0,
            is_op: user.user_id == thread_author,
            retracted_at: None,
            children: vec![],
        }),
    ))
}
