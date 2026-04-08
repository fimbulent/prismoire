use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::session::{AuthUser, OptionalAuthUser};
use crate::signing;
use crate::state::AppState;
use crate::trust::{MINIMUM_TRUST_THRESHOLD, TrustInfo, load_block_set};

const MIN_TITLE_LEN: usize = 5;
const MAX_TITLE_LEN: usize = 150;
const MAX_BODY_LEN: usize = 50_000;
const MAX_REPLY_BODY_LEN: usize = 10_000;
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
    pub trust: TrustInfo,
}

#[derive(Serialize)]
pub struct ThreadListResponse {
    pub threads: Vec<ThreadSummary>,
    pub next_cursor: Option<String>,
}

/// Sort mode for thread listings and thread detail.
///
/// Trust-windowed modes filter to threads with activity within the window,
/// then sort by the reader's forward trust distance to the OP author
/// (closest first). `New` sorts by last activity descending.
#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
pub enum ThreadSort {
    #[serde(rename = "new")]
    New,
    #[serde(rename = "trust_24h")]
    Trust24h,
    #[default]
    #[serde(rename = "trust_7d")]
    Trust7d,
    #[serde(rename = "trust_30d")]
    Trust30d,
    #[serde(rename = "trust_1y")]
    Trust1y,
    #[serde(rename = "trust_all")]
    TrustAll,
}

impl ThreadSort {
    /// Returns the activity window as a chrono::Duration, or None for
    /// `TrustAll` and `New` (no time filter).
    fn window(self) -> Option<chrono::Duration> {
        match self {
            Self::Trust24h => Some(chrono::Duration::hours(24)),
            Self::Trust7d => Some(chrono::Duration::days(7)),
            Self::Trust30d => Some(chrono::Duration::days(30)),
            Self::Trust1y => Some(chrono::Duration::days(365)),
            Self::TrustAll | Self::New => None,
        }
    }

    fn is_trust(self) -> bool {
        !matches!(self, Self::New)
    }
}

#[derive(Deserialize)]
pub struct PaginationParams {
    pub cursor: Option<String>,
    #[serde(default)]
    pub sort: ThreadSort,
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
    pub trust: TrustInfo,
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

pub fn validate_body(body: &str, max_len: usize) -> Result<String, String> {
    let trimmed = body.trim().to_string();
    if trimmed.is_empty() {
        return Err("body cannot be empty".into());
    }
    if trimmed.len() > max_len {
        return Err(format!("body must be at most {max_len} characters"));
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
    let body = validate_body(&req.body, MAX_BODY_LEN).map_err(AppError::BadRequest)?;

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
                trust: TrustInfo::self_trust(),
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

/// Number of trusted authors to include per batch when iteratively fetching
/// threads for trust-sorted listings.
const TRUST_BATCH_SIZE: usize = 50;

/// Sort a thread list in-place by the reader's forward trust distance to
/// the OP author (closest first), with last_activity descending as tiebreaker.
fn sort_threads_by_trust(threads: &mut [ThreadSummary], trust_map: &HashMap<String, f64>) {
    threads.sort_by(|a, b| {
        let da = trust_map.get(&a.author_id).copied().unwrap_or(f64::MAX);
        let db = trust_map.get(&b.author_id).copied().unwrap_or(f64::MAX);
        da.partial_cmp(&db)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                let ta = a.last_activity.as_deref().unwrap_or(&a.created_at);
                let tb = b.last_activity.as_deref().unwrap_or(&b.created_at);
                tb.cmp(ta)
            })
    });
}

/// Compute the cutoff timestamp string for a trust-window sort mode.
fn window_cutoff(sort: ThreadSort) -> Option<String> {
    sort.window().map(|dur| {
        let cutoff = chrono::Utc::now().naive_utc() - dur;
        cutoff.format("%Y-%m-%d %H:%M:%S").to_string()
    })
}

/// Sorted list of (author_id, distance) from the trust map, closest first.
fn ranked_authors(trust_map: &HashMap<String, f64>) -> Vec<(&str, f64)> {
    let mut authors: Vec<(&str, f64)> = trust_map.iter().map(|(id, &d)| (id.as_str(), d)).collect();
    authors.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    authors
}

/// Check whether a thread is visible to the reader in a listing.
///
/// A thread (represented by its OP) is visible if any of the following hold:
/// 1. The reader is the thread author.
/// 2. The thread is in a public room.
/// 3. The author's trust-in-reader (reverse score) meets `MINIMUM_TRUST_THRESHOLD`.
fn is_thread_visible(
    author_id: &str,
    room_public: bool,
    reader_id: &str,
    reverse_map: &HashMap<String, f64>,
) -> bool {
    if author_id == reader_id {
        return true;
    }
    if room_public {
        return true;
    }
    if let Some(&score) = reverse_map.get(author_id)
        && score >= MINIMUM_TRUST_THRESHOLD
    {
        return true;
    }
    false
}

/// Generate SQL placeholders for a batch of values: "(?, ?, ?)".
fn sql_placeholders(n: usize) -> String {
    let mut s = String::with_capacity(n * 3 + 2);
    s.push('(');
    for i in 0..n {
        if i > 0 {
            s.push_str(", ");
        }
        s.push('?');
    }
    s.push(')');
    s
}

// ---------------------------------------------------------------------------
// Shared iterative top-K trust-sorted fetch
// ---------------------------------------------------------------------------

type AllThreadsRow = (
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
    i64,
    Option<String>,
);
type RoomThreadsRow = (
    String,
    String,
    String,
    String,
    String,
    bool,
    i64,
    Option<String>,
);

fn all_threads_to_summary(
    row: AllThreadsRow,
    trust_map: &HashMap<String, f64>,
    block_set: &HashSet<String>,
) -> ThreadSummary {
    let (
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
    ) = row;
    let trust = TrustInfo::build(&author_id, trust_map, block_set);
    ThreadSummary {
        trust,
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
}

fn room_threads_to_summary(
    row: RoomThreadsRow,
    room_id: &str,
    room_name: &str,
    room_slug: &str,
    room_public: bool,
    trust_map: &HashMap<String, f64>,
    block_set: &HashSet<String>,
) -> ThreadSummary {
    let (id, title, author_id, author_name, created_at, locked, reply_count, last_activity) = row;
    let trust = TrustInfo::build(&author_id, trust_map, block_set);
    ThreadSummary {
        trust,
        id,
        title,
        author_id,
        author_name,
        room_id: room_id.to_string(),
        room_name: room_name.to_string(),
        room_slug: room_slug.to_string(),
        created_at,
        locked,
        room_public,
        reply_count,
        last_activity,
    }
}

/// Iterative top-K trust-sorted fetch for the all-rooms thread listing.
///
/// Fetches threads authored by the reader's most-trusted users in batches,
/// closest trust first. If trusted-author batches don't fill a page, a
/// backfill query fetches recent threads from any remaining author.
/// Threads whose OP author hasn't granted the reader visibility are excluded.
#[allow(clippy::too_many_arguments)]
async fn fetch_trust_sorted_all_threads(
    db: &sqlx::SqlitePool,
    trust_map: &HashMap<String, f64>,
    block_set: &HashSet<String>,
    reverse_map: &HashMap<String, f64>,
    reader_id: &str,
    sort: ThreadSort,
) -> Result<Vec<ThreadSummary>, AppError> {
    let cutoff = window_cutoff(sort);
    let authors = ranked_authors(trust_map);
    let mut threads: Vec<ThreadSummary> = Vec::with_capacity(PAGE_SIZE);
    let mut seen_ids: HashSet<String> = HashSet::new();

    for batch in authors.chunks(TRUST_BATCH_SIZE) {
        if threads.len() >= PAGE_SIZE {
            break;
        }

        let placeholders = sql_placeholders(batch.len());
        let sql = if cutoff.is_some() {
            format!(
                "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
                 r.id, r.name, r.slug, t.locked, r.public, \
                 (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
                 (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 JOIN rooms r ON r.id = t.room \
                 WHERE r.merged_into IS NULL \
                   AND t.author IN {placeholders} \
                   AND NOT (reply_count = 0 \
                        AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
                   AND COALESCE(last_activity, t.created_at) >= ? \
                 ORDER BY last_activity DESC NULLS LAST, t.created_at DESC \
                 LIMIT ?"
            )
        } else {
            format!(
                "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
                 r.id, r.name, r.slug, t.locked, r.public, \
                 (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
                 (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 JOIN rooms r ON r.id = t.room \
                 WHERE r.merged_into IS NULL \
                   AND t.author IN {placeholders} \
                   AND NOT (reply_count = 0 \
                        AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
                 ORDER BY last_activity DESC NULLS LAST, t.created_at DESC \
                 LIMIT ?"
            )
        };

        let mut query = sqlx::query_as::<_, AllThreadsRow>(&sql);
        for &(author_id, _) in batch {
            query = query.bind(author_id);
        }
        if let Some(ref cutoff_ts) = cutoff {
            query = query.bind(cutoff_ts);
        }
        query = query.bind(PAGE_SIZE as i64);

        let rows = query.fetch_all(db).await?;
        for row in rows {
            if seen_ids.insert(row.0.clone())
                && is_thread_visible(&row.2, row.9, reader_id, reverse_map)
            {
                threads.push(all_threads_to_summary(row, trust_map, block_set));
            }
        }
    }

    if threads.len() < PAGE_SIZE {
        let exclude = sql_placeholders(seen_ids.len().max(1));
        let sql = if cutoff.is_some() {
            format!(
                "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
                 r.id, r.name, r.slug, t.locked, r.public, \
                 (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
                 (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 JOIN rooms r ON r.id = t.room \
                 WHERE r.merged_into IS NULL \
                   AND t.id NOT IN {exclude} \
                   AND NOT (reply_count = 0 \
                        AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
                   AND COALESCE(last_activity, t.created_at) >= ? \
                 ORDER BY last_activity DESC NULLS LAST, t.created_at DESC \
                 LIMIT ?"
            )
        } else {
            format!(
                "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
                 r.id, r.name, r.slug, t.locked, r.public, \
                 (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
                 (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 JOIN rooms r ON r.id = t.room \
                 WHERE r.merged_into IS NULL \
                   AND t.id NOT IN {exclude} \
                   AND NOT (reply_count = 0 \
                        AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
                 ORDER BY last_activity DESC NULLS LAST, t.created_at DESC \
                 LIMIT ?"
            )
        };

        let mut query = sqlx::query_as::<_, AllThreadsRow>(&sql);
        if seen_ids.is_empty() {
            query = query.bind("");
        } else {
            for id in &seen_ids {
                query = query.bind(id.as_str());
            }
        }
        if let Some(ref cutoff_ts) = cutoff {
            query = query.bind(cutoff_ts);
        }
        let remaining = (PAGE_SIZE - threads.len()) as i64;
        query = query.bind(remaining);

        let rows = query.fetch_all(db).await?;
        for row in rows {
            if is_thread_visible(&row.2, row.9, reader_id, reverse_map) {
                threads.push(all_threads_to_summary(row, trust_map, block_set));
            }
        }
    }

    sort_threads_by_trust(&mut threads, trust_map);
    threads.truncate(PAGE_SIZE);
    Ok(threads)
}

/// Iterative top-K trust-sorted fetch for a single room's thread listing.
/// Threads whose OP author hasn't granted the reader visibility are excluded.
#[allow(clippy::too_many_arguments)]
async fn fetch_trust_sorted_room_threads(
    db: &sqlx::SqlitePool,
    trust_map: &HashMap<String, f64>,
    block_set: &HashSet<String>,
    reverse_map: &HashMap<String, f64>,
    reader_id: &str,
    sort: ThreadSort,
    room_id: &str,
    room_name: &str,
    room_slug: &str,
    room_public: bool,
) -> Result<Vec<ThreadSummary>, AppError> {
    let cutoff = window_cutoff(sort);
    let authors = ranked_authors(trust_map);
    let mut threads: Vec<ThreadSummary> = Vec::with_capacity(PAGE_SIZE);
    let mut seen_ids: HashSet<String> = HashSet::new();

    for batch in authors.chunks(TRUST_BATCH_SIZE) {
        if threads.len() >= PAGE_SIZE {
            break;
        }

        let placeholders = sql_placeholders(batch.len());
        let sql = if cutoff.is_some() {
            format!(
                "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
                 t.locked, \
                 (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
                 (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 WHERE t.room = ? \
                   AND t.author IN {placeholders} \
                   AND NOT (reply_count = 0 \
                        AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
                   AND COALESCE(last_activity, t.created_at) >= ? \
                 ORDER BY last_activity DESC NULLS LAST, t.created_at DESC \
                 LIMIT ?"
            )
        } else {
            format!(
                "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
                 t.locked, \
                 (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
                 (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 WHERE t.room = ? \
                   AND t.author IN {placeholders} \
                   AND NOT (reply_count = 0 \
                        AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
                 ORDER BY last_activity DESC NULLS LAST, t.created_at DESC \
                 LIMIT ?"
            )
        };

        let mut query = sqlx::query_as::<_, RoomThreadsRow>(&sql);
        query = query.bind(room_id);
        for &(author_id, _) in batch {
            query = query.bind(author_id);
        }
        if let Some(ref cutoff_ts) = cutoff {
            query = query.bind(cutoff_ts);
        }
        query = query.bind(PAGE_SIZE as i64);

        let rows = query.fetch_all(db).await?;
        for row in rows {
            if seen_ids.insert(row.0.clone())
                && is_thread_visible(&row.2, room_public, reader_id, reverse_map)
            {
                threads.push(room_threads_to_summary(
                    row,
                    room_id,
                    room_name,
                    room_slug,
                    room_public,
                    trust_map,
                    block_set,
                ));
            }
        }
    }

    if threads.len() < PAGE_SIZE {
        let exclude = sql_placeholders(seen_ids.len().max(1));
        let sql = if cutoff.is_some() {
            format!(
                "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
                 t.locked, \
                 (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
                 (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 WHERE t.room = ? \
                   AND t.id NOT IN {exclude} \
                   AND NOT (reply_count = 0 \
                        AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
                   AND COALESCE(last_activity, t.created_at) >= ? \
                 ORDER BY last_activity DESC NULLS LAST, t.created_at DESC \
                 LIMIT ?"
            )
        } else {
            format!(
                "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
                 t.locked, \
                 (SELECT COUNT(*) FROM posts p WHERE p.thread = t.id AND p.parent IS NOT NULL) AS reply_count, \
                 (SELECT MAX(p2.created_at) FROM posts p2 WHERE p2.thread = t.id) AS last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 WHERE t.room = ? \
                   AND t.id NOT IN {exclude} \
                   AND NOT (reply_count = 0 \
                        AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
                 ORDER BY last_activity DESC NULLS LAST, t.created_at DESC \
                 LIMIT ?"
            )
        };

        let mut query = sqlx::query_as::<_, RoomThreadsRow>(&sql);
        query = query.bind(room_id);
        if seen_ids.is_empty() {
            query = query.bind("");
        } else {
            for id in &seen_ids {
                query = query.bind(id.as_str());
            }
        }
        if let Some(ref cutoff_ts) = cutoff {
            query = query.bind(cutoff_ts);
        }
        let remaining = (PAGE_SIZE - threads.len()) as i64;
        query = query.bind(remaining);

        let rows = query.fetch_all(db).await?;
        for row in rows {
            if is_thread_visible(&row.2, room_public, reader_id, reverse_map) {
                threads.push(room_threads_to_summary(
                    row,
                    room_id,
                    room_name,
                    room_slug,
                    room_public,
                    trust_map,
                    block_set,
                ));
            }
        }
    }

    sort_threads_by_trust(&mut threads, trust_map);
    threads.truncate(PAGE_SIZE);
    Ok(threads)
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
                    trust: TrustInfo::unknown(),
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
// TODO: The windowed/non-windowed SQL branches in fetch_trust_sorted_all_threads
// and fetch_trust_sorted_room_threads are near-identical (only the cutoff clause
// differs). Deduplicate when migrating to sqlx::query!().

/// List threads across all rooms, with sort mode and cursor pagination.
///
/// - `sort=new`: chronological (most recently active first), cursor-paginated.
/// - `sort=trust_*`: iterative top-K fetch — threads from the reader's most-
///   trusted authors first, with a backfill for untrusted content. No cursor
///   pagination (trust ordering is per-reader and not SQL-indexable).
pub async fn list_all_threads(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, AppError> {
    let reader_uuid = Uuid::parse_str(&user.user_id).unwrap_or(Uuid::nil());
    let graph = state.get_trust_graph()?;
    let trust_map = graph.distance_map(reader_uuid);
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let block_set = load_block_set(&state.db, &user.user_id).await?;

    if params.sort.is_trust() {
        let threads = fetch_trust_sorted_all_threads(
            &state.db,
            &trust_map,
            &block_set,
            &reverse_map,
            &user.user_id,
            params.sort,
        )
        .await?;
        return Ok(Json(ThreadListResponse {
            threads,
            next_cursor: None,
        }));
    }

    // sort=new: chronological with cursor pagination
    let rows = if let Some(ref cursor) = params.cursor {
        let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
        sqlx::query_as::<_, AllThreadsRow>(
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
        sqlx::query_as::<_, AllThreadsRow>(
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
        .filter(|row| is_thread_visible(&row.2, row.9, &user.user_id, &reverse_map))
        .map(|row| all_threads_to_summary(row, &trust_map, &block_set))
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

/// List threads in a room, with sort mode and cursor pagination.
pub async fn list_threads(
    State(state): State<Arc<AppState>>,
    Path(room_id_or_slug): Path<String>,
    user: AuthUser,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, AppError> {
    let reader_uuid = Uuid::parse_str(&user.user_id).unwrap_or(Uuid::nil());
    let graph = state.get_trust_graph()?;
    let trust_map = graph.distance_map(reader_uuid);
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let block_set = load_block_set(&state.db, &user.user_id).await?;
    let room: Option<(String, String, String, bool)> = sqlx::query_as(
        "SELECT id, name, slug, public FROM rooms WHERE (id = ? OR slug = ?) AND merged_into IS NULL",
    )
    .bind(&room_id_or_slug)
    .bind(&room_id_or_slug)
    .fetch_optional(&state.db)
    .await?;

    let (room_id, room_name, room_slug, room_public) =
        room.ok_or_else(|| AppError::NotFound("room not found".into()))?;

    if params.sort.is_trust() {
        let threads = fetch_trust_sorted_room_threads(
            &state.db,
            &trust_map,
            &block_set,
            &reverse_map,
            &user.user_id,
            params.sort,
            &room_id,
            &room_name,
            &room_slug,
            room_public,
        )
        .await?;
        return Ok(Json(ThreadListResponse {
            threads,
            next_cursor: None,
        }));
    }

    // sort=new: chronological with cursor pagination
    let rows = if let Some(ref cursor) = params.cursor {
        let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
        sqlx::query_as::<_, RoomThreadsRow>(
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
        sqlx::query_as::<_, RoomThreadsRow>(
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
        .filter(|row| is_thread_visible(&row.2, room_public, &user.user_id, &reverse_map))
        .map(|row| {
            room_threads_to_summary(
                row,
                &room_id,
                &room_name,
                &room_slug,
                room_public,
                &trust_map,
                &block_set,
            )
        })
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

/// Sort mode for thread detail view (post ordering within the tree).
#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
pub enum PostSort {
    #[default]
    #[serde(rename = "trust")]
    Trust,
    #[serde(rename = "new")]
    New,
}

#[derive(Deserialize, Default)]
pub struct ThreadDetailQuery {
    #[serde(default)]
    sort: PostSort,
}

/// Get thread detail including all posts as a nested reply tree.
///
/// Fetches every post in the thread with its latest revision, then
/// reconstructs the parent-child tree in memory. The OP (parent IS NULL)
/// is returned as `post`, with its `children` populated recursively.
///
/// Trust-aware behaviour (authenticated readers only):
/// - **Visibility filtering (reverse trust):** A post is hidden — along with
///   its entire subtree — unless the author's trust in the reader meets
///   `MINIMUM_TRUST_THRESHOLD`. Exceptions: the reader's own posts, OP in
///   public rooms, and the reply visibility grant (the direct parent author
///   can always see a reply to their post).
/// - **Relevance sorting (forward trust):** Within each sibling group,
///   children are sorted by the reader's forward trust distance to the
///   author (ascending — closest/highest trust first), with `created_at`
///   as a tiebreaker.
///
/// Accepts an optional `?sort=new` query parameter (default: trust sort).
pub async fn get_thread(
    State(state): State<Arc<AppState>>,
    Path(thread_id): Path<String>,
    Query(query): Query<ThreadDetailQuery>,
    OptionalAuthUser(user): OptionalAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let sort_by_new = query.sort == PostSort::New;
    let (trust_map, reverse_map, block_set, reader_id) = match user.as_ref() {
        Some(u) => {
            let reader_uuid = Uuid::parse_str(&u.user_id).unwrap_or(Uuid::nil());
            let graph = state.get_trust_graph()?;
            let dm = graph.distance_map(reader_uuid);
            let rm = graph.reverse_score_map(reader_uuid);
            let bs = load_block_set(&state.db, &u.user_id).await?;
            (dm, rm, bs, Some(u.user_id.clone()))
        }
        None => (HashMap::new(), HashMap::new(), HashSet::new(), None),
    };
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

    let mut posts: Vec<Option<PostResponse>> = Vec::with_capacity(rows.len());
    let mut id_to_index: HashMap<String, usize> = HashMap::new();
    let mut retracted: HashSet<usize> = HashSet::new();
    let mut author_of: Vec<String> = Vec::with_capacity(rows.len());
    let mut parent_author_of: Vec<Option<String>> = Vec::with_capacity(rows.len());

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
        author_of.push(author_id.clone());
        parent_author_of.push(None);
        posts.push(Some(PostResponse {
            trust: TrustInfo::build(author_id, &trust_map, &block_set),
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
                parent_author_of[i] = Some(author_of[parent_idx].clone());
            }
        } else {
            root_idx = Some(i);
        }
    }

    struct TreeCtx<'a> {
        children_map: &'a HashMap<usize, Vec<usize>>,
        retracted: &'a HashSet<usize>,
        reader_id: &'a Option<String>,
        author_of: &'a [String],
        parent_author_of: &'a [Option<String>],
        reverse_map: &'a HashMap<String, f64>,
        trust_map: &'a HashMap<String, f64>,
        room_public: bool,
        sort_by_new: bool,
    }

    impl TreeCtx<'_> {
        /// Check whether a post at `idx` is visible to the current reader.
        ///
        /// A post is visible if any of the following hold:
        /// 1. No authenticated reader (unauthenticated viewers see all).
        /// 2. The reader is the post's author.
        /// 3. The post is the OP in a public room.
        /// 4. The author's trust-in-reader (reverse score) meets the threshold.
        /// 5. Reply visibility grant: the reader authored the direct parent.
        fn is_visible(&self, idx: usize, is_root: bool) -> bool {
            let reader = match self.reader_id {
                Some(r) => r,
                None => return true,
            };
            let author = &self.author_of[idx];
            if author == reader {
                return true;
            }
            if is_root && self.room_public {
                return true;
            }
            if let Some(&score) = self.reverse_map.get(author)
                && score >= MINIMUM_TRUST_THRESHOLD
            {
                return true;
            }
            if let Some(ref parent_author) = self.parent_author_of[idx]
                && parent_author == reader
            {
                return true;
            }
            false
        }

        /// Recursively build the nested reply tree with trust-aware visibility
        /// filtering and relevance sorting.
        fn build_tree(&self, idx: usize, posts: &mut Vec<Option<PostResponse>>) -> PostResponse {
            let mut child_indices: Vec<usize> =
                self.children_map.get(&idx).cloned().unwrap_or_default();

            if self.sort_by_new {
                child_indices.sort_by(|&a, &b| {
                    let ts_a = posts[a]
                        .as_ref()
                        .map(|p| p.created_at.as_str())
                        .unwrap_or("");
                    let ts_b = posts[b]
                        .as_ref()
                        .map(|p| p.created_at.as_str())
                        .unwrap_or("");
                    ts_b.cmp(ts_a)
                });
            } else {
                // Sort key: reader's own posts first (0.0), then by forward trust
                // distance (ascending — closest first), then unknown/untrusted last
                // (f64::MAX). Tiebreaker: created_at ascending.
                let sort_key = |idx: usize| -> f64 {
                    let author = &self.author_of[idx];
                    if self.reader_id.as_ref().is_some_and(|r| r == author) {
                        0.0
                    } else {
                        self.trust_map.get(author).copied().unwrap_or(f64::MAX)
                    }
                };
                child_indices.sort_by(|&a, &b| {
                    sort_key(a)
                        .partial_cmp(&sort_key(b))
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| {
                            let ts_a = posts[a]
                                .as_ref()
                                .map(|p| p.created_at.as_str())
                                .unwrap_or("");
                            let ts_b = posts[b]
                                .as_ref()
                                .map(|p| p.created_at.as_str())
                                .unwrap_or("");
                            ts_a.cmp(ts_b)
                        })
                });
            }

            let children: Vec<PostResponse> = child_indices
                .into_iter()
                .filter_map(|ci| {
                    if self.retracted.contains(&ci) && !self.children_map.contains_key(&ci) {
                        return None;
                    }
                    if !self.is_visible(ci, false) {
                        return None;
                    }
                    Some(self.build_tree(ci, posts))
                })
                .collect();
            let mut post = posts[idx].take().expect("post already taken from tree");
            post.children = children;
            post
        }
    }

    let root_idx =
        root_idx.ok_or_else(|| AppError::Internal("thread has no opening post".into()))?;
    let ctx = TreeCtx {
        children_map: &children_map,
        retracted: &retracted,
        reader_id: &reader_id,
        author_of: &author_of,
        parent_author_of: &parent_author_of,
        reverse_map: &reverse_map,
        trust_map: &trust_map,
        room_public,
        sort_by_new,
    };
    let op = ctx.build_tree(root_idx, &mut posts);

    fn count_replies(post: &PostResponse) -> i64 {
        let mut count = post.children.len() as i64;
        for child in &post.children {
            count += count_replies(child);
        }
        count
    }
    let reply_count = count_replies(&op);

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
    let body = validate_body(&req.body, MAX_REPLY_BODY_LEN).map_err(AppError::BadRequest)?;

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
            trust: TrustInfo::self_trust(),
        }),
    ))
}
