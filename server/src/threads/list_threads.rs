use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use uuid::Uuid;

use crate::error::AppError;
use crate::session::AuthUser;
use crate::state::AppState;
use crate::trust::{TrustInfo, load_block_set};

use super::common::{
    PAGE_SIZE, PaginationParams, ThreadListResponse, ThreadSort, ThreadSummary, is_thread_visible,
    make_cursor, parse_cursor, ranked_authors, sort_threads_by_trust, sql_placeholders,
    window_cutoff,
};

/// Number of trusted authors to include per batch when iteratively fetching
/// threads for trust-sorted listings.
const TRUST_BATCH_SIZE: usize = 50;

// ---------------------------------------------------------------------------
// Row types for query results
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

// ---------------------------------------------------------------------------
// Row-to-summary converters
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Shared iterative top-K trust-sorted fetch
// ---------------------------------------------------------------------------

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
