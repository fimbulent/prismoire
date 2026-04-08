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
    PAGE_SIZE, PaginationParams, RecentReplier, ThreadListResponse, ThreadSort, ThreadSummary,
    is_thread_visible, make_cursor, make_cursor_created_at, parse_cursor, ranked_authors,
    score_trusted_recent, score_warm, sort_threads_by_trust, sql_placeholders, window_cutoff,
};

/// Number of trusted authors to include per batch when iteratively fetching
/// threads for trust-sorted listings.
const TRUST_BATCH_SIZE: usize = 50;

/// Maximum number of candidate threads to fetch for warm sort scoring.
///
/// The design doc suggests 2000 as an upper bound, but 500 is sufficient in
/// practice: visibility filtering reduces the pool further, and rank decay
/// makes threads beyond ~position 50 negligible. Keeps the replier data
/// load (500 × 50 = 25K rows) fast.
const WARM_CANDIDATE_LIMIT: i64 = 500;

// ---------------------------------------------------------------------------
// Shared SQL fragments
// ---------------------------------------------------------------------------

/// WHERE clause that hides retracted OPs with no replies.
const RETRACTED_OP_FILTER: &str = "NOT (t.reply_count = 0 \
     AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)";

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
// Shared helpers: fetch recent repliers for warm sort
// ---------------------------------------------------------------------------

/// Fetch recent repliers for a set of candidate thread IDs from the
/// denormalized `thread_recent_repliers` table.
async fn fetch_repliers(
    db: &sqlx::SqlitePool,
    thread_ids: &[String],
) -> Result<Vec<RecentReplier>, AppError> {
    if thread_ids.is_empty() {
        return Ok(Vec::new());
    }

    let placeholders = sql_placeholders(thread_ids.len());
    let sql = format!(
        "SELECT thread_id, replier_id, replied_at \
         FROM thread_recent_repliers \
         WHERE thread_id IN {placeholders} \
         ORDER BY thread_id, reply_rank ASC"
    );

    let mut query = sqlx::query_as::<_, (String, String, String)>(&sql);
    for id in thread_ids {
        query = query.bind(id);
    }

    let rows = query.fetch_all(db).await?;
    Ok(rows
        .into_iter()
        .map(|(thread_id, replier_id, replied_at)| RecentReplier {
            thread_id,
            replier_id,
            replied_at,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Shared helpers: viewer-specific reply counts
// ---------------------------------------------------------------------------

/// Replace global `reply_count` on each thread with a viewer-specific count
/// that only includes replies visible to the reader.
///
/// Visibility rules match `get_thread`:
/// 1. The reader authored the reply.
/// 2. The reply author's reverse trust meets `MINIMUM_TRUST_THRESHOLD`.
/// 3. Reply visibility grant: the reader authored the reply's direct parent.
///
/// Batch-fetches `(thread, author, parent_author)` for the given threads,
/// then filters in Rust using `reverse_map` point lookups.
async fn apply_visible_reply_counts(
    db: &sqlx::SqlitePool,
    threads: &mut [ThreadSummary],
    reverse_map: &HashMap<String, f64>,
    reader_id: &str,
) -> Result<(), AppError> {
    if threads.is_empty() {
        return Ok(());
    }

    let thread_ids: Vec<&str> = threads.iter().map(|t| t.id.as_str()).collect();
    let placeholders = sql_placeholders(thread_ids.len());
    let sql = format!(
        "SELECT p.thread, p.author, COALESCE(parent_post.author, '') \
         FROM posts p \
         LEFT JOIN posts parent_post ON parent_post.id = p.parent \
         WHERE p.thread IN {placeholders} \
           AND p.parent IS NOT NULL"
    );

    let mut query = sqlx::query_as::<_, (String, String, String)>(&sql);
    for id in &thread_ids {
        query = query.bind(*id);
    }

    let rows = query.fetch_all(db).await?;

    use crate::trust::MINIMUM_TRUST_THRESHOLD;
    let mut counts: HashMap<&str, i64> = HashMap::new();
    for (thread_id, author_id, parent_author_id) in &rows {
        let visible = author_id == reader_id
            || reverse_map
                .get(author_id)
                .is_some_and(|&s| s >= MINIMUM_TRUST_THRESHOLD)
            || parent_author_id == reader_id;
        if visible {
            *counts.entry(thread_id.as_str()).or_default() += 1;
        }
    }

    for thread in threads.iter_mut() {
        thread.reply_count = counts.get(thread.id.as_str()).copied().unwrap_or(0);
    }

    Ok(())
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
                 t.reply_count, t.last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 JOIN rooms r ON r.id = t.room \
                 WHERE r.merged_into IS NULL \
                   AND t.author IN {placeholders} \
                   AND {RETRACTED_OP_FILTER} \
                   AND COALESCE(t.last_activity, t.created_at) >= ? \
                 ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC \
                 LIMIT ?"
            )
        } else {
            format!(
                "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
                 r.id, r.name, r.slug, t.locked, r.public, \
                 t.reply_count, t.last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 JOIN rooms r ON r.id = t.room \
                 WHERE r.merged_into IS NULL \
                   AND t.author IN {placeholders} \
                   AND {RETRACTED_OP_FILTER} \
                 ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC \
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
                 t.reply_count, t.last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 JOIN rooms r ON r.id = t.room \
                 WHERE r.merged_into IS NULL \
                   AND t.id NOT IN {exclude} \
                   AND {RETRACTED_OP_FILTER} \
                   AND COALESCE(t.last_activity, t.created_at) >= ? \
                 ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC \
                 LIMIT ?"
            )
        } else {
            format!(
                "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
                 r.id, r.name, r.slug, t.locked, r.public, \
                 t.reply_count, t.last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 JOIN rooms r ON r.id = t.room \
                 WHERE r.merged_into IS NULL \
                   AND t.id NOT IN {exclude} \
                   AND {RETRACTED_OP_FILTER} \
                 ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC \
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
                 t.locked, t.reply_count, t.last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 WHERE t.room = ? \
                   AND t.author IN {placeholders} \
                   AND {RETRACTED_OP_FILTER} \
                   AND COALESCE(t.last_activity, t.created_at) >= ? \
                 ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC \
                 LIMIT ?"
            )
        } else {
            format!(
                "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
                 t.locked, t.reply_count, t.last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 WHERE t.room = ? \
                   AND t.author IN {placeholders} \
                   AND {RETRACTED_OP_FILTER} \
                 ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC \
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
                 t.locked, t.reply_count, t.last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 WHERE t.room = ? \
                   AND t.id NOT IN {exclude} \
                   AND {RETRACTED_OP_FILTER} \
                   AND COALESCE(t.last_activity, t.created_at) >= ? \
                 ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC \
                 LIMIT ?"
            )
        } else {
            format!(
                "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
                 t.locked, t.reply_count, t.last_activity \
                 FROM threads t \
                 JOIN users u ON u.id = t.author \
                 WHERE t.room = ? \
                   AND t.id NOT IN {exclude} \
                   AND {RETRACTED_OP_FILTER} \
                 ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC \
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
        sqlx::query_as::<_, AllThreadsRow>(
            "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
             r.id, r.name, r.slug, t.locked, r.public, \
             t.reply_count, t.last_activity \
             FROM threads t \
             JOIN users u ON u.id = t.author \
             JOIN rooms r ON r.id = t.room \
             WHERE r.merged_into IS NULL \
               AND r.public = 1 \
               AND NOT (t.reply_count = 0 \
                    AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
               AND (COALESCE(t.last_activity, t.created_at) < ? \
                    OR (COALESCE(t.last_activity, t.created_at) = ? AND t.id < ?)) \
             ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC \
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
             t.reply_count, t.last_activity \
             FROM threads t \
             JOIN users u ON u.id = t.author \
             JOIN rooms r ON r.id = t.room \
             WHERE r.merged_into IS NULL \
               AND r.public = 1 \
               AND NOT (t.reply_count = 0 \
                    AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
             ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC \
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
        .map(|row| {
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
// GET /api/threads — list threads across all rooms
// ---------------------------------------------------------------------------

/// List threads across all rooms, with sort mode and cursor pagination.
///
/// - `sort=warm` (default): rank-based decay × trust signal from visible
///   repliers. No cursor pagination.
/// - `sort=trusted`: rank-based decay × OP trust (no replier signal),
///   with self-trust = 1.0. No cursor pagination.
/// - `sort=trust_*`: flat OP trust sort with optional time window
///   (iterative top-K fetch). No cursor pagination.
/// - `sort=new`: thread creation time descending. Cursor-paginated.
/// - `sort=active`: last reply time descending. Cursor-paginated.
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

    if params.sort == ThreadSort::Warm {
        let mut threads = fetch_warm_candidates_all(
            &state.db,
            &trust_map,
            &block_set,
            &reverse_map,
            &user.user_id,
        )
        .await?;
        let thread_ids: Vec<String> = threads.iter().map(|t| t.id.clone()).collect();
        let repliers = fetch_repliers(&state.db, &thread_ids).await?;
        score_warm(
            &mut threads,
            &repliers,
            &trust_map,
            &reverse_map,
            &user.user_id,
        );
        apply_visible_reply_counts(&state.db, &mut threads, &reverse_map, &user.user_id).await?;
        return Ok(Json(ThreadListResponse {
            threads,
            next_cursor: None,
        }));
    }

    if params.sort == ThreadSort::Trusted {
        let mut threads = fetch_warm_candidates_all(
            &state.db,
            &trust_map,
            &block_set,
            &reverse_map,
            &user.user_id,
        )
        .await?;
        score_trusted_recent(&mut threads, &trust_map, &user.user_id);
        apply_visible_reply_counts(&state.db, &mut threads, &reverse_map, &user.user_id).await?;
        return Ok(Json(ThreadListResponse {
            threads,
            next_cursor: None,
        }));
    }

    if params.sort.is_top_trusted() {
        let mut threads = fetch_trust_sorted_all_threads(
            &state.db,
            &trust_map,
            &block_set,
            &reverse_map,
            &user.user_id,
            params.sort,
        )
        .await?;
        apply_visible_reply_counts(&state.db, &mut threads, &reverse_map, &user.user_id).await?;
        return Ok(Json(ThreadListResponse {
            threads,
            next_cursor: None,
        }));
    }

    // sort=new (creation time) or sort=active (last reply time)
    let use_created_at = params.sort == ThreadSort::New;
    let (order_col, order_col_coalesce) = if use_created_at {
        ("t.created_at", "t.created_at")
    } else {
        ("t.last_activity", "COALESCE(t.last_activity, t.created_at)")
    };

    let rows = if let Some(ref cursor) = params.cursor {
        let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
        let sql = format!(
            "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
             r.id, r.name, r.slug, t.locked, r.public, \
             t.reply_count, t.last_activity \
             FROM threads t \
             JOIN users u ON u.id = t.author \
             JOIN rooms r ON r.id = t.room \
             WHERE r.merged_into IS NULL \
               AND {RETRACTED_OP_FILTER} \
               AND ({order_col_coalesce} < ? \
                    OR ({order_col_coalesce} = ? AND t.id < ?)) \
             ORDER BY {order_col} DESC NULLS LAST, t.created_at DESC, t.id DESC \
             LIMIT ?"
        );
        sqlx::query_as::<_, AllThreadsRow>(&sql)
            .bind(&cursor_ts)
            .bind(&cursor_ts)
            .bind(&cursor_id)
            .bind(PAGE_SIZE as i64 + 1)
            .fetch_all(&state.db)
            .await?
    } else {
        let sql = format!(
            "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
             r.id, r.name, r.slug, t.locked, r.public, \
             t.reply_count, t.last_activity \
             FROM threads t \
             JOIN users u ON u.id = t.author \
             JOIN rooms r ON r.id = t.room \
             WHERE r.merged_into IS NULL \
               AND {RETRACTED_OP_FILTER} \
             ORDER BY {order_col} DESC NULLS LAST, t.created_at DESC, t.id DESC \
             LIMIT ?"
        );
        sqlx::query_as::<_, AllThreadsRow>(&sql)
            .bind(PAGE_SIZE as i64 + 1)
            .fetch_all(&state.db)
            .await?
    };

    let has_more = rows.len() > PAGE_SIZE;
    let mut threads: Vec<ThreadSummary> = rows
        .into_iter()
        .take(PAGE_SIZE)
        .filter(|row| is_thread_visible(&row.2, row.9, &user.user_id, &reverse_map))
        .map(|row| all_threads_to_summary(row, &trust_map, &block_set))
        .collect();

    apply_visible_reply_counts(&state.db, &mut threads, &reverse_map, &user.user_id).await?;

    let next_cursor = if has_more {
        threads.last().map(if use_created_at {
            make_cursor_created_at
        } else {
            make_cursor
        })
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

    if params.sort == ThreadSort::Warm {
        let mut threads = fetch_warm_candidates_room(
            &state.db,
            &trust_map,
            &block_set,
            &reverse_map,
            &user.user_id,
            &room_id,
            &room_name,
            &room_slug,
            room_public,
        )
        .await?;
        let thread_ids: Vec<String> = threads.iter().map(|t| t.id.clone()).collect();
        let repliers = fetch_repliers(&state.db, &thread_ids).await?;
        score_warm(
            &mut threads,
            &repliers,
            &trust_map,
            &reverse_map,
            &user.user_id,
        );
        apply_visible_reply_counts(&state.db, &mut threads, &reverse_map, &user.user_id).await?;
        return Ok(Json(ThreadListResponse {
            threads,
            next_cursor: None,
        }));
    }

    if params.sort == ThreadSort::Trusted {
        let mut threads = fetch_warm_candidates_room(
            &state.db,
            &trust_map,
            &block_set,
            &reverse_map,
            &user.user_id,
            &room_id,
            &room_name,
            &room_slug,
            room_public,
        )
        .await?;
        score_trusted_recent(&mut threads, &trust_map, &user.user_id);
        apply_visible_reply_counts(&state.db, &mut threads, &reverse_map, &user.user_id).await?;
        return Ok(Json(ThreadListResponse {
            threads,
            next_cursor: None,
        }));
    }

    if params.sort.is_top_trusted() {
        let mut threads = fetch_trust_sorted_room_threads(
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
        apply_visible_reply_counts(&state.db, &mut threads, &reverse_map, &user.user_id).await?;
        return Ok(Json(ThreadListResponse {
            threads,
            next_cursor: None,
        }));
    }

    // sort=new (creation time) or sort=active (last reply time)
    let use_created_at = params.sort == ThreadSort::New;
    let (order_col, order_col_coalesce) = if use_created_at {
        ("t.created_at", "t.created_at")
    } else {
        ("t.last_activity", "COALESCE(t.last_activity, t.created_at)")
    };

    let rows = if let Some(ref cursor) = params.cursor {
        let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
        let sql = format!(
            "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
             t.locked, t.reply_count, t.last_activity \
             FROM threads t \
             JOIN users u ON u.id = t.author \
             WHERE t.room = ? \
               AND {RETRACTED_OP_FILTER} \
               AND ({order_col_coalesce} < ? \
                    OR ({order_col_coalesce} = ? AND t.id < ?)) \
             ORDER BY {order_col} DESC NULLS LAST, t.created_at DESC, t.id DESC \
             LIMIT ?"
        );
        sqlx::query_as::<_, RoomThreadsRow>(&sql)
            .bind(&room_id)
            .bind(&cursor_ts)
            .bind(&cursor_ts)
            .bind(&cursor_id)
            .bind(PAGE_SIZE as i64 + 1)
            .fetch_all(&state.db)
            .await?
    } else {
        let sql = format!(
            "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
             t.locked, t.reply_count, t.last_activity \
             FROM threads t \
             JOIN users u ON u.id = t.author \
             WHERE t.room = ? \
               AND {RETRACTED_OP_FILTER} \
             ORDER BY {order_col} DESC NULLS LAST, t.created_at DESC, t.id DESC \
             LIMIT ?"
        );
        sqlx::query_as::<_, RoomThreadsRow>(&sql)
            .bind(&room_id)
            .bind(PAGE_SIZE as i64 + 1)
            .fetch_all(&state.db)
            .await?
    };

    let has_more = rows.len() > PAGE_SIZE;
    let mut threads: Vec<ThreadSummary> = rows
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

    apply_visible_reply_counts(&state.db, &mut threads, &reverse_map, &user.user_id).await?;

    let next_cursor = if has_more {
        threads.last().map(if use_created_at {
            make_cursor_created_at
        } else {
            make_cursor
        })
    } else {
        None
    };

    Ok(Json(ThreadListResponse {
        threads,
        next_cursor,
    }))
}

// ---------------------------------------------------------------------------
// Warm sort candidate fetchers
// ---------------------------------------------------------------------------

/// Fetch visible candidate threads across all rooms for warm sort scoring.
///
/// Uses global `last_activity` for candidate ordering (safe proxy — not used
/// for ranking). Filters to threads visible to the reader.
async fn fetch_warm_candidates_all(
    db: &sqlx::SqlitePool,
    trust_map: &HashMap<String, f64>,
    block_set: &HashSet<String>,
    reverse_map: &HashMap<String, f64>,
    reader_id: &str,
) -> Result<Vec<ThreadSummary>, AppError> {
    let rows = sqlx::query_as::<_, AllThreadsRow>(
        "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
         r.id, r.name, r.slug, t.locked, r.public, \
         t.reply_count, t.last_activity \
         FROM threads t \
         JOIN users u ON u.id = t.author \
         JOIN rooms r ON r.id = t.room \
         WHERE r.merged_into IS NULL \
           AND NOT (t.reply_count = 0 \
                AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
         ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC \
         LIMIT ?",
    )
    .bind(WARM_CANDIDATE_LIMIT)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .filter(|row| is_thread_visible(&row.2, row.9, reader_id, reverse_map))
        .map(|row| all_threads_to_summary(row, trust_map, block_set))
        .collect())
}

/// Fetch visible candidate threads in a single room for warm sort scoring.
#[allow(clippy::too_many_arguments)]
async fn fetch_warm_candidates_room(
    db: &sqlx::SqlitePool,
    trust_map: &HashMap<String, f64>,
    block_set: &HashSet<String>,
    reverse_map: &HashMap<String, f64>,
    reader_id: &str,
    room_id: &str,
    room_name: &str,
    room_slug: &str,
    room_public: bool,
) -> Result<Vec<ThreadSummary>, AppError> {
    let rows = sqlx::query_as::<_, RoomThreadsRow>(
        "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
         t.locked, t.reply_count, t.last_activity \
         FROM threads t \
         JOIN users u ON u.id = t.author \
         WHERE t.room = ? \
           AND NOT (t.reply_count = 0 \
                AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL) \
         ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC \
         LIMIT ?",
    )
    .bind(room_id)
    .bind(WARM_CANDIDATE_LIMIT)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .filter(|row| is_thread_visible(&row.2, room_public, reader_id, reverse_map))
        .map(|row| {
            room_threads_to_summary(
                row,
                room_id,
                room_name,
                room_slug,
                room_public,
                trust_map,
                block_set,
            )
        })
        .collect())
}
