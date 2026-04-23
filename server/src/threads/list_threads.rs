use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use uuid::Uuid;

use crate::error::{AppError, ErrorCode};
use crate::session::AuthUser;
use crate::state::AppState;
use crate::trust::{TrustInfo, UserStatus, load_distrust_set};

use super::common::{
    MAX_SEEN_IDS, PAGE_SIZE, PaginationParams, RecentReplier, ThreadListResponse, ThreadSort,
    ThreadSummary, WarmPaginationRequest, is_thread_visible, make_cursor, make_cursor_created_at,
    make_warm_cursor, parse_cursor, parse_warm_cursor, score_trusted_recent, score_warm,
};

/// Maximum number of candidate threads to fetch for warm sort scoring (page 1).
///
/// The design doc suggests 2000 as an upper bound, but 500 is sufficient in
/// practice: visibility filtering reduces the pool further, and rank decay
/// makes threads beyond ~position 50 negligible. Keeps the replier data
/// load (500 × 50 = 25K rows) fast.
const WARM_CANDIDATE_LIMIT: i64 = 500;

/// Hard cap on candidate fetch size for page 2+ to prevent pathological queries.
const WARM_CANDIDATE_MAX: i64 = 5000;

// ---------------------------------------------------------------------------
// Row types for query results
//
// These are named structs (not tuples) so they can be used with
// `sqlx::query_as!` for compile-time query checking. The SELECTs that
// populate them must alias columns to the field names below and cast
// bool/expression columns (see CLAUDE.md column-override cheat-sheet).
// ---------------------------------------------------------------------------

/// Row type for "list threads across all rooms" SELECTs, carrying the
/// joined room info because listings span multiple rooms.
#[derive(Debug)]
struct AllThreadsRow {
    id: String,
    title: String,
    author_id: String,
    author_name: String,
    author_status: String,
    author_deleted_at: Option<String>,
    created_at: String,
    room_id: String,
    room_slug: String,
    locked: bool,
    is_announcement: bool,
    reply_count: i64,
    last_activity: Option<String>,
}

/// Row type for "list threads in a single room" SELECTs. The caller
/// already knows room_id / room_slug / is_announcement, so those are
/// stitched in during conversion instead of selected per-row.
#[derive(Debug)]
struct RoomThreadsRow {
    id: String,
    title: String,
    author_id: String,
    author_name: String,
    author_status: String,
    author_deleted_at: Option<String>,
    created_at: String,
    locked: bool,
    reply_count: i64,
    last_activity: Option<String>,
}

// ---------------------------------------------------------------------------
// Row-to-summary converters
// ---------------------------------------------------------------------------

fn all_threads_to_summary(
    row: AllThreadsRow,
    trust_map: &HashMap<String, f64>,
    distrust_set: &HashSet<String>,
) -> ThreadSummary {
    let raw = UserStatus::try_from(row.author_status.as_str()).unwrap_or(UserStatus::Active);
    let status = UserStatus::effective(raw, row.author_deleted_at.as_deref());
    let trust = TrustInfo::build(&row.author_id, trust_map, distrust_set, status);
    ThreadSummary {
        trust,
        id: row.id,
        title: row.title,
        author_id: row.author_id,
        author_name: row.author_name,
        room_id: row.room_id,
        room_slug: row.room_slug,
        created_at: row.created_at,
        locked: row.locked,
        is_announcement: row.is_announcement,
        reply_count: row.reply_count,
        last_activity: row.last_activity,
    }
}

fn room_threads_to_summary(
    row: RoomThreadsRow,
    room_id: &str,
    room_slug: &str,
    is_announcement: bool,
    trust_map: &HashMap<String, f64>,
    distrust_set: &HashSet<String>,
) -> ThreadSummary {
    let raw = UserStatus::try_from(row.author_status.as_str()).unwrap_or(UserStatus::Active);
    let status = UserStatus::effective(raw, row.author_deleted_at.as_deref());
    let trust = TrustInfo::build(&row.author_id, trust_map, distrust_set, status);
    ThreadSummary {
        trust,
        id: row.id,
        title: row.title,
        author_id: row.author_id,
        author_name: row.author_name,
        room_id: room_id.to_string(),
        room_slug: room_slug.to_string(),
        created_at: row.created_at,
        locked: row.locked,
        is_announcement,
        reply_count: row.reply_count,
        last_activity: row.last_activity,
    }
}

// ---------------------------------------------------------------------------
// Shared helpers: fetch recent repliers for warm sort
// ---------------------------------------------------------------------------

/// Fetch recent repliers for a set of candidate thread IDs from the
/// denormalized `thread_recent_repliers` table.
///
/// The variable-length `IN` list is expressed via SQLite's `json_each`
/// so the whole query is one statement with a single bound parameter,
/// which is what `sqlx::query!` needs to validate at compile time.
async fn fetch_repliers(
    db: &sqlx::SqlitePool,
    thread_ids: &[String],
) -> Result<Vec<RecentReplier>, AppError> {
    if thread_ids.is_empty() {
        return Ok(Vec::new());
    }

    let ids_json =
        serde_json::to_string(thread_ids).map_err(|_| AppError::code(ErrorCode::Internal))?;

    let rows = sqlx::query!(
        r#"SELECT thread_id, replier_id, replied_at
           FROM thread_recent_repliers
           WHERE thread_id IN (SELECT value FROM json_each(?))
           ORDER BY thread_id, reply_rank ASC"#,
        ids_json,
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| RecentReplier {
            thread_id: r.thread_id,
            replier_id: r.replier_id,
            replied_at: r.replied_at,
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
/// then filters in Rust using `reverse_map` point lookups. Uses
/// `json_each` for the variable-length thread-ID list (see
/// `fetch_repliers` for the rationale).
async fn apply_visible_reply_counts(
    db: &sqlx::SqlitePool,
    threads: &mut [ThreadSummary],
    reverse_map: &HashMap<String, f64>,
    distrust_set: &HashSet<String>,
    reader_id: &str,
) -> Result<(), AppError> {
    if threads.is_empty() {
        return Ok(());
    }

    let thread_ids: Vec<&str> = threads.iter().map(|t| t.id.as_str()).collect();
    let ids_json =
        serde_json::to_string(&thread_ids).map_err(|_| AppError::code(ErrorCode::Internal))?;

    let rows = sqlx::query!(
        r#"SELECT p.thread AS "thread!", p.author AS "author!",
                  COALESCE(parent_post.author, '') AS "parent_author!: String"
           FROM posts p
           LEFT JOIN posts parent_post ON parent_post.id = p.parent
           WHERE p.thread IN (SELECT value FROM json_each(?))
             AND p.parent IS NOT NULL"#,
        ids_json,
    )
    .fetch_all(db)
    .await?;

    use crate::trust::MINIMUM_TRUST_THRESHOLD;
    let mut counts: HashMap<String, i64> = HashMap::new();
    for row in &rows {
        // Distrusted authors' replies are pruned from the reader's view
        // (spec §"Distrust action UX"), so they must not contribute to the
        // viewer-specific reply count either.
        if row.author != reader_id && distrust_set.contains(&row.author) {
            continue;
        }
        let visible = row.author == reader_id
            || reverse_map
                .get(&row.author)
                .is_some_and(|&s| s >= MINIMUM_TRUST_THRESHOLD)
            || row.parent_author == reader_id;
        if visible {
            *counts.entry(row.thread.clone()).or_default() += 1;
        }
    }

    for thread in threads.iter_mut() {
        thread.reply_count = counts.get(&thread.id).copied().unwrap_or(0);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Warm/trusted candidate fetch result (carries metadata for pagination)
// ---------------------------------------------------------------------------

/// Result of a candidate fetch, carrying metadata needed for pagination
/// cursor construction and visibility rate calculation.
struct CandidateBatch {
    /// Visible threads after filtering (converted to ThreadSummary).
    visible: Vec<ThreadSummary>,
    /// Total number of raw candidates fetched from the DB (before visibility filtering).
    candidates_fetched: usize,
    /// The global `last_activity` (or created_at fallback) of the last candidate
    /// in the raw batch (the one with oldest activity). Used for cursor construction
    /// when there are no leftovers.
    last_candidate_activity: Option<String>,
    /// The thread ID of the last candidate in the raw batch.
    last_candidate_id: Option<String>,
}

// ---------------------------------------------------------------------------
// GET /api/threads/public — list threads in public rooms (no auth required)
// ---------------------------------------------------------------------------

/// List threads from the announcement room only, ordered by last activity, with cursor pagination.
/// This endpoint does not require authentication and is used for the logged-out landing page.
pub async fn list_public_announcement_threads(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, AppError> {
    let limit = PAGE_SIZE as i64 + 1;
    let rows = if let Some(ref cursor) = params.cursor {
        let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
        sqlx::query_as!(
            AllThreadsRow,
            r#"SELECT t.id, t.title,
                      t.author AS author_id,
                      u.display_name AS author_name,
                      u.status AS author_status,
                      u.deleted_at AS author_deleted_at,
                      t.created_at,
                      r.id AS room_id,
                      r.slug AS room_slug,
                      t.locked AS "locked: bool",
                      (r.slug = 'announcements') AS "is_announcement!: bool",
                      t.reply_count,
                      t.last_activity
               FROM threads t
               JOIN users u ON u.id = t.author
               JOIN rooms r ON r.id = t.room
               WHERE r.merged_into IS NULL
                 AND r.slug = 'announcements'
                 AND NOT (t.reply_count = 0
                      AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
                 AND (COALESCE(t.last_activity, t.created_at) < ?
                      OR (COALESCE(t.last_activity, t.created_at) = ? AND t.id < ?))
               ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC
               LIMIT ?"#,
            cursor_ts,
            cursor_ts,
            cursor_id,
            limit,
        )
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as!(
            AllThreadsRow,
            r#"SELECT t.id, t.title,
                      t.author AS author_id,
                      u.display_name AS author_name,
                      u.status AS author_status,
                      u.deleted_at AS author_deleted_at,
                      t.created_at,
                      r.id AS room_id,
                      r.slug AS room_slug,
                      t.locked AS "locked: bool",
                      (r.slug = 'announcements') AS "is_announcement!: bool",
                      t.reply_count,
                      t.last_activity
               FROM threads t
               JOIN users u ON u.id = t.author
               JOIN rooms r ON r.id = t.room
               WHERE r.merged_into IS NULL
                 AND r.slug = 'announcements'
                 AND NOT (t.reply_count = 0
                      AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
               ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC
               LIMIT ?"#,
            limit,
        )
        .fetch_all(&state.db)
        .await?
    };

    let has_more = rows.len() > PAGE_SIZE;
    let threads: Vec<ThreadSummary> = rows
        .into_iter()
        .take(PAGE_SIZE)
        .map(|row| {
            let raw =
                UserStatus::try_from(row.author_status.as_str()).unwrap_or(UserStatus::Active);
            ThreadSummary {
                id: row.id,
                title: row.title,
                author_id: row.author_id,
                author_name: row.author_name,
                room_id: row.room_id,
                room_slug: row.room_slug,
                created_at: row.created_at,
                locked: row.locked,
                is_announcement: row.is_announcement,
                reply_count: row.reply_count,
                last_activity: row.last_activity,
                trust: TrustInfo {
                    distance: None,
                    distrusted: false,
                    status: UserStatus::effective(raw, row.author_deleted_at.as_deref()),
                },
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
// GET /api/threads — list threads across all rooms (page 1)
// ---------------------------------------------------------------------------

/// List threads across all rooms, with sort mode and cursor pagination.
///
/// - `sort=warm` (default): rank-based decay × trust signal from visible
///   repliers. Page 1 returns a warm cursor for subsequent POST requests.
/// - `sort=trusted`: rank-based decay × OP trust (no replier signal),
///   with self-trust = 1.0. Same pagination model as warm.
/// - `sort=new`: thread creation time descending. Cursor-paginated via GET.
/// - `sort=active`: last reply time descending. Cursor-paginated via GET.
pub async fn list_all_threads(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ThreadListResponse>, AppError> {
    let reader_uuid = Uuid::parse_str(&user.user_id).unwrap_or(Uuid::nil());
    let graph = state.get_trust_graph()?;
    let trust_map = graph.distance_map(reader_uuid);
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;

    if params.sort == ThreadSort::Warm || params.sort == ThreadSort::Trusted {
        let sort = params.sort;
        let batch = fetch_warm_candidates_all(
            &state.db,
            &trust_map,
            &distrust_set,
            &reverse_map,
            &user.user_id,
            WARM_CANDIDATE_LIMIT,
            None,
        )
        .await?;
        let score_fn = build_score_fn(
            &state.db,
            sort,
            &batch.visible,
            None,
            &trust_map,
            &reverse_map,
            &user.user_id,
            0,
        )
        .await?;
        return score_and_paginate(
            &state.db,
            batch,
            reverse_map.clone(),
            distrust_set,
            user.user_id.clone(),
            None,
            None,
            0,
            WARM_CANDIDATE_LIMIT as usize,
            sort,
            score_fn,
        )
        .await;
    }

    // sort=new (creation time) or sort=active (last reply time). The
    // column choice has to be baked into the SQL at compile time for
    // `query_as!`, so the two sorts are expanded into four literal
    // queries (cursor × sort). The shared SELECT is intentionally
    // duplicated in exchange for compile-time checking.
    let use_created_at = params.sort == ThreadSort::New;
    let limit = PAGE_SIZE as i64 + 1;

    let rows = match (&params.cursor, use_created_at) {
        (Some(cursor), true) => {
            let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
            sqlx::query_as!(
                AllThreadsRow,
                r#"SELECT t.id, t.title,
                          t.author AS author_id,
                          u.display_name AS author_name,
                          u.status AS author_status,
                          u.deleted_at AS author_deleted_at,
                          t.created_at,
                          r.id AS room_id,
                          r.slug AS room_slug,
                          t.locked AS "locked: bool",
                          (r.slug = 'announcements') AS "is_announcement!: bool",
                          t.reply_count,
                          t.last_activity
                   FROM threads t
                   JOIN users u ON u.id = t.author
                   JOIN rooms r ON r.id = t.room
                   WHERE r.merged_into IS NULL
                     AND NOT (t.reply_count = 0
                          AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
                     AND (t.created_at < ? OR (t.created_at = ? AND t.id < ?))
                   ORDER BY t.created_at DESC NULLS LAST, t.created_at DESC, t.id DESC
                   LIMIT ?"#,
                cursor_ts,
                cursor_ts,
                cursor_id,
                limit,
            )
            .fetch_all(&state.db)
            .await?
        }
        (Some(cursor), false) => {
            let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
            sqlx::query_as!(
                AllThreadsRow,
                r#"SELECT t.id, t.title,
                          t.author AS author_id,
                          u.display_name AS author_name,
                          u.status AS author_status,
                          u.deleted_at AS author_deleted_at,
                          t.created_at,
                          r.id AS room_id,
                          r.slug AS room_slug,
                          t.locked AS "locked: bool",
                          (r.slug = 'announcements') AS "is_announcement!: bool",
                          t.reply_count,
                          t.last_activity
                   FROM threads t
                   JOIN users u ON u.id = t.author
                   JOIN rooms r ON r.id = t.room
                   WHERE r.merged_into IS NULL
                     AND NOT (t.reply_count = 0
                          AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
                     AND (COALESCE(t.last_activity, t.created_at) < ?
                          OR (COALESCE(t.last_activity, t.created_at) = ? AND t.id < ?))
                   ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC
                   LIMIT ?"#,
                cursor_ts,
                cursor_ts,
                cursor_id,
                limit,
            )
            .fetch_all(&state.db)
            .await?
        }
        (None, true) => {
            sqlx::query_as!(
                AllThreadsRow,
                r#"SELECT t.id, t.title,
                          t.author AS author_id,
                          u.display_name AS author_name,
                          u.status AS author_status,
                          u.deleted_at AS author_deleted_at,
                          t.created_at,
                          r.id AS room_id,
                          r.slug AS room_slug,
                          t.locked AS "locked: bool",
                          (r.slug = 'announcements') AS "is_announcement!: bool",
                          t.reply_count,
                          t.last_activity
                   FROM threads t
                   JOIN users u ON u.id = t.author
                   JOIN rooms r ON r.id = t.room
                   WHERE r.merged_into IS NULL
                     AND NOT (t.reply_count = 0
                          AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
                   ORDER BY t.created_at DESC NULLS LAST, t.created_at DESC, t.id DESC
                   LIMIT ?"#,
                limit,
            )
            .fetch_all(&state.db)
            .await?
        }
        (None, false) => {
            sqlx::query_as!(
                AllThreadsRow,
                r#"SELECT t.id, t.title,
                          t.author AS author_id,
                          u.display_name AS author_name,
                          u.status AS author_status,
                          u.deleted_at AS author_deleted_at,
                          t.created_at,
                          r.id AS room_id,
                          r.slug AS room_slug,
                          t.locked AS "locked: bool",
                          (r.slug = 'announcements') AS "is_announcement!: bool",
                          t.reply_count,
                          t.last_activity
                   FROM threads t
                   JOIN users u ON u.id = t.author
                   JOIN rooms r ON r.id = t.room
                   WHERE r.merged_into IS NULL
                     AND NOT (t.reply_count = 0
                          AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
                   ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC
                   LIMIT ?"#,
                limit,
            )
            .fetch_all(&state.db)
            .await?
        }
    };

    let has_more = rows.len() > PAGE_SIZE;
    let mut threads: Vec<ThreadSummary> = rows
        .into_iter()
        .take(PAGE_SIZE)
        .filter(|row| {
            is_thread_visible(
                &row.author_id,
                row.is_announcement,
                &user.user_id,
                &reverse_map,
                &distrust_set,
            )
        })
        .map(|row| all_threads_to_summary(row, &trust_map, &distrust_set))
        .collect();

    apply_visible_reply_counts(
        &state.db,
        &mut threads,
        &reverse_map,
        &distrust_set,
        &user.user_id,
    )
    .await?;

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
// Shared: resolve a room id-or-slug and return (id, slug, is_announcement)
// ---------------------------------------------------------------------------

/// Look up a room by id or slug, skipping merged-away rooms. Used by
/// both the GET and POST "load more" handlers for a single room.
async fn resolve_room(
    db: &sqlx::SqlitePool,
    room_id_or_slug: &str,
) -> Result<(String, String, bool), AppError> {
    let row = sqlx::query!(
        r#"SELECT id, slug,
                  (slug = 'announcements') AS "is_announcement!: bool"
           FROM rooms
           WHERE (id = ? OR slug = ?) AND merged_into IS NULL"#,
        room_id_or_slug,
        room_id_or_slug,
    )
    .fetch_optional(db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::RoomNotFound))?;

    Ok((row.id, row.slug, row.is_announcement))
}

// ---------------------------------------------------------------------------
// GET /api/rooms/:id/threads — list threads in a room (page 1)
// ---------------------------------------------------------------------------

/// List threads in a room, with sort mode and cursor pagination.
pub async fn list_threads(
    State(state): State<Arc<AppState>>,
    Path(room_id_or_slug): Path<String>,
    user: AuthUser,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ThreadListResponse>, AppError> {
    let reader_uuid = Uuid::parse_str(&user.user_id).unwrap_or(Uuid::nil());
    let graph = state.get_trust_graph()?;
    let trust_map = graph.distance_map(reader_uuid);
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;

    let (room_id, room_slug, is_announcement) = resolve_room(&state.db, &room_id_or_slug).await?;

    if params.sort == ThreadSort::Warm || params.sort == ThreadSort::Trusted {
        let sort = params.sort;
        let batch = fetch_warm_candidates_room(
            &state.db,
            &trust_map,
            &distrust_set,
            &reverse_map,
            &user.user_id,
            &room_id,
            &room_slug,
            is_announcement,
            WARM_CANDIDATE_LIMIT,
            None,
        )
        .await?;
        let score_fn = build_score_fn(
            &state.db,
            sort,
            &batch.visible,
            None,
            &trust_map,
            &reverse_map,
            &user.user_id,
            0,
        )
        .await?;
        return score_and_paginate(
            &state.db,
            batch,
            reverse_map.clone(),
            distrust_set,
            user.user_id.clone(),
            None,
            None,
            0,
            WARM_CANDIDATE_LIMIT as usize,
            sort,
            score_fn,
        )
        .await;
    }

    // sort=new (creation time) or sort=active (last reply time). Same
    // 4-way expansion pattern as `list_all_threads`.
    let use_created_at = params.sort == ThreadSort::New;
    let limit = PAGE_SIZE as i64 + 1;

    let rows = match (&params.cursor, use_created_at) {
        (Some(cursor), true) => {
            let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
            sqlx::query_as!(
                RoomThreadsRow,
                r#"SELECT t.id, t.title,
                          t.author AS author_id,
                          u.display_name AS author_name,
                          u.status AS author_status,
                          u.deleted_at AS author_deleted_at,
                          t.created_at,
                          t.locked AS "locked: bool",
                          t.reply_count,
                          t.last_activity
                   FROM threads t
                   JOIN users u ON u.id = t.author
                   WHERE t.room = ?
                     AND NOT (t.reply_count = 0
                          AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
                     AND (t.created_at < ? OR (t.created_at = ? AND t.id < ?))
                   ORDER BY t.created_at DESC NULLS LAST, t.created_at DESC, t.id DESC
                   LIMIT ?"#,
                room_id,
                cursor_ts,
                cursor_ts,
                cursor_id,
                limit,
            )
            .fetch_all(&state.db)
            .await?
        }
        (Some(cursor), false) => {
            let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
            sqlx::query_as!(
                RoomThreadsRow,
                r#"SELECT t.id, t.title,
                          t.author AS author_id,
                          u.display_name AS author_name,
                          u.status AS author_status,
                          u.deleted_at AS author_deleted_at,
                          t.created_at,
                          t.locked AS "locked: bool",
                          t.reply_count,
                          t.last_activity
                   FROM threads t
                   JOIN users u ON u.id = t.author
                   WHERE t.room = ?
                     AND NOT (t.reply_count = 0
                          AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
                     AND (COALESCE(t.last_activity, t.created_at) < ?
                          OR (COALESCE(t.last_activity, t.created_at) = ? AND t.id < ?))
                   ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC
                   LIMIT ?"#,
                room_id,
                cursor_ts,
                cursor_ts,
                cursor_id,
                limit,
            )
            .fetch_all(&state.db)
            .await?
        }
        (None, true) => {
            sqlx::query_as!(
                RoomThreadsRow,
                r#"SELECT t.id, t.title,
                          t.author AS author_id,
                          u.display_name AS author_name,
                          u.status AS author_status,
                          u.deleted_at AS author_deleted_at,
                          t.created_at,
                          t.locked AS "locked: bool",
                          t.reply_count,
                          t.last_activity
                   FROM threads t
                   JOIN users u ON u.id = t.author
                   WHERE t.room = ?
                     AND NOT (t.reply_count = 0
                          AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
                   ORDER BY t.created_at DESC NULLS LAST, t.created_at DESC, t.id DESC
                   LIMIT ?"#,
                room_id,
                limit,
            )
            .fetch_all(&state.db)
            .await?
        }
        (None, false) => {
            sqlx::query_as!(
                RoomThreadsRow,
                r#"SELECT t.id, t.title,
                          t.author AS author_id,
                          u.display_name AS author_name,
                          u.status AS author_status,
                          u.deleted_at AS author_deleted_at,
                          t.created_at,
                          t.locked AS "locked: bool",
                          t.reply_count,
                          t.last_activity
                   FROM threads t
                   JOIN users u ON u.id = t.author
                   WHERE t.room = ?
                     AND NOT (t.reply_count = 0
                          AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
                   ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC
                   LIMIT ?"#,
                room_id,
                limit,
            )
            .fetch_all(&state.db)
            .await?
        }
    };

    let has_more = rows.len() > PAGE_SIZE;
    let mut threads: Vec<ThreadSummary> = rows
        .into_iter()
        .take(PAGE_SIZE)
        .filter(|row| {
            is_thread_visible(
                &row.author_id,
                is_announcement,
                &user.user_id,
                &reverse_map,
                &distrust_set,
            )
        })
        .map(|row| {
            room_threads_to_summary(
                row,
                &room_id,
                &room_slug,
                is_announcement,
                &trust_map,
                &distrust_set,
            )
        })
        .collect();

    apply_visible_reply_counts(
        &state.db,
        &mut threads,
        &reverse_map,
        &distrust_set,
        &user.user_id,
    )
    .await?;

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
// POST /api/threads/more — paginated warm/trusted for all rooms
// ---------------------------------------------------------------------------

/// Load more threads across all rooms using warm/trusted pagination.
///
/// Accepts a warm cursor and seen_ids in the POST body. The cursor encodes
/// the sort mode, candidate position, visibility rate, and rank offset.
pub async fn load_more_all_threads(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(body): Json<WarmPaginationRequest>,
) -> Result<Json<ThreadListResponse>, AppError> {
    if body.seen_ids.len() > MAX_SEEN_IDS {
        return Err(AppError::with_message(
            ErrorCode::SeenIdsExceeded,
            format!("seen_ids exceeds maximum of {MAX_SEEN_IDS}"),
        ));
    }

    let cursor = parse_warm_cursor(&body.cursor)?;
    let reader_uuid = Uuid::parse_str(&user.user_id).unwrap_or(Uuid::nil());
    let graph = state.get_trust_graph()?;
    let trust_map = graph.distance_map(reader_uuid);
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;

    let seen_ids: HashSet<String> = body.seen_ids.into_iter().collect();

    // Dynamic fetch limit: compensate for seen_ids that may appear in the
    // overlap region. Clamp between WARM_CANDIDATE_LIMIT and WARM_CANDIDATE_MAX.
    let fetch_limit = compute_fetch_limit(cursor.visibility_rate, seen_ids.len());

    let batch = fetch_warm_candidates_all(
        &state.db,
        &trust_map,
        &distrust_set,
        &reverse_map,
        &user.user_id,
        fetch_limit,
        Some((&cursor.last_activity, &cursor.thread_id)),
    )
    .await?;

    let score_fn = build_score_fn(
        &state.db,
        cursor.sort,
        &batch.visible,
        Some(&seen_ids),
        &trust_map,
        &reverse_map,
        &user.user_id,
        cursor.rank_offset,
    )
    .await?;

    score_and_paginate(
        &state.db,
        batch,
        reverse_map,
        distrust_set,
        user.user_id,
        Some(&seen_ids),
        Some(cursor.visibility_rate),
        cursor.rank_offset,
        fetch_limit as usize,
        cursor.sort,
        score_fn,
    )
    .await
}

// ---------------------------------------------------------------------------
// POST /api/rooms/:id/threads/more — paginated warm/trusted for a room
// ---------------------------------------------------------------------------

/// Load more threads in a room using warm/trusted pagination.
pub async fn load_more_room_threads(
    State(state): State<Arc<AppState>>,
    Path(room_id_or_slug): Path<String>,
    user: AuthUser,
    Json(body): Json<WarmPaginationRequest>,
) -> Result<Json<ThreadListResponse>, AppError> {
    if body.seen_ids.len() > MAX_SEEN_IDS {
        return Err(AppError::with_message(
            ErrorCode::SeenIdsExceeded,
            format!("seen_ids exceeds maximum of {MAX_SEEN_IDS}"),
        ));
    }

    let cursor = parse_warm_cursor(&body.cursor)?;
    let reader_uuid = Uuid::parse_str(&user.user_id).unwrap_or(Uuid::nil());
    let graph = state.get_trust_graph()?;
    let trust_map = graph.distance_map(reader_uuid);
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;

    let (room_id, room_slug, is_announcement) = resolve_room(&state.db, &room_id_or_slug).await?;

    let seen_ids: HashSet<String> = body.seen_ids.into_iter().collect();
    let fetch_limit = compute_fetch_limit(cursor.visibility_rate, seen_ids.len());

    let batch = fetch_warm_candidates_room(
        &state.db,
        &trust_map,
        &distrust_set,
        &reverse_map,
        &user.user_id,
        &room_id,
        &room_slug,
        is_announcement,
        fetch_limit,
        Some((&cursor.last_activity, &cursor.thread_id)),
    )
    .await?;

    let score_fn = build_score_fn(
        &state.db,
        cursor.sort,
        &batch.visible,
        Some(&seen_ids),
        &trust_map,
        &reverse_map,
        &user.user_id,
        cursor.rank_offset,
    )
    .await?;

    score_and_paginate(
        &state.db,
        batch,
        reverse_map,
        distrust_set,
        user.user_id,
        Some(&seen_ids),
        Some(cursor.visibility_rate),
        cursor.rank_offset,
        fetch_limit as usize,
        cursor.sort,
        score_fn,
    )
    .await
}

// ---------------------------------------------------------------------------
// Shared warm/trusted pagination: score, detect leftovers, build cursor
// ---------------------------------------------------------------------------

/// Callback that applies the sort-specific scoring function to a mutable
/// thread vec. Called by `score_and_paginate` so callers only differ in
/// which scoring function they supply.
type ScoreFn = Box<dyn FnOnce(&mut Vec<ThreadSummary>) + Send>;

/// Build the sort-specific scoring closure for warm or trusted sort.
///
/// For warm sort, fetches replier data for candidates not in `seen_ids`
/// (or all candidates on page 1 when `seen_ids` is None). For trusted
/// sort, no replier data is needed.
#[allow(clippy::too_many_arguments)]
async fn build_score_fn(
    db: &sqlx::SqlitePool,
    sort: ThreadSort,
    candidates: &[ThreadSummary],
    seen_ids: Option<&HashSet<String>>,
    trust_map: &Arc<HashMap<String, f64>>,
    reverse_map: &Arc<HashMap<String, f64>>,
    reader_id: &str,
    rank_offset: usize,
) -> Result<ScoreFn, AppError> {
    match sort {
        ThreadSort::Warm => {
            let replier_ids: Vec<String> = candidates
                .iter()
                .filter(|t| seen_ids.is_none_or(|seen| !seen.contains(&t.id)))
                .map(|t| t.id.clone())
                .collect();
            let repliers = fetch_repliers(db, &replier_ids).await?;
            let tm = trust_map.clone();
            let rm = reverse_map.clone();
            let uid = reader_id.to_string();
            Ok(Box::new(move |threads| {
                score_warm(threads, &repliers, &tm, &rm, &uid, rank_offset);
            }))
        }
        ThreadSort::Trusted => {
            let tm = trust_map.clone();
            let uid = reader_id.to_string();
            Ok(Box::new(move |threads| {
                score_trusted_recent(threads, &tm, &uid, rank_offset);
            }))
        }
        _ => Err(AppError::code(ErrorCode::InvalidSortMode)),
    }
}

/// Shared post-fetch pipeline for warm/trusted sort pages.
///
/// 1. Optionally excludes `seen_ids` (page 2+).
/// 2. Snapshots each thread's `(activity, id)` before scoring.
/// 3. Calls `score_fn` which truncates `threads` to `PAGE_SIZE`.
/// 4. Detects leftovers and builds the next cursor.
/// 5. Applies viewer-specific reply counts.
#[allow(clippy::too_many_arguments)]
async fn score_and_paginate(
    db: &sqlx::SqlitePool,
    batch: CandidateBatch,
    reverse_map: Arc<HashMap<String, f64>>,
    distrust_set: HashSet<String>,
    reader_id: String,
    seen_ids: Option<&HashSet<String>>,
    visibility_rate_override: Option<f64>,
    rank_offset: usize,
    fetch_limit: usize,
    sort: ThreadSort,
    score_fn: ScoreFn,
) -> Result<Json<ThreadListResponse>, AppError> {
    let candidates_fetched = batch.candidates_fetched;
    let last_candidate_activity = batch.last_candidate_activity;
    let last_candidate_id = batch.last_candidate_id;

    // For page 1 we compute visibility_rate from the batch; for page 2+
    // it's carried forward from the cursor.
    let visibility_rate = visibility_rate_override.unwrap_or_else(|| {
        if candidates_fetched > 0 {
            batch.visible.len() as f64 / candidates_fetched as f64
        } else {
            0.0
        }
    });

    // Exclude already-rendered threads (page 2+ only).
    let mut threads: Vec<ThreadSummary> = if let Some(seen) = seen_ids {
        batch
            .visible
            .into_iter()
            .filter(|t| !seen.contains(&t.id))
            .collect()
    } else {
        batch.visible
    };

    if threads.is_empty() {
        return Ok(Json(ThreadListResponse {
            threads: Vec::new(),
            next_cursor: None,
        }));
    }

    // Snapshot (activity, id) for every visible thread *before* scoring
    // truncates the vec. Owned strings avoid borrow conflicts with score_fn.
    let activity_map: HashMap<String, String> = threads
        .iter()
        .map(|t| {
            let activity = t
                .last_activity
                .clone()
                .unwrap_or_else(|| t.created_at.clone());
            (t.id.clone(), activity)
        })
        .collect();
    let pre_score_ids: Vec<String> = threads.iter().map(|t| t.id.clone()).collect();

    // Apply sort-specific scoring (mutates + truncates threads to PAGE_SIZE).
    score_fn(&mut threads);

    // Identify leftovers: visible threads that scoring didn't select.
    let returned_ids: HashSet<&str> = threads.iter().map(|t| t.id.as_str()).collect();
    let leftover_ids: Vec<&str> = pre_score_ids
        .iter()
        .filter(|id| !returned_ids.contains(id.as_str()))
        .map(|id| id.as_str())
        .collect();

    apply_visible_reply_counts(db, &mut threads, &reverse_map, &distrust_set, &reader_id).await?;

    let next_cursor = build_warm_cursor(
        sort,
        &threads,
        &leftover_ids,
        &activity_map,
        candidates_fetched,
        fetch_limit,
        last_candidate_activity.as_deref(),
        last_candidate_id.as_deref(),
        visibility_rate,
        rank_offset,
    );

    Ok(Json(ThreadListResponse {
        threads,
        next_cursor,
    }))
}

// ---------------------------------------------------------------------------
// Warm cursor construction
// ---------------------------------------------------------------------------

/// Build the warm/trusted pagination cursor.
///
/// When leftovers exist (visible threads that didn't make the PAGE_SIZE cut),
/// the cursor must point to the **newest** leftover's activity so the next
/// page's candidate window includes it. When there are no leftovers but the
/// DB batch was full, the cursor advances to the last candidate (oldest
/// activity in the window).
#[allow(clippy::too_many_arguments)]
fn build_warm_cursor(
    sort: ThreadSort,
    returned_threads: &[ThreadSummary],
    leftover_ids: &[&str],
    activity_map: &HashMap<String, String>,
    candidates_fetched: usize,
    fetch_limit: usize,
    last_candidate_activity: Option<&str>,
    last_candidate_id: Option<&str>,
    visibility_rate: f64,
    prev_rank_offset: usize,
) -> Option<String> {
    if returned_threads.is_empty() {
        return None;
    }

    let has_leftovers = !leftover_ids.is_empty();
    let batch_was_full = candidates_fetched >= fetch_limit;

    if !has_leftovers && !batch_was_full {
        return None;
    }

    let rank_offset = prev_rank_offset + returned_threads.len();

    if has_leftovers {
        // Find the leftover with the most recent (lexicographically largest)
        // global activity. The cursor is set to this timestamp so the next
        // page's candidate window (which fetches activity <= cursor) includes
        // all leftovers. seen_ids prevents duplicates.
        if let Some((activity, id)) = leftover_ids
            .iter()
            .filter_map(|&id| activity_map.get(id).map(|act| (act.as_str(), id)))
            .max_by_key(|(act, _)| *act)
        {
            return Some(make_warm_cursor(
                sort,
                activity,
                id,
                visibility_rate,
                rank_offset,
            ));
        }
    }

    // No leftovers but batch was full — more candidates exist beyond this window.
    if let (Some(activity), Some(id)) = (last_candidate_activity, last_candidate_id) {
        Some(make_warm_cursor(
            sort,
            activity,
            id,
            visibility_rate,
            rank_offset,
        ))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Fetch limit calculation for page 2+
// ---------------------------------------------------------------------------

/// Compute the dynamic candidate fetch limit for page 2+.
///
/// Formula: `clamp((PAGE_SIZE + seen_count) / visibility_rate, WARM_CANDIDATE_LIMIT, WARM_CANDIDATE_MAX)`
///
/// The numerator includes `seen_count` because some seen threads may fall
/// in the overlap region between the previous and current candidate windows.
/// In practice, most seen threads have more recent activity than the cursor
/// and won't appear, making this conservatively over-sized — which is fine,
/// as extra candidates are filtered cheaply in memory.
fn compute_fetch_limit(visibility_rate: f64, seen_count: usize) -> i64 {
    if visibility_rate <= 0.0 {
        return WARM_CANDIDATE_LIMIT;
    }
    let raw = (PAGE_SIZE + seen_count) as f64 / visibility_rate;
    (raw.ceil() as i64).clamp(WARM_CANDIDATE_LIMIT, WARM_CANDIDATE_MAX)
}

// ---------------------------------------------------------------------------
// Warm sort candidate fetchers
// ---------------------------------------------------------------------------

/// Fetch candidate threads across all rooms for warm/trusted sort scoring.
///
/// Uses global `last_activity` for candidate ordering (safe proxy — not used
/// for ranking). Returns raw metadata alongside visible threads for pagination.
///
/// When `cursor` is Some, fetches candidates starting from that position
/// (inclusive) for page 2+ queries.
#[allow(clippy::too_many_arguments)]
async fn fetch_warm_candidates_all(
    db: &sqlx::SqlitePool,
    trust_map: &HashMap<String, f64>,
    distrust_set: &HashSet<String>,
    reverse_map: &HashMap<String, f64>,
    reader_id: &str,
    limit: i64,
    cursor: Option<(&str, &str)>,
) -> Result<CandidateBatch, AppError> {
    let rows = if let Some((cursor_ts, cursor_id)) = cursor {
        // Page 2+: fetch from cursor position (inclusive).
        // Uses <= on ID for inclusivity — the cursor thread is a leftover
        // that must be re-evaluated on this page.
        sqlx::query_as!(
            AllThreadsRow,
            r#"SELECT t.id, t.title,
                      t.author AS author_id,
                      u.display_name AS author_name,
                      u.status AS author_status,
                      u.deleted_at AS author_deleted_at,
                      t.created_at,
                      r.id AS room_id,
                      r.slug AS room_slug,
                      t.locked AS "locked: bool",
                      (r.slug = 'announcements') AS "is_announcement!: bool",
                      t.reply_count,
                      t.last_activity
               FROM threads t
               JOIN users u ON u.id = t.author
               JOIN rooms r ON r.id = t.room
               WHERE r.merged_into IS NULL
                 AND NOT (t.reply_count = 0
                      AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
                 AND (COALESCE(t.last_activity, t.created_at) < ?
                      OR (COALESCE(t.last_activity, t.created_at) = ? AND t.id <= ?))
               ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC
               LIMIT ?"#,
            cursor_ts,
            cursor_ts,
            cursor_id,
            limit,
        )
        .fetch_all(db)
        .await?
    } else {
        // Page 1: fetch from the top.
        sqlx::query_as!(
            AllThreadsRow,
            r#"SELECT t.id, t.title,
                      t.author AS author_id,
                      u.display_name AS author_name,
                      u.status AS author_status,
                      u.deleted_at AS author_deleted_at,
                      t.created_at,
                      r.id AS room_id,
                      r.slug AS room_slug,
                      t.locked AS "locked: bool",
                      (r.slug = 'announcements') AS "is_announcement!: bool",
                      t.reply_count,
                      t.last_activity
               FROM threads t
               JOIN users u ON u.id = t.author
               JOIN rooms r ON r.id = t.room
               WHERE r.merged_into IS NULL
                 AND NOT (t.reply_count = 0
                      AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
               ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC
               LIMIT ?"#,
            limit,
        )
        .fetch_all(db)
        .await?
    };

    let candidates_fetched = rows.len();

    // Record the last candidate's activity and ID for cursor construction.
    let (last_candidate_activity, last_candidate_id) = rows
        .last()
        .map(|row| {
            let activity = row
                .last_activity
                .clone()
                .unwrap_or_else(|| row.created_at.clone());
            (Some(activity), Some(row.id.clone()))
        })
        .unwrap_or((None, None));

    let visible = rows
        .into_iter()
        .filter(|row| {
            is_thread_visible(
                &row.author_id,
                row.is_announcement,
                reader_id,
                reverse_map,
                distrust_set,
            )
        })
        .map(|row| all_threads_to_summary(row, trust_map, distrust_set))
        .collect();

    Ok(CandidateBatch {
        visible,
        candidates_fetched,
        last_candidate_activity,
        last_candidate_id,
    })
}

/// Fetch candidate threads in a single room for warm/trusted sort scoring.
#[allow(clippy::too_many_arguments)]
async fn fetch_warm_candidates_room(
    db: &sqlx::SqlitePool,
    trust_map: &HashMap<String, f64>,
    distrust_set: &HashSet<String>,
    reverse_map: &HashMap<String, f64>,
    reader_id: &str,
    room_id: &str,
    room_slug: &str,
    is_announcement: bool,
    limit: i64,
    cursor: Option<(&str, &str)>,
) -> Result<CandidateBatch, AppError> {
    let rows = if let Some((cursor_ts, cursor_id)) = cursor {
        sqlx::query_as!(
            RoomThreadsRow,
            r#"SELECT t.id, t.title,
                      t.author AS author_id,
                      u.display_name AS author_name,
                      u.status AS author_status,
                      u.deleted_at AS author_deleted_at,
                      t.created_at,
                      t.locked AS "locked: bool",
                      t.reply_count,
                      t.last_activity
               FROM threads t
               JOIN users u ON u.id = t.author
               WHERE t.room = ?
                 AND NOT (t.reply_count = 0
                      AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
                 AND (COALESCE(t.last_activity, t.created_at) < ?
                      OR (COALESCE(t.last_activity, t.created_at) = ? AND t.id <= ?))
               ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC
               LIMIT ?"#,
            room_id,
            cursor_ts,
            cursor_ts,
            cursor_id,
            limit,
        )
        .fetch_all(db)
        .await?
    } else {
        sqlx::query_as!(
            RoomThreadsRow,
            r#"SELECT t.id, t.title,
                      t.author AS author_id,
                      u.display_name AS author_name,
                      u.status AS author_status,
                      u.deleted_at AS author_deleted_at,
                      t.created_at,
                      t.locked AS "locked: bool",
                      t.reply_count,
                      t.last_activity
               FROM threads t
               JOIN users u ON u.id = t.author
               WHERE t.room = ?
                 AND NOT (t.reply_count = 0
                      AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
               ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC
               LIMIT ?"#,
            room_id,
            limit,
        )
        .fetch_all(db)
        .await?
    };

    let candidates_fetched = rows.len();
    let (last_candidate_activity, last_candidate_id) = rows
        .last()
        .map(|row| {
            let activity = row
                .last_activity
                .clone()
                .unwrap_or_else(|| row.created_at.clone());
            (Some(activity), Some(row.id.clone()))
        })
        .unwrap_or((None, None));

    let visible = rows
        .into_iter()
        .filter(|row| {
            is_thread_visible(
                &row.author_id,
                is_announcement,
                reader_id,
                reverse_map,
                distrust_set,
            )
        })
        .map(|row| {
            room_threads_to_summary(
                row,
                room_id,
                room_slug,
                is_announcement,
                trust_map,
                distrust_set,
            )
        })
        .collect();

    Ok(CandidateBatch {
        visible,
        candidates_fetched,
        last_candidate_activity,
        last_candidate_id,
    })
}
