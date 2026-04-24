//! Room endpoints: list, tab-bar, search, detail, and the per-viewer
//! activity + sparkline computation shared by all of them.
//!
//! The listing (`GET /api/rooms`, `POST /api/rooms/more`) and tab-bar
//! (`GET /api/rooms/tab-bar`) endpoints compute a *viewer-specific* 7-day
//! sparkline + thread count per room by filtering candidate threads
//! through the same visibility rule as thread listings
//! (`is_thread_visible`). Every room response therefore changes shape per
//! reader — the wire `thread_count` field is the number of threads the
//! reader can see that had their last activity within the past 7 UTC
//! calendar days, and the `sparkline` is the per-day bucketing of those
//! same threads (`sparkline[6]` = today-so-far, `sparkline[0]` = six days
//! ago).
//!
//! Sort order is "most recent visible activity", falling back to the
//! room's creation time for rooms with no activity in the viewer's 7-day
//! window. Cursor pagination is a simple lexicographic
//! `<timestamp>|<room_id>` — the sort key is deterministic across pages,
//! so no warm-style seen-ids set is needed.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use chrono::{DateTime, Datelike, Duration, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, ErrorCode};
use crate::room_name::is_announcements;
use crate::session::AuthUser;
use crate::state::AppState;
use crate::threads::{is_thread_visible, parse_cursor};
use crate::trust::load_distrust_set;

/// Rooms per page in the paginated `/api/rooms` listing.
const ROOMS_PAGE_SIZE: usize = 30;

/// Tab-bar capacity: favorites (in user order) backfilled with most
/// active non-favorited rooms up to this total. The frontend drops
/// entries that don't fit the viewport via ResizeObserver.
const TAB_BAR_SLOTS: usize = 6;

/// Maximum sparkline window — one entry per UTC calendar day, ending on
/// today (last index). The actual returned window may be shorter at
/// federation scale when the activity-scope query hits its LIMIT before
/// reaching 7 days back; see `compute_scoped_activity`.
const MAX_ACTIVITY_WINDOW_DAYS: usize = 7;

/// Query-1 LIMIT: how many recent visible threads to scan to discover
/// which rooms have viewer-relevant activity right now. Small relative to
/// federation-scale thread volume, but large enough that any room with
/// real weekly activity for the viewer will reliably surface (the
/// paginated listing tolerates rooms reshuffling across pages; the
/// client dedups on room id).
const TOP_ACTIVITY_CANDIDATES: i64 = 500;

/// Query-2 LIMIT: how many visible threads to bucket into sparklines
/// within the scoped room set. The oldest returned thread's date sets
/// the response's `activity_window_days`; hitting the LIMIT means the
/// window shrinks below 7 days rather than returning incomplete buckets.
const ROOM_ACTIVITY_SCOPE_LIMIT: i64 = 500;

/// Hard upper bound on how many rooms a single search request can return.
const ROOM_SEARCH_MAX: i64 = 20;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Full room response used by `/api/rooms`, `/api/rooms/more`, and
/// `/api/rooms/{id}`. Viewer-specific fields (`favorited`,
/// `recent_thread_count`, `sparkline`, `last_visible_activity`) are
/// computed per-request.
///
/// Activity window: `sparkline` has length `activity_window_days`
/// (between 1 and `MAX_ACTIVITY_WINDOW_DAYS = 7`). The window shrinks
/// below 7 days when the scoped activity query hits its LIMIT — the
/// client should render e.g. "42 threads last 5d" when
/// `activity_window_days < 7` and "42 threads this week" when it is 7.
#[derive(Serialize)]
pub struct RoomResponse {
    pub id: String,
    pub slug: String,
    pub is_announcement: bool,
    pub created_by: String,
    pub created_by_name: String,
    pub created_at: String,
    /// Number of threads the viewer can see that had their last activity
    /// within the returned window (see `activity_window_days`). Equals
    /// `sparkline.iter().sum()`.
    pub recent_thread_count: i64,
    /// One entry per UTC calendar day, oldest first. Last index is
    /// today-so-far. Length matches `activity_window_days`.
    pub sparkline: Vec<i64>,
    /// Number of UTC calendar day buckets in `sparkline`. 1..=7; equals
    /// `sparkline.len()`. The same value is applied across every room in
    /// a given response so the UI can render a consistent window label.
    pub activity_window_days: u8,
    /// Most recent `last_activity` among the viewer-visible threads in
    /// the window. `None` if the viewer sees no recent activity.
    pub last_visible_activity: Option<String>,
    /// Whether the viewing user has favorited this room.
    pub favorited: bool,
}

#[derive(Serialize)]
pub struct RoomListResponse {
    pub rooms: Vec<RoomResponse>,
    pub next_cursor: Option<String>,
}

/// Tab-bar entry: favorites first (in user order), then backfilled with
/// most-active non-favorited rooms. Intentionally lightweight — the
/// frontend only needs the slug and announcement flag to render.
#[derive(Serialize)]
pub struct TabBarEntry {
    pub slug: String,
    pub is_announcement: bool,
    pub favorited: bool,
}

#[derive(Serialize)]
pub struct TabBarResponse {
    pub rooms: Vec<TabBarEntry>,
}

/// Lightweight room chip returned by the search endpoint.
#[derive(Serialize)]
pub struct RoomChip {
    pub id: String,
    pub slug: String,
    pub is_announcement: bool,
    /// Count of visible threads in the response's activity window.
    pub recent_thread_count: i64,
    /// Length of the activity window in UTC calendar days (1..=7).
    pub activity_window_days: u8,
}

#[derive(Serialize)]
pub struct RoomSearchResponse {
    pub rooms: Vec<RoomChip>,
}

#[derive(Deserialize)]
pub struct RoomSearchQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Deserialize)]
pub struct RoomListQuery {
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct LoadMoreRoomsRequest {
    pub cursor: String,
}

// ---------------------------------------------------------------------------
// Internal row + aggregate types
// ---------------------------------------------------------------------------

/// Basic room metadata fetched from `rooms` + `users`. Populated once per
/// request and then enriched with viewer-specific activity.
#[derive(Clone)]
struct RoomRow {
    id: String,
    slug: String,
    created_by: String,
    created_by_name: String,
    created_at: String,
}

/// Per-room viewer-specific activity, computed from the scoped thread
/// batch. `sparkline` length equals the containing response's
/// `activity_window_days` — the same width across every room in one
/// response so the UI can render a consistent window label.
struct RoomActivity {
    sparkline: Vec<i64>,
    last_visible_activity: Option<String>,
}

impl RoomActivity {
    fn empty(window_days: usize) -> Self {
        Self {
            sparkline: vec![0; window_days],
            last_visible_activity: None,
        }
    }
}

/// Result of the scoped activity computation. `by_room` maps room id to
/// its per-viewer `RoomActivity`; `window_days` is applied uniformly to
/// every room in the response (even rooms with no activity — their
/// sparklines are zero-padded to the same width).
struct ActivityResult {
    by_room: HashMap<String, RoomActivity>,
    window_days: u8,
}

impl ActivityResult {
    /// Neutral result when there are no scope rooms to query. The window
    /// defaults to the maximum so downstream zero-padded rooms get the
    /// familiar "this week" label.
    fn empty() -> Self {
        Self {
            by_room: HashMap::new(),
            window_days: MAX_ACTIVITY_WINDOW_DAYS as u8,
        }
    }
}

/// Sort key for a room in the listing.
///
/// Ordering (highest first):
/// 1. `last_visible_activity` if any visible threads exist in the 7-day
///    window — rooms with viewer-relevant recent activity float to the top.
/// 2. `created_at` otherwise — quiet or entirely-invisible rooms sort by
///    creation time so new rooms are discoverable.
///
/// The cursor encodes this exact tuple so pagination is deterministic.
fn room_sort_key<'a>(room: &'a RoomRow, activity: Option<&'a RoomActivity>) -> &'a str {
    activity
        .and_then(|a| a.last_visible_activity.as_deref())
        .unwrap_or(&room.created_at)
}

// ---------------------------------------------------------------------------
// Per-viewer activity computation
// ---------------------------------------------------------------------------

/// Compute the full-window UTC cutoff + day-start list ending on today.
///
/// `day_starts[i]` is midnight UTC of the i-th bucket (0 = oldest,
/// last = today). The cutoff string is suitable for a direct SQL `>=`
/// compare against the `last_activity` column.
fn full_window_bounds() -> (String, Vec<NaiveDate>) {
    window_bounds(MAX_ACTIVITY_WINDOW_DAYS)
}

/// Compute the cutoff + day-start list for a window of `window_days`
/// days ending on today (inclusive). `window_days` is clamped to
/// `[1, MAX_ACTIVITY_WINDOW_DAYS]`.
fn window_bounds(window_days: usize) -> (String, Vec<NaiveDate>) {
    let window_days = window_days.clamp(1, MAX_ACTIVITY_WINDOW_DAYS);
    let today = Utc::now().date_naive();
    let mut days = Vec::with_capacity(window_days);
    for i in 0..window_days {
        days.push(today - Duration::days((window_days - 1 - i) as i64));
    }
    let cutoff = Utc
        .with_ymd_and_hms(days[0].year(), days[0].month(), days[0].day(), 0, 0, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    (cutoff, days)
}

/// Map a `last_activity` ISO string to its sparkline bucket index
/// relative to `day_starts`. Returns `None` for timestamps outside the
/// window or that fail to parse.
fn bucket_for(last_activity: &str, day_starts: &[NaiveDate]) -> Option<usize> {
    let parsed: DateTime<Utc> = DateTime::parse_from_rfc3339(last_activity)
        .ok()?
        .with_timezone(&Utc);
    let d = parsed.date_naive();
    for (i, start) in day_starts.iter().enumerate() {
        let end = *start + Duration::days(1);
        if d >= *start && d < end {
            return Some(i);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Bounded activity computation
//
// The rooms area used to run one unbounded query per request
// (`WHERE last_activity >= <7-day-cutoff>`), which scaled linearly with
// federation-wide thread volume — the weak link compared to
// `list_all_threads`, which caps its candidate pool at a SQL-level LIMIT.
//
// The bounded replacement is two queries:
//
// 1. `discover_active_rooms` — top-N recent visible threads across every
//    active room. Distinct room ids from the visible subset (preserving
//    most-recent-visible-activity order) identify which rooms are worth
//    rendering a sparkline for. Used by `list_rooms` (to narrow scope)
//    and `tab_bar` (which needs nothing more than this — no sparklines).
//
// 2. `compute_scoped_activity` — given an explicit set of room ids,
//    pull their recent visible threads up to `ROOM_ACTIVITY_SCOPE_LIMIT`
//    and bucket by UTC calendar day. The oldest returned timestamp sets
//    `activity_window_days`: if the LIMIT was hit we shrink the window
//    so every returned bucket is complete (days earlier than the oldest
//    returned thread's date are incomplete and excluded). This is the
//    "X threads last 5d" fallback when the reader's visible activity is
//    too busy to fit a full 7-day window in one bounded scan.
//
// Callers choose a scope explicitly:
//   - `list_rooms`/`search_rooms` — discovery ∪ favorites
//   - `build_favorites_response` — just favorites (no discovery pass)
//   - `get_room` — just the single room
//   - `tab_bar` — discovery only (uses order, skips sparkline)
//
// A quiet favorite whose only activity falls outside the scope-query
// LIMIT will show zero sparkline and sort by `created_at`, same as a
// room with no activity in the 7-day window used to. This is the same
// degradation as today's boundary condition, just reached at a higher
// instance-wide thread volume.
// ---------------------------------------------------------------------------

/// Discover which rooms have viewer-relevant activity right now.
///
/// Pulls the top [`TOP_ACTIVITY_CANDIDATES`] most-recent threads
/// instance-wide, applies the visibility filter, and returns distinct
/// room ids in most-recent-visible-activity-first order. Used both as
/// the scope hint for `list_rooms`/`search_rooms` and as the sort order
/// for `tab_bar` backfill.
async fn discover_active_rooms(
    db: &sqlx::SqlitePool,
    reader_id: &str,
    reverse_map: &HashMap<String, f64>,
    distrust_set: &HashSet<String>,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT t.room AS "room!: String", t.author AS "author!: String",
                  t.last_activity AS "last_activity!: String",
                  (r.slug = 'announcements') AS "is_announcement!: bool"
           FROM threads t
           JOIN rooms r ON r.id = t.room
           WHERE r.merged_into IS NULL AND r.deleted_at IS NULL
             AND t.last_activity IS NOT NULL
             AND NOT (t.reply_count = 0
                  AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
           ORDER BY t.last_activity DESC
           LIMIT ?"#,
        TOP_ACTIVITY_CANDIDATES,
    )
    .fetch_all(db)
    .await?;

    let mut seen: HashSet<String> = HashSet::new();
    let mut ordered: Vec<String> = Vec::new();
    for row in rows {
        if !is_thread_visible(
            &row.author,
            row.is_announcement,
            reader_id,
            reverse_map,
            distrust_set,
        ) {
            continue;
        }
        if seen.insert(row.room.clone()) {
            ordered.push(row.room);
        }
    }
    Ok(ordered)
}

/// Compute per-room sparkline + last-visible-activity for exactly the
/// room ids in `scope`, bucketing into UTC calendar days.
///
/// Implementation detail: we first query with the full `MAX_ACTIVITY_WINDOW_DAYS`
/// cutoff and `LIMIT ROOM_ACTIVITY_SCOPE_LIMIT`. If the LIMIT was hit
/// (returned `==` LIMIT), the oldest returned thread's date sets the
/// effective window — days older than that date are incomplete and
/// excluded, so the UI gets a narrower but accurate sparkline.
///
/// TODO: Cache candidate. Viewer-specific (reader UUID + scope), stale
/// on any new visible post. `quick_cache::sync::Cache` keyed on
/// `(reader_id, sorted scope ids hash)` with short TTL would collapse
/// repeat calls within a session — especially useful on `/rooms` where
/// `render_room_page` and `build_favorites_response` both call this
/// back-to-back with overlapping scopes.
async fn compute_scoped_activity(
    db: &sqlx::SqlitePool,
    reader_id: &str,
    reverse_map: &HashMap<String, f64>,
    distrust_set: &HashSet<String>,
    scope: &[String],
) -> Result<ActivityResult, AppError> {
    if scope.is_empty() {
        return Ok(ActivityResult::empty());
    }

    let (full_cutoff, _full_day_starts) = full_window_bounds();

    // Bind `scope` as a dynamic `IN (?,?,...)` list. sqlx 0.8's
    // compile-time macros don't support variadic IN, so build a placeholder
    // string and use `query_as` with a runtime-checked query. The shape
    // is small and the columns few, so the minor loss of compile-time
    // checking here is worth the bounded scope.
    let placeholders = std::iter::repeat_n("?", scope.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        r#"SELECT t.room AS room,
                  t.author AS author,
                  t.last_activity AS last_activity,
                  (r.slug = 'announcements') AS is_announcement
           FROM threads t
           JOIN rooms r ON r.id = t.room
           WHERE r.merged_into IS NULL AND r.deleted_at IS NULL
             AND t.room IN ({placeholders})
             AND t.last_activity IS NOT NULL
             AND t.last_activity >= ?
             AND NOT (t.reply_count = 0
                  AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
           ORDER BY t.last_activity DESC
           LIMIT ?"#
    );
    let mut q = sqlx::query_as::<_, ScopedThreadRow>(&sql);
    for id in scope {
        q = q.bind(id);
    }
    q = q.bind(&full_cutoff).bind(ROOM_ACTIVITY_SCOPE_LIMIT);
    let rows = q.fetch_all(db).await?;

    let hit_limit = rows.len() as i64 >= ROOM_ACTIVITY_SCOPE_LIMIT;

    // Visibility filter in Rust, same rule as thread listings.
    let visible: Vec<ScopedThreadRow> = rows
        .into_iter()
        .filter(|row| {
            is_thread_visible(
                &row.author,
                row.is_announcement,
                reader_id,
                reverse_map,
                distrust_set,
            )
        })
        .collect();

    // Determine window. If the LIMIT was hit, the oldest returned
    // thread's date caps our completeness guarantee: days strictly
    // earlier than that date were potentially truncated, so we only
    // expose day buckets covering `(oldest_date, today]`, i.e. a window
    // of `(today - oldest_date).num_days()` days. If the LIMIT wasn't
    // hit we saw everything in the 7-day cutoff, so the window is the
    // full max.
    let today = Utc::now().date_naive();
    let window_days: usize = if hit_limit {
        visible
            .last()
            .and_then(|r| DateTime::parse_from_rfc3339(&r.last_activity).ok())
            .map(|ts| {
                let oldest = ts.with_timezone(&Utc).date_naive();
                (today - oldest).num_days() as usize
            })
            .unwrap_or(MAX_ACTIVITY_WINDOW_DAYS)
            .clamp(1, MAX_ACTIVITY_WINDOW_DAYS)
    } else {
        MAX_ACTIVITY_WINDOW_DAYS
    };

    let (_cutoff, day_starts) = window_bounds(window_days);

    let mut by_room: HashMap<String, RoomActivity> = HashMap::new();
    for row in visible {
        let Some(bucket) = bucket_for(&row.last_activity, &day_starts) else {
            continue;
        };
        let entry = by_room
            .entry(row.room)
            .or_insert_with(|| RoomActivity::empty(window_days));
        entry.sparkline[bucket] += 1;
        if entry
            .last_visible_activity
            .as_deref()
            .is_none_or(|cur| row.last_activity.as_str() > cur)
        {
            entry.last_visible_activity = Some(row.last_activity);
        }
    }

    Ok(ActivityResult {
        by_room,
        window_days: window_days as u8,
    })
}

/// Row shape for the scoped activity query. Named struct (instead of a
/// tuple) so `query_as` can map by column name.
#[derive(sqlx::FromRow)]
struct ScopedThreadRow {
    room: String,
    author: String,
    last_activity: String,
    is_announcement: bool,
}

/// Fetch every active room with its creator display name. Kept as a
/// single flat query — per-request cost scales with room count, which is
/// small by instance policy.
async fn fetch_all_rooms(db: &sqlx::SqlitePool) -> Result<Vec<RoomRow>, AppError> {
    let rows = sqlx::query!(
        "SELECT r.id, r.slug, r.created_by, u.display_name, r.created_at \
         FROM rooms r \
         JOIN users u ON u.id = r.created_by \
         WHERE r.merged_into IS NULL AND r.deleted_at IS NULL",
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| RoomRow {
            id: r.id,
            slug: r.slug,
            created_by: r.created_by,
            created_by_name: r.display_name,
            created_at: r.created_at,
        })
        .collect())
}

/// Load the user's favorite set as `room_id -> position`. Used both to
/// populate the `favorited` flag on list responses and to drive the tab
/// bar ordering.
async fn fetch_favorites_map(
    db: &sqlx::SqlitePool,
    user_id: &str,
) -> Result<HashMap<String, i64>, AppError> {
    let rows = sqlx::query!(
        "SELECT room_id, position FROM room_favorites WHERE user_id = ?",
        user_id,
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.room_id, r.position)).collect())
}

/// Build a `RoomResponse` by combining room metadata, the viewer's
/// activity for that room, and the viewer's favorite flag.
///
/// `window_days` is the response-wide sparkline width; rooms without
/// recorded activity get a zero-padded sparkline of the same length so
/// the UI can render a consistent bar count across rows.
fn build_response(
    room: RoomRow,
    activity: Option<RoomActivity>,
    favorited: bool,
    window_days: u8,
) -> RoomResponse {
    let activity = activity.unwrap_or_else(|| RoomActivity::empty(window_days as usize));
    let recent_thread_count = activity.sparkline.iter().sum();
    let is_announcement = is_announcements(&room.slug);
    RoomResponse {
        id: room.id,
        slug: room.slug,
        is_announcement,
        created_by: room.created_by,
        created_by_name: room.created_by_name,
        created_at: room.created_at,
        recent_thread_count,
        sparkline: activity.sparkline,
        activity_window_days: window_days,
        last_visible_activity: activity.last_visible_activity,
        favorited,
    }
}

// ---------------------------------------------------------------------------
// GET /api/rooms — paginated listing with viewer-specific activity
// ---------------------------------------------------------------------------

/// GET /api/rooms — list active rooms sorted by viewer-visible activity.
///
/// Each response carries a 7-day sparkline + thread count filtered to
/// threads the reader can see. Pagination cursor is `<timestamp>|<id>`
/// where `timestamp` is the room's sort key (last visible activity, or
/// creation time when there is none).
pub async fn list_rooms(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<RoomListQuery>,
) -> Result<impl IntoResponse, AppError> {
    render_room_page(&state, &user, params.cursor.as_deref()).await
}

/// POST /api/rooms/more — page 2+ of the paginated listing.
pub async fn load_more_rooms(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(body): Json<LoadMoreRoomsRequest>,
) -> Result<impl IntoResponse, AppError> {
    render_room_page(&state, &user, Some(body.cursor.as_str())).await
}

/// Shared pagination core for `list_rooms` and `load_more_rooms`.
///
/// Fetches every active room, computes per-viewer activity, sorts by the
/// shared sort key, and slices out the requested page.
async fn render_room_page(
    state: &Arc<AppState>,
    user: &AuthUser,
    cursor: Option<&str>,
) -> Result<Json<RoomListResponse>, AppError> {
    let reader_uuid = user.uuid();
    let graph = state.get_trust_graph()?;
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;

    let rooms = fetch_all_rooms(&state.db).await?;
    let favorites = fetch_favorites_map(&state.db, &user.user_id).await?;

    // Discover which rooms have viewer-relevant activity, then broaden
    // the scope with the reader's favorites so their sparklines survive
    // even if their latest thread is buried beyond the discovery LIMIT.
    let discovered =
        discover_active_rooms(&state.db, &user.user_id, &reverse_map, &distrust_set).await?;
    let mut scope_set: HashSet<String> = discovered.into_iter().collect();
    for fav_id in favorites.keys() {
        scope_set.insert(fav_id.clone());
    }
    let scope: Vec<String> = scope_set.into_iter().collect();
    let mut result = compute_scoped_activity(
        &state.db,
        &user.user_id,
        &reverse_map,
        &distrust_set,
        &scope,
    )
    .await?;
    let window_days = result.window_days;

    // Sort by (sort_key DESC, id DESC). Collect into a Vec of (room,
    // activity_opt, favorited) so we can cursor-slice afterwards without
    // re-hashing.
    let mut entries: Vec<(RoomRow, Option<RoomActivity>, bool)> = rooms
        .into_iter()
        .map(|room| {
            let act = result.by_room.remove(&room.id);
            let fav = favorites.contains_key(&room.id);
            (room, act, fav)
        })
        .collect();

    entries.sort_by(|a, b| {
        let ka = room_sort_key(&a.0, a.1.as_ref());
        let kb = room_sort_key(&b.0, b.1.as_ref());
        kb.cmp(ka).then_with(|| b.0.id.cmp(&a.0.id))
    });

    // Apply cursor by skipping entries >= cursor position.
    //
    // Stale-cursor case: if no entry is lex-less than the cursor (e.g.
    // the cursor points at a room that has since been deleted, or a
    // room whose activity has shifted it elsewhere in the ordering),
    // `position(...)` returns `None` and we fall through to
    // `entries.len()` — i.e. an empty page with `next_cursor: null`.
    // The client treats that as "no more pages" and stops requesting.
    // This fails closed rather than loops or errors: the viewer simply
    // stops paginating, which is the least-bad outcome given that any
    // alternative (restart from the top, error) would be more
    // surprising than hitting the end of the list early.
    let start_idx = if let Some(cursor) = cursor {
        let (cursor_ts, cursor_id) = parse_cursor(cursor)?;
        entries
            .iter()
            .position(|(room, act, _)| {
                let key = room_sort_key(room, act.as_ref());
                // Strictly past the cursor: cursor points to the last
                // entry on the previous page, so we include everything
                // lex-less than that (or equal-key and lex-less-id).
                match key.cmp(cursor_ts.as_str()) {
                    std::cmp::Ordering::Less => true,
                    std::cmp::Ordering::Greater => false,
                    std::cmp::Ordering::Equal => room.id < cursor_id,
                }
            })
            .unwrap_or(entries.len())
    } else {
        0
    };

    let end_idx = (start_idx + ROOMS_PAGE_SIZE).min(entries.len());
    let has_more = end_idx < entries.len();

    let page: Vec<RoomResponse> = entries
        .drain(start_idx..end_idx)
        .map(|(room, act, fav)| build_response(room, act, fav, window_days))
        .collect();

    let next_cursor = if has_more {
        page.last().map(|r| {
            let ts = r.last_visible_activity.as_deref().unwrap_or(&r.created_at);
            format!("{}|{}", ts, r.id)
        })
    } else {
        None
    };

    Ok(Json(RoomListResponse {
        rooms: page,
        next_cursor,
    }))
}

/// Shared helper used by the `GET /api/me/favorites` endpoint (in the
/// `favorites` module) to return the viewer's full favorite list with
/// per-room sparklines + thread counts, ordered by the user's stored
/// `position`.
///
/// Scope is *just* the favorites — we skip the discovery pass entirely
/// since we already know which rooms we care about.
///
/// Kept here (rather than in `favorites.rs`) so it can reuse the
/// private `fetch_all_rooms` / `compute_scoped_activity` / `build_response`
/// helpers without exposing them publicly.
pub async fn build_favorites_response(
    db: &sqlx::SqlitePool,
    user_id: &str,
    reverse_map: &HashMap<String, f64>,
    distrust_set: &HashSet<String>,
) -> Result<Vec<RoomResponse>, AppError> {
    let rooms = fetch_all_rooms(db).await?;
    let favorites = fetch_favorites_map(db, user_id).await?;

    let scope: Vec<String> = favorites.keys().cloned().collect();
    let mut result =
        compute_scoped_activity(db, user_id, reverse_map, distrust_set, &scope).await?;
    let window_days = result.window_days;

    // Index the fetched rooms so we can pull by id in position order.
    let mut rooms_by_id: HashMap<String, RoomRow> =
        rooms.into_iter().map(|r| (r.id.clone(), r)).collect();

    let mut ordered: Vec<(String, i64)> = favorites.iter().map(|(k, v)| (k.clone(), *v)).collect();
    ordered.sort_by_key(|(_, pos)| *pos);

    let mut out = Vec::with_capacity(ordered.len());
    for (room_id, _) in ordered {
        // Favorites that point at a soft-deleted or merged room are
        // silently skipped. The `room_favorites` row remains until the
        // next cleanup sweep, but rendering it with no metadata would
        // confuse the client.
        let Some(room) = rooms_by_id.remove(&room_id) else {
            continue;
        };
        let act = result.by_room.remove(&room.id);
        out.push(build_response(room, act, true, window_days));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// GET /api/rooms/tab-bar — favorites in order, backfilled with top rooms
// ---------------------------------------------------------------------------

/// GET /api/rooms/tab-bar — per-user tab bar listing.
///
/// Returns the user's favorite rooms in their chosen order, followed by
/// the most-active non-favorited rooms sorted by viewer-visible activity,
/// up to [`TAB_BAR_SLOTS`] total entries. The frontend drops entries that
/// don't fit the viewport rather than scrolling horizontally, so the
/// server always returns the full slot count and lets the client pick.
pub async fn tab_bar(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let rooms = fetch_all_rooms(&state.db).await?;
    let favorites = fetch_favorites_map(&state.db, &user.user_id).await?;

    // Build slug lookup for the favorites that still point at an
    // active room. Favorites referencing a deleted/merged room are
    // silently skipped — the FK cascade drops them on hard delete, but
    // soft deletes leave the row around until the next cleanup sweep.
    let mut favorite_entries: Vec<TabBarEntry> = Vec::new();
    let mut favorites_ordered: Vec<(String, i64)> =
        favorites.iter().map(|(k, v)| (k.clone(), *v)).collect();
    favorites_ordered.sort_by_key(|(_, pos)| *pos);
    let rooms_by_id: HashMap<&str, &RoomRow> = rooms.iter().map(|r| (r.id.as_str(), r)).collect();
    for (room_id, _pos) in favorites_ordered {
        if let Some(room) = rooms_by_id.get(room_id.as_str()) {
            favorite_entries.push(TabBarEntry {
                slug: room.slug.clone(),
                is_announcement: is_announcements(&room.slug),
                favorited: true,
            });
            if favorite_entries.len() == TAB_BAR_SLOTS {
                break;
            }
        }
    }

    // If favorites already fill every slot, short-circuit: the backfill
    // is the only consumer of viewer-visible activity, and computing
    // that requires the trust graph + distrust set, which is by far the
    // most expensive work in this handler. Skipping it when unused
    // makes the tab bar effectively free for heavy favoriters.
    if favorite_entries.len() < TAB_BAR_SLOTS {
        let reader_uuid = user.uuid();
        let graph = state.get_trust_graph()?;
        let reverse_map = graph.reverse_score_map(reader_uuid);
        let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;

        // Only the ordering matters here; we don't render sparklines on
        // the tab bar, so skip the scoped sparkline pass entirely and
        // let the bounded discovery scan drive backfill order.
        let discovered =
            discover_active_rooms(&state.db, &user.user_id, &reverse_map, &distrust_set).await?;

        for room_id in discovered {
            if favorite_entries.len() >= TAB_BAR_SLOTS {
                break;
            }
            if favorites.contains_key(&room_id) {
                continue;
            }
            let Some(room) = rooms.iter().find(|r| r.id == room_id) else {
                continue;
            };
            favorite_entries.push(TabBarEntry {
                slug: room.slug.clone(),
                is_announcement: is_announcements(&room.slug),
                favorited: false,
            });
        }
    }

    Ok(Json(TabBarResponse {
        rooms: favorite_entries,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/rooms/search — typeahead chip search
// ---------------------------------------------------------------------------

/// GET /api/rooms/search?q=&limit= — prefix-match search over active rooms.
///
/// Drives the autocomplete dropdown on forms that pick a room (new thread,
/// admin "delete room"). Returns a lightweight `RoomChip` with a
/// viewer-visible recent thread count; per-bucket sparklines are
/// deliberately omitted since the dropdown UI does not render them.
///
/// TODO: may change shape. This endpoint fires per debounced keystroke, and
/// its per-request cost is ~equivalent to `list_rooms` (trust BFS + two
/// bounded thread scans). Candidates for lightening: drop
/// `recent_thread_count` so we can skip `compute_scoped_activity` entirely
/// (dropdown would show slug + announcement badge only), or add a
/// `(reader_id, scope hash)` micro-cache in front of the scoped-activity
/// call so adjacent-prefix queries collapse to one real compute.
pub async fn search_rooms(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<RoomSearchQuery>,
) -> Result<impl IntoResponse, AppError> {
    let reader_uuid = user.uuid();
    let graph = state.get_trust_graph()?;
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;

    let limit = q
        .limit
        .unwrap_or(ROOM_SEARCH_MAX / 2)
        .clamp(1, ROOM_SEARCH_MAX) as usize;
    let query = q.q.unwrap_or_default().trim().to_lowercase();

    let rooms = fetch_all_rooms(&state.db).await?;

    // Use discovery as the scope hint: rooms not in the top-N visible
    // threads will have no recorded activity and sort by `created_at`.
    let discovered =
        discover_active_rooms(&state.db, &user.user_id, &reverse_map, &distrust_set).await?;
    let result = compute_scoped_activity(
        &state.db,
        &user.user_id,
        &reverse_map,
        &distrust_set,
        &discovered,
    )
    .await?;
    let activity = &result.by_room;
    let window_days = result.window_days;

    let mut matched: Vec<&RoomRow> = if query.is_empty() {
        rooms.iter().collect()
    } else {
        rooms
            .iter()
            .filter(|r| r.slug.starts_with(&query))
            .collect()
    };

    if query.is_empty() {
        // Default ordering: most-active first.
        matched.sort_by(|a, b| {
            let ka = room_sort_key(a, activity.get(&a.id));
            let kb = room_sort_key(b, activity.get(&b.id));
            kb.cmp(ka)
        });
    } else {
        // Prefix match: shortest-match-first is the standard autocomplete
        // expectation, then alphabetical.
        matched.sort_by(|a, b| a.slug.len().cmp(&b.slug.len()).then(a.slug.cmp(&b.slug)));
    }

    let chips: Vec<RoomChip> = matched
        .into_iter()
        .take(limit)
        .map(|r| {
            let recent_thread_count: i64 = activity
                .get(&r.id)
                .map(|a| a.sparkline.iter().sum())
                .unwrap_or(0);
            RoomChip {
                id: r.id.clone(),
                slug: r.slug.clone(),
                is_announcement: is_announcements(&r.slug),
                recent_thread_count,
                activity_window_days: window_days,
            }
        })
        .collect();

    Ok(Json(RoomSearchResponse { rooms: chips }))
}

// ---------------------------------------------------------------------------
// GET /api/rooms/:id — single room detail
// ---------------------------------------------------------------------------

/// GET /api/rooms/:id — get room detail by ID or slug.
///
/// Mirrors the list response shape: returns sparkline, weekly thread
/// count, last visible activity, and favorited flag so the room header
/// page does not need a separate activity round-trip.
pub async fn get_room(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id_or_slug): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let reader_uuid = user.uuid();
    let graph = state.get_trust_graph()?;
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;

    let row = sqlx::query!(
        "SELECT r.id, r.slug, r.created_by, u.display_name, r.created_at \
         FROM rooms r \
         JOIN users u ON u.id = r.created_by \
         WHERE (r.id = ? OR r.slug = ?) AND r.merged_into IS NULL AND r.deleted_at IS NULL",
        id_or_slug,
        id_or_slug,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::RoomNotFound))?;

    let room = RoomRow {
        id: row.id,
        slug: row.slug,
        created_by: row.created_by,
        created_by_name: row.display_name,
        created_at: row.created_at,
    };

    // Scoped activity: a single-room query is the cheapest possible
    // path — the `IN (?)` becomes a single bound param, and the
    // window_days is derived solely from this room's own threads.
    let scope = vec![room.id.clone()];
    let mut result = compute_scoped_activity(
        &state.db,
        &user.user_id,
        &reverse_map,
        &distrust_set,
        &scope,
    )
    .await?;
    let window_days = result.window_days;

    let favorited = sqlx::query!(
        "SELECT room_id FROM room_favorites WHERE user_id = ? AND room_id = ?",
        user.user_id,
        room.id,
    )
    .fetch_optional(&state.db)
    .await?
    .is_some();

    let act = result.by_room.remove(&room.id);
    Ok(Json(build_response(room, act, favorited, window_days)))
}
