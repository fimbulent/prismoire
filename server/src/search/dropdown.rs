//! Cross-cutting search across rooms, users, and threads.
//!
//! This module currently implements just the autocomplete dropdown
//! surface (`GET /api/search`), which returns up to three hits per
//! kind (rooms, users, threads) for a single keystroke. Posts are
//! intentionally excluded from the dropdown for cost reasons; they
//! are exposed only on the dedicated `/search` results page.
//!
//! Visibility rules mirror `list_threads.rs` and `users.rs`. See
//! `docs/search.md` for the design rationale.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::display_name::display_name_skeleton;
use crate::error::AppError;
use crate::room_name::is_announcements;
use crate::session::AuthUser;
use crate::state::AppState;
use crate::threads::is_thread_visible;
use crate::trust::{
    MINIMUM_TRUST_THRESHOLD, UserStatus, UserViewerInfo, load_distrust_set, load_tag_map,
};

use super::threads::THREAD_FIELDS;
use super::{ALPHA, HALFLIFE_RANK, build_fts_query_with_fields, escape_like};

// ---------------------------------------------------------------------------
// Tunables (dropdown-specific; shared knobs live in `super`)
// ---------------------------------------------------------------------------

/// Number of hits returned per section in the autocomplete dropdown.
const DROPDOWN_LIMIT: i64 = 3;

/// FTS oversample for the dropdown's thread section. Many candidates may
/// be invisible to the viewer; we fetch a generous slice to leave room
/// after the visibility filter, but stay well below the `/search`
/// page's 200-row oversample because we only need three hits.
const DROPDOWN_THREAD_CANDIDATES: i64 = 60;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: Option<String>,
}

#[derive(Serialize)]
pub struct RoomHit {
    pub id: String,
    pub slug: String,
    pub is_announcement: bool,
}

#[derive(Serialize)]
pub struct UserHit {
    pub id: String,
    pub display_name: String,
    pub viewer: UserViewerInfo,
}

#[derive(Serialize)]
pub struct ThreadHit {
    pub id: String,
    pub title: String,
    pub author_id: String,
    pub author_name: String,
    pub room_id: String,
    pub room_slug: String,
    pub is_announcement: bool,
    pub created_at: String,
    pub last_activity: Option<String>,
    pub viewer: UserViewerInfo,
}

#[derive(Serialize)]
pub struct DropdownResponse {
    pub rooms: Vec<RoomHit>,
    pub users: Vec<UserHit>,
    pub threads: Vec<ThreadHit>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /api/search?q=…` — sectioned autocomplete dropdown.
///
/// Returns up to three rooms, three users, and three threads for the
/// given query. Posts are intentionally excluded — body search lives on
/// the dedicated `/search` page.
///
/// An empty / whitespace-only query short-circuits to an empty
/// response so the frontend can render the dropdown skeleton without
/// the server doing a wildcard scan.
pub async fn search_dropdown(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<SearchQuery>,
) -> Result<impl IntoResponse, AppError> {
    let raw = q.q.unwrap_or_default();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Json(DropdownResponse {
            rooms: Vec::new(),
            users: Vec::new(),
            threads: Vec::new(),
        }));
    }
    super::validate_query_length(trimmed)?;

    let reader_uuid = user.uuid();
    let graph = state.get_trust_graph()?;
    let reader_delta = state.pending_deltas.get(reader_uuid);
    let trust_map = graph.distance_map_with_delta(reader_uuid, &reader_delta);
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;
    let tag_map = load_tag_map(&state.db, &user.user_id).await?;

    let rooms = search_rooms_section(&state.db, trimmed).await?;
    let users = search_users_section(
        &state.db,
        trimmed,
        &user.user_id,
        &trust_map,
        &reverse_map,
        &distrust_set,
        &tag_map,
    )
    .await?;
    let threads = search_threads_section(
        &state.db,
        trimmed,
        &user.user_id,
        &trust_map,
        &reverse_map,
        &distrust_set,
        &tag_map,
    )
    .await?;

    Ok(Json(DropdownResponse {
        rooms,
        users,
        threads,
    }))
}

// ---------------------------------------------------------------------------
// Section: rooms
// ---------------------------------------------------------------------------

/// Substring `LIKE` over `rooms.slug`, prioritising exact matches and
/// shorter slugs. Rooms are visible to all authenticated viewers, so
/// no trust filtering is needed.
async fn search_rooms_section(
    db: &sqlx::SqlitePool,
    query: &str,
) -> Result<Vec<RoomHit>, AppError> {
    let lower = query.to_lowercase();
    let escaped = escape_like(&lower);
    let substring_pattern = format!("%{escaped}%");
    let prefix_pattern = format!("{escaped}%");

    // Substring `LIKE` runs against `rooms_fts.slug` (trigram FTS5)
    // so the per-keystroke cost is index-bound regardless of room
    // count. The active-room filter on `rooms` is defensive — triggers
    // keep deleted / merged rooms out of `rooms_fts` already.
    let rows = sqlx::query!(
        r#"SELECT r.id, r.slug
           FROM rooms_fts
           JOIN rooms r ON r.rowid = rooms_fts.rowid
           WHERE rooms_fts.slug LIKE ? ESCAPE '\'
             AND r.merged_into IS NULL
             AND r.deleted_at IS NULL
           ORDER BY (LOWER(r.slug) = ?) DESC,
                    (LOWER(r.slug) LIKE ? ESCAPE '\') DESC,
                    LENGTH(r.slug),
                    r.slug
           LIMIT ?"#,
        substring_pattern,
        lower,
        prefix_pattern,
        DROPDOWN_LIMIT,
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| RoomHit {
            is_announcement: is_announcements(&r.slug),
            id: r.id,
            slug: r.slug,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Section: users
// ---------------------------------------------------------------------------

/// Skeleton-prefix match on `users.display_name_skeleton`, filtered to
/// users mutually visible to the viewer:
///
/// ```text
/// visible(A, V) =
///    reverse_score_map[A] >= MINIMUM_TRUST_THRESHOLD     -- A's posts visible to V
/// || distance_map.contains_key(A)                        -- V trusts A enough
/// ```
///
/// Both maps are already threshold-filtered (see `trust.rs`), so a
/// `contains_key` check on the forward map is equivalent to comparing
/// the score against `MINIMUM_TRUST_THRESHOLD`. Distrusted users are
/// pruned regardless.
async fn search_users_section(
    db: &sqlx::SqlitePool,
    query: &str,
    reader_id: &str,
    trust_map: &std::collections::HashMap<String, f64>,
    reverse_map: &std::collections::HashMap<String, f64>,
    distrust_set: &std::collections::HashSet<String>,
    tag_map: &std::collections::HashMap<String, String>,
) -> Result<Vec<UserHit>, AppError> {
    // Match on the skeleton (confusable-folded, lowercased) so search is
    // resilient to homoglyphs and case differences. See `users.rs::search_users`.
    let skeleton = display_name_skeleton(query);
    let pattern = format!("{}%", escape_like(&skeleton));

    // Oversample: the visibility filter rejects most rows on small
    // instances, but on a dense graph the top-N skeleton matches are
    // typically all visible. A 5x multiplier on `DROPDOWN_LIMIT` is a
    // cheap safety net before we hit the LIMIT.
    let candidate_limit = DROPDOWN_LIMIT * 5;

    let rows = sqlx::query!(
        r#"SELECT id, display_name, status, deleted_at
           FROM users
           WHERE deleted_at IS NULL
             AND display_name_skeleton LIKE ? ESCAPE '\'
           ORDER BY (display_name_skeleton = ?) DESC,
                    LENGTH(display_name),
                    display_name
           LIMIT ?"#,
        pattern,
        skeleton,
        candidate_limit,
    )
    .fetch_all(db)
    .await?;

    let mut hits: Vec<UserHit> = Vec::with_capacity(DROPDOWN_LIMIT as usize);
    for r in rows {
        // Mutual-visibility predicate. Self is always visible — a
        // user searching their own name expects their profile to
        // surface (e.g. as a quick way to check the public view of it
        // or copy a link). Trust gating still applies to everyone
        // else.
        let is_self = r.id == reader_id;
        if !is_self {
            if distrust_set.contains(&r.id) {
                continue;
            }
            let viewer_trusts_them = trust_map.contains_key(&r.id);
            let they_trust_viewer = reverse_map
                .get(&r.id)
                .is_some_and(|&s| s >= MINIMUM_TRUST_THRESHOLD);
            if !viewer_trusts_them && !they_trust_viewer {
                continue;
            }
        }

        let raw = UserStatus::try_from(r.status.as_str()).unwrap_or(UserStatus::Active);
        let status = UserStatus::effective(raw, r.deleted_at.as_deref());
        let viewer = UserViewerInfo::build(&r.id, trust_map, distrust_set, tag_map, status);
        hits.push(UserHit {
            id: r.id,
            display_name: r.display_name,
            viewer,
        });
        if hits.len() == DROPDOWN_LIMIT as usize {
            break;
        }
    }
    Ok(hits)
}

// ---------------------------------------------------------------------------
// Section: threads
// ---------------------------------------------------------------------------

struct ThreadFtsRow {
    id: String,
    title: String,
    author_id: String,
    author_name: String,
    author_status: String,
    author_deleted_at: Option<String>,
    created_at: String,
    room_id: String,
    room_slug: String,
    is_announcement: bool,
    last_activity: Option<String>,
    bm25: f64,
}

/// FTS5 MATCH on `threads_fts`, filtered through `is_thread_visible`,
/// then re-ranked by `bm25_norm × trust × recency_decay`.
async fn search_threads_section(
    db: &sqlx::SqlitePool,
    query: &str,
    reader_id: &str,
    trust_map: &std::collections::HashMap<String, f64>,
    reverse_map: &std::collections::HashMap<String, f64>,
    distrust_set: &std::collections::HashSet<String>,
    tag_map: &std::collections::HashMap<String, String>,
) -> Result<Vec<ThreadHit>, AppError> {
    let Some(fts_query) = build_fts_query_with_fields(query, THREAD_FIELDS) else {
        return Ok(Vec::new());
    };

    // BM25 weights: title 4.0, op_body 1.0, link_url 1.0. A title hit
    // dominates, but URL and OP-body matches still surface with lower
    // relevance.
    //
    // FTS5 returns `bm25` as a negative value where smaller = better
    // match (it's a cost-style metric). We project the bm25 value too
    // so we can compute `bm25_norm` in Rust.
    let rows = sqlx::query_as!(
        ThreadFtsRow,
        r#"SELECT t.id AS "id!",
                  t.title AS "title!",
                  t.author AS "author_id!",
                  u.display_name AS "author_name!",
                  u.status AS "author_status!",
                  u.deleted_at AS "author_deleted_at?",
                  t.created_at AS "created_at!",
                  r.id AS "room_id!",
                  r.slug AS "room_slug!",
                  (r.slug = 'announcements') AS "is_announcement!: bool",
                  t.last_activity AS "last_activity?",
                  bm25(threads_fts, 4.0, 1.0, 1.0) AS "bm25!: f64"
           FROM threads_fts
           JOIN threads t ON t.rowid = threads_fts.rowid
           JOIN users u ON u.id = t.author
           JOIN rooms r ON r.id = t.room
           WHERE threads_fts MATCH ?
             AND r.merged_into IS NULL
             AND r.deleted_at IS NULL
           ORDER BY bm25(threads_fts, 4.0, 1.0, 1.0)
           LIMIT ?"#,
        fts_query,
        DROPDOWN_THREAD_CANDIDATES,
    )
    .fetch_all(db)
    .await?;

    // Visibility filter. Mirrors `list_all_threads`'s post-fetch filter.
    let mut visible: Vec<ThreadFtsRow> = rows
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
        .collect();

    // Recency rank: position of each candidate when the visible set is
    // sorted by `last_activity` (falling back to `created_at`)
    // descending. This is the rank-based decay axis described in
    // `docs/search.md` — it self-calibrates across instances of any
    // activity tempo, the same way `score_warm` does.
    let mut recency_rank: std::collections::HashMap<String, usize> =
        std::collections::HashMap::with_capacity(visible.len());
    {
        let mut by_recency: Vec<&ThreadFtsRow> = visible.iter().collect();
        by_recency.sort_by(|a, b| {
            let ta = a.last_activity.as_deref().unwrap_or(a.created_at.as_str());
            let tb = b.last_activity.as_deref().unwrap_or(b.created_at.as_str());
            tb.cmp(ta)
        });
        for (i, row) in by_recency.iter().enumerate() {
            recency_rank.insert(row.id.clone(), i);
        }
    }

    // Final score per candidate.
    let mut scored: Vec<(usize, f64)> = visible
        .iter()
        .enumerate()
        .map(|(i, row)| {
            // bm25 is non-positive (FTS5 convention). Map to (0, 1].
            let bm25_norm = 1.0 / (1.0 + (-row.bm25).max(0.0));
            // Self-trust is 1.0; mirrors `score_warm` / `score_trusted_recent`.
            let trust_op = if row.author_id == reader_id {
                1.0
            } else {
                trust_map.get(&row.author_id).copied().unwrap_or(0.0)
            };
            let r = recency_rank.get(&row.id).copied().unwrap_or(0);
            let recency = 1.0 / (1.0 + (r as f64) / HALFLIFE_RANK);
            let score = bm25_norm * (ALPHA + (1.0 - ALPHA) * trust_op) * recency;
            (i, score)
        })
        .collect();

    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let top: Vec<usize> = scored
        .into_iter()
        .take(DROPDOWN_LIMIT as usize)
        .map(|(i, _)| i)
        .collect();

    let mut taken: Vec<Option<ThreadFtsRow>> = visible.drain(..).map(Some).collect();
    let mut hits: Vec<ThreadHit> = Vec::with_capacity(top.len());
    for idx in top {
        let row = taken[idx].take().expect("each index taken once");
        let raw = UserStatus::try_from(row.author_status.as_str()).unwrap_or(UserStatus::Active);
        let status = UserStatus::effective(raw, row.author_deleted_at.as_deref());
        let viewer =
            UserViewerInfo::build(&row.author_id, trust_map, distrust_set, tag_map, status);
        hits.push(ThreadHit {
            viewer,
            id: row.id,
            title: row.title,
            author_id: row.author_id,
            author_name: row.author_name,
            room_id: row.room_id,
            room_slug: row.room_slug,
            is_announcement: row.is_announcement,
            created_at: row.created_at,
            last_activity: row.last_activity,
        });
    }
    Ok(hits)
}
