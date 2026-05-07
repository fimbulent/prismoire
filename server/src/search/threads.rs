//! `GET /api/search/threads?q=…&cursor=…` — paginated threads.
//!
//! Two candidate sources, merged into a single ranked list:
//!
//! 1. **FTS5 MATCH** on `threads_fts` (title weighted 4×, op_body 1×) —
//!    primary signal for substantive title / body matches.
//! 2. **`link_url LIKE`** substring match — surfaces link-post threads
//!    when the user pastes (or partially types) a URL fragment that
//!    happens to live in the linked URL but not in the title or OP body.
//!
//! Both pools are visibility-filtered through `is_thread_visible`, then
//! re-ranked by `bm25_norm × trust × recency_decay`. URL-only hits
//! (rows in the LIKE pool that the FTS query did not match) get a
//! fixed `bm25_norm` below typical title hits, so a strong title match
//! still wins against a URL substring match all else equal.
//!
//! No body snippets are returned — the threads tab on `/search` only
//! shows titles, matching the room-listing UX.

use std::collections::HashSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::session::AuthUser;
use crate::state::AppState;
use crate::threads::is_thread_visible;
use crate::trust::{UserStatus, UserViewerInfo, load_distrust_set, load_tag_map};

use super::{
    ALPHA, FTS_OVERSAMPLE, HALFLIFE_RANK, MoreSearchRequest, PAGE_SIZE, build_fts_query,
    decode_offset_cursor, encode_offset_cursor, escape_like, validate_query_length,
    validate_seen_ids,
};

/// Synthetic `bm25_norm` assigned to threads that match only on
/// `link_url` (no FTS hit). Chosen to sit below the typical normalized
/// score of a title hit so URL-only hits surface but don't crowd out
/// substantive title/body matches when both are present.
const URL_ONLY_BM25_NORM: f64 = 0.6;

#[derive(Deserialize)]
pub struct ThreadSearchQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Wire shape mirrors `ThreadSummary` from `threads/common.rs`. The
/// `/search?kind=threads` tab renders titles only — no body snippet —
/// so this struct intentionally omits any snippet field.
#[derive(Serialize)]
pub struct ThreadSearchHit {
    pub id: String,
    pub title: String,
    pub author_id: String,
    pub author_name: String,
    pub room_id: String,
    pub room_slug: String,
    pub created_at: String,
    pub locked: bool,
    pub is_announcement: bool,
    pub reply_count: i64,
    pub last_activity: Option<String>,
    pub link_url: Option<String>,
    pub viewer: UserViewerInfo,
}

#[derive(Serialize)]
pub struct ThreadSearchPageResponse {
    pub threads: Vec<ThreadSearchHit>,
    pub next_cursor: Option<String>,
}

/// Internal candidate row carrying everything needed for visibility
/// filtering, scoring, and the wire response.
struct ThreadCandidate {
    id: String,
    title: String,
    author_id: String,
    author_name: String,
    author_status: String,
    author_deleted_at: Option<String>,
    created_at: String,
    locked: bool,
    room_id: String,
    room_slug: String,
    is_announcement: bool,
    reply_count: i64,
    last_activity: Option<String>,
    link_url: Option<String>,
    /// `Some` for FTS-matched rows (raw `bm25(threads_fts, …)` value);
    /// `None` for URL-only matches, which are scored at
    /// [`URL_ONLY_BM25_NORM`].
    bm25: Option<f64>,
}

/// `GET /api/search/threads?q=…&cursor=…` — page-1 (and SSR) entry
/// point. Subsequent pages should use [`load_more_threads`] so the
/// client can pass `seen_ids` for cross-page dedup.
pub async fn search_threads_paginated(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<ThreadSearchQuery>,
) -> Result<impl IntoResponse, AppError> {
    search_threads_core(&state, &user, q.q, q.cursor.as_deref(), &HashSet::new()).await
}

/// `POST /api/search/threads/more` — page-2+ entry point. Body carries
/// the query, the previous page's cursor, and `seen_ids` (capped at
/// [`super::MAX_SEEN_IDS`]) for cross-page dedup.
pub async fn load_more_threads(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(body): Json<MoreSearchRequest>,
) -> Result<impl IntoResponse, AppError> {
    validate_seen_ids(&body.seen_ids)?;
    let seen: HashSet<String> = body.seen_ids.into_iter().collect();
    search_threads_core(&state, &user, body.q, Some(body.cursor.as_str()), &seen).await
}

async fn search_threads_core(
    state: &Arc<AppState>,
    user: &AuthUser,
    q: Option<String>,
    cursor: Option<&str>,
    seen_ids: &HashSet<String>,
) -> Result<Json<ThreadSearchPageResponse>, AppError> {
    let raw = q.unwrap_or_default();
    let trimmed = raw.trim();
    let offset = decode_offset_cursor(cursor)?;

    if trimmed.is_empty() {
        return Ok(Json(ThreadSearchPageResponse {
            threads: Vec::new(),
            next_cursor: None,
        }));
    }
    validate_query_length(trimmed)?;

    let reader_uuid = user.uuid();
    let graph = state.get_trust_graph()?;
    let reader_delta = state.pending_deltas.get(reader_uuid);
    let trust_map = graph.distance_map_with_delta(reader_uuid, &reader_delta);
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;
    let tag_map = load_tag_map(&state.db, &user.user_id).await?;

    let mut candidates: Vec<ThreadCandidate> = Vec::new();
    // Tracks IDs already pulled in by the FTS pool, so the URL-LIKE
    // pool below skips them rather than producing duplicate candidates
    // (the FTS hit's bm25 score wins). Distinct from the request's
    // `seen_ids` parameter, which is the cross-page client dedup set.
    let mut pool_dedup: HashSet<String> = HashSet::new();

    // ---- Pool 1: FTS-matched rows ----------------------------------
    //
    // BM25 weights: title 4.0, op_body 1.0. We deliberately do not
    // pull `op_body` into the result row — the threads tab renders
    // titles only — so no body snippet generation is needed.
    if let Some(fts_query) = build_fts_query(trimmed) {
        let rows = sqlx::query!(
            r#"SELECT t.id AS "id!: String",
                      t.title AS "title!: String",
                      t.author AS "author_id!: String",
                      u.display_name AS "author_name!: String",
                      u.status AS "author_status!: String",
                      u.deleted_at AS "author_deleted_at?: String",
                      t.created_at AS "created_at!: String",
                      t.locked AS "locked!: bool",
                      r.id AS "room_id!: String",
                      r.slug AS "room_slug!: String",
                      (r.slug = 'announcements') AS "is_announcement!: bool",
                      t.reply_count AS "reply_count!: i64",
                      t.last_activity AS "last_activity?: String",
                      t.link_url AS "link_url?: String",
                      bm25(threads_fts, 4.0, 1.0) AS "bm25!: f64"
               FROM threads_fts
               JOIN threads t ON t.rowid = threads_fts.rowid
               JOIN users u ON u.id = t.author
               JOIN rooms r ON r.id = t.room
               WHERE threads_fts MATCH ?
                 AND r.merged_into IS NULL
                 AND r.deleted_at IS NULL
               ORDER BY bm25(threads_fts, 4.0, 1.0)
               LIMIT ?"#,
            fts_query,
            FTS_OVERSAMPLE,
        )
        .fetch_all(&state.db)
        .await?;

        for row in rows {
            pool_dedup.insert(row.id.clone());
            candidates.push(ThreadCandidate {
                id: row.id,
                title: row.title,
                author_id: row.author_id,
                author_name: row.author_name,
                author_status: row.author_status,
                author_deleted_at: row.author_deleted_at,
                created_at: row.created_at,
                locked: row.locked,
                room_id: row.room_id,
                room_slug: row.room_slug,
                is_announcement: row.is_announcement,
                reply_count: row.reply_count,
                last_activity: row.last_activity,
                link_url: row.link_url,
                bm25: Some(row.bm25),
            });
        }
    }

    // ---- Pool 2: URL substring matches -----------------------------
    //
    // Substring match against `link_url`. SQLite does the LIKE
    // case-insensitively because the column is BLOB-or-TEXT and we
    // lowercase both sides explicitly. Bounded by `FTS_OVERSAMPLE`
    // (same envelope as the FTS pool) and ordered by recency so
    // recent URL matches survive truncation.
    let lowered = trimmed.to_lowercase();
    let url_pattern = format!("%{}%", escape_like(&lowered));
    let url_rows = sqlx::query!(
        r#"SELECT t.id AS "id!: String",
                  t.title AS "title!: String",
                  t.author AS "author_id!: String",
                  u.display_name AS "author_name!: String",
                  u.status AS "author_status!: String",
                  u.deleted_at AS "author_deleted_at?: String",
                  t.created_at AS "created_at!: String",
                  t.locked AS "locked!: bool",
                  r.id AS "room_id!: String",
                  r.slug AS "room_slug!: String",
                  (r.slug = 'announcements') AS "is_announcement!: bool",
                  t.reply_count AS "reply_count!: i64",
                  t.last_activity AS "last_activity?: String",
                  t.link_url AS "link_url?: String"
           FROM threads t
           JOIN users u ON u.id = t.author
           JOIN rooms r ON r.id = t.room
           WHERE t.link_url IS NOT NULL
             AND LOWER(t.link_url) LIKE ? ESCAPE '\'
             AND r.merged_into IS NULL
             AND r.deleted_at IS NULL
           ORDER BY COALESCE(t.last_activity, t.created_at) DESC
           LIMIT ?"#,
        url_pattern,
        FTS_OVERSAMPLE,
    )
    .fetch_all(&state.db)
    .await?;

    for row in url_rows {
        if !pool_dedup.insert(row.id.clone()) {
            // Already in the FTS pool — its (better) bm25 score wins.
            continue;
        }
        candidates.push(ThreadCandidate {
            id: row.id,
            title: row.title,
            author_id: row.author_id,
            author_name: row.author_name,
            author_status: row.author_status,
            author_deleted_at: row.author_deleted_at,
            created_at: row.created_at,
            locked: row.locked,
            room_id: row.room_id,
            room_slug: row.room_slug,
            is_announcement: row.is_announcement,
            reply_count: row.reply_count,
            last_activity: row.last_activity,
            link_url: row.link_url,
            bm25: None,
        });
    }

    if candidates.is_empty() {
        return Ok(Json(ThreadSearchPageResponse {
            threads: Vec::new(),
            next_cursor: None,
        }));
    }

    // ---- Visibility filter ----------------------------------------
    let visible: Vec<ThreadCandidate> = candidates
        .into_iter()
        .filter(|row| {
            is_thread_visible(
                &row.author_id,
                row.is_announcement,
                &user.user_id,
                &reverse_map,
                &distrust_set,
            )
        })
        .collect();

    // ---- Recency rank within the visible candidate set ------------
    let mut by_recency: Vec<usize> = (0..visible.len()).collect();
    by_recency.sort_by(|&a, &b| {
        let ta = visible[a]
            .last_activity
            .as_deref()
            .unwrap_or(visible[a].created_at.as_str());
        let tb = visible[b]
            .last_activity
            .as_deref()
            .unwrap_or(visible[b].created_at.as_str());
        tb.cmp(ta)
    });
    let mut recency_rank = vec![0usize; visible.len()];
    for (rank, idx) in by_recency.iter().enumerate() {
        recency_rank[*idx] = rank;
    }

    // ---- Score and sort -------------------------------------------
    let mut scored: Vec<(usize, f64)> = visible
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let bm25_norm = match row.bm25 {
                Some(raw) => 1.0 / (1.0 + (-raw).max(0.0)),
                None => URL_ONLY_BM25_NORM,
            };
            let trust_op = if row.author_id == user.user_id {
                1.0
            } else {
                trust_map.get(&row.author_id).copied().unwrap_or(0.0)
            };
            let r = recency_rank[i];
            let recency = 1.0 / (1.0 + (r as f64) / HALFLIFE_RANK);
            (i, bm25_norm * (ALPHA + (1.0 - ALPHA) * trust_op) * recency)
        })
        .collect();

    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let total_visible = scored.len();
    let page_indices: Vec<usize> = scored
        .into_iter()
        .skip(offset)
        .take(PAGE_SIZE)
        .map(|(i, _)| i)
        .collect();

    // ---- Materialize the page -------------------------------------
    //
    // Drop any slice rows already in the client's `seen_ids` set
    // (post-slice safety net for cross-page duplicates introduced by
    // candidate-pool drift between requests). The cursor still
    // advances by `PAGE_SIZE` regardless — see `MoreSearchRequest`.
    let mut taken: Vec<Option<ThreadCandidate>> = visible.into_iter().map(Some).collect();
    let mut hits: Vec<ThreadSearchHit> = Vec::with_capacity(page_indices.len());
    for idx in page_indices {
        let row = taken[idx].take().expect("each index taken once");
        if seen_ids.contains(&row.id) {
            continue;
        }
        let raw_status =
            UserStatus::try_from(row.author_status.as_str()).unwrap_or(UserStatus::Active);
        let status = UserStatus::effective(raw_status, row.author_deleted_at.as_deref());
        let viewer =
            UserViewerInfo::build(&row.author_id, &trust_map, &distrust_set, &tag_map, status);
        hits.push(ThreadSearchHit {
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
            link_url: row.link_url,
            viewer,
        });
    }

    let next_cursor = encode_offset_cursor(offset + PAGE_SIZE, total_visible);

    Ok(Json(ThreadSearchPageResponse {
        threads: hits,
        next_cursor,
    }))
}
