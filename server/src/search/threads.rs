//! `GET /api/search/threads?q=…&cursor=…` — paginated threads.
//!
//! A single FTS5 MATCH on `threads_fts` (title, op_body, link_url) —
//! BM25 weights `title × 4.0`, `op_body × 1.0`, `link_url × 1.0`.
//! Candidates are visibility-filtered through `is_thread_visible`,
//! then re-ranked by `bm25_norm × trust × recency_decay`.
//!
//! `link_url` is indexed via `threads.link_url_normalized`, which has
//! the scheme and a leading `www.` stripped so those near-universal
//! tokens never appear in the index (`docs/search_efficiency.md`).
//!
//! Field-filter syntax: users can write `title:foo`, `body:foo`, or
//! `url:foo` to scope a term to a specific column; `axum url:github`
//! finds threads matching "axum" anywhere AND "github" in the URL.
//! See `THREAD_FIELDS` and [`build_fts_query_with_fields`].
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
use crate::trust::{UserStatus, UserViewerInfo, load_distrust_set, load_tag_map, lookup_score};

use super::{
    ALPHA, FTS_OVERSAMPLE, HALFLIFE_RANK, MoreSearchRequest, PAGE_SIZE,
    build_fts_query_with_fields, decode_offset_cursor, encode_offset_cursor, validate_query_length,
    validate_seen_ids,
};

/// User-facing field aliases for `threads_fts` column filters. Maps
/// the shorter, user-friendly name to the actual FTS5 column. Shared
/// with the dropdown's thread section.
///
/// `body` aliases to `op_body` because the OP body is the only post
/// body indexed at the thread level (reply bodies live in `posts_fts`,
/// not here).
pub(crate) const THREAD_FIELDS: &[(&str, &str)] =
    &[("title", "title"), ("body", "op_body"), ("url", "link_url")];

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
    /// Lowercase-hex pubkey of the thread OP author.
    pub author_public_key_hex: String,
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
    author_public_key: Vec<u8>,
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
    /// Raw `bm25(threads_fts, …)` value (FTS5 convention: non-positive,
    /// smaller = better match). Normalised in the scoring pass.
    bm25: f64,
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

    // ---- FTS-matched rows ------------------------------------------
    //
    // BM25 weights: title 4.0, op_body 1.0, link_url 1.0. URL matches
    // and OP-body matches both sit a tier below title matches but
    // still surface. We do not pull `op_body` into the result row —
    // the threads tab renders titles only — so no body snippet
    // generation is needed.
    if let Some(fts_query) = build_fts_query_with_fields(trimmed, THREAD_FIELDS) {
        let rows = sqlx::query!(
            r#"SELECT t.id AS "id!: String",
                      t.title AS "title!: String",
                      t.author AS "author_id!: String",
                      u.display_name AS "author_name!: String",
                      u.public_key AS "author_public_key!: Vec<u8>",
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
            FTS_OVERSAMPLE,
        )
        .fetch_all(&state.db)
        .await?;

        for row in rows {
            candidates.push(ThreadCandidate {
                id: row.id,
                title: row.title,
                author_id: row.author_id,
                author_name: row.author_name,
                author_public_key: row.author_public_key,
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
                bm25: row.bm25,
            });
        }
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
            // bm25 is non-positive (FTS5 convention). Map to (0, 1].
            let bm25_norm = 1.0 / (1.0 + (-row.bm25).max(0.0));
            let trust_op = if row.author_id == user.user_id {
                1.0
            } else {
                lookup_score(&trust_map, &row.author_id).unwrap_or(0.0)
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
            author_public_key_hex: crate::users::hex_lower(&row.author_public_key),
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
