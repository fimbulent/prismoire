//! `GET /api/search/posts?q=…&cursor=…` — paginated posts.
//!
//! FTS5 MATCH on `posts_fts` (latest non-retracted body per post),
//! filtered by a per-post visibility predicate (deliberately tighter
//! than `get_thread`'s — no reply-visibility grant), then re-ranked by
//! `bm25_norm × reverse_trust × recency_decay × thread_title_bump`.
//!
//! See `docs/search.md` §Visibility/Posts and §Ranking/Posts.

use std::collections::HashSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::session::AuthUser;
use crate::state::AppState;
use crate::trust::{
    MINIMUM_TRUST_THRESHOLD, UserStatus, UserViewerInfo, load_distrust_set, load_tag_map,
};

use super::{
    ALPHA, FTS_OVERSAMPLE, HALFLIFE_RANK, MoreSearchRequest, PAGE_SIZE, build_fts_query,
    decode_offset_cursor, encode_offset_cursor, validate_query_length, validate_seen_ids,
};

/// Multiplicative bump applied when the post's enclosing thread title
/// also matches the query — rewards posts whose surrounding thread is
/// also about the query.
const TITLE_MATCH_BUMP: f64 = 1.2;

#[derive(Deserialize)]
pub struct PostSearchQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Serialize)]
pub struct PostSearchHit {
    pub id: String,
    pub thread_id: String,
    pub thread_title: String,
    pub room_id: String,
    pub room_slug: String,
    pub is_announcement: bool,
    pub author_id: String,
    pub author_name: String,
    pub created_at: String,
    /// Full post body (markdown). The frontend renders it via the
    /// shared `Markdown` component so the post appears in its native
    /// formatting — preferred over a contextless FTS snippet for the
    /// dedicated `/search` results page.
    pub body: String,
    /// True when this post is the thread's opening post (no parent).
    /// Lets the frontend pick the `full` markdown profile for OPs and
    /// the trimmed `reply` profile for replies, matching how posts
    /// render in their native context.
    pub is_op: bool,
    pub viewer: UserViewerInfo,
}

#[derive(Serialize)]
pub struct PostSearchPageResponse {
    pub posts: Vec<PostSearchHit>,
    pub next_cursor: Option<String>,
}

struct PostFtsRow {
    id: String,
    thread_id: String,
    thread_title: String,
    room_id: String,
    room_slug: String,
    is_announcement: bool,
    author_id: String,
    author_name: String,
    author_status: String,
    author_deleted_at: Option<String>,
    created_at: String,
    /// Latest non-retracted body, served verbatim to the client.
    body: String,
    /// `posts.parent IS NULL` — the OP of the enclosing thread.
    is_op: bool,
    bm25: f64,
}

/// `GET /api/search/posts?q=…&cursor=…` — page-1 (and SSR) entry
/// point. Subsequent pages should use [`load_more_posts`] so the
/// client can pass `seen_ids` for cross-page dedup.
pub async fn search_posts(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<PostSearchQuery>,
) -> Result<impl IntoResponse, AppError> {
    search_posts_core(&state, &user, q.q, q.cursor.as_deref(), &HashSet::new()).await
}

/// `POST /api/search/posts/more` — page-2+ entry point. Body carries
/// the query, the previous page's cursor, and `seen_ids` (capped at
/// [`super::MAX_SEEN_IDS`]) for cross-page dedup.
pub async fn load_more_posts(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(body): Json<MoreSearchRequest>,
) -> Result<impl IntoResponse, AppError> {
    validate_seen_ids(&body.seen_ids)?;
    let seen: HashSet<String> = body.seen_ids.into_iter().collect();
    search_posts_core(&state, &user, body.q, Some(body.cursor.as_str()), &seen).await
}

async fn search_posts_core(
    state: &Arc<AppState>,
    user: &AuthUser,
    q: Option<String>,
    cursor: Option<&str>,
    seen_ids: &HashSet<String>,
) -> Result<Json<PostSearchPageResponse>, AppError> {
    let raw = q.unwrap_or_default();
    let trimmed = raw.trim();
    let offset = decode_offset_cursor(cursor)?;

    if trimmed.is_empty() {
        return Ok(Json(PostSearchPageResponse {
            posts: Vec::new(),
            next_cursor: None,
        }));
    }
    validate_query_length(trimmed)?;

    let Some(fts_query) = build_fts_query(trimmed) else {
        return Ok(Json(PostSearchPageResponse {
            posts: Vec::new(),
            next_cursor: None,
        }));
    };

    let reader_uuid = user.uuid();
    let graph = state.get_trust_graph()?;
    let reader_delta = state.pending_deltas.get(reader_uuid);
    let trust_map = graph.distance_map_with_delta(reader_uuid, &reader_delta);
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;
    let tag_map = load_tag_map(&state.db, &user.user_id).await?;

    // Title-match set for the thread-title bump. FTS5 column-restricted
    // syntax: `{column} : (expr)` — quoting in case the column name
    // ever collides with a reserved word, and parenthesising the
    // sub-expression so multi-token queries are handled as a group.
    let title_only_fts_query = format!("{{title}} : ({fts_query})");
    let title_match_thread_ids: HashSet<String> = sqlx::query_scalar!(
        r#"SELECT t.id AS "id!"
           FROM threads_fts
           JOIN threads t ON t.rowid = threads_fts.rowid
           WHERE threads_fts MATCH ?
           LIMIT ?"#,
        title_only_fts_query,
        FTS_OVERSAMPLE,
    )
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .collect();

    // Body MATCH on posts_fts. The `posts_fts` table only holds rows
    // for non-retracted posts (the retraction trigger deletes them),
    // but we re-check `p.retracted_at IS NULL` defensively in case the
    // trigger ever falls behind during a bulk operation.
    // Body is pulled from `post_revisions` (latest revision) rather
    // than via `snippet(posts_fts, ...)`, which returns empty strings
    // on contentless FTS5 tables. The full body ships to the client
    // and renders through the shared Markdown component, preserving
    // the post's native formatting on the search results page.
    let rows = sqlx::query_as!(
        PostFtsRow,
        r#"SELECT p.id AS "id!",
                  p.thread AS "thread_id!",
                  t.title AS "thread_title!",
                  r.id AS "room_id!",
                  r.slug AS "room_slug!",
                  (r.slug = 'announcements') AS "is_announcement!: bool",
                  p.author AS "author_id!",
                  u.display_name AS "author_name!",
                  u.status AS "author_status!",
                  u.deleted_at AS "author_deleted_at?",
                  p.created_at AS "created_at!",
                  COALESCE(
                      (SELECT pr.body
                       FROM post_revisions pr
                       WHERE pr.post_id = p.id
                       ORDER BY pr.revision DESC
                       LIMIT 1),
                      ''
                  ) AS "body!: String",
                  (p.parent IS NULL) AS "is_op!: bool",
                  bm25(posts_fts) AS "bm25!: f64"
           FROM posts_fts
           JOIN posts p ON p.rowid = posts_fts.rowid
           JOIN threads t ON t.id = p.thread
           JOIN rooms r ON r.id = t.room
           JOIN users u ON u.id = p.author
           WHERE posts_fts MATCH ?
             AND p.retracted_at IS NULL
             AND r.merged_into IS NULL
             AND r.deleted_at IS NULL
           ORDER BY bm25(posts_fts)
           LIMIT ?"#,
        fts_query,
        FTS_OVERSAMPLE,
    )
    .fetch_all(&state.db)
    .await?;

    // Per-post visibility — deliberately tighter than `get_thread`'s
    // predicate. No announcement carve-out, no reply-visibility grant.
    // See `docs/search.md` §Visibility/Posts.
    let visible: Vec<PostFtsRow> = rows
        .into_iter()
        .filter(|row| {
            if row.author_id == user.user_id {
                return true;
            }
            if distrust_set.contains(&row.author_id) {
                return false;
            }
            reverse_map
                .get(&row.author_id)
                .is_some_and(|&s| s >= MINIMUM_TRUST_THRESHOLD)
        })
        .collect();

    // Recency rank uses the post's own `created_at`, not the
    // surrounding thread's `last_activity` — see spec.
    let mut by_recency: Vec<usize> = (0..visible.len()).collect();
    by_recency.sort_by(|&a, &b| visible[b].created_at.cmp(&visible[a].created_at));
    let mut recency_rank = vec![0usize; visible.len()];
    for (rank, idx) in by_recency.iter().enumerate() {
        recency_rank[*idx] = rank;
    }

    let mut scored: Vec<(usize, f64)> = visible
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let bm25_norm = 1.0 / (1.0 + (-row.bm25).max(0.0));
            // Posts use *reverse* trust (author → reader): the spec's
            // "reverse_trust_author" column. Self-trust = 1.0.
            let trust_author = if row.author_id == user.user_id {
                1.0
            } else {
                reverse_map.get(&row.author_id).copied().unwrap_or(0.0)
            };
            let r = recency_rank[i];
            let recency = 1.0 / (1.0 + (r as f64) / HALFLIFE_RANK);
            let title_bump = if title_match_thread_ids.contains(&row.thread_id) {
                TITLE_MATCH_BUMP
            } else {
                1.0
            };
            (
                i,
                bm25_norm * (ALPHA + (1.0 - ALPHA) * trust_author) * recency * title_bump,
            )
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

    // Drop slice rows already in the client's `seen_ids` (post-slice
    // safety net for cross-page duplicates introduced by candidate
    // pool drift). Cursor still advances by `PAGE_SIZE` regardless.
    let mut taken: Vec<Option<PostFtsRow>> = visible.into_iter().map(Some).collect();
    let mut hits: Vec<PostSearchHit> = Vec::with_capacity(page_indices.len());
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
        hits.push(PostSearchHit {
            id: row.id,
            thread_id: row.thread_id,
            thread_title: row.thread_title,
            room_id: row.room_id,
            room_slug: row.room_slug,
            is_announcement: row.is_announcement,
            author_id: row.author_id,
            author_name: row.author_name,
            created_at: row.created_at,
            body: row.body,
            is_op: row.is_op,
            viewer,
        });
    }

    let next_cursor = encode_offset_cursor(offset + PAGE_SIZE, total_visible);

    Ok(Json(PostSearchPageResponse {
        posts: hits,
        next_cursor,
    }))
}
