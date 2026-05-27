//! `GET /api/threads/by-link?url=…` — exact-link lookup for the
//! "suggest existing threads with the same URL" affordance on the
//! new-thread page.
//!
//! Semantics differ from `/api/search/threads?q=url:…`:
//!
//! - **Exact equality**, not BM25-fuzzy. A thread matches iff its
//!   `link_url_normalized` is byte-equal to the normalized form of the
//!   query URL. This is what dupe-detection wants — sharing a domain
//!   is not a dupe; sharing the exact link is.
//! - No scoring, no recency rank, no pagination. The handler returns
//!   at most [`MAX_SUGGESTIONS`] visible matches, ordered by recency
//!   (last activity descending). The call site is a suggestion panel,
//!   not a search results page.
//!
//! Normalization (scheme + leading `www.` stripped, host case-folded)
//! happens via [`normalize_url_for_fts`] — the same function that
//! populates `threads.link_url_normalized` at insert time, so the
//! query side and the index side always agree. As a result,
//! `https://www.example.com/x`, `http://example.com/x`, and
//! `https://Example.COM/x` all collapse to the same lookup key.
//!
//! Visibility is filtered through [`is_thread_visible`] using the
//! same reverse-trust / distrust-set / announcement-carveout rules as
//! `list_all_threads`, so a reader never sees a "this was already
//! posted" suggestion they wouldn't be able to read.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::session::AuthUser;
use crate::state::AppState;
use crate::trust::{UserStatus, UserViewerInfo, load_distrust_set, load_tag_map};

use super::common::{MAX_LINK_LEN, ThreadSummary, is_thread_visible, normalize_url_for_fts};

/// Cap returned suggestions. Five rows is more than enough context for
/// "is this a dupe?" and keeps the panel small.
const MAX_SUGGESTIONS: usize = 5;

/// Over-fetch factor: visibility filtering may drop some hits, so we
/// pull a few more candidates than we intend to return. A handful of
/// rows here is fine — the index lookup is cheap and the filter is
/// in-memory point lookups.
const FETCH_OVERSAMPLE: i64 = 20;

#[derive(Deserialize)]
pub struct ByLinkQuery {
    pub url: String,
}

#[derive(Serialize)]
pub struct ByLinkResponse {
    pub threads: Vec<ThreadSummary>,
}

/// Row shape for the link-equality SELECT. Mirrors the join used by
/// `list_all_threads` so the resulting `ThreadSummary` is identical to
/// what the room/all-threads listings emit.
struct ByLinkRow {
    id: String,
    title: String,
    author_id: String,
    author_name: String,
    author_public_key: Vec<u8>,
    author_status: String,
    author_deleted_at: Option<String>,
    created_at: String,
    room_id: String,
    room_slug: String,
    locked: bool,
    is_announcement: bool,
    reply_count: i64,
    last_activity: Option<String>,
    link_url: Option<String>,
}

/// `GET /api/threads/by-link?url=…`
///
/// Returns up to [`MAX_SUGGESTIONS`] threads whose normalized link
/// matches the normalized form of the supplied URL. Empty / malformed
/// / over-long URLs return an empty list rather than an error — the
/// suggestion panel is a hint, not a hard validator (the submit-side
/// `validate_link` is the source of truth for what's accepted as a
/// link post).
pub async fn get_threads_by_link(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<ByLinkQuery>,
) -> Result<Json<ByLinkResponse>, AppError> {
    let trimmed = params.url.trim();

    // Silently degrade on the trivial "no input" cases. The frontend
    // gates the call by `linkError === null && link.trim() !== ''`
    // already; this is defence-in-depth for direct API users.
    if trimmed.is_empty() || trimmed.len() > MAX_LINK_LEN {
        return Ok(Json(ByLinkResponse {
            threads: Vec::new(),
        }));
    }

    let normalized = normalize_url_for_fts(trimmed);
    if normalized.is_empty() {
        return Ok(Json(ByLinkResponse {
            threads: Vec::new(),
        }));
    }

    let reader_uuid = user.uuid();
    let graph = state.get_trust_graph()?;
    let reader_delta = state.pending_deltas.get(reader_uuid);
    let trust_map = graph.distance_map_with_delta(reader_uuid, &reader_delta);
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;
    let tag_map = load_tag_map(&state.db, &user.user_id).await?;

    // Exact-equality match on the normalized form. Same retracted-OP /
    // merged-room exclusions as the public listings — a thread the
    // user couldn't reach via /r/foo shouldn't surface here either.
    //
    // No viewer-specific reply counts: this is a small suggestion
    // panel, and the global `reply_count` is the same field the
    // listing rows use as a coarse "is there activity here?" signal.
    // Skipping the second `apply_visible_reply_counts` query is a
    // deliberate cost tradeoff.
    let rows = sqlx::query_as!(
        ByLinkRow,
        r#"SELECT t.id, t.title,
                  t.author AS author_id,
                  u.display_name AS author_name,
                  u.public_key AS author_public_key,
                  u.status AS author_status,
                  u.deleted_at AS author_deleted_at,
                  t.created_at,
                  r.id AS room_id,
                  r.slug AS room_slug,
                  t.locked AS "locked: bool",
                  (r.slug = 'announcements') AS "is_announcement!: bool",
                  t.reply_count,
                  t.last_activity,
                  t.link_url
           FROM threads t
           JOIN users u ON u.id = t.author
           JOIN rooms r ON r.id = t.room
           WHERE t.link_url_normalized = ?
             AND r.merged_into IS NULL
             AND NOT (t.reply_count = 0
                  AND (SELECT retracted_at FROM posts op WHERE op.thread = t.id AND op.parent IS NULL) IS NOT NULL)
           ORDER BY t.last_activity DESC NULLS LAST, t.created_at DESC, t.id DESC
           LIMIT ?"#,
        normalized,
        FETCH_OVERSAMPLE,
    )
    .fetch_all(&state.db)
    .await?;

    let threads: Vec<ThreadSummary> = rows
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
        .take(MAX_SUGGESTIONS)
        .map(|row| {
            let raw =
                UserStatus::try_from(row.author_status.as_str()).unwrap_or(UserStatus::Active);
            let status = UserStatus::effective(raw, row.author_deleted_at.as_deref());
            let viewer =
                UserViewerInfo::build(&row.author_id, &trust_map, &distrust_set, &tag_map, status);
            ThreadSummary {
                viewer,
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
            }
        })
        .collect();

    Ok(Json(ByLinkResponse { threads }))
}
