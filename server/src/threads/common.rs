use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, ErrorCode};
use crate::trust::TrustInfo;

pub const MIN_TITLE_LEN: usize = 5;
pub const MAX_TITLE_LEN: usize = 150;
pub const MAX_BODY_LEN: usize = 50_000;
pub const MAX_REPLY_BODY_LEN: usize = 10_000;
pub const PAGE_SIZE: usize = 20;

/// Maximum number of recent repliers stored per thread for warm sort scoring.
pub const RECENT_REPLIERS_BUFFER: i64 = 50;

/// Maximum number of seen IDs the client may send for warm/trusted pagination.
/// Requests exceeding this are rejected with 400.
pub const MAX_SEEN_IDS: usize = 200;

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

/// Sort mode for thread listings.
///
/// - `Warm` (default): rank-based decay × trust signal from visible repliers.
/// - `New`: thread creation time descending. Cursor-paginable.
/// - `Active`: last reply time descending. Cursor-paginable.
///   TODO: Currently uses global last_activity (all replies). Consider
///   viewer-specific activity, but that would break cursor pagination.
/// - `Trusted`: OP trust with rank-based decay.
#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
pub enum ThreadSort {
    #[default]
    #[serde(rename = "warm")]
    Warm,
    #[serde(rename = "new")]
    New,
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "trusted")]
    Trusted,
}

#[derive(Deserialize)]
pub struct PaginationParams {
    pub cursor: Option<String>,
    #[serde(default)]
    pub sort: ThreadSort,
}

/// Request body for warm/trusted paginated "load more" (POST endpoints).
#[derive(Deserialize)]
pub struct WarmPaginationRequest {
    pub cursor: String,
    #[serde(default)]
    pub seen_ids: Vec<String>,
}

/// Parsed warm/trusted cursor with pagination state.
///
/// Format: `<sort>:<last_activity>|<thread_id>:<visibility_rate>:<rank_offset>`
/// Example: `warm:2024-01-15T10:30:00|a1b2c3d4-e5f6-7890-abcd-ef1234567890:0.05:20`
pub struct WarmCursor {
    pub sort: ThreadSort,
    pub last_activity: String,
    pub thread_id: String,
    pub visibility_rate: f64,
    pub rank_offset: usize,
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
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub has_more_children: bool,
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
    pub total_reply_count: i64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub has_more_replies: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focused_post_id: Option<String>,
}

/// Response for the subtree expansion endpoint.
#[derive(Serialize)]
pub struct SubtreeResponse {
    pub post: PostResponse,
}

/// Response for top-level replies pagination.
#[derive(Serialize)]
pub struct RepliesPageResponse {
    pub replies: Vec<PostResponse>,
    pub has_more: bool,
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

pub fn validate_title(title: &str) -> Result<String, String> {
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
// Shared helpers
// ---------------------------------------------------------------------------

/// Parse a simple cursor string into (timestamp, id).
///
/// Used by `new` and `active` sorts. Format: `<ISO timestamp>|<UUID>`.
pub fn parse_cursor(cursor: &str) -> Result<(String, String), AppError> {
    let (ts, id) = cursor
        .split_once('|')
        .ok_or_else(|| AppError::code(ErrorCode::InvalidCursor))?;
    // Strip trailing 'Z' (UTC indicator) for NaiveDateTime validation;
    // the original timestamp string is preserved for SQL comparisons.
    let ts_clean = ts.strip_suffix('Z').unwrap_or(ts);
    let _: chrono::NaiveDateTime = ts_clean
        .parse()
        .map_err(|_| AppError::code(ErrorCode::InvalidCursor))?;
    let _: uuid::Uuid = id
        .parse()
        .map_err(|_| AppError::code(ErrorCode::InvalidCursor))?;
    Ok((ts.to_string(), id.to_string()))
}

/// Parse a warm/trusted pagination cursor.
///
/// Format: `<sort>:<last_activity>|<thread_id>:<visibility_rate>:<rank_offset>`
pub fn parse_warm_cursor(cursor: &str) -> Result<WarmCursor, AppError> {
    let bad = || AppError::code(ErrorCode::InvalidCursor);

    // Split on first ':' to get sort prefix
    let (sort_str, rest) = cursor.split_once(':').ok_or_else(bad)?;
    let sort = match sort_str {
        "warm" => ThreadSort::Warm,
        "trusted" => ThreadSort::Trusted,
        _ => return Err(bad()),
    };

    // Remaining format: <timestamp>|<uuid>:<visibility_rate>:<rank_offset>
    // The timestamp may contain colons (ISO 8601), so split from the right
    // to extract rank_offset and visibility_rate first.
    let (rest, rank_offset_str) = rest.rsplit_once(':').ok_or_else(bad)?;
    let (rest, rate_str) = rest.rsplit_once(':').ok_or_else(bad)?;

    // Now `rest` is `<timestamp>|<uuid>`
    let (ts, thread_id) = rest.rsplit_once('|').ok_or_else(bad)?;

    // Timestamps may have a trailing 'Z' (UTC indicator) which NaiveDateTime
    // doesn't accept — strip it before validation.
    let ts_clean = ts.strip_suffix('Z').unwrap_or(ts);
    let _: chrono::NaiveDateTime = ts_clean.parse().map_err(|_| bad())?;
    let _: uuid::Uuid = thread_id.parse().map_err(|_| bad())?;
    let visibility_rate: f64 = rate_str.parse().map_err(|_| bad())?;
    let rank_offset: usize = rank_offset_str.parse().map_err(|_| bad())?;

    if !(0.0..=1.0).contains(&visibility_rate) {
        return Err(bad());
    }

    Ok(WarmCursor {
        sort,
        last_activity: ts.to_string(),
        thread_id: thread_id.to_string(),
        visibility_rate,
        rank_offset,
    })
}

/// Build a warm/trusted pagination cursor string.
pub fn make_warm_cursor(
    sort: ThreadSort,
    last_activity: &str,
    thread_id: &str,
    visibility_rate: f64,
    rank_offset: usize,
) -> String {
    let prefix = match sort {
        ThreadSort::Warm => "warm",
        ThreadSort::Trusted => "trusted",
        _ => "warm",
    };
    format!("{prefix}:{last_activity}|{thread_id}:{visibility_rate}:{rank_offset}")
}

/// Build a cursor string from a thread summary using last_activity.
pub fn make_cursor(thread: &ThreadSummary) -> String {
    let ts = thread
        .last_activity
        .as_deref()
        .unwrap_or(&thread.created_at);
    format!("{}|{}", ts, thread.id)
}

/// Build a cursor string from a thread summary using created_at.
pub fn make_cursor_created_at(thread: &ThreadSummary) -> String {
    format!("{}|{}", thread.created_at, thread.id)
}

/// Check whether a thread is visible to the reader in a listing.
///
/// A thread (represented by its OP) is visible if any of the following hold:
/// 1. The reader is the thread author.
/// 2. The thread is in a public room.
/// 3. The author's trust-in-reader (reverse score) meets `MINIMUM_TRUST_THRESHOLD`.
pub fn is_thread_visible(
    author_id: &str,
    room_public: bool,
    reader_id: &str,
    reverse_map: &HashMap<String, f64>,
) -> bool {
    use crate::trust::MINIMUM_TRUST_THRESHOLD;

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
pub fn sql_placeholders(n: usize) -> String {
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
// Warm sort scoring
// ---------------------------------------------------------------------------

/// OP trust weight in the warm score formula. Replier trust dominates.
const WARM_BETA: f64 = 0.3;

/// Thread rank at which thread_decay reaches 0.5.
const WARM_HALFLIFE_RANK: f64 = 12.0;

/// Reply rank (among visible replies) at which reply_decay reaches 0.5.
const WARM_HALFLIFE_REPLY_RANK: f64 = 10.0;

/// `thread_decay(rank) = 1 / (1 + rank / halflife_rank)`
fn thread_decay(rank: usize) -> f64 {
    1.0 / (1.0 + rank as f64 / WARM_HALFLIFE_RANK)
}

/// `reply_decay(reply_rank) = 1 / (1 + reply_rank / halflife_reply_rank)`
fn reply_decay(reply_rank: usize) -> f64 {
    1.0 / (1.0 + reply_rank as f64 / WARM_HALFLIFE_REPLY_RANK)
}

/// Replier entry from the denormalized `thread_recent_repliers` table.
pub struct RecentReplier {
    pub thread_id: String,
    pub replier_id: String,
    pub replied_at: String,
}

/// Compute warm scores for candidate threads given their replier data.
///
/// Returns threads sorted by warm score descending, truncated to `PAGE_SIZE`.
/// The `trust_map` is the viewer's forward trust (viewer → authors).
/// The `reverse_map` is reverse trust (authors → viewer), used for visibility.
///
/// `rank_offset` shifts the starting rank for `thread_decay`, ensuring smooth
/// decay continuity across pages (page 1 uses 0, page 2 uses PAGE_SIZE, etc.).
pub fn score_warm(
    threads: &mut Vec<ThreadSummary>,
    repliers: &[RecentReplier],
    trust_map: &HashMap<String, f64>,
    reverse_map: &HashMap<String, f64>,
    reader_id: &str,
    rank_offset: usize,
) {
    use crate::trust::MINIMUM_TRUST_THRESHOLD;
    use std::collections::HashMap as Map;

    let mut repliers_by_thread: Map<&str, Vec<&RecentReplier>> = Map::new();
    for r in repliers {
        repliers_by_thread
            .entry(r.thread_id.as_str())
            .or_default()
            .push(r);
    }

    struct ScoredThread {
        viewer_last_activity: Option<String>,
        trust_signal: f64,
    }

    let mut scored: Map<String, ScoredThread> = Map::new();

    for thread in threads.iter() {
        let mut best_signal: f64 = 0.0;
        let mut viewer_last_activity: Option<String> = None;
        let mut visible_rank: usize = 0;

        if let Some(thread_repliers) = repliers_by_thread.get(thread.id.as_str()) {
            for r in thread_repliers {
                let is_visible = r.replier_id == reader_id
                    || reverse_map
                        .get(&r.replier_id)
                        .is_some_and(|&s| s >= MINIMUM_TRUST_THRESHOLD);
                if !is_visible {
                    continue;
                }

                if viewer_last_activity.is_none() {
                    viewer_last_activity = Some(r.replied_at.clone());
                }

                // Self-trust: the viewer's own replies are max trust (1.0), so
                // threads you're participating in get a warm boost.
                let fwd_trust = if r.replier_id == reader_id {
                    1.0
                } else {
                    trust_map.get(&r.replier_id).copied().unwrap_or(0.0)
                };
                let signal = fwd_trust * reply_decay(visible_rank);
                if signal > best_signal {
                    best_signal = signal;
                }
                visible_rank += 1;
            }
        }

        scored.insert(
            thread.id.clone(),
            ScoredThread {
                viewer_last_activity,
                trust_signal: best_signal,
            },
        );
    }

    threads.sort_by(|a, b| {
        let sa = scored.get(a.id.as_str());
        let sb = scored.get(b.id.as_str());
        let la = sa.and_then(|s| s.viewer_last_activity.as_deref());
        let lb = sb.and_then(|s| s.viewer_last_activity.as_deref());
        let fallback_a = a.last_activity.as_deref().unwrap_or(&a.created_at);
        let fallback_b = b.last_activity.as_deref().unwrap_or(&b.created_at);
        let ta = la.unwrap_or(fallback_a);
        let tb = lb.unwrap_or(fallback_b);
        tb.cmp(ta)
    });

    let mut warm_scores: Vec<(usize, f64)> = Vec::with_capacity(threads.len());
    for (i, thread) in threads.iter().enumerate() {
        let rank = rank_offset + i;
        let s = scored.get(thread.id.as_str());
        let trust_signal = s.map(|s| s.trust_signal).unwrap_or(0.0);
        // Self-trust: your own threads are treated as max OP trust.
        let trust_op = if thread.author_id == reader_id {
            1.0
        } else {
            trust_map.get(&thread.author_id).copied().unwrap_or(0.0)
        };
        let score = thread_decay(rank) * (WARM_BETA * trust_op + (1.0 - WARM_BETA) * trust_signal);
        warm_scores.push((i, score));
    }

    warm_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let top_indices: Vec<usize> = warm_scores
        .into_iter()
        .take(PAGE_SIZE)
        .map(|(idx, _)| idx)
        .collect();

    let mut old: Vec<Option<ThreadSummary>> = threads.drain(..).map(Some).collect();
    for idx in top_indices {
        if let Some(thread) = old[idx].take() {
            threads.push(thread);
        }
    }
}

/// Score threads by rank-based decay × OP trust only (no replier signal).
///
/// Used by the "Trusted + Recent" sort. Threads are first ranked by
/// `last_activity` descending (establishing positional rank), then scored
/// as `thread_decay(rank) × trust_op`. Self-trust: the viewer's own
/// threads are treated as trust 1.0.
///
/// `rank_offset` shifts the starting rank for `thread_decay`, ensuring smooth
/// decay continuity across pages (page 1 uses 0, page 2 uses PAGE_SIZE, etc.).
///
/// Returns threads sorted by score descending, truncated to `PAGE_SIZE`.
pub fn score_trusted_recent(
    threads: &mut Vec<ThreadSummary>,
    trust_map: &HashMap<String, f64>,
    reader_id: &str,
    rank_offset: usize,
) {
    threads.sort_by(|a, b| {
        let ta = a.last_activity.as_deref().unwrap_or(&a.created_at);
        let tb = b.last_activity.as_deref().unwrap_or(&b.created_at);
        tb.cmp(ta)
    });

    let mut scores: Vec<(usize, f64)> = Vec::with_capacity(threads.len());
    for (i, thread) in threads.iter().enumerate() {
        let rank = rank_offset + i;
        // Self-trust: your own threads are treated as max OP trust.
        let trust_op = if thread.author_id == reader_id {
            1.0
        } else {
            trust_map.get(&thread.author_id).copied().unwrap_or(0.0)
        };
        scores.push((i, thread_decay(rank) * trust_op));
    }

    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let top_indices: Vec<usize> = scores
        .into_iter()
        .take(PAGE_SIZE)
        .map(|(idx, _)| idx)
        .collect();

    let mut old: Vec<Option<ThreadSummary>> = threads.drain(..).map(Some).collect();
    for idx in top_indices {
        if let Some(thread) = old[idx].take() {
            threads.push(thread);
        }
    }
}
