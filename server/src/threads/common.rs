use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::trust::TrustInfo;

pub const MIN_TITLE_LEN: usize = 5;
pub const MAX_TITLE_LEN: usize = 150;
pub const MAX_BODY_LEN: usize = 50_000;
pub const MAX_REPLY_BODY_LEN: usize = 10_000;
pub const PAGE_SIZE: usize = 20;

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

/// Sort mode for thread listings and thread detail.
///
/// Trust-windowed modes filter to threads with activity within the window,
/// then sort by the reader's forward trust distance to the OP author
/// (closest first). `New` sorts by last activity descending.
#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
pub enum ThreadSort {
    #[serde(rename = "new")]
    New,
    #[serde(rename = "trust_24h")]
    Trust24h,
    #[default]
    #[serde(rename = "trust_7d")]
    Trust7d,
    #[serde(rename = "trust_30d")]
    Trust30d,
    #[serde(rename = "trust_1y")]
    Trust1y,
    #[serde(rename = "trust_all")]
    TrustAll,
}

impl ThreadSort {
    /// Returns the activity window as a chrono::Duration, or None for
    /// `TrustAll` and `New` (no time filter).
    pub fn window(self) -> Option<chrono::Duration> {
        match self {
            Self::Trust24h => Some(chrono::Duration::hours(24)),
            Self::Trust7d => Some(chrono::Duration::days(7)),
            Self::Trust30d => Some(chrono::Duration::days(30)),
            Self::Trust1y => Some(chrono::Duration::days(365)),
            Self::TrustAll | Self::New => None,
        }
    }

    pub fn is_trust(self) -> bool {
        !matches!(self, Self::New)
    }
}

#[derive(Deserialize)]
pub struct PaginationParams {
    pub cursor: Option<String>,
    #[serde(default)]
    pub sort: ThreadSort,
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

/// Parse a cursor string into (timestamp, id).
///
/// Cursors encode the last-seen sort key so the next page starts after it.
/// Format: `<ISO timestamp>|<UUID>`.
pub fn parse_cursor(cursor: &str) -> Result<(String, String), AppError> {
    let (ts, id) = cursor
        .split_once('|')
        .ok_or_else(|| AppError::BadRequest("invalid cursor".into()))?;
    let _: chrono::NaiveDateTime = ts
        .parse()
        .map_err(|_| AppError::BadRequest("invalid cursor".into()))?;
    let _: uuid::Uuid = id
        .parse()
        .map_err(|_| AppError::BadRequest("invalid cursor".into()))?;
    Ok((ts.to_string(), id.to_string()))
}

/// Build a cursor string from a thread summary.
pub fn make_cursor(thread: &ThreadSummary) -> String {
    let ts = thread
        .last_activity
        .as_deref()
        .unwrap_or(&thread.created_at);
    format!("{}|{}", ts, thread.id)
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

/// Sort a thread list in-place by the reader's forward trust distance to
/// the OP author (closest first), with last_activity descending as tiebreaker.
pub fn sort_threads_by_trust(threads: &mut [ThreadSummary], trust_map: &HashMap<String, f64>) {
    threads.sort_by(|a, b| {
        let da = trust_map.get(&a.author_id).copied().unwrap_or(f64::MAX);
        let db = trust_map.get(&b.author_id).copied().unwrap_or(f64::MAX);
        da.partial_cmp(&db)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                let ta = a.last_activity.as_deref().unwrap_or(&a.created_at);
                let tb = b.last_activity.as_deref().unwrap_or(&b.created_at);
                tb.cmp(ta)
            })
    });
}

/// Compute the cutoff timestamp string for a trust-window sort mode.
pub fn window_cutoff(sort: ThreadSort) -> Option<String> {
    sort.window().map(|dur| {
        let cutoff = chrono::Utc::now().naive_utc() - dur;
        cutoff.format("%Y-%m-%d %H:%M:%S").to_string()
    })
}

/// Sorted list of (author_id, distance) from the trust map, closest first.
pub fn ranked_authors(trust_map: &HashMap<String, f64>) -> Vec<(&str, f64)> {
    let mut authors: Vec<(&str, f64)> = trust_map.iter().map(|(id, &d)| (id.as_str(), d)).collect();
    authors.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    authors
}
