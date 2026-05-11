//! Cross-cutting search across rooms, users, threads, and posts.
//!
//! Two surfaces:
//!
//! - `dropdown` — `GET /api/search`, the sectioned autocomplete in the
//!   top nav. Returns up to three rooms / users / threads in a single
//!   round-trip. Posts are intentionally excluded for cost reasons.
//! - Per-kind paginated endpoints powering the `/search` results page:
//!   - `GET /api/search/threads` and `GET /api/search/posts` — FTS5-backed,
//!     live in this module's `threads` and `posts` submodules.
//!   - `GET /api/search/rooms` and `GET /api/search/users` — plain SQL
//!     `LIKE` filtering, live in their respective domain modules
//!     (`crate::rooms`, `crate::users`) so all room/user-handling code
//!     stays co-located.
//!
//! Visibility filtering reuses the same trust primitives as
//! `list_threads.rs` and `users.rs`. See `docs/search.md` for the
//! design rationale.

pub mod dropdown;
pub mod posts;
pub mod threads;

pub use dropdown::search_dropdown;
pub use posts::{load_more_posts, search_posts};
pub use threads::{load_more_threads, search_threads_paginated};

use serde::Deserialize;

use crate::error::{AppError, ErrorCode};

// ---------------------------------------------------------------------------
// Tunables — shared across dropdown and per-kind paginated endpoints.
// ---------------------------------------------------------------------------

// Tuning note (`docs/search.md` §Implementation order step 7): ALPHA,
// HALFLIFE_RANK, and the per-endpoint BM25 column weights are first
// guesses chosen from the spec. They should be re-checked against real
// query traffic once the search surface has been live long enough to
// produce signal — there is no point tweaking them in the dark. A
// `prefix='2 3'` index on `posts_fts` was also considered but deferred:
// post search lives only on the explicit `/search` page (not as-you-
// type), so the storage cost would not pay for itself today.

/// Soft trust weighting in the *ranking* formula. Visibility is gated
/// separately by the reverse-trust filter (`is_thread_visible` for
/// threads, an inline reverse-trust check for posts) — so by the time
/// ALPHA is applied every candidate is already an author who trusts
/// the reader. ALPHA controls how much *forward* trust (reader →
/// author) influences the order among those visible candidates: with
/// `ALPHA = 0.2`, an author the reader has not yet built forward
/// trust toward gets a 0.2× ranking factor instead of 0×, so they
/// still surface but trusted authors outrank them. See
/// `docs/search.md` for the chosen value.
pub(crate) const ALPHA: f64 = 0.2;

/// Rank at which `recency_decay` reaches 0.5 — mirrors `score_warm`'s
/// `WARM_HALFLIFE_RANK` so the same self-calibrating shape applies to
/// search.
pub(crate) const HALFLIFE_RANK: f64 = 12.0;

/// FTS oversample for the paginated `/search/threads` and
/// `/search/posts` endpoints. Visibility filtering happens after this
/// slice is fetched, so the visible count is typically lower.
pub(crate) const FTS_OVERSAMPLE: i64 = 200;

/// Substring oversample for the paginated `/search/users` and
/// `/search/rooms` endpoints. Same role as `FTS_OVERSAMPLE` but for
/// the `LIKE`-based candidate queries.
pub(crate) const SUBSTRING_OVERSAMPLE: i64 = 200;

/// Page size for paginated search endpoints.
pub(crate) const PAGE_SIZE: usize = 20;

/// Maximum offset accepted in a cursor. Bounds the work the client can
/// request — the candidate pool itself is at most `FTS_OVERSAMPLE` rows
/// (typically less after visibility filtering), so any cursor past
/// `FTS_OVERSAMPLE` is guaranteed to be empty.
pub(crate) const MAX_CURSOR_OFFSET: usize = FTS_OVERSAMPLE as usize;

/// Maximum length (in bytes) of a search query. Defence-in-depth
/// against pathological inputs — well beyond any plausible legitimate
/// query but short enough to keep tokenisation, FTS5 parsing, and
/// `LIKE` pattern construction bounded. Counted in bytes (not chars)
/// so the cap matches what the database / FTS5 actually processes.
pub(crate) const MAX_QUERY_LENGTH: usize = 256;

/// Maximum number of seen IDs the client may send when loading more
/// search results via the POST `/more` endpoints. Matched to
/// [`FTS_OVERSAMPLE`] / [`SUBSTRING_OVERSAMPLE`]: the candidate pool is
/// at most that wide, so a larger seen-set carries no extra signal
/// while still costing memory + parsing. Mirrors
/// [`crate::threads::MAX_SEEN_IDS`].
pub(crate) const MAX_SEEN_IDS: usize = FTS_OVERSAMPLE as usize;

/// POST body for paginated search "load more" endpoints. Mirrors the
/// shape of [`crate::threads::WarmPaginationRequest`] (cursor +
/// `seen_ids`) but also carries the query, since search has no
/// per-thread implicit context the way warm thread pagination does.
#[derive(Deserialize)]
pub struct MoreSearchRequest {
    /// The search query — same field as the GET `?q=` param. Optional
    /// only because all five `q` fields share `Option<String>` for
    /// uniform empty-query handling; in practice the client always
    /// sends it.
    #[serde(default)]
    pub q: Option<String>,
    /// Opaque integer offset cursor returned in the previous page's
    /// response. Required for "load more" — page 1 uses GET.
    pub cursor: String,
    /// IDs the client has already rendered. Capped at [`MAX_SEEN_IDS`].
    /// Applied as a *post-slice* safety net: the cursor still advances
    /// by `PAGE_SIZE` per page, and any row in the slice that the
    /// client has already seen is dropped before materialising the
    /// response. This catches duplicates introduced by candidate-pool
    /// drift (new posts indexed, trust changes) between pages without
    /// changing the cursor semantics.
    #[serde(default)]
    pub seen_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Cursor: opaque integer offset within the candidate pool.
// ---------------------------------------------------------------------------

/// Decode a cursor string to an integer offset within the candidate
/// pool. Empty / `None` cursors decode to `0`. Rejects non-numeric or
/// out-of-range values with a 400.
pub(crate) fn decode_offset_cursor(cursor: Option<&str>) -> Result<usize, AppError> {
    let Some(c) = cursor.map(str::trim).filter(|c| !c.is_empty()) else {
        return Ok(0);
    };
    let n: usize = c
        .parse()
        .map_err(|_| AppError::with_message(ErrorCode::BadRequest, "invalid cursor"))?;
    if n > MAX_CURSOR_OFFSET {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "cursor out of range",
        ));
    }
    Ok(n)
}

/// Encode the next-page cursor, or `None` when there are no more
/// pages. `next_offset` is the absolute offset of the first row of the
/// next page within the visibility-filtered candidate pool.
pub(crate) fn encode_offset_cursor(next_offset: usize, total_visible: usize) -> Option<String> {
    if next_offset >= total_visible || next_offset >= MAX_CURSOR_OFFSET {
        None
    } else {
        Some(next_offset.to_string())
    }
}

/// Reject "load more" requests whose `seen_ids` exceeds
/// [`MAX_SEEN_IDS`] with a 400. Mirrors the equivalent guard in
/// `crate::threads::list_threads`.
pub(crate) fn validate_seen_ids(seen_ids: &[String]) -> Result<(), AppError> {
    if seen_ids.len() > MAX_SEEN_IDS {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            format!("seen_ids exceeds maximum of {MAX_SEEN_IDS}"),
        ));
    }
    Ok(())
}

/// Reject queries longer than [`MAX_QUERY_LENGTH`] bytes with a 400.
/// Call after trimming, before tokenisation / pattern construction —
/// every search entry point shares this cap so a single oversized
/// query can't make it through any handler.
pub(crate) fn validate_query_length(trimmed: &str) -> Result<(), AppError> {
    if trimmed.len() > MAX_QUERY_LENGTH {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            "query too long",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// FTS / LIKE input sanitisation.
// ---------------------------------------------------------------------------

/// Escape a string for SQLite `LIKE ... ESCAPE '\'` patterns.
pub(crate) fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// One parsed clause produced by [`build_fts_query_with_fields`]: an
/// optional column filter plus the list of sub-tokens that make up the
/// clause body. Empty `terms` means the clause carried no usable
/// content and is dropped before rendering.
struct Clause<'a> {
    /// FTS5 column name if the user wrote `<alias>:term` with a known
    /// alias; `None` for unscoped (free) text.
    column: Option<&'a str>,
    /// Already-sub-split, non-empty tokens to emit inside this clause.
    terms: Vec<String>,
}

/// Split a single content chunk on non-alphanumeric chars (keeping
/// `'` and `-` which legitimately occur inside words like `don't` and
/// `state-of-the-art`). Empty pieces are dropped.
fn sub_split(s: &str) -> Vec<String> {
    s.split(|c: char| !(c.is_alphanumeric() || c == '\'' || c == '-'))
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

/// Render one sub-token. Last-term-of-last-clause gets the FTS5
/// prefix marker `*` (only valid as a bareword on ASCII-alphanumeric
/// tokens); everything else is quoted so FTS5 metacharacters can't
/// escape into the parser.
fn render_term(term: &str, is_query_tail: bool) -> String {
    if is_query_tail && term.chars().all(|c| c.is_ascii_alphanumeric()) {
        format!("{term}*")
    } else {
        let escaped = term.replace('"', "\"\"");
        format!("\"{escaped}\"")
    }
}

/// Build an FTS5 MATCH expression from raw user input.
///
/// Convenience wrapper for callers that don't expose `field:term`
/// syntax (e.g. `posts_fts`, which indexes a single column). All input
/// is treated as free text.
pub(crate) fn build_fts_query(input: &str) -> Option<String> {
    build_fts_query_with_fields(input, &[])
}

/// Build an FTS5 MATCH expression from raw user input, with optional
/// `field:term` column-filter support.
///
/// Whitespace separates clauses. Within each clause:
///
/// - If the chunk starts with `<alias>:` where `<alias>` matches one of
///   `allowed_fields` (case-sensitive), the rest becomes a column-
///   filtered clause against the mapped FTS5 column. Example with
///   `allowed_fields = [("title", "title"), ("url", "link_url")]`:
///   `url:github axum` → `link_url:(github) axum*`.
/// - Otherwise the chunk is treated as free text and sub-split on
///   non-alphanumeric characters (preserving `'` and `-`).
///
/// The very last sub-token of the very last non-empty clause gets the
/// FTS5 prefix marker `*` (and only if it's ASCII alphanumeric, since
/// the bareword + `*` form is the only one FTS5 accepts as a prefix
/// expression). Everything else is quoted to neutralise FTS5
/// metacharacters.
///
/// Returns `None` when no usable tokens survive sub-splitting — empty
/// input, all-punctuation, or `field:!!!` where the term yields zero
/// sub-tokens.
pub(crate) fn build_fts_query_with_fields(
    input: &str,
    allowed_fields: &[(&str, &str)],
) -> Option<String> {
    let mut clauses: Vec<Clause<'_>> = Vec::new();

    for chunk in input.split_whitespace() {
        // Try to interpret the chunk as a `field:term` filter. We only
        // commit to that interpretation if the alias is in the
        // allow-list — otherwise stray colons (e.g. in pasted URLs)
        // would be silently dropped by `sub_split`, which is the
        // correct fallback.
        let parsed: Option<(&str, &str)> = chunk.split_once(':').and_then(|(alias, rest)| {
            if alias.is_empty() || rest.is_empty() {
                return None;
            }
            allowed_fields
                .iter()
                .find(|(a, _)| *a == alias)
                .map(|(_, col)| (*col, rest))
        });

        let (column, body) = match parsed {
            Some((col, rest)) => (Some(col), rest),
            None => (None, chunk),
        };

        let terms = sub_split(body);
        if terms.is_empty() {
            continue;
        }
        clauses.push(Clause { column, terms });
    }

    if clauses.is_empty() {
        return None;
    }

    let last_clause_idx = clauses.len() - 1;
    let mut parts: Vec<String> = Vec::with_capacity(clauses.len());

    for (ci, clause) in clauses.iter().enumerate() {
        let last_term_idx = clause.terms.len() - 1;
        let mut term_strs: Vec<String> = Vec::with_capacity(clause.terms.len());
        for (ti, term) in clause.terms.iter().enumerate() {
            let is_query_tail = ci == last_clause_idx && ti == last_term_idx;
            term_strs.push(render_term(term, is_query_tail));
        }
        let joined = term_strs.join(" ");
        if let Some(col) = clause.column {
            // Always parenthesise the column-filtered body: FTS5 only
            // accepts a *phrase* directly after `col:`, not arbitrary
            // expressions (prefix queries, multi-term groups). Parens
            // let us reuse the same render for single and multi-term
            // cases.
            parts.push(format!("{col}:({joined})"));
        } else {
            parts.push(joined);
        }
    }

    Some(parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Threads' field-filter aliases, mirrored from
    /// `crate::search::threads`. Defined here so the tests don't have
    /// to reach into the submodule.
    const TEST_THREAD_FIELDS: &[(&str, &str)] =
        &[("title", "title"), ("body", "op_body"), ("url", "link_url")];

    #[test]
    fn fts_query_empty() {
        assert_eq!(build_fts_query(""), None);
        assert_eq!(build_fts_query("   "), None);
        assert_eq!(build_fts_query("\"\""), None);
    }

    #[test]
    fn fts_query_single_token_prefix() {
        assert_eq!(build_fts_query("trust"), Some("trust*".to_string()));
    }

    #[test]
    fn fts_query_multi_token() {
        assert_eq!(
            build_fts_query("trust decay"),
            Some("\"trust\" decay*".to_string())
        );
    }

    #[test]
    fn fts_query_strips_punctuation() {
        assert_eq!(
            build_fts_query("hello, world!"),
            Some("\"hello\" world*".to_string())
        );
    }

    #[test]
    fn fts_query_quotes_non_ascii_last_token() {
        // Non-ASCII word: cannot use bareword prefix form.
        let out = build_fts_query("café").unwrap();
        assert!(out.starts_with('\"') && out.ends_with('\"'));
    }

    #[test]
    fn fts_query_sub_splits_url_like_token() {
        // Pasted URL splits on non-alphanumeric so each path segment
        // becomes its own searchable token. The previous char-strip
        // implementation would have produced one merged blob like
        // `httpsfoobarcom` — useless against the new FTS index.
        assert_eq!(
            build_fts_query("https://foo.bar/baz"),
            Some("\"https\" \"foo\" \"bar\" baz*".to_string())
        );
    }

    #[test]
    fn fts_query_field_single_term() {
        assert_eq!(
            build_fts_query_with_fields("url:github", TEST_THREAD_FIELDS),
            Some("link_url:(github*)".to_string())
        );
    }

    #[test]
    fn fts_query_field_term_with_free_term() {
        // `url:github` is a sealed clause; `axum` is the as-you-type
        // tail and gets the prefix marker.
        assert_eq!(
            build_fts_query_with_fields("url:github axum", TEST_THREAD_FIELDS),
            Some("link_url:(\"github\") axum*".to_string())
        );
    }

    #[test]
    fn fts_query_field_multi_term_uses_parens() {
        // A pasted dotted URL after `url:` becomes multiple sub-tokens
        // — they share the column filter via FTS5's `col:(...)` form.
        assert_eq!(
            build_fts_query_with_fields("url:github.com/anthropics", TEST_THREAD_FIELDS),
            Some("link_url:(\"github\" \"com\" anthropics*)".to_string())
        );
    }

    #[test]
    fn fts_query_unknown_field_falls_back_to_text() {
        // `weird:` isn't in the allow-list; the colon is just
        // punctuation and the chunk sub-splits like any other.
        assert_eq!(
            build_fts_query_with_fields("weird:thing", TEST_THREAD_FIELDS),
            Some("\"weird\" thing*".to_string())
        );
    }

    #[test]
    fn fts_query_field_alias_maps_to_column() {
        // `body` aliases to `op_body` (the actual FTS5 column).
        assert_eq!(
            build_fts_query_with_fields("body:hello", TEST_THREAD_FIELDS),
            Some("op_body:(hello*)".to_string())
        );
    }

    #[test]
    fn fts_query_empty_field_value_drops_clause() {
        // `url:` with no body, or with only punctuation, produces zero
        // sub-tokens and is dropped. The remaining clause carries on.
        assert_eq!(
            build_fts_query_with_fields("url:!!! github", TEST_THREAD_FIELDS),
            Some("github*".to_string())
        );
    }

    #[test]
    fn fts_query_no_allowed_fields_treats_colon_as_punctuation() {
        // Backstop for posts search and other callers that pass an
        // empty allow-list.
        assert_eq!(
            build_fts_query_with_fields("body:foo bar", &[]),
            Some("\"body\" \"foo\" bar*".to_string())
        );
    }

    #[test]
    fn cursor_decode_empty() {
        assert_eq!(decode_offset_cursor(None).unwrap(), 0);
        assert_eq!(decode_offset_cursor(Some("")).unwrap(), 0);
        assert_eq!(decode_offset_cursor(Some("   ")).unwrap(), 0);
    }

    #[test]
    fn cursor_decode_valid() {
        assert_eq!(decode_offset_cursor(Some("0")).unwrap(), 0);
        assert_eq!(decode_offset_cursor(Some("20")).unwrap(), 20);
        assert_eq!(
            decode_offset_cursor(Some(&MAX_CURSOR_OFFSET.to_string())).unwrap(),
            MAX_CURSOR_OFFSET
        );
    }

    #[test]
    fn cursor_decode_rejects_invalid() {
        assert!(decode_offset_cursor(Some("abc")).is_err());
        assert!(decode_offset_cursor(Some("-1")).is_err());
        assert!(decode_offset_cursor(Some(&(MAX_CURSOR_OFFSET + 1).to_string())).is_err());
    }

    #[test]
    fn cursor_encode_terminates() {
        // Last page: next_offset == total_visible → no cursor.
        assert_eq!(encode_offset_cursor(40, 40), None);
        // Mid-pool: more rows available.
        assert_eq!(encode_offset_cursor(20, 40), Some("20".to_string()));
        // At the cap: no further pages.
        assert_eq!(
            encode_offset_cursor(MAX_CURSOR_OFFSET, MAX_CURSOR_OFFSET + 50),
            None
        );
    }
}
