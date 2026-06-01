//! `GET /api/attachments/{hash}` — trust-gated blob serve
//! (`docs/attachments.md` §4 / §6.2).
//!
//! Visibility is the same predicate as `search/posts.rs`: the post
//! whose binding we serve must be visible to the requester, where
//! visibility = (self-author) || (!distrust && reverse_score ≥
//! [`MINIMUM_TRUST_THRESHOLD`]). The serving binding is selected by
//! the §4 step 4 ordering and supplies `Content-Disposition` /
//! `Content-Type` / `filename`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use super::bind::parse_hash_hex;
use crate::error::{AppError, ErrorCode};
use crate::federation::{attachment_cache, attachment_fetch};
use crate::session::AuthUser;
use crate::state::AppState;
use crate::trust::{MINIMUM_TRUST_THRESHOLD, load_distrust_set, lookup_score};

/// Candidate visible binding for the requested hash. The serving
/// binding is selected from this set by the §4 step 4 ordering — but
/// that ordering is applied in SQL (`ORDER BY pr.created_at DESC,
/// p.id ASC, pa.position ASC`), so only the fields the response
/// actually consumes are carried into Rust.
struct Binding {
    author_id: String,
    filename: String,
}

/// `GET /api/attachments/{hash}` — serve the blob bytes if the
/// requester is allowed to see at least one current binding for them.
pub async fn serve_attachment(
    State(state): State<Arc<AppState>>,
    Path(hash_hex): Path<String>,
    user: AuthUser,
) -> Result<Response, AppError> {
    let Some(hash) = parse_hash_hex(&hash_hex) else {
        return Err(AppError::code(ErrorCode::AttachmentNotFound));
    };
    let hash_bytes: Vec<u8> = hash.to_vec();

    // §6.2 latest-revision rule: a binding only counts if it lives on
    // the post's *latest* revision and the post is not retracted.
    // `posts.revision_count - 1` gives the latest revision index since
    // the counter is denormalised. The ordering matches §4 step 4 so
    // the serving binding (the first row) is deterministic across
    // serve / export.
    let candidates = sqlx::query!(
        r#"SELECT p.author AS "author_id!: String",
                  pa.filename AS "filename!: String"
             FROM post_attachments pa
             JOIN posts p ON p.id = pa.post_id
             JOIN post_revisions pr
                  ON pr.post_id = pa.post_id AND pr.revision = pa.revision
            WHERE pa.content_hash = ?
              AND pa.revision = p.revision_count - 1
              AND p.retracted_at IS NULL
            ORDER BY pr.created_at DESC, p.id ASC, pa.position ASC"#,
        hash_bytes,
    )
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .map(|r| Binding {
        author_id: r.author_id,
        filename: r.filename,
    })
    .collect::<Vec<_>>();

    if candidates.is_empty() {
        return Err(AppError::code(ErrorCode::AttachmentNotFound));
    }

    // Visibility filter — identical to the post-visibility predicate
    // used in `search/posts.rs`. Self-authored posts are always
    // visible; otherwise the author must not be distrusted by the
    // viewer and must have a reverse trust score over the threshold.
    let reader_uuid = user.uuid();
    let graph = state.get_trust_graph()?;
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;

    let visible: Vec<&Binding> = candidates
        .iter()
        .filter(|b| {
            if b.author_id == user.user_id {
                return true;
            }
            if distrust_set.contains(&b.author_id) {
                return false;
            }
            lookup_score(&reverse_map, &b.author_id).is_some_and(|s| s >= MINIMUM_TRUST_THRESHOLD)
        })
        .collect();

    // §4 step 2: do not distinguish "doesn't exist" from "not visible
    // to you" — same wire response in both cases.
    let Some(serving) = visible.first().copied() else {
        return Err(AppError::code(ErrorCode::AttachmentNotFound));
    };

    // Pull the blob bytes plus content_type. A NULL `blob` is the
    // fetch-pending / cache-evicted state (§11.4 / §11.6); we surface
    // it as 404 so the placeholder UX is consistent with "blob fully
    // GC'd" and "never existed."
    let blob_row = sqlx::query!(
        r#"SELECT blob, content_type AS "content_type!: String"
             FROM attachment_blobs WHERE content_hash = ?"#,
        hash_bytes,
    )
    .fetch_optional(&state.db)
    .await?;

    let Some(blob_row) = blob_row else {
        return Err(AppError::code(ErrorCode::AttachmentNotFound));
    };
    let content_type = blob_row.content_type;

    // §11.4 synchronous fetch trigger: a visible binding with a NULL
    // blob is the fetch-pending state for a federated attachment. Try
    // to pull the bytes inline (subject to the failure-table backoff),
    // and re-read the row on success. A locally-authored attachment is
    // never NULL here, so this only fires for remote posts. If the
    // trigger can't obtain the bytes we fall through to the same 404 as
    // a cache-evicted / never-existed blob — the placeholder UX.
    let blob_bytes = match blob_row.blob {
        Some(bytes) => bytes,
        None => {
            if !attachment_fetch::try_fetch_for_serve(&state, hash).await {
                return Err(AppError::code(ErrorCode::AttachmentNotFound));
            }
            let refetched = sqlx::query!(
                "SELECT blob FROM attachment_blobs WHERE content_hash = ?",
                hash_bytes,
            )
            .fetch_optional(&state.db)
            .await?;
            match refetched.and_then(|r| r.blob) {
                Some(bytes) => bytes,
                None => return Err(AppError::code(ErrorCode::AttachmentNotFound)),
            }
        }
    };

    // §11.5 sloppy-LRU touch: this is the local-serve path that hands
    // bytes to logged-in viewers (either an origin-authored upload or
    // a federation-fetched cache entry). Bump `accessed_at` so the
    // cache-eviction sweep treats this hash as warm. The helper applies
    // its own staleness floor, so back-to-back serves of the same hash
    // collapse to a single UPDATE. Failures are logged and swallowed —
    // an LRU-bump must never fail the response.
    attachment_cache::bump_accessed_at(&state.db, &hash_bytes).await;

    // Build the Content-Disposition header per RFC 6266. Inline-vs-
    // download is now derived from the blob MIME: only `image/*` is
    // ever served inline (the post body's `![](name)` reference is
    // what actually controls *whether* the image renders inline in
    // the UI; this header just keeps a direct-hit `/api/attachments/{hash}`
    // open in the browser instead of forcing a download). Everything
    // else (PDFs, archives, plain text) gets `attachment` so clicking a
    // download chip writes a file rather than opening a tab. The
    // binding's filename supplies the name. We emit both an ASCII-
    // fallback `filename=` and an RFC 5987 `filename*=UTF-8''…` form so
    // intermediaries that don't support the extended parameter still
    // get a usable name.
    let disposition = build_content_disposition(&content_type, &serving.filename);

    let body = Body::from(blob_bytes);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, &content_type)
        // §4 step 5: nosniff is mandatory on every serve so a browser
        // cannot reinterpret a text/plain attachment as HTML.
        .header("X-Content-Type-Options", "nosniff")
        // §4 step 5 cache policy. The bytes are content-addressed
        // by SHA-256 and therefore truly immutable forever; what's
        // *not* immutable is the authorization decision (which
        // serving binding a given viewer gets, or whether they're
        // allowed to fetch the blob at all). We split those two
        // concerns across header fields:
        //
        // - `private` blocks shared intermediaries, since
        //   trust-gating means two viewers can legitimately receive
        //   different Content-Disposition for the same hash.
        // - `max-age=31536000, immutable` lets the browser's own
        //   disk cache hold the bytes — they really do never change
        //   for a given hash, so cache hits on repeated renders are
        //   correct and a meaningful perf win.
        // - `Vary: Cookie` keys cache entries by the Cookie header,
        //   so an account-switch on a shared device produces a
        //   different cache key and forces a cache miss + fresh
        //   server-side trust check. This is what makes the long
        //   max-age safe: the browser cache is now per-(URL,
        //   viewer-session), not per-URL.
        .header(
            header::CACHE_CONTROL,
            "private, max-age=31536000, immutable",
        )
        .header(header::VARY, "Cookie")
        .header(header::CONTENT_DISPOSITION, disposition)
        .body(body)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to build attachment response");
            AppError::code(ErrorCode::Internal)
        })?;

    Ok(response.into_response())
}

/// Build an RFC 6266 `Content-Disposition` header value.
///
/// Emits both the ASCII-fallback `filename="…"` (with non-ASCII /
/// quote / backslash characters replaced by `_`) and the RFC 5987
/// `filename*=UTF-8''…` percent-encoded form so HTTP intermediaries
/// that don't understand the extended parameter still get a valid
/// name.
fn build_content_disposition(mime: &str, filename: &str) -> String {
    // Image MIMEs get `inline` so a direct GET on the bytes opens in
    // the browser tab; every other MIME gets `attachment` so the
    // download chip path saves a file (`docs/attachments.md` §4 step 5).
    let disp = if mime.starts_with("image/") {
        "inline"
    } else {
        "attachment"
    };

    // ASCII fallback. Replace anything that is not a safe printable
    // ASCII character (and is not `"` or `\\`) with `_` so the
    // quoted form is unambiguous. Browsers treat this as the legacy
    // name when they cannot interpret the extended form.
    let mut ascii_fallback = String::with_capacity(filename.len());
    for c in filename.chars() {
        if c.is_ascii() && c != '"' && c != '\\' && !c.is_control() {
            ascii_fallback.push(c);
        } else {
            ascii_fallback.push('_');
        }
    }

    // RFC 5987 extended form: `filename*=UTF-8''<pct-encoded>`. Only
    // `attr-char` survives unencoded — every other byte is
    // percent-encoded.
    let mut ext = String::with_capacity(filename.len() * 3);
    for &b in filename.as_bytes() {
        if is_attr_char(b) {
            ext.push(b as char);
        } else {
            ext.push_str(&format!("%{:02X}", b));
        }
    }

    format!("{disp}; filename=\"{ascii_fallback}\"; filename*=UTF-8''{ext}")
}

/// RFC 5987 `attr-char`: ALPHA / DIGIT and a fixed set of safe
/// punctuation. Anything else must be percent-encoded.
fn is_attr_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

#[cfg(test)]
mod tests {
    // Hash-decoding tests live with the canonical
    // `attachments::bind::parse_hash_hex` they exercise; this module
    // only owns the Content-Disposition helpers below.
    use super::*;

    #[test]
    fn disposition_inline_for_image() {
        let v = build_content_disposition("image/png", "photo.png");
        assert!(v.starts_with("inline; filename=\"photo.png\""));
        assert!(v.contains("filename*=UTF-8''photo.png"));
    }

    #[test]
    fn disposition_attachment_for_non_image() {
        let v = build_content_disposition("application/pdf", "notes.pdf");
        assert!(v.starts_with("attachment; "));
    }

    #[test]
    fn disposition_attachment_for_video() {
        // Video MIMEs are explicitly not inlined — they take the
        // download chip path in the UI and should hand the user a
        // saved file rather than opening a tab.
        let v = build_content_disposition("video/mp4", "clip.mp4");
        assert!(v.starts_with("attachment; "));
    }

    #[test]
    fn disposition_pct_encodes_non_ascii() {
        let v = build_content_disposition("application/pdf", "café.pdf");
        // The extended form must percent-encode the UTF-8 bytes of é.
        assert!(v.contains("filename*=UTF-8''caf%C3%A9.pdf"));
        // The ASCII fallback replaces non-ASCII with a single
        // underscore per char (not per byte) — 'é' is one `char`.
        assert!(v.contains("filename=\"caf_.pdf\""));
    }
}
