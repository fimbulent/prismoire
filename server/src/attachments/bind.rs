//! Request → revision binding for attachments
//! (`docs/attachments.md` §6).
//!
//! Bridges the JSON wire shape carried on `POST /api/threads` /
//! `PATCH /api/posts/{id}` request bodies into both:
//!
//! 1. The `Vec<AttachmentRef>` that goes into the signed `post-rev`
//!    canonical CBOR (so federation peers see the same array the
//!    author signed).
//! 2. The `post_attachments` projection rows that drive serve-time
//!    filename / display-mode / position selection (§4 step 4).
//!
//! The helper runs inside the caller's transaction so the binding
//! rows, the staging row delete, and the post insert all commit
//! atomically.
//!
//! Authorization is intentionally narrow: a binding is accepted only
//! when the caller staged the hash themselves or has already bound it
//! to a post they author. This blocks "bind by guessed hash" — a
//! second user can't ride a blob another user just staged.

use std::collections::HashSet;

use pulldown_cmark::{Event, Parser, Tag};
use serde::Deserialize;

use crate::error::{AppError, ErrorCode};
use crate::signed::{
    ALLOWED_MIMES, AttachmentRef, MAX_ATTACHMENTS_PER_OP, sanitize_attachment_filename,
};

/// JSON wire shape for a single request-side attachment binding.
///
/// `content_hash` is lower-case hex (64 chars). `filename` is the
/// author-supplied display name; it must already be canonical per
/// `FILENAME_RULES` (the same form the verifier requires). Layout
/// intent (inline vs chip) is **not** part of the wire shape — it is
/// derived from `![](filename)` references in the post body
/// (`docs/attachments.md` §3 inline-rules).
#[derive(Deserialize, Clone, Debug)]
pub struct AttachmentBindRef {
    pub content_hash: String,
    pub filename: String,
}

/// Lower-case hex encode a byte slice. Shared by the upload path
/// (which echoes the new blob's hash in its 201 response) and the
/// read path (which surfaces `content_hash` in `PostResponse` so the
/// frontend can construct `/api/attachments/{hash}` URLs).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Decode a 64-character lower- or upper-case hex string into 32
/// bytes (a SHA-256 content hash). Returns `None` for any length or
/// character mismatch.
///
/// This is the **single source of truth** for hash hex-decoding
/// across the attachment surface. Every path that turns the
/// hex form of a `content_hash` back into 32 raw bytes — the bind
/// path, the serve handler, and the edit-time set-diff in
/// `posts::edit_post` — routes through here so a future tweak
/// (e.g. tightening to lower-case only, or rejecting embedded
/// whitespace) only has to land in one place.
pub fn parse_hash_hex(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(raw.as_bytes()[i * 2])?;
        let lo = hex_nibble(raw.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Validate the request-side attachment array and resolve each entry
/// into a `Vec<AttachmentRef>` ready to be signed.
///
/// Read-only on the DB: no rows are inserted or deleted. The caller
/// signs with the returned `Vec<AttachmentRef>` and then calls
/// [`persist_attachment_bindings`] inside the same transaction once
/// the `post_revisions` row exists (the `post_attachments` FK requires
/// the parent revision row first).
pub async fn validate_attachments(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: &str,
    refs: &[AttachmentBindRef],
) -> Result<Vec<AttachmentRef>, AppError> {
    if refs.len() > MAX_ATTACHMENTS_PER_OP {
        return Err(AppError::with_message(
            ErrorCode::BadRequest,
            format!("at most {MAX_ATTACHMENTS_PER_OP} attachments are allowed per post"),
        ));
    }

    let mut seen_hashes: HashSet<[u8; 32]> = HashSet::new();
    let mut seen_filenames: HashSet<String> = HashSet::new();
    let mut signed_refs: Vec<AttachmentRef> = Vec::with_capacity(refs.len());

    for r in refs.iter() {
        let hash = parse_hash_hex(&r.content_hash)
            .ok_or_else(|| AppError::code(ErrorCode::AttachmentNotFound))?;
        if !seen_hashes.insert(hash) {
            // The DB UNIQUE (post_id, revision, content_hash) would
            // catch this too, but a clean 400 is friendlier than the
            // generic Internal a constraint violation would produce.
            return Err(AppError::code(ErrorCode::AttachmentDuplicateHash));
        }

        // Filename must already be in canonical form — running the
        // sanitizer and comparing byte-identically matches what a
        // verifier does on the signed array per §2.2 step 6.
        let sanitized = sanitize_attachment_filename(&r.filename)
            .ok_or_else(|| AppError::code(ErrorCode::AttachmentFilenameInvalid))?;
        if sanitized != r.filename {
            return Err(AppError::code(ErrorCode::AttachmentFilenameInvalid));
        }

        // Reject duplicate filenames within the same revision. Body
        // `![](filename)` references resolve by filename, so two
        // attachments sharing a name would either silently pick one
        // (lossy) or force the renderer to invent disambiguation
        // syntax. Failing fast at bind time keeps the resolution
        // rule unambiguous (`docs/attachments.md` §3).
        if !seen_filenames.insert(sanitized.clone()) {
            return Err(AppError::code(ErrorCode::AttachmentDuplicateFilename));
        }

        let hash_vec: Vec<u8> = hash.to_vec();
        let blob_row = sqlx::query!(
            r#"SELECT content_type AS "content_type!: String",
                      size AS "size!: i64"
                 FROM attachment_blobs WHERE content_hash = ?"#,
            hash_vec,
        )
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| AppError::code(ErrorCode::AttachmentNotFound))?;

        if !ALLOWED_MIMES.contains(&blob_row.content_type.as_str()) {
            return Err(AppError::code(ErrorCode::AttachmentMimeRejected));
        }

        // Authorization: caller must either own the staging row or
        // have an existing binding on a post they author. Either form
        // proves they got the hash legitimately (uploaded it, or
        // previously published a post that used it). Both queries are
        // covered by indexes (`attachment_staging` PK; the
        // `idx_post_attachments_content_hash` index on
        // `post_attachments`).
        let staged_by_self = sqlx::query!(
            "SELECT 1 AS \"n!: i64\" FROM attachment_staging \
              WHERE content_hash = ? AND uploader = ?",
            hash_vec,
            user_id,
        )
        .fetch_optional(&mut **tx)
        .await?
        .is_some();

        // This check only sees live bindings: `retract_post` removes
        // the post's rows from `post_attachments` (posts.rs §retract),
        // so a hash that was bound to a since-retracted post will
        // *not* satisfy this predicate — the caller would need to
        // re-upload (or hold a current binding on a different post)
        // to re-bind it.
        let already_bound_by_self = sqlx::query!(
            "SELECT 1 AS \"n!: i64\" FROM post_attachments pa \
               JOIN posts p ON p.id = pa.post_id \
              WHERE pa.content_hash = ? AND p.author = ? LIMIT 1",
            hash_vec,
            user_id,
        )
        .fetch_optional(&mut **tx)
        .await?
        .is_some();

        if !staged_by_self && !already_bound_by_self {
            // Same wire response as "no such hash" — we don't leak
            // whether a hash exists but is owned by someone else.
            return Err(AppError::code(ErrorCode::AttachmentNotFound));
        }

        let size = u64::try_from(blob_row.size).map_err(|_| {
            tracing::error!(content_hash = %r.content_hash, size = blob_row.size, "negative blob size");
            AppError::code(ErrorCode::Internal)
        })?;

        signed_refs.push(AttachmentRef {
            content_hash: hash,
            mime: blob_row.content_type,
            size,
            filename: sanitized,
        });
    }

    Ok(signed_refs)
}

/// Insert the `post_attachments` projection rows for an already-
/// validated attachment array and drop any matching `attachment_staging`
/// rows.
///
/// Must run inside an open transaction whose `post_revisions` row for
/// `(post_id, revision)` is already present (FK requirement). The
/// trigger on `post_attachments` AFTER INSERT bumps the corresponding
/// `attachment_blobs.refcount`.
pub async fn persist_attachment_bindings(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    post_id: &str,
    revision: i64,
    refs: &[AttachmentRef],
) -> Result<(), AppError> {
    for (idx, r) in refs.iter().enumerate() {
        let position = idx as i64;
        let hash_vec: Vec<u8> = r.content_hash.to_vec();
        sqlx::query!(
            "INSERT INTO post_attachments \
                 (post_id, revision, position, content_hash, filename) \
             VALUES (?, ?, ?, ?, ?)",
            post_id,
            revision,
            position,
            hash_vec,
            r.filename,
        )
        .execute(&mut **tx)
        .await?;

        // Idempotent: drop the staging row if this hash was staged.
        // No-op when the hash arrived via `already_bound_by_self`.
        sqlx::query!(
            "DELETE FROM attachment_staging WHERE content_hash = ?",
            hash_vec,
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Drop any `attachment_blobs` row whose refcount is zero and which is
/// not held by a staging row.
///
/// This is the **single source of truth** for the `docs/attachments.md`
/// §5 orphan-blob GC predicate. Every path that can leave a blob with
/// no bindings and no staging anchor MUST run through here, so the
/// predicate stays in lockstep across paths and a future schema change
/// (e.g. adding a new "blob is still held" anchor) only has to land
/// here. Known callers:
///
/// - inline GC inside `edit_post` / `retract_post` (prompt eviction
///   for paths the operator can name),
/// - the background `attachments::sweep::run_sweep` pass on a timer,
/// - `privacy::soft_delete_user` after the user's posts retract and
///   their staging rows are dropped.
///
/// Returns the raw `sqlx::Error` so callers that propagate via `?`
/// into a `Result<_, AppError>` get the existing `From<sqlx::Error>`
/// conversion automatically, while the background sweep — which logs
/// the error via `tracing` rather than surfacing it through Axum —
/// can format it directly.
pub async fn gc_orphan_blobs(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM attachment_blobs \
          WHERE refcount = 0 \
            AND NOT EXISTS ( \
                SELECT 1 FROM attachment_staging s \
                 WHERE s.content_hash = attachment_blobs.content_hash \
            )"
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Walk a post body's markdown and return every inline image URL —
/// i.e. the `name` in `![alt](name)` — in document order, with
/// duplicates preserved.
///
/// We delegate to `pulldown-cmark` rather than a regex so the parse is
/// CommonMark-correct: `![](foo)` inside a fenced code block, an inline
/// `` `…` `` span, or HTML is *not* an image reference and must not
/// trigger validation. `Tag::Image` only fires for the real
/// image-syntax position.
///
/// Returns the URL exactly as it appeared in the source (no
/// percent-decoding, no sanitizer). Resolution against the attachment
/// array is by byte-identical comparison with the canonical
/// `filename`, which the bind path already enforces via
/// `sanitize_attachment_filename`.
pub fn extract_inline_image_refs(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for ev in Parser::new(body) {
        if let Event::Start(Tag::Image { dest_url, .. }) = ev {
            out.push(dest_url.into_string());
        }
    }
    out
}

/// Validate that the body's `![](filename)` image references are
/// consistent with the signed `attachments[]` array.
///
/// Two invariants are enforced (`docs/attachments.md` §3):
///
/// 1. **No duplicate inline refs.** A reader can't sensibly render the
///    same image at two different points in a post — the §6.1 set-diff
///    treats the binding as a single entity, and our serve-time
///    `Content-Disposition` is single-valued per blob. Two `![](foo)`
///    occurrences for the same `foo` (when `foo` resolves to an
///    attachment) trip [`ErrorCode::AttachmentInlineRefDuplicate`].
///
/// 2. **Inline refs must be image attachments.** Non-image MIMEs
///    (PDF, plain text) render only as a download chip; an inline
///    reference to one would either silently fail to render or open
///    a non-image in an `<img>` tag, both worse than failing at bind
///    time. Trips [`ErrorCode::AttachmentInlineRefNotImage`].
///
/// References that don't match any attachment filename are
/// **deliberately not rejected** — a typo in `![](dog.jpb)` is a UX
/// problem, not an authorship one, and the renderer will surface it
/// as a broken-image placeholder. Failing the whole post over a typo
/// would force the author to clean every dangling ref before they
/// could publish.
pub fn validate_body_attachment_refs(body: &str, refs: &[AttachmentRef]) -> Result<(), AppError> {
    // Build a filename → MIME lookup once. The bind path already
    // rejected duplicate filenames within `refs`, so a HashMap is fine.
    let by_filename: std::collections::HashMap<&str, &str> = refs
        .iter()
        .map(|r| (r.filename.as_str(), r.mime.as_str()))
        .collect();

    let mut seen: HashSet<String> = HashSet::new();
    for url in extract_inline_image_refs(body) {
        // Only references that resolve to one of *this post's*
        // attachments are subject to the dup/mime rules. Dangling refs
        // fall through (lax — renderer handles the placeholder).
        let Some(&mime) = by_filename.get(url.as_str()) else {
            continue;
        };
        if !is_inlineable_image_mime(mime) {
            return Err(AppError::code(ErrorCode::AttachmentInlineRefNotImage));
        }
        if !seen.insert(url) {
            return Err(AppError::code(ErrorCode::AttachmentInlineRefDuplicate));
        }
    }
    Ok(())
}

/// Image MIMEs eligible for inline rendering. A subset of
/// [`ALLOWED_MIMES`] — the same prefix predicate
/// [`crate::attachments::serve`] uses for `Content-Disposition`.
fn is_inlineable_image_mime(mime: &str) -> bool {
    mime.starts_with("image/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lowercase_hash() {
        let h = parse_hash_hex(&"0".repeat(64)).expect("valid");
        assert_eq!(h, [0u8; 32]);
    }

    #[test]
    fn rejects_short_hash() {
        assert!(parse_hash_hex("deadbeef").is_none());
    }

    #[test]
    fn rejects_non_hex() {
        assert!(parse_hash_hex(&"z".repeat(64)).is_none());
    }

    #[test]
    fn parses_mixed_case() {
        let h = parse_hash_hex(&"Aa".repeat(32)).expect("valid");
        assert_eq!(h, [0xAAu8; 32]);
    }

    // -- Body image-ref extraction & validation -----------------------

    fn att(filename: &str, mime: &str) -> AttachmentRef {
        AttachmentRef {
            content_hash: [0u8; 32],
            mime: mime.to_string(),
            size: 1,
            filename: filename.to_string(),
        }
    }

    #[test]
    fn extracts_inline_image_urls_in_order() {
        let body = "hello ![](a.png) world\n\n![alt text](b.png)";
        assert_eq!(extract_inline_image_refs(body), vec!["a.png", "b.png"]);
    }

    #[test]
    fn ignores_image_syntax_in_code_blocks() {
        // CommonMark says fenced code blocks contain literal text — no
        // image parsing inside them. A regex-based extractor would
        // wrongly fire here; pulldown-cmark gets it right.
        let body = "```\n![](leaked.png)\n```\n";
        assert!(extract_inline_image_refs(body).is_empty());
    }

    #[test]
    fn ignores_image_syntax_in_inline_code() {
        let body = "see `![](nope.png)` for the syntax";
        assert!(extract_inline_image_refs(body).is_empty());
    }

    #[test]
    fn validate_body_refs_accepts_single_image_ref() {
        let refs = vec![att("dog.png", "image/png")];
        assert!(validate_body_attachment_refs("![](dog.png)", &refs).is_ok());
    }

    #[test]
    fn validate_body_refs_accepts_dangling_ref() {
        // Typo: body references a name that doesn't match any
        // attachment. Lax path — the renderer will surface a broken
        // image placeholder; we don't fail the post.
        let refs = vec![att("dog.png", "image/png")];
        assert!(validate_body_attachment_refs("![](dgo.png)", &refs).is_ok());
    }

    #[test]
    fn validate_body_refs_rejects_duplicate_inline_ref() {
        let refs = vec![att("dog.png", "image/png")];
        let body = "![](dog.png)\n\n![](dog.png)";
        let err = validate_body_attachment_refs(body, &refs).unwrap_err();
        assert!(matches!(
            err.error_code(),
            ErrorCode::AttachmentInlineRefDuplicate
        ));
    }

    #[test]
    fn validate_body_refs_rejects_non_image_inline_ref() {
        let refs = vec![att("report.pdf", "application/pdf")];
        let body = "![](report.pdf)";
        let err = validate_body_attachment_refs(body, &refs).unwrap_err();
        assert!(matches!(
            err.error_code(),
            ErrorCode::AttachmentInlineRefNotImage
        ));
    }

    #[test]
    fn validate_body_refs_allows_empty_body() {
        let refs = vec![att("dog.png", "image/png")];
        assert!(validate_body_attachment_refs("", &refs).is_ok());
    }

    #[test]
    fn validate_body_refs_allows_no_attachments() {
        // No attachments + body that happens to use image syntax →
        // every ref is dangling, which is lax.
        assert!(validate_body_attachment_refs("![](anything.png)", &[]).is_ok());
    }
}
