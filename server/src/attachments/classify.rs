//! Two-stage MIME classifier for attachment uploads
//! (`docs/attachments.md` §3 step 2).
//!
//! Declared MIME from the multipart part is advisory throughout — the
//! authoritative MIME is whatever this module returns. Two-stage gate:
//!
//! 1. `infer::get(bytes)` looks at binary signatures (magic bytes). If
//!    it returns a MIME on our allowlist (PNG / JPEG / WebP / PDF), we
//!    accept with that MIME. **GIF is explicitly excluded** even though
//!    `infer` recognises it (animation pushes toward image-driven
//!    culture; static GIF is strictly worse than PNG). HTML / SVG are
//!    excluded for the same security reason as elsewhere — text by
//!    encoding but executable in a browser.
//! 2. If `infer` returned no recognised signature, validate the bytes
//!    as valid UTF-8. Valid → `text/plain`. Invalid → reject.
//!
//! This covers code files (`*.py`, `*.rs`, `*.toml`), markdown
//! (`README.md`), structured text (JSON, CSV, logs) under `text/plain`.
//! Language / format hints live in the user-supplied filename.

use crate::signed::ALLOWED_MIMES;

/// Result of classifying upload bytes.
pub enum ClassifyOutcome {
    /// The bytes carry a recognised binary signature on
    /// [`ALLOWED_MIMES`]. Carries the canonical MIME string.
    BinaryAllowed(&'static str),
    /// `infer` recognised a binary signature, but it is not on the
    /// allowlist (GIF, HTML, SVG, etc.). Reject.
    BinaryRejected,
    /// `infer` saw no recognised signature; the bytes parse as valid
    /// UTF-8. Classify as `text/plain`.
    TextPlain,
    /// `infer` saw no recognised signature and the bytes are not valid
    /// UTF-8. Reject (unknown binary or malformed text).
    InvalidUtf8,
}

/// Run the two-stage classifier over a candidate upload's bytes.
///
/// See module docs for the rule. Returns the [`ClassifyOutcome`] enum
/// so the caller can map each branch to the correct error code (the
/// "binary rejected" and "invalid utf8" branches both surface as
/// `AttachmentMimeRejected` on the wire but stay distinct here for
/// clearer logging).
pub fn classify(bytes: &[u8]) -> ClassifyOutcome {
    if let Some(kind) = infer::get(bytes) {
        let mime = kind.mime_type();
        // The allowlist is the source of truth — even if `infer`
        // recognises a MIME, we only accept it if `ALLOWED_MIMES`
        // contains the exact string. GIF, HTML, SVG, etc. fall to
        // the rejection branch this way.
        if let Some(canonical) = ALLOWED_MIMES.iter().find(|m| **m == mime) {
            return ClassifyOutcome::BinaryAllowed(canonical);
        }
        return ClassifyOutcome::BinaryRejected;
    }

    // No magic-byte match. Fall through to the UTF-8 check.
    if std::str::from_utf8(bytes).is_ok() {
        ClassifyOutcome::TextPlain
    } else {
        ClassifyOutcome::InvalidUtf8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_png_signature() {
        // PNG magic bytes.
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0];
        match classify(&png) {
            ClassifyOutcome::BinaryAllowed("image/png") => {}
            _ => panic!("expected image/png"),
        }
    }

    #[test]
    fn classifies_jpeg_signature() {
        // JPEG SOI + APP0 JFIF marker.
        let jpeg = [
            0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10, b'J', b'F', b'I', b'F', 0, 0,
        ];
        match classify(&jpeg) {
            ClassifyOutcome::BinaryAllowed("image/jpeg") => {}
            _ => panic!("expected image/jpeg"),
        }
    }

    #[test]
    fn rejects_gif_even_though_infer_recognises() {
        // GIF89a header — `infer` will return image/gif, which is NOT
        // on our allowlist. Must classify as BinaryRejected.
        let gif = b"GIF89a\x01\x00\x01\x00\x00";
        match classify(gif) {
            ClassifyOutcome::BinaryRejected => {}
            _ => panic!("expected GIF to be rejected"),
        }
    }

    #[test]
    fn classifies_utf8_text_as_text_plain() {
        let text = b"hello world\n";
        match classify(text) {
            ClassifyOutcome::TextPlain => {}
            _ => panic!("expected text/plain"),
        }
    }

    #[test]
    fn rejects_random_non_utf8_bytes() {
        // Random bytes that are not valid UTF-8 and don't match a
        // known signature.
        let bytes = [0x80, 0x81, 0x82, 0xFF, 0xFE, 0xFD];
        match classify(&bytes) {
            ClassifyOutcome::InvalidUtf8 => {}
            _ => panic!("expected invalid utf8"),
        }
    }

    #[test]
    fn classifies_pdf_signature() {
        // %PDF-1.4 prefix.
        let pdf = b"%PDF-1.4\n%trailer\n";
        match classify(pdf) {
            ClassifyOutcome::BinaryAllowed("application/pdf") => {}
            _ => panic!("expected application/pdf"),
        }
    }
}
