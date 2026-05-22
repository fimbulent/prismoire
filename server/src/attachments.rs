//! Attachments: upload, serve, background staging GC.
//!
//! See `docs/attachments.md` for the design. Splits into three
//! sub-modules:
//!
//! - [`upload`] — `POST /api/attachments`: multipart upload, classifier,
//!   image re-encode, budget debit, staging insert.
//! - [`serve`] — `GET /api/attachments/{hash}`: trust-gated blob serve.
//! - [`sweep`] — background TTL sweep + orphan-GC over
//!   `attachment_staging` and `attachment_blobs`.
//! - [`bind`] — shared helper called by `create_thread` / `edit_post`
//!   to validate the request-side attachment array and insert the
//!   `post_attachments` projection rows inside the caller's tx.

pub mod bind;
mod classify;
mod serve;
mod sweep;
mod upload;

pub use bind::{
    AttachmentBindRef, gc_orphan_blobs, hex_encode, parse_hash_hex, persist_attachment_bindings,
    validate_attachments, validate_body_attachment_refs,
};
pub use serve::serve_attachment;
pub use sweep::sweep_loop;
pub use upload::upload_attachment;
