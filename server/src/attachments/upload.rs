//! `POST /api/attachments` — multipart upload handler
//! (`docs/attachments.md` §3 step 1).
//!
//! Validation pipeline, all inside one transaction (after the
//! out-of-tx classify + re-encode + hash work):
//!
//! 0. Body size cap (an outer Axum layer on the route, not here).
//! 1. Size ≤ `MAX_ATTACHMENT_SIZE` on the input bytes; reject empty.
//! 2. Two-stage classifier (`classify` module): binary signatures
//!    first, UTF-8 fallback to `text/plain`.
//! 3. For images: header dimensions → decode → downscale if needed →
//!    re-encode, then re-check size against the stored bytes.
//! 4. For PDF / text: store as-is.
//! 5. SHA-256 over the stored bytes; debit user budget (lazy refill);
//!    upsert `attachment_blobs`; insert `attachment_staging`.

use std::io::Cursor;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Multipart, State};
use axum::response::IntoResponse;
use image::{ImageFormat, ImageReader};
use serde::Serialize;
use sha2::Digest;

use super::bind::hex_encode;
use crate::error::{AppError, ErrorCode};
use crate::session::AuthUser;
use crate::signed::MAX_ATTACHMENT_SIZE;
use crate::state::AppState;

use super::classify::{ClassifyOutcome, classify};

/// JSON response for a successful upload.
#[derive(Serialize)]
pub struct UploadResponse {
    /// Lower-case hex SHA-256 of the stored bytes. The frontend echoes
    /// this back in `POST /api/threads` to bind the attachment.
    pub content_hash: String,
    /// Stored size in bytes (post-re-encode for images).
    pub size: u64,
    /// Canonical MIME string from the classifier — one of
    /// `signed::ALLOWED_MIMES`. May differ from the multipart-declared
    /// MIME, which is advisory throughout.
    pub mime: String,
}

/// Read the single file part out of the multipart body.
///
/// Returns the accumulated bytes. Errors map to
/// `AttachmentMultipartInvalid` so the wire shape stays consistent —
/// the multipart spec has many ways to be malformed and we don't
/// distinguish them on the response.
async fn read_file_part(mut multipart: Multipart) -> Result<Vec<u8>, AppError> {
    // The contract is one file part named "file"; we accept any single
    // part with bytes to keep the frontend ergonomic, but reject if
    // multiple parts are present so a client can't smuggle extra data
    // into the upload. Other small form fields (e.g. a declared
    // filename) are not consumed here — the binding step in
    // `POST /api/threads` is where the filename gets signed.
    let mut bytes: Option<Vec<u8>> = None;
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        tracing::debug!(error = %e, "multipart upload malformed");
        AppError::code(ErrorCode::AttachmentMultipartInvalid)
    })? {
        if bytes.is_some() {
            // A second part means the client tried to send more than
            // one file — bail.
            return Err(AppError::code(ErrorCode::AttachmentMultipartInvalid));
        }
        let data = field.bytes().await.map_err(|e| {
            tracing::debug!(error = %e, "multipart field bytes failed");
            AppError::code(ErrorCode::AttachmentMultipartInvalid)
        })?;
        bytes = Some(data.to_vec());
    }
    bytes.ok_or_else(|| AppError::code(ErrorCode::AttachmentMultipartInvalid))
}

/// Outcome of the classify + re-encode pipeline: the bytes that will
/// actually be stored, plus the canonical MIME for them.
struct ProcessedUpload {
    stored_bytes: Vec<u8>,
    mime: &'static str,
}

/// Apply the classifier and image re-encode pipeline to the raw upload
/// bytes. Pure CPU work — runs outside the DB transaction.
fn process_bytes(
    input: &[u8],
    max_image_px_decode: u32,
    max_image_px_output: u32,
) -> Result<ProcessedUpload, AppError> {
    let outcome = classify(input);
    let mime = match outcome {
        ClassifyOutcome::BinaryAllowed(m) => m,
        ClassifyOutcome::BinaryRejected | ClassifyOutcome::InvalidUtf8 => {
            return Err(AppError::code(ErrorCode::AttachmentMimeRejected));
        }
        ClassifyOutcome::TextPlain => "text/plain",
    };

    match mime {
        "image/png" | "image/jpeg" | "image/webp" => {
            let format = match mime {
                "image/png" => ImageFormat::Png,
                "image/jpeg" => ImageFormat::Jpeg,
                "image/webp" => ImageFormat::WebP,
                _ => unreachable!(),
            };
            let stored = process_image(input, format, max_image_px_decode, max_image_px_output)?;
            Ok(ProcessedUpload {
                stored_bytes: stored,
                mime,
            })
        }
        // PDF / text are stored verbatim.
        _ => Ok(ProcessedUpload {
            stored_bytes: input.to_vec(),
            mime,
        }),
    }
}

/// Read header dimensions, decode, downscale if needed, and re-encode.
/// EXIF and ancillary chunks are dropped as a side effect of
/// decode-then-re-encode through `DynamicImage`.
fn process_image(
    input: &[u8],
    format: ImageFormat,
    max_px_decode: u32,
    max_px_output: u32,
) -> Result<Vec<u8>, AppError> {
    // Step 3.1: read dimensions without decoding the pixel buffer.
    // Classifier output is authoritative — we pin the format with
    // `with_format` rather than calling `with_guessed_format`.
    let reader = ImageReader::with_format(Cursor::new(input), format);
    let (w, h) = reader.into_dimensions().map_err(|e| {
        tracing::debug!(error = %e, "image header dimensions failed");
        AppError::code(ErrorCode::AttachmentImageDecode)
    })?;
    if w > max_px_decode || h > max_px_decode {
        return Err(AppError::code(ErrorCode::AttachmentImageDimensions));
    }

    // Step 3.2: decode now that the pixel buffer is bounded.
    let img = image::load_from_memory_with_format(input, format).map_err(|e| {
        tracing::debug!(error = %e, "image decode failed");
        AppError::code(ErrorCode::AttachmentImageDecode)
    })?;

    // Step 3.3: downscale to MAX_IMAGE_PX_OUTPUT longest side, aspect
    // preserved. This is belt-and-suspenders against a client that
    // skipped its own resize. `thumbnail` is a fast box filter; the
    // resulting bytes still go through re-encode below so EXIF /
    // exploit data is dropped either way.
    let img = if w > max_px_output || h > max_px_output {
        // `thumbnail` accepts target bounding box dimensions and
        // preserves aspect ratio internally.
        img.thumbnail(max_px_output, max_px_output)
    } else {
        img
    };

    // Step 3.4: re-encode, preserving the source MIME.
    let mut out: Vec<u8> = Vec::new();
    match format {
        ImageFormat::Png => {
            let encoder = image::codecs::png::PngEncoder::new_with_quality(
                &mut out,
                image::codecs::png::CompressionType::Default,
                image::codecs::png::FilterType::Adaptive,
            );
            img.write_with_encoder(encoder).map_err(|e| {
                tracing::debug!(error = %e, "PNG re-encode failed");
                AppError::code(ErrorCode::AttachmentImageDecode)
            })?;
        }
        ImageFormat::Jpeg => {
            // Quality 85 — pinned so encoder behaviour is deterministic
            // for a given crate version (docs/attachments.md §3 step 3.4).
            let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 85);
            img.write_with_encoder(encoder).map_err(|e| {
                tracing::debug!(error = %e, "JPEG re-encode failed");
                AppError::code(ErrorCode::AttachmentImageDecode)
            })?;
        }
        ImageFormat::WebP => {
            // `image` crate's WebP encoder is lossless-only as of
            // 0.25. A lossless re-encode of a lossy 1600 px input
            // frequently busts the 500 KiB cap, so we go through the
            // `webp` crate for lossy quality 85 instead.
            let rgba = img.to_rgba8();
            let (w, h) = (rgba.width(), rgba.height());
            let encoder = webp::Encoder::from_rgba(rgba.as_raw(), w, h);
            let encoded = encoder.encode(85.0);
            out = encoded.to_vec();
        }
        _ => unreachable!("image format pinned by classifier"),
    }

    Ok(out)
}

/// Atomic lazy-refill + check + debit on a single user's storage
/// budget row. Runs inside the upload transaction so a concurrent
/// upload cannot race the check.
///
/// On first upload by a user, the row doesn't exist yet; we insert it
/// at `cap - bytes` (full bucket minus this upload). On subsequent
/// uploads we recompute the refill from the elapsed time since
/// `last_refill_at`, then debit. Overdraft → `BudgetExceeded`.
async fn debit_budget(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: &str,
    bytes: u64,
    cap_bytes: u64,
    refill_bytes_per_day: u64,
) -> Result<(), AppError> {
    // Pull the existing row (if any). Locking is implicit via SQLite's
    // transaction model.
    let row = sqlx::query!(
        r#"SELECT available_bytes AS "available_bytes!: i64",
                  last_refill_at AS "last_refill_at!: String",
                  lifetime_spent AS "lifetime_spent!: i64"
             FROM user_storage_budgets
            WHERE user_id = ?"#,
        user_id,
    )
    .fetch_optional(&mut **tx)
    .await?;

    let now_dt = chrono::Utc::now();
    let now_str = now_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let (new_available, new_lifetime) = if let Some(row) = row {
        // Lazy refill: `available = min(cap, available + rate * dt)`,
        // then check, then debit.
        let prior_dt = chrono::DateTime::parse_from_rfc3339(&row.last_refill_at)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or(now_dt);
        let elapsed_secs = (now_dt - prior_dt).num_seconds().max(0) as u64;
        // Refill is `refill_bytes_per_day * elapsed_secs / 86400` —
        // compute in u128 to avoid overflow on long-idle accounts.
        let refilled: u64 = (refill_bytes_per_day as u128 * elapsed_secs as u128 / 86_400u128)
            .min(u64::MAX as u128) as u64;
        let prior_available = row.available_bytes.max(0) as u64;
        let after_refill = prior_available.saturating_add(refilled).min(cap_bytes);
        if after_refill < bytes {
            return Err(AppError::code(ErrorCode::BudgetExceeded));
        }
        let new_available = after_refill - bytes;
        let new_lifetime = (row.lifetime_spent.max(0) as u64).saturating_add(bytes);
        (new_available, new_lifetime)
    } else {
        // First upload: implicit full budget, debit immediately.
        if cap_bytes < bytes {
            return Err(AppError::code(ErrorCode::BudgetExceeded));
        }
        (cap_bytes - bytes, bytes)
    };

    let new_available_i64 = new_available.min(i64::MAX as u64) as i64;
    let new_lifetime_i64 = new_lifetime.min(i64::MAX as u64) as i64;

    sqlx::query!(
        "INSERT INTO user_storage_budgets
            (user_id, available_bytes, last_refill_at, lifetime_spent)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
            available_bytes = excluded.available_bytes,
            last_refill_at  = excluded.last_refill_at,
            lifetime_spent  = excluded.lifetime_spent",
        user_id,
        new_available_i64,
        now_str,
        new_lifetime_i64,
    )
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// `POST /api/attachments` — multipart upload entry point.
///
/// One file per request. Authoritative MIME comes from the classifier;
/// the multipart-declared part name and content-type are not trusted.
/// Response: `201 { content_hash, size, mime }` per §3 step 7.
pub async fn upload_attachment(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    // 1. Read the bytes.
    let input = read_file_part(multipart).await?;

    // 2. Cheap pre-checks before any decode work.
    if input.is_empty() {
        return Err(AppError::code(ErrorCode::AttachmentEmpty));
    }
    if input.len() > MAX_ATTACHMENT_SIZE {
        return Err(AppError::code(ErrorCode::AttachmentTooLarge));
    }

    // 3. Classify + re-encode pipeline (CPU, no DB). Image decode +
    //    re-encode at up to `max_image_px_decode` is real CPU work
    //    (tens of ms on adversarial inputs), so we hand it to the
    //    blocking pool to keep the async worker free for the rest of
    //    the request mix. `input` moves into the closure since we no
    //    longer need it past this point — the stored bytes live on
    //    `processed.stored_bytes`.
    let cfg = &state.attachments_config;
    let cfg_decode = cfg.max_image_px_decode;
    let cfg_output = cfg.max_image_px_output;
    let processed =
        tokio::task::spawn_blocking(move || process_bytes(&input, cfg_decode, cfg_output))
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "image processing task panicked");
                AppError::code(ErrorCode::Internal)
            })??;

    // 4. Authoritative size check on the about-to-be-stored bytes.
    //    For images this branch is reachable because re-encode can
    //    grow an adversarial input.
    if processed.stored_bytes.len() > MAX_ATTACHMENT_SIZE {
        return Err(AppError::code(ErrorCode::AttachmentTooLarge));
    }
    let stored_len = processed.stored_bytes.len() as u64;

    // 5. Hash the stored bytes.
    let content_hash: [u8; 32] = sha2::Sha256::digest(&processed.stored_bytes).into();
    let hash_hex = hex_encode(&content_hash);
    let hash_bytes = content_hash.to_vec();

    // 6. DB transaction: debit budget, upsert blob, insert staging.
    //    A snapshot of the admin-dynamic budget is read once per
    //    upload — admin edits via `/api/admin/config` take effect on
    //    the next upload without a restart.
    let budget = {
        let guard = state.attachment_budget.read().map_err(|_| {
            tracing::error!("attachment_budget lock poisoned");
            AppError::code(ErrorCode::Internal)
        })?;
        *guard
    };

    let mut tx = state.db.begin().await?;

    debit_budget(
        &mut tx,
        &user.user_id,
        stored_len,
        budget.cap_bytes,
        budget.refill_bytes_per_day,
    )
    .await?;

    // Upsert the blob row. Content-addressing means a second upload of
    // identical bytes finds the existing row; we want to keep its
    // existing `uploader` (the first uploader's identity) and only
    // populate `blob` if it was previously NULL (cache-evicted state).
    // Refcount stays unchanged — staging does not count as a binding.
    let stored_size_i64 = stored_len.min(i64::MAX as u64) as i64;
    let now_str = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    sqlx::query!(
        "INSERT INTO attachment_blobs
            (content_hash, blob, content_type, size, uploader, created_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(content_hash) DO UPDATE SET
            blob = COALESCE(attachment_blobs.blob, excluded.blob)",
        hash_bytes,
        processed.stored_bytes,
        processed.mime,
        stored_size_i64,
        user.user_id,
        now_str,
    )
    .execute(&mut *tx)
    .await?;

    // Staging row. Keyed on content_hash, so a second upload of the
    // same hash while the first is still staged is a unique-conflict;
    // we treat that as success (the first uploader's staging row
    // stands, see migration comments) by using INSERT OR IGNORE.
    let expires_dt = chrono::Utc::now() + chrono::Duration::seconds(cfg.staging_ttl_seconds as i64);
    let expires_at = expires_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    sqlx::query!(
        "INSERT OR IGNORE INTO attachment_staging
            (content_hash, uploader, expires_at, created_at)
         VALUES (?, ?, ?, ?)",
        hash_bytes,
        user.user_id,
        expires_at,
        now_str,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(UploadResponse {
            content_hash: hash_hex,
            size: stored_len,
            mime: processed.mime.to_string(),
        }),
    ))
}
