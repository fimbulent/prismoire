//! §11.3 receiver fetch client — pulls absent attachment blob bytes
//! from the §11 origin (or a §11.4 fallback peer) and stores them.
//!
//! Phase A ([`crate::federation::attachments_projection`]) projects a
//! remote post-rev's signed `attachments[]` into local
//! `post_attachments` bindings plus fetch-pending `attachment_blobs`
//! rows (`blob = NULL`). This module is what later fills that `blob`
//! in: given a content hash whose bytes are absent, it signs a §11.2
//! envelope GET against `/federation/v1/attachments/{hex}`, verifies
//! the response per §11.3 (SHA-256 of the body must equal the
//! requested hash), and writes the bytes — but only over a row that is
//! still `NULL`, never clobbering a copy that landed meanwhile.
//!
//! ## §11.4 candidate order
//!
//! The §11 origin is authoritative, so it is tried first: it is the
//! `posts.home_instance` of any remote post binding this hash. On a
//! 404/transport failure we fall back to the active peer set
//! ([`list_active_peers`], clipped to `MAX_FETCH_FALLBACK_PEERS`),
//! mirroring [`crate::federation::prior_home_recovery::proactive_author_backfill`].
//! §11.5 forbids forwarding peers from serving, so fallback peers
//! mostly 404 unless they also consume that author locally — an
//! accepted tension, not a bug.
//!
//! ## Terminal vs transient (the Phase C seam)
//!
//! This module does **not** persist failure state — the
//! `attachment_fetch_failures` table is introduced by Phase C, which
//! owns the serve-side retry/backoff policy. Phase B instead reports
//! *why* a fetch failed via [`FetchError`] so Phase C can map it:
//!
//! - [`FetchError::HashMismatch`] — a candidate returned bytes that
//!   did not hash to the requested value. The bytes are discarded, the
//!   §20 counter is bumped, and (per §11.4) this is a hard/terminal
//!   integrity failure: Phase C records it as no-further-fetches.
//! - [`FetchError::Unavailable`] — every candidate 404'd or the
//!   transport failed; the bytes may simply not be resident yet. Phase
//!   C records this as a transient backoff.
//! - [`FetchError::NoOrigin`] — no remote binding exists to resolve an
//!   origin from, so there is nothing to fetch.
//! - [`FetchError::Db`] — a local DB error reading bindings or writing
//!   the blob.
//!
//! A hash mismatch from *any* candidate (origin or fallback) is treated
//! as terminal even if other candidates remain untried: a
//! content-addressed mismatch means someone is serving wrong bytes for
//! a hash, which §11.4 escalates to operator intervention. The §20
//! counter surfaces it; the synchronous-fetch trigger (Phase C) is
//! where the durable hard-fail gate lives.

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{Method, Request, StatusCode, header};
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::federation::envelope::{self, AUTH_HEADER};
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::prior_home_recovery::list_active_peers;
use crate::federation::transport::PeerId;
use crate::users::hex_lower;

/// Cap on §11.4 fallback peers tried after the origin, mirroring
/// `prior_home_recovery::MAX_FALLBACK_PEERS`. Bounds the fan-out a
/// single miss can trigger.
const MAX_FETCH_FALLBACK_PEERS: usize = 16;

/// Why a [`fetch_attachment`] call did not result in stored bytes.
/// Phase C maps these onto `attachment_fetch_failures` rows; here they
/// are pure signal so this module stays migration-free.
#[derive(Debug)]
pub enum FetchError {
    /// No remote post binds this hash, so we cannot resolve a §11
    /// origin to fetch from. Either the hash is locally-authored
    /// (origin is us — nothing to fetch) or the binding row is gone.
    NoOrigin,
    /// Every candidate (origin + fallbacks) answered 404 or the
    /// transport failed. The bytes may appear later — §11.4 transient.
    Unavailable,
    /// A candidate returned bytes whose SHA-256 ≠ the requested hash.
    /// Discarded; §11.4 terminal (integrity violation).
    HashMismatch,
    /// Local DB error resolving the origin or persisting the blob.
    Db(sqlx::Error),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::NoOrigin => write!(f, "no remote binding to resolve a §11 origin"),
            FetchError::Unavailable => write!(f, "no candidate served the attachment"),
            FetchError::HashMismatch => write!(f, "fetched bytes did not match requested hash"),
            FetchError::Db(e) => write!(f, "db error: {e}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// §11.3 fetch the bytes for `content_hash` and store them into the
/// fetch-pending `attachment_blobs` row.
///
/// Resolves the §11 origin from `posts.home_instance` of a remote post
/// binding this hash, tries it first, then falls back to active peers.
/// On the first candidate whose response hash-verifies, writes the
/// bytes (over a still-`NULL` row only) and returns `Ok(())`.
///
/// Returns [`FetchError`] describing the failure mode so the caller
/// (Phase C) can choose terminal vs transient persistence. Idempotent
/// against a concurrent fetch: the `blob IS NULL` guard on the write
/// means a double-fetch of the same hash stores once and the loser is
/// a harmless no-op.
pub async fn fetch_attachment(
    state: &Arc<AppState>,
    content_hash: [u8; 32],
) -> Result<(), FetchError> {
    let hash_hex = hex_lower(&content_hash);

    // Candidate order: §11 origin(s) first (authoritative), then the
    // §11.4 active-peer fallback. De-dup so an origin that is also an
    // active peer isn't tried twice.
    let mut candidates = resolve_origins(state, &content_hash).await?;
    if candidates.is_empty() {
        return Err(FetchError::NoOrigin);
    }
    match list_active_peers(state).await {
        Ok(peers) => {
            for (key, _domain) in peers.into_iter().take(MAX_FETCH_FALLBACK_PEERS) {
                if !candidates.contains(&key) {
                    candidates.push(key);
                }
            }
        }
        Err(e) => {
            // Fallbacks are best-effort; an origin attempt can still
            // succeed, so log and continue rather than abort.
            tracing::debug!(
                hash = %hash_hex,
                error = %e,
                "attachment fetch: db error listing active peers; trying origin only",
            );
        }
    }

    let path = format!("/federation/v1/attachments/{hash_hex}");
    let mut saw_mismatch = false;

    for candidate in candidates {
        match fetch_from_candidate(state, candidate, &path, &content_hash).await {
            CandidateOutcome::Stored => return Ok(()),
            CandidateOutcome::Mismatch => {
                // Terminal per §11.4: stop fanning out, a
                // content-addressed mismatch is an integrity failure.
                state.metrics.record_attachment_hash_mismatch();
                tracing::warn!(
                    hash = %hash_hex,
                    peer = %hex_lower(&candidate),
                    "attachment fetch: response hash mismatch; discarding bytes",
                );
                saw_mismatch = true;
                break;
            }
            CandidateOutcome::Db(e) => return Err(FetchError::Db(e)),
            CandidateOutcome::Unavailable => {
                // 404 / transport failure — try the next candidate.
            }
        }
    }

    if saw_mismatch {
        Err(FetchError::HashMismatch)
    } else {
        Err(FetchError::Unavailable)
    }
}

/// Outcome of a single candidate fetch, kept private so the public
/// surface is just [`FetchError`].
enum CandidateOutcome {
    /// Bytes verified and written (or already present — the `NULL`
    /// guard made the write a no-op).
    Stored,
    /// 200 with bytes that did not hash to the requested value.
    Mismatch,
    /// 404, non-200, or transport failure.
    Unavailable,
    /// Local DB error writing the blob.
    Db(sqlx::Error),
}

/// Sign + send one §11.2 envelope GET to `candidate` and, on a verified
/// 200, persist the bytes.
async fn fetch_from_candidate(
    state: &Arc<AppState>,
    candidate: [u8; 32],
    path: &str,
    content_hash: &[u8; 32],
) -> CandidateOutcome {
    let header_value =
        envelope::sign_outbound(&state.instance_key, candidate, &Method::GET, path, b"");
    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .header(AUTH_HEADER, header_value)
        .body(Bytes::new())
        .expect("request builder");

    let response = match state
        .federation_transport
        .request(&PeerId::from_bytes(candidate), request)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(
                peer = %hex_lower(&candidate),
                error = %e,
                "attachment fetch: transport error",
            );
            return CandidateOutcome::Unavailable;
        }
    };

    // §11.1: 404 (and any non-200) collapse to "this candidate doesn't
    // have it" — move on. The error body, if any, is CBOR we don't
    // need.
    if response.status() != StatusCode::OK {
        return CandidateOutcome::Unavailable;
    }

    let body = response.into_body();

    // §11.3 integrity check: the bytes are content-addressed, so the
    // SHA-256 of the body is the authoritative identity. A mismatch
    // means corrupt/wrong bytes regardless of who served them.
    if &sha256(&body) != content_hash {
        return CandidateOutcome::Mismatch;
    }

    let hash_vec: Vec<u8> = content_hash.to_vec();
    let blob: &[u8] = &body;
    // Never clobber: another fetch (or a local upload of identical
    // content) may have filled the row while this request was in
    // flight. `blob IS NULL` makes the loser a harmless no-op.
    match sqlx::query!(
        "UPDATE attachment_blobs SET blob = ? WHERE content_hash = ? AND blob IS NULL",
        blob,
        hash_vec,
    )
    .execute(&state.db)
    .await
    {
        Ok(_) => CandidateOutcome::Stored,
        Err(e) => CandidateOutcome::Db(e),
    }
}

/// Resolve §11 origin candidate pubkeys for `content_hash`: the
/// distinct `posts.home_instance` values of remote posts binding this
/// hash. A locally-authored binding (`home_instance IS NULL`) is
/// excluded — we are the origin for those, so there is nothing to
/// fetch. Most-recent revision first is irrelevant; we just need a
/// reachable origin, so order is unspecified.
async fn resolve_origins(
    state: &Arc<AppState>,
    content_hash: &[u8; 32],
) -> Result<Vec<[u8; 32]>, FetchError> {
    let hash_vec: Vec<u8> = content_hash.to_vec();
    let rows = sqlx::query!(
        r#"SELECT DISTINCT p.home_instance AS "home_instance!: Vec<u8>"
             FROM post_attachments pa
             JOIN posts p ON p.id = pa.post_id
            WHERE pa.content_hash = ?
              AND p.home_instance IS NOT NULL"#,
        hash_vec,
    )
    .fetch_all(&state.db)
    .await
    .map_err(FetchError::Db)?;

    Ok(rows
        .into_iter()
        .filter_map(|r| <[u8; 32]>::try_from(r.home_instance.as_slice()).ok())
        .collect())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}
