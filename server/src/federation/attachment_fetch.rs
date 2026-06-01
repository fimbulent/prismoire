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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::http::{Method, Request, StatusCode, header};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

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

/// How long a `'transient'` failure suppresses re-fetches on the
/// synchronous serve path. A remote post whose bytes 404'd everywhere
/// might gain a resident copy later (the origin comes back, a fallback
/// peer consumes the author), so we retry — but only once the failure
/// row is older than this, to keep a render storm from hammering an
/// origin that is simply down. `'mismatch'` failures are terminal and
/// ignore this entirely.
const ATTACHMENT_RETRY_BACKOFF: Duration = Duration::from_secs(60);

/// Wall-clock budget for the inline [`fetch_attachment`] call on the
/// synchronous serve path. The viewer is blocked on this request, so a
/// candidate that hangs must not hold the response open indefinitely —
/// on timeout we record a transient failure and 404 to the placeholder.
const ATTACHMENT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// §11.6 per-peer cap on concurrent outbound attachment fetches. A
/// thread render can fan out to many distinct hashes homed at one
/// origin; without a cap, a burst of simultaneous first-renders would
/// open one connection per hash to that peer. 8 bounds the fan-out to
/// any single peer while leaving distinct peers fully parallel.
pub const ATTACHMENT_CONCURRENT_PER_PEER: usize = 8;

/// §11.6 per-peer concurrency gate for outbound §11.3 fetches.
///
/// One process-wide instance lives on [`crate::AppState`]; every
/// candidate dispatch in [`fetch_from_candidate`] holds a permit for
/// the target peer across the transport request. Waiting (rather than
/// skipping) on saturation is deliberate: the wait is bounded by
/// [`ATTACHMENT_FETCH_TIMEOUT`], a healthy origin drains its queue fast
/// enough that legitimate bursts just serialise past 8-in-flight, and a
/// dead peer times out the same way it would without the gate — so a
/// merely-busy origin never spuriously records a §11.4 failure.
///
/// The per-peer `Semaphore` map grows by distinct-peer count and is
/// never pruned: each entry is a single `Arc<Semaphore>`, so the
/// footprint is O(peers-ever-fetched-from), negligible next to the
/// blob cache itself.
#[derive(Default)]
pub struct AttachmentFetchGate {
    inner: Mutex<HashMap<[u8; 32], Arc<Semaphore>>>,
}

impl AttachmentFetchGate {
    /// Acquire a permit for an outbound fetch to `peer`, waiting if the
    /// per-peer cap is currently saturated. The returned permit releases
    /// the slot on drop.
    pub async fn acquire(&self, peer: [u8; 32]) -> OwnedSemaphorePermit {
        let sem = {
            let mut g = self.inner.lock().expect("attachment fetch gate poisoned");
            g.entry(peer)
                .or_insert_with(|| Arc::new(Semaphore::new(ATTACHMENT_CONCURRENT_PER_PEER)))
                .clone()
        };
        sem.acquire_owned()
            .await
            .expect("attachment fetch semaphore is never closed")
    }
}

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

/// §11.4 synchronous serve trigger: the bridge between the local serve
/// path ([`crate::attachments::serve`]) and [`fetch_attachment`].
///
/// Called when `/api/attachments/{hash}` finds a visible binding but a
/// `NULL` (fetch-pending) blob. Returns `true` iff the bytes are now
/// resident — the caller re-reads the row and serves 200; `false` means
/// 404 → placeholder. The durable `attachment_fetch_failures` row is
/// what keeps this from re-fetching on every render:
///
/// - `'mismatch'` present → terminal (§11.4 integrity violation needing
///   operator intervention). Never re-fetch; `false`.
/// - `'transient'` present and younger than [`ATTACHMENT_RETRY_BACKOFF`]
///   → still backing off; `false` without a transport attempt.
/// - otherwise → attempt [`fetch_attachment`] under
///   [`ATTACHMENT_FETCH_TIMEOUT`] and map the result:
///   - stored → delete any failure row, `true`.
///   - [`FetchError::HashMismatch`] → upsert `'mismatch'`, `false`.
///   - [`FetchError::Unavailable`] / [`FetchError::Db`] / timeout →
///     upsert `'transient'` (refreshing `last_attempt_at`), `false`.
///   - [`FetchError::NoOrigin`] → `false`, no row (nothing to fetch from
///     and nothing to back off; a binding may arrive later).
///
/// Failures to read/write the failure table are logged and swallowed:
/// the serve outcome follows the fetch, never a bookkeeping error.
pub async fn try_fetch_for_serve(state: &Arc<AppState>, content_hash: [u8; 32]) -> bool {
    let hash_vec: Vec<u8> = content_hash.to_vec();
    let now_ms = chrono::Utc::now().timestamp_millis();

    match sqlx::query!(
        "SELECT kind, last_attempt_at FROM attachment_fetch_failures WHERE content_hash = ?",
        hash_vec,
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => {
            if row.kind == "mismatch" {
                // Terminal: bytes are corrupt at the source. Don't fetch.
                return false;
            }
            // 'transient': honour the backoff window.
            let age_ms = now_ms.saturating_sub(row.last_attempt_at);
            if age_ms < ATTACHMENT_RETRY_BACKOFF.as_millis() as i64 {
                return false;
            }
        }
        Ok(None) => {}
        Err(e) => {
            // Can't read the gate — fall through and attempt the fetch
            // rather than wedging a servable attachment behind a DB blip.
            tracing::debug!(
                hash = %hex_lower(&content_hash),
                error = %e,
                "attachment serve trigger: failed to read failure row; attempting fetch",
            );
        }
    }

    match tokio::time::timeout(
        ATTACHMENT_FETCH_TIMEOUT,
        fetch_attachment(state, content_hash),
    )
    .await
    {
        Ok(Ok(())) => {
            clear_failure(state, &hash_vec).await;
            true
        }
        Ok(Err(FetchError::NoOrigin)) => false,
        Ok(Err(FetchError::HashMismatch)) => {
            record_failure(state, &hash_vec, "mismatch", now_ms).await;
            false
        }
        Ok(Err(FetchError::Unavailable)) | Ok(Err(FetchError::Db(_))) => {
            record_failure(state, &hash_vec, "transient", now_ms).await;
            false
        }
        Err(_elapsed) => {
            tracing::debug!(
                hash = %hex_lower(&content_hash),
                "attachment serve trigger: fetch timed out; recording transient failure",
            );
            record_failure(state, &hash_vec, "transient", now_ms).await;
            false
        }
    }
}

/// Upsert a failure row for `hash_vec`, refreshing `last_attempt_at`.
/// A `'transient'` row may be promoted to `'mismatch'`, and a
/// `'mismatch'` row stays terminal even if a later attempt is transient
/// (the conflict update only ever moves `kind` to the value passed and
/// refreshes the timestamp). Errors are logged and swallowed.
async fn record_failure(state: &Arc<AppState>, hash_vec: &[u8], kind: &str, now_ms: i64) {
    if let Err(e) = sqlx::query!(
        "INSERT INTO attachment_fetch_failures (content_hash, kind, last_attempt_at) \
         VALUES (?, ?, ?) \
         ON CONFLICT(content_hash) DO UPDATE SET kind = excluded.kind, \
                                                 last_attempt_at = excluded.last_attempt_at",
        hash_vec,
        kind,
        now_ms,
    )
    .execute(&state.db)
    .await
    {
        tracing::warn!(
            hash = %hex_lower(hash_vec),
            kind,
            error = %e,
            "attachment serve trigger: failed to persist failure row",
        );
    }
}

/// Drop the failure row for `hash_vec` after a successful fetch so a
/// later cache eviction starts from a clean slate. Errors are logged
/// and swallowed — the bytes are already resident.
async fn clear_failure(state: &Arc<AppState>, hash_vec: &[u8]) {
    if let Err(e) = sqlx::query!(
        "DELETE FROM attachment_fetch_failures WHERE content_hash = ?",
        hash_vec,
    )
    .execute(&state.db)
    .await
    {
        tracing::warn!(
            hash = %hex_lower(hash_vec),
            error = %e,
            "attachment serve trigger: failed to clear failure row after fetch",
        );
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
    // §11.6: hold a per-peer concurrency permit across the dispatch so a
    // burst of fetches homed at one origin can't open unbounded
    // simultaneous connections to it. Released on drop at fn exit.
    let _permit = state.attachment_fetch_gate.acquire(candidate).await;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Holding all of one peer's permits blocks a further acquire for
    /// that peer until a slot frees.
    #[tokio::test]
    async fn gate_caps_concurrency_per_peer() {
        let gate = AttachmentFetchGate::default();
        let peer = [7u8; 32];

        let mut held = Vec::new();
        for _ in 0..ATTACHMENT_CONCURRENT_PER_PEER {
            held.push(gate.acquire(peer).await);
        }

        // The next acquire must wait — prove it by showing it does not
        // complete within a short budget while all permits are held.
        let blocked = tokio::time::timeout(Duration::from_millis(50), gate.acquire(peer)).await;
        assert!(blocked.is_err(), "over-cap fetch to one peer must wait");

        // Freeing a slot admits the waiter.
        held.pop();
        let unblocked = tokio::time::timeout(Duration::from_millis(50), gate.acquire(peer)).await;
        assert!(unblocked.is_ok(), "a freed slot admits the next fetch");
    }

    /// Saturating one peer's permits leaves a different peer's full
    /// budget untouched.
    #[tokio::test]
    async fn gate_budget_is_per_peer() {
        let gate = AttachmentFetchGate::default();

        let mut held = Vec::new();
        for _ in 0..ATTACHMENT_CONCURRENT_PER_PEER {
            held.push(gate.acquire([1u8; 32]).await);
        }

        let other = tokio::time::timeout(Duration::from_millis(50), gate.acquire([2u8; 32])).await;
        assert!(other.is_ok(), "one saturated peer must not block another");
    }
}
