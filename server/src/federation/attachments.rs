//! `GET /federation/v1/attachments/{hash}` — attachment fetch-on-demand
//! (`docs/federation-protocol.md` §11).
//!
//! Mounts one route under `/federation/v1`:
//!
//! ```text
//! GET /federation/v1/attachments/{sha256}   (§11.1)
//! ```
//!
//! Behind `verify_known_peer`: per §11.2 the envelope applies (the
//! recipient signs `GET /federation/v1/attachments/{sha256}` with the
//! body-hash field bound to `SHA-256("")`). There is no public
//! unauthenticated fetch route — attachments serve exclusively across
//! peering relationships.
//!
//! ## §11.5 origin-only serve
//!
//! The blob serves **only** when this instance is the §11 origin for
//! it: there must be a current (latest-revision) attachment binding
//! from a locally-authored, non-retracted post. The forwarding-cache
//! distinction in §11.5 is explicit: "a peer that received a post via
//! gossip-forwarding but does not consume the author locally MUST NOT
//! serve attachments from any locally-acquired copy." We may have the
//! blob bytes resident from a federation fetch (locally-resident
//! attachments table) — but unless a locally-authored post currently
//! binds the hash, we 404.
//!
//! ## Response shape
//!
//! Success is the only non-CBOR response on the entire federation
//! surface: 200 OK with the raw blob bytes and `Content-Type` taken
//! from `attachment_blobs.content_type`. Errors follow the §1.7
//! CBOR `{ "error": <code> }` convention via the shared helpers in
//! [`errors`].
//!
//! Status codes per §11.1:
//!
//! - `200 OK` with body — blob is present, currently bound to a
//!   locally-authored post, and we are origin.
//! - `404 Not Found` — blob row absent, blob bytes NULL (fetch-pending
//!   or evicted per §11.5), or no current locally-authored binding.
//!   §11.4 collapses "unknown", "evicted", and "edit-removal" into the
//!   same wire response by design; we do the same.
//! - `401 Unauthorized`, `415 Unsupported Media Type` — emitted by the
//!   §6.5 envelope middleware before the handler runs.
//!
//! Status codes from the §11.1 table that **don't** apply on the
//! serving side:
//!
//! - `413 Payload Too Large` — the spec explicitly notes this "should
//!   not occur for references the recipient just received" because
//!   feature-aware peers reject post-revs whose signed `size` exceeds
//!   the cap before the reference ever propagates. We never emit it.
//! - `429 Too Many Requests` — the §11.6 operational tunables
//!   (`ATTACHMENT_RPM_PER_PEER`, `ATTACHMENT_BYTES_PER_MIN_PER_PEER`)
//!   are not yet wired in; once they land they'll layer on top of
//!   this handler without changing its core behaviour.
//!
//! The §10.5.6 `410 Gone`-with-authority shape used by the by-hash
//! signed-object route is **not** applicable here: attachment blobs
//! are not signed objects, they have no erasure authority of their
//! own, and §11.4 directs that edit-removal / admin-rm cases collapse
//! to 404. The impl-plan's "410 with authority for removed" line
//! refers to that signed-object pattern; for blob bytes the §11
//! contract is 404 across the board.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::attachments::parse_hash_hex;
use crate::federation::errors::{internal_error, not_found};
use crate::signed::FedEnvelope;

/// §11.6 `ATTACHMENT_RPM_PER_PEER`: per-source-peer request cap inside
/// the limiter's rolling 60-second window. Generous relative to the
/// status/backfill routes — a single thread render can legitimately
/// fan out to dozens of distinct attachment GETs — but still bounds a
/// peer that loops on the route. Spec default; revisit on soak data.
pub const ATTACHMENT_RPM_PER_PEER: u32 = 600;

/// §11.6 `ATTACHMENT_BYTES_PER_MIN_PER_PEER`: per-source-peer served-
/// byte budget inside the same 60-second window. 50 MiB — the dominant
/// cost on this route is bytes on the wire, not request count, so this
/// is the budget that actually gates a peer draining large blobs.
pub const ATTACHMENT_BYTES_PER_MIN_PER_PEER: u64 = 50 * 1024 * 1024;

/// `GET /federation/v1/attachments/{hash}` handler (§11.1).
///
/// The `{hash}` segment is the lowercase hex form of the 32-byte
/// SHA-256 content hash per §3 URL encoding. Malformed hex collapses
/// to 404, matching §11.4's "we authoritatively don't have this".
pub async fn handle_attachment_fetch(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Path(hash_hex): Path<String>,
) -> Response {
    // §11.6 per-source-peer rate limit. Gated on entry — before any
    // hex-decode or DB work — so a peer that floods the route (even
    // with malformed hashes) is shed cheaply. The byte budget is
    // charged after a successful 200 below; an in-flight response that
    // tips the peer over still completes, and only subsequent requests
    // see the 429 (the fixed-window `try_admit` / `charge_bytes`
    // contract, identical to the §10.5.5 backfill limiter).
    if !state
        .attachment_serve_rate_limiter
        .try_admit(envelope.sender)
    {
        return too_many_requests();
    }

    // Hex decode — bad form is observationally indistinguishable from
    // "no such blob" per §11.4 (the spec collapses every "we don't
    // have it" sub-case into the same 404).
    let Some(hash) = parse_hash_hex(&hash_hex) else {
        return not_found("attachment_not_found");
    };
    let hash_bytes: Vec<u8> = hash.to_vec();

    // §11.5 origin-only check + blob fetch in one query. The
    // `EXISTS` subquery enforces that a current-revision,
    // non-retracted binding from a *locally-authored*, non-deleted
    // post references this hash; without that, even if the bytes
    // are resident (e.g. we fetched them ourselves while pulling
    // content from a peer), §11.5 forbids serving them across
    // federation.
    //
    // The canonical "locally-authored" predicate is
    // `posts.home_instance IS NULL` (migration
    // `..165755_add_home_instance_to_posts_and_threads.sql`): every
    // federated receive stamps the remote home's pubkey on the
    // `posts` row, and only locally-authored posts keep it NULL.
    // Keying on this — rather than on the author's `users` row
    // existing — closes the cross-instance-registered-local-user
    // hole where a user who registered here via §13 but authored a
    // post elsewhere would otherwise pass an `author IN users`
    // check despite the post's bytes belonging to that remote
    // instance's §11 origin.
    //
    // The `users.deleted_at IS NULL` clause is the Phase 9 (c)
    // defence-in-depth gate for the Phase 9.5 remote-author
    // hydration window: once remote authors land as `users` rows,
    // a `deactivate` (§10.3) propagating into our local stub MUST
    // stop the serve on the next request. It also gives us the
    // right behaviour for local users whose accounts were deleted
    // before the §7.b binding sweep ran: 404 immediately, don't
    // wait for the orphan-GC to catch up.
    let row = match sqlx::query!(
        r#"SELECT ab.blob,
                  ab.content_type AS "content_type!: String",
                  EXISTS (
                      SELECT 1
                        FROM post_attachments pa
                        JOIN posts p ON p.id = pa.post_id
                        JOIN users u ON u.id = p.author
                       WHERE pa.content_hash = ab.content_hash
                         AND pa.revision = p.revision_count - 1
                         AND p.retracted_at IS NULL
                         AND p.home_instance IS NULL
                         AND u.deleted_at IS NULL
                  ) AS "has_local_binding!: i64"
             FROM attachment_blobs ab
            WHERE ab.content_hash = ?"#,
        hash_bytes,
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(opt) => opt,
        Err(e) => {
            tracing::error!(error = %e, "db error reading attachment_blobs");
            return internal_error();
        }
    };

    // §11.4 sub-cases that collapse to 404:
    //   - blob row absent (we never stored this hash)
    //   - blob bytes NULL (fetch-pending or evicted per §11.5)
    //   - no current locally-authored binding (forwarding-cache rule)
    let Some(row) = row else {
        return not_found("attachment_not_found");
    };
    let Some(blob_bytes) = row.blob else {
        return not_found("attachment_not_found");
    };
    if row.has_local_binding == 0 {
        return not_found("attachment_not_found");
    }

    // §11.1 success shape: raw bytes + Content-Type from the
    // attachment record. Content-Length is derived by Axum from the
    // body and emitted automatically. We deliberately do NOT emit
    // Content-Disposition here — that's a UX header for browser-facing
    // `/api/attachments/{hash}` (see `attachments/serve.rs`); the
    // federation route serves machine consumers that hash-verify the
    // bytes per §11.3 and never render the filename.
    //
    // No Cache-Control: the §6 envelope's `created_at` + nonce already
    // bind the response to a specific request, and the recipient owns
    // its local cache policy per §11.5. Letting an upstream cache
    // intermediary hold the bytes would also defeat the envelope's
    // peer-binding intent.
    let content_type = match HeaderValue::from_str(&row.content_type) {
        Ok(v) => v,
        Err(e) => {
            // Stored MIMEs come from the §10.1 `ALLOWED_MIMES`
            // allowlist (all ASCII), so a non-header-safe value here
            // is a local-state corruption, not a wire issue.
            tracing::error!(
                error = %e,
                content_type = %row.content_type,
                "attachment_blobs.content_type is not a valid header value",
            );
            return internal_error();
        }
    };

    // §11.6 byte budget: charge the served payload to the source peer's
    // current window now that we know we're returning 200 with these
    // bytes. Errors / 404s above never reach here, so they cost a
    // request slot but no byte budget.
    state
        .attachment_serve_rate_limiter
        .charge_bytes(envelope.sender, blob_bytes.len() as u64);

    let mut response = (StatusCode::OK, Body::from(blob_bytes)).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
}

/// §11.6 `429 Too Many Requests` with `Retry-After: 60`. Empty body —
/// the `Retry-After` header is the only signal the sender consumes,
/// matching the §10.5.5 backfill limiter's overflow shape.
fn too_many_requests() -> Response {
    let mut r = (StatusCode::TOO_MANY_REQUESTS, "").into_response();
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_many_requests_carries_retry_after_60() {
        let r = too_many_requests();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            r.headers()
                .get(header::RETRY_AFTER)
                .unwrap()
                .to_str()
                .unwrap(),
            "60",
        );
    }
}
