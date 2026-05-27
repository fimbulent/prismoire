//! Content push handler (`docs/federation-protocol.md` §10).
//!
//! Mounts one route under `/federation/v1`:
//!
//! ```text
//! POST /federation/v1/content   (§10.1 push)
//! ```
//!
//! Behind `verify_known_peer`: per §6 the sender must be an `active`
//! peer. Body is `{ "objects": [WireFormat, ...] }` per §10.1; response
//! is `{ "results": [{ canonical_hash, status, reason? }, ...] }` in the
//! same array order as the request (senders correlate by position).
//!
//! ## Per-object state machine
//!
//! 1. WireFormat decode → `rejected/schema_invalid` on failure.
//! 2. Per-object size cap ([`MAX_POSTREV_SIZE`]) → `object_too_large`.
//! 3. `signed_objects` lookup — erased row → `rejected/erased`,
//!    live row → `duplicate`.
//! 4. `SignedPayload::parse` + class dispatch:
//!    - `post-rev` / `retract` / `admin-rm` / `profile` /
//!      `thread-create` / `deactivate` — accepted classes per §10.1.
//!    - `trust-edge` / `move` / `user-status` / `thread-status` /
//!      `report` — recognised but belong on a different route →
//!      `wrong_class`.
//!    - Anything else recognised but not on this route, or unrecognised
//!      → `unknown_class`.
//! 5. Ed25519 verify against the payload's author key.
//! 6. §10.4 receive-time admin-rm precedence check for `post-rev` /
//!    `retract`: lookup `admin_rm_authorities` by `post_id`. Match →
//!    `rejected/admin_removed`.
//! 7. Persist canonical bytes via `store_signed_object`. For the
//!    erasure-authority classes (`retract`, `admin-rm`, `deactivate`)
//!    cascade payload erasure per §10.1 "On-receipt erasure". For
//!    `admin-rm` additionally project into `admin_rm_authorities`.
//! 8. Applied → forward via §7.5 to other interested peers.
//!
//! ## Phase 6 explicit punts
//!
//! - **Deferred-orphan buffer.** A `post-rev` whose
//!   `prior_revision_hash` references a hash we don't yet have, or a
//!   `thread-create` awaiting its OP `post-rev`, returns
//!   `status: deferred` but is NOT persisted and triggers no
//!   autonomous backfill. Phase 8 will land the pending-validation
//!   buffer + autonomous `POST /backfill/by-hash` issuance.
//! - **Remote-author projection.** Edges.rs already takes the
//!   "store canonical bytes, skip projection when endpoints aren't
//!   local" punt for federated trust-edges; this module does the
//!   analogous thing for content classes. The bytes are durable for
//!   relay, audit, and `signed_objects` dedup; full hydration into
//!   `post_revisions` / `threads` / `profile_revisions` for remote
//!   authors waits on a later phase.
//! - **No `move` declaration resolution.** `apply_admin_rm`'s
//!   "are we the home of target_author?" check is a one-shot
//!   `users.public_key` lookup. A user who has filed a §3.2 `move`
//!   declaration off this instance is still treated as local; their
//!   new home's admin-rms route here as `wrong_route`. The supporting
//!   move-resolution table doesn't exist yet — Phase 7 introduces it.
//! - **Trust-on-first-claim authoritative admin-rm.** When the target
//!   author is NOT a local user (no `users` row), we accept the
//!   sender's `signing_instance` claim and project the admin-rm as
//!   authoritative. This trusts every active peer to correctly
//!   identify itself as the home of any remote user — a malicious
//!   peer could mass-erase content for users it does not host. The
//!   defense in depth comes from the §3.2 `move`-declaration chain
//!   that authoritatively names a user's current home; until that
//!   lookup is wired in, this is a Phase 6 known limitation against
//!   peer-on-peer abuse (operators MAY de-peer; protocol-level
//!   prevention is Phase 7+).
//!
//! ## §10.6 per-source rate limit (Phase 7 fold-in)
//!
//! The `/content` route is whole-batch rate-limited per source-instance
//! via [`ContentRateLimiter`], capped at
//! [`MAX_CONTENT_OBJECTS_PER_HOUR`] objects/hour/source. A push that
//! would exceed the budget returns `400 { "error": "rate_limited" }`
//! before per-object processing. Closes the Phase-6 abuse-window punt
//! (a single peer could otherwise sustain `MAX_CONTENT_BATCH = 64`
//! objects per request indefinitely).
//!
//! [`ContentRateLimiter`]: crate::federation::content_rate_limit::ContentRateLimiter
//! [`MAX_CONTENT_OBJECTS_PER_HOUR`]: crate::federation::content_rate_limit::MAX_CONTENT_OBJECTS_PER_HOUR

use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AppState;
use crate::federation::envelope::decode_signed_object;
use crate::federation::errors::{bad_request, internal_error};
use crate::federation::forwarder::forward_signed_object;
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::middleware::VerifiedBody;
use crate::federation::routing::ForwardingClass;
use crate::signed::{self, FedEnvelope, SignedPayload};
use crate::signing::{erase_post_rev_payloads, store_signed_object};

/// §10.6 `MAX_CONTENT_BATCH`: receiver-enforced object-count cap.
/// Overflow returns `400 { "error": "batch_too_large" }`.
pub const MAX_CONTENT_BATCH: usize = 64;

/// §10.6 `MAX_POSTREV_SIZE`: per-object byte cap. A WireFormat blob
/// larger than this is rejected with `object_too_large`; the rest of
/// the batch may still apply.
pub const MAX_POSTREV_SIZE: usize = 512 * 1024;

// ---------------------------------------------------------------------------
// Per-object result vocabulary (§10.1)
// ---------------------------------------------------------------------------

/// Top-level status per the §10.1 result table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentStatus {
    Applied,
    Duplicate,
    Deferred,
    Rejected(ContentRejectReason),
}

impl ContentStatus {
    fn status_tag(&self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Duplicate => "duplicate",
            Self::Deferred => "deferred",
            Self::Rejected(_) => "rejected",
        }
    }

    fn reason_tag(&self) -> Option<&'static str> {
        match self {
            Self::Rejected(r) => Some(r.as_str()),
            _ => None,
        }
    }
}

/// The §10.1 enumerated `reason` vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentRejectReason {
    InvalidSignature,
    SchemaInvalid,
    UnknownAuthorKey,
    ObjectTooLarge,
    WrongRoute,
    WrongClass,
    UnknownClass,
    ThreadLocked,
    DeactivatedAuthor,
    AdminRemoved,
    Erased,
    UnauthorizedSigner,
}

impl ContentRejectReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid_signature",
            Self::SchemaInvalid => "schema_invalid",
            Self::UnknownAuthorKey => "unknown_author_key",
            Self::ObjectTooLarge => "object_too_large",
            Self::WrongRoute => "wrong_route",
            Self::WrongClass => "wrong_class",
            Self::UnknownClass => "unknown_class",
            Self::ThreadLocked => "thread_locked",
            Self::DeactivatedAuthor => "deactivated_author",
            Self::AdminRemoved => "admin_removed",
            Self::Erased => "erased",
            Self::UnauthorizedSigner => "unauthorized_signer",
        }
    }
}

/// One row of the §10.1 `results` array.
struct ContentResult {
    canonical_hash: [u8; 32],
    status: ContentStatus,
}

// ---------------------------------------------------------------------------
// Request body decoder
// ---------------------------------------------------------------------------

/// Decoded view of the §10.1 push body.
///
/// Each element is the raw WireFormat bytes for one object. Same
/// `bstr`-per-element invariant as `edges.rs::EdgesBody` (the receiver
/// must re-hash the bytes verbatim, so wrapping each in `bstr`
/// preserves them across re-encode round-trips).
struct ContentBody {
    objects: Vec<Vec<u8>>,
}

impl ContentBody {
    fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        // Strict map decode: reject non-text keys, duplicate keys,
        // and unknown top-level keys. Mirrors `envelope::decode_signed_object`
        // strictness so an attacker can't smuggle ambiguous bodies past
        // the receiver (e.g. two `objects` arrays where only one is
        // sniffable by a deep inspector).
        let mut objects_field: Option<Vec<Value>> = None;
        for (k, v) in entries {
            let key = match k {
                Value::Text(s) => s,
                _ => return None,
            };
            match key.as_str() {
                "objects" => {
                    if objects_field.is_some() {
                        return None;
                    }
                    match v {
                        Value::Array(a) => objects_field = Some(a),
                        _ => return None,
                    }
                }
                _ => return None,
            }
        }
        let arr = objects_field?;
        let mut objects = Vec::with_capacity(arr.len());
        for item in arr {
            match item {
                Value::Bytes(b) => objects.push(b),
                _ => return None,
            }
        }
        Some(Self { objects })
    }
}

// ---------------------------------------------------------------------------
// Response encoder
// ---------------------------------------------------------------------------

fn encode_results(results: &[ContentResult]) -> Vec<u8> {
    let arr: Vec<Value> = results
        .iter()
        .map(|r| {
            let mut entries: Vec<(Value, Value)> = vec![
                (
                    Value::Text("canonical_hash".into()),
                    Value::Bytes(r.canonical_hash.to_vec()),
                ),
                (
                    Value::Text("status".into()),
                    Value::Text(r.status.status_tag().into()),
                ),
            ];
            if let Some(reason) = r.status.reason_tag() {
                entries.push((Value::Text("reason".into()), Value::Text(reason.into())));
            }
            Value::Map(entries)
        })
        .collect();

    let body = Value::Map(vec![(Value::Text("results".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + 64 * results.len());
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    buf
}

fn results_response(results: Vec<ContentResult>) -> Response {
    let body = encode_results(&results);
    let mut r = (StatusCode::OK, body).into_response();
    r.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    r
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `POST /federation/v1/content` handler (§10.1).
pub async fn handle_content_push(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let parsed = match ContentBody::decode(&body) {
        Some(p) => p,
        None => return bad_request("malformed"),
    };
    if parsed.objects.is_empty() {
        return bad_request("empty_batch");
    }
    if parsed.objects.len() > MAX_CONTENT_BATCH {
        return bad_request("batch_too_large");
    }
    // §10.6 fold-in (Phase 7): per-source rolling-hour object cap.
    // Whole-batch reject on overflow — simplest backpressure signal that
    // lets a well-behaved sender drop into backoff rather than retrying
    // object-by-object. A rejected batch does not burn budget.
    if !state
        .content_rate_limiter
        .check_and_count(envelope.sender, parsed.objects.len() as u32)
    {
        return bad_request("rate_limited");
    }

    let mut results: Vec<ContentResult> = Vec::with_capacity(parsed.objects.len());
    for wire_bytes in &parsed.objects {
        let result = match apply_one_object(&state, wire_bytes, envelope.sender).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "db error applying federated content object");
                return internal_error();
            }
        };
        results.push(result);
    }

    results_response(results)
}

/// Resolve the canonical instance_domain for a peer pubkey.
///
/// Takes an executor (not `&AppState`) so callers in the middle of an
/// open transaction can use the same connection — the SQLite pool is
/// configured `max_connections = 1` in tests (and contention-bounded
/// in prod), so a second-connection fetch from inside an open tx
/// deadlocks under load.
async fn peer_domain_for<'e, E: sqlx::SqliteExecutor<'e>>(
    executor: E,
    pubkey: &[u8; 32],
) -> Result<Option<String>, sqlx::Error> {
    let key_slice: &[u8] = pubkey.as_slice();
    let row = sqlx::query!(
        "SELECT instance_domain FROM peers WHERE instance_pubkey = ?",
        key_slice,
    )
    .fetch_optional(executor)
    .await?;
    Ok(row.map(|r| r.instance_domain))
}

/// Apply a single signed WireFormat blob against local state.
async fn apply_one_object(
    state: &Arc<AppState>,
    wire_bytes: &[u8],
    arrived_from: [u8; 32],
) -> Result<ContentResult, sqlx::Error> {
    // Step 1: per-object byte cap. §10.1 says `object_too_large` is a
    // *per-object* rejection, not a request-level fail — the rest of
    // the batch may still apply. Counted on the raw WireFormat bytes
    // since that's what's on the wire.
    if wire_bytes.len() > MAX_POSTREV_SIZE {
        return Ok(ContentResult {
            canonical_hash: sha256(wire_bytes),
            status: ContentStatus::Rejected(ContentRejectReason::ObjectTooLarge),
        });
    }

    // Step 2: WireFormat decode.
    let (payload_bytes, signature_bytes) = match decode_signed_object(wire_bytes) {
        Some(p) => p,
        None => {
            return Ok(ContentResult {
                canonical_hash: sha256(wire_bytes),
                status: ContentStatus::Rejected(ContentRejectReason::SchemaInvalid),
            });
        }
    };
    let canonical_hash = sha256(&payload_bytes);

    // Step 3: signed_objects dedup / erasure check.
    let hash_slice: &[u8] = canonical_hash.as_slice();
    let existing = sqlx::query!(
        "SELECT erased_at, (payload IS NULL) AS \"payload_null!: i64\" \
         FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_optional(&state.db)
    .await?;
    if let Some(row) = existing {
        if row.erased_at.is_some() || row.payload_null != 0 {
            return Ok(ContentResult {
                canonical_hash,
                status: ContentStatus::Rejected(ContentRejectReason::Erased),
            });
        }
        return Ok(ContentResult {
            canonical_hash,
            status: ContentStatus::Duplicate,
        });
    }

    // Step 4: parse + class dispatch.
    let payload = match SignedPayload::parse(&payload_bytes) {
        Ok(p) => p,
        Err(_) => {
            return Ok(ContentResult {
                canonical_hash,
                status: ContentStatus::Rejected(ContentRejectReason::SchemaInvalid),
            });
        }
    };

    // Per-class dispatch yields the inner-class string for
    // `store_signed_object` plus the author key for signature
    // verification. Classes that don't belong on /content collapse to
    // `wrong_class` (when there's a correct route) or `unknown_class`.
    let (inner_class, author_key, class_action) = match &payload {
        SignedPayload::PostRevision(p) => ("post-rev", p.author, ClassAction::PostRev(p.post_id)),
        SignedPayload::Retraction(r) => ("retract", r.author, ClassAction::Retract(r.post_id)),
        SignedPayload::AdminRemoval(a) => (
            "admin-rm",
            // admin-rm is instance-signed: the author key for
            // verification is the signing instance's pubkey, resolved
            // by domain. We look that up below in handle_admin_rm.
            [0u8; 32],
            ClassAction::AdminRm(
                a.post_id,
                a.target_author,
                a.signing_instance.clone(),
                a.created_at,
            ),
        ),
        SignedPayload::ProfileRevision(p) => ("profile", p.user, ClassAction::Profile),
        SignedPayload::ThreadCreate(t) => ("thread-create", t.author, ClassAction::ThreadCreate),
        SignedPayload::Deactivation(d) => ("deactivate", d.user, ClassAction::Deactivate(d.user)),
        // Classes recognised but belonging on a different route.
        SignedPayload::TrustEdge(_)
        | SignedPayload::Move(_)
        | SignedPayload::UserStatus(_)
        | SignedPayload::ThreadStatus(_)
        | SignedPayload::Report(_)
        | SignedPayload::Attestation(_) => {
            return Ok(ContentResult {
                canonical_hash,
                status: ContentStatus::Rejected(ContentRejectReason::WrongClass),
            });
        }
        // Ephemeral classes have no business on a push route at all.
        SignedPayload::FedEnvelope(_)
        | SignedPayload::RegistrationChallenge(_)
        | SignedPayload::RecoveryChallenge(_)
        | SignedPayload::RecoveryResponse(_) => {
            return Ok(ContentResult {
                canonical_hash,
                status: ContentStatus::Rejected(ContentRejectReason::UnknownClass),
            });
        }
    };

    // Step 5: signature verification. admin-rm is special-cased
    // (instance-signed) and re-resolves the author_key inside the
    // class-action branch below; every other class binds the author
    // pubkey into the payload directly.
    if !matches!(class_action, ClassAction::AdminRm(..)) {
        let vk = match VerifyingKey::from_bytes(&author_key) {
            Ok(k) => k,
            Err(_) => {
                return Ok(ContentResult {
                    canonical_hash,
                    status: ContentStatus::Rejected(ContentRejectReason::InvalidSignature),
                });
            }
        };
        if signed::verify(&payload_bytes, &signature_bytes, &vk).is_err() {
            return Ok(ContentResult {
                canonical_hash,
                status: ContentStatus::Rejected(ContentRejectReason::InvalidSignature),
            });
        }
    }

    // Step 6: §10.4 receive-time admin-rm precedence check for
    // post-rev / retract — an authoritative admin-rm we already
    // accepted blocks re-acceptance of any post-rev / retract for the
    // same post_id.
    match &class_action {
        ClassAction::PostRev(post_id) | ClassAction::Retract(post_id) => {
            if admin_rm_blocks(&state.db, post_id).await? {
                return Ok(ContentResult {
                    canonical_hash,
                    status: ContentStatus::Rejected(ContentRejectReason::AdminRemoved),
                });
            }
        }
        _ => {}
    }

    // Step 7: persist + cascade effects under BEGIN IMMEDIATE so the
    // erasure cascades observe the just-inserted authority.
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    let status = match class_action {
        ClassAction::AdminRm(post_id, target_author, signing_instance, created_at_ms) => {
            apply_admin_rm(
                &mut tx,
                arrived_from,
                &payload_bytes,
                &signature_bytes,
                &canonical_hash,
                post_id,
                target_author,
                &signing_instance,
                created_at_ms,
            )
            .await?
        }
        ClassAction::Retract(post_id) => {
            store_signed_object(
                &mut *tx,
                inner_class,
                &payload_bytes,
                &signature_bytes,
                &canonical_hash,
            )
            .await?;
            // §10.1 on-receipt erasure: erase every post-rev payload
            // for the named post_id. Uses the text-uuid form because
            // post_revisions / posts store post_id as text-uuid. The
            // retract is itself the erasure authority recorded against
            // each NULLed row (§10.5.3 410-Gone forward-link).
            let post_id_text = Uuid::from_bytes(post_id).to_string();
            erase_post_rev_payloads(&mut *tx, &post_id_text, Some(&canonical_hash)).await?;
            ContentStatus::Applied
        }
        ClassAction::Deactivate(user_key) => {
            store_signed_object(
                &mut *tx,
                inner_class,
                &payload_bytes,
                &signature_bytes,
                &canonical_hash,
            )
            .await?;
            erase_all_for_user_key(&mut tx, &user_key, &canonical_hash).await?;
            ContentStatus::Applied
        }
        ClassAction::PostRev(_) | ClassAction::Profile | ClassAction::ThreadCreate => {
            // Phase 6 punt: store canonical bytes only. Full local
            // projection (post_revisions / profile_revisions /
            // threads rows for remote authors) waits on remote-user
            // stub hydration in a later phase. Same shape as
            // edges.rs's "no projection target → store and call it
            // applied".
            store_signed_object(
                &mut *tx,
                inner_class,
                &payload_bytes,
                &signature_bytes,
                &canonical_hash,
            )
            .await?;
            ContentStatus::Applied
        }
    };

    tx.commit().await?;

    // §7.5 fan out applied objects to other interested peers. Skip
    // duplicates and rejected results — matching edges.rs.
    if matches!(status, ContentStatus::Applied) {
        // Routing key per §7.4: author pubkey for every Authored
        // class. admin-rm's routing key is the target post's author,
        // which we already used as `author_key` above for the non-
        // admin-rm path; here we re-derive it from the parsed payload
        // (we have it via class_action; lift it explicitly).
        let routing_key = routing_key_for(&payload);
        forward_signed_object(
            state.clone(),
            canonical_hash,
            ForwardingClass::Authored,
            routing_key,
            wire_bytes.to_vec(),
            Some(arrived_from),
        )
        .await;
    }

    Ok(ContentResult {
        canonical_hash,
        status,
    })
}

/// Inner per-class dispatch state. Keeps `apply_one_object` linear
/// without exploding the parsed `SignedPayload` enum across half the
/// function body.
enum ClassAction {
    PostRev([u8; 16]),
    Retract([u8; 16]),
    /// `(post_id, target_author, signing_instance, created_at_ms)` —
    /// `created_at_ms` is threaded through from the already-parsed
    /// payload so the `admin_rm_authorities` projection doesn't have
    /// to re-decode the canonical bytes (and silently fall back to 0
    /// on parse failure, which would corrupt the operator-visible
    /// removal timestamp).
    AdminRm([u8; 16], [u8; 32], String, u64),
    Profile,
    ThreadCreate,
    Deactivate([u8; 32]),
}

/// §7.4 routing key derivation. For every content class the key is
/// the author pubkey (admin-rm uses the target post's author). For
/// admin-rm we extract `target_author` from the parsed payload; for
/// every other class the key is the standard author field.
fn routing_key_for(payload: &SignedPayload) -> Vec<u8> {
    match payload {
        SignedPayload::PostRevision(p) => p.author.to_vec(),
        SignedPayload::Retraction(r) => r.author.to_vec(),
        SignedPayload::AdminRemoval(a) => a.target_author.to_vec(),
        SignedPayload::ProfileRevision(p) => p.user.to_vec(),
        SignedPayload::ThreadCreate(t) => t.author.to_vec(),
        SignedPayload::Deactivation(d) => d.user.to_vec(),
        // Other variants never reach the forwarder from this module
        // (they hit `wrong_class` / `unknown_class` and never get a
        // `ContentStatus::Applied`). The debug_assert makes this an
        // invariant in debug builds; release falls through to an
        // empty routing key, which the forwarder treats as "no
        // interested peers" rather than panicking.
        _ => {
            debug_assert!(
                false,
                "routing_key_for called on non-content class — \
                 handler dispatch should have rejected this before applied",
            );
            Vec::new()
        }
    }
}

/// §10.4 receive-time admin-rm precedence: returns true iff an
/// authoritative admin-rm has already been projected against this
/// post. Indexed lookup against the `admin_rm_authorities` table
/// (PK on `post_id`).
async fn admin_rm_blocks(db: &sqlx::SqlitePool, post_id: &[u8; 16]) -> Result<bool, sqlx::Error> {
    let pid: &[u8] = post_id.as_slice();
    let row = sqlx::query_scalar!(
        "SELECT 1 AS \"present!: i64\" FROM admin_rm_authorities WHERE post_id = ? LIMIT 1",
        pid,
    )
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// Apply an admin-rm received over `/content`.
///
/// §10.4 disposition:
/// - **Advisory** (signer ≠ author's home). On `/content` this is
///   `wrong_route` per §10.1; the sender must retry via
///   `/admin-rm-report`.
/// - **Authoritative** (signer == author's home). Verify the inner
///   instance signature against the sender's pubkey (the envelope
///   sender == the signer for the admin-rm we're processing on this
///   route — the sender is the home and the home is the signer).
///   Persist, erase the target post's revisions, project into
///   `admin_rm_authorities`.
///
/// "Are we the home of target_author?" is the simple heuristic we
/// use to identify advisory traffic at this layer: a local `users`
/// row for `target_author` means we host that user → an admin-rm
/// from anyone else is advisory by definition. Without a local row
/// we cannot tell, so we trust the sender's `signing_instance`
/// claim and accept the admin-rm as authoritative.
#[allow(clippy::too_many_arguments)]
async fn apply_admin_rm(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    arrived_from: [u8; 32],
    payload_bytes: &[u8],
    signature_bytes: &[u8],
    canonical_hash: &[u8; 32],
    post_id: [u8; 16],
    target_author: [u8; 32],
    signing_instance: &str,
    created_at_ms: u64,
) -> Result<ContentStatus, sqlx::Error> {
    // Wrong-route check: we host the target author → this admin-rm
    // can only ever be advisory; sender should have used the §10.4
    // advisory route.
    let target_slice: &[u8] = target_author.as_slice();
    let target_local = sqlx::query_scalar!(
        "SELECT 1 AS \"present!: i64\" FROM users WHERE public_key = ? LIMIT 1",
        target_slice,
    )
    .fetch_optional(&mut **tx)
    .await?;
    if target_local.is_some() {
        return Ok(ContentStatus::Rejected(ContentRejectReason::WrongRoute));
    }

    // Verify the inner instance signature. The signer MUST be the
    // envelope sender (the home is the signer, the sender is the
    // home), and `signing_instance` must match the sender's recorded
    // domain.
    // Use the open-tx connection so the pool's max-connection cap
    // (1 in tests) doesn't deadlock against the still-held tx.
    let sender_domain = match peer_domain_for(&mut **tx, &arrived_from).await? {
        Some(d) => d,
        None => {
            // Defensive: known_peer middleware already gated this,
            // but rather than panic surface as unauthorized_signer
            // so the per-object rejection is visible to the sender.
            return Ok(ContentStatus::Rejected(
                ContentRejectReason::UnauthorizedSigner,
            ));
        }
    };
    if sender_domain != signing_instance {
        return Ok(ContentStatus::Rejected(
            ContentRejectReason::UnauthorizedSigner,
        ));
    }
    let vk = match VerifyingKey::from_bytes(&arrived_from) {
        Ok(k) => k,
        Err(_) => {
            return Ok(ContentStatus::Rejected(
                ContentRejectReason::InvalidSignature,
            ));
        }
    };
    if signed::verify(payload_bytes, signature_bytes, &vk).is_err() {
        return Ok(ContentStatus::Rejected(
            ContentRejectReason::InvalidSignature,
        ));
    }

    // Persist canonical bytes.
    store_signed_object(
        &mut **tx,
        "admin-rm",
        payload_bytes,
        signature_bytes,
        canonical_hash,
    )
    .await?;

    // Erase the named post's revisions (§10.1 on-receipt erasure).
    // The post_revisions / posts tables use text-uuid for post_id.
    // The admin-rm canonical hash is recorded as `erased_by` so the
    // §10.5.3 410-Gone path can return it as the authority.
    let post_id_text = Uuid::from_bytes(post_id).to_string();
    erase_post_rev_payloads(&mut **tx, &post_id_text, Some(canonical_hash)).await?;

    // §10.4 receive-time precedence projection. PK on `post_id`
    // enforces first-and-only semantics. The early signed_objects
    // dedup at step 3 catches *byte-identical* replays, but two
    // distinct admin-rms targeting the same post_id (different
    // signers, or same signer with different `created_at`) would
    // both pass that check and race here. `INSERT OR IGNORE` keeps
    // the §10.4 "first authoritative wins" rule on PK collision —
    // both signed-object byte rows persist (different canonical_hash)
    // for audit + relay, but only the first projection wins.
    let post_id_bytes: Vec<u8> = post_id.to_vec();
    let target_author_db: Vec<u8> = target_author.to_vec();
    let canonical_hash_db: Vec<u8> = canonical_hash.to_vec();
    let created_at_db = created_at_ms as i64;
    sqlx::query!(
        "INSERT OR IGNORE INTO admin_rm_authorities \
         (post_id, target_author, signing_instance, created_at, canonical_hash) \
         VALUES (?, ?, ?, ?, ?)",
        post_id_bytes,
        target_author_db,
        signing_instance,
        created_at_db,
        canonical_hash_db,
    )
    .execute(&mut **tx)
    .await?;

    Ok(ContentStatus::Applied)
}

/// Cascade payload erasure for a `deactivate`: NULL the
/// `signed_objects.payload` bytes of every signed object whose
/// author key is `user_key`, across every class. Matches the §3.1
/// "deactivate is terminal" semantics: receivers retain hashes /
/// signatures for chain walks and audit but the readable content is
/// gone.
///
/// Strategy: enumerate the candidate `canonical_hash` set by
/// scanning every local-projection table that records an author
/// pubkey, then NULL the payloads. `trust_edges` / `profile_revisions`
/// already have dedicated helpers (`erase_user_trust_edge_payloads`
/// / `erase_user_profile_revision_payloads`) but they take a user_id
/// (text-uuid), which we may not have for a remote author. The wider
/// helper below works on the inner author key directly.
async fn erase_all_for_user_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_key: &[u8; 32],
    authority_hash: &[u8; 32],
) -> Result<(), sqlx::Error> {
    let key_slice: &[u8] = user_key.as_slice();

    // Resolve the local users.id (if any) so we can drive the
    // existing per-table erasure helpers. For remote authors no row
    // exists; the post-rev / profile / trust-edge tables FK to
    // users.id so they don't carry projection rows for that author
    // either — there's nothing local to NULL via projection lookup.
    let user_id: Option<String> =
        sqlx::query_scalar!("SELECT id FROM users WHERE public_key = ?", key_slice,)
            .fetch_optional(&mut **tx)
            .await?;

    if let Some(uid) = user_id {
        crate::signing::erase_user_trust_edge_payloads(&mut **tx, &uid, Some(authority_hash))
            .await?;
        crate::signing::erase_user_profile_revision_payloads(&mut **tx, &uid, Some(authority_hash))
            .await?;
        // Erase every post-rev payload the user authored. Subquery
        // walks `posts WHERE author = uid` to find the post ids,
        // then `post_revisions` to find the canonical hashes. The
        // deactivate canonical_hash is recorded as `erased_by` so the
        // §10.5.3 410-Gone path can return it as the authority.
        let authority_slice: &[u8] = authority_hash.as_slice();
        sqlx::query!(
            "UPDATE signed_objects \
             SET payload = NULL, \
                 erased_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
                 erased_by = COALESCE(erased_by, ?) \
             WHERE payload IS NOT NULL \
               AND canonical_hash IN ( \
                   SELECT pr.canonical_hash FROM post_revisions pr \
                   JOIN posts p ON p.id = pr.post_id \
                   WHERE p.author = ? \
               )",
            authority_slice,
            uid,
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Layer-0 unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_response_uses_spec_status_tags() {
        let results = vec![
            ContentResult {
                canonical_hash: [1u8; 32],
                status: ContentStatus::Applied,
            },
            ContentResult {
                canonical_hash: [2u8; 32],
                status: ContentStatus::Duplicate,
            },
            ContentResult {
                canonical_hash: [3u8; 32],
                status: ContentStatus::Deferred,
            },
            ContentResult {
                canonical_hash: [4u8; 32],
                status: ContentStatus::Rejected(ContentRejectReason::AdminRemoved),
            },
            ContentResult {
                canonical_hash: [5u8; 32],
                status: ContentStatus::Rejected(ContentRejectReason::WrongClass),
            },
        ];
        let bytes = encode_results(&results);
        let v: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let Value::Map(m) = v else {
            panic!("top-level not a map");
        };
        let results_field = m
            .into_iter()
            .find_map(|(k, v)| match k {
                Value::Text(t) if t == "results" => Some(v),
                _ => None,
            })
            .expect("results key");
        let Value::Array(arr) = results_field else {
            panic!("results not an array");
        };
        assert_eq!(arr.len(), 5);

        let expected: &[(usize, &str, Option<&str>)] = &[
            (0, "applied", None),
            (1, "duplicate", None),
            (2, "deferred", None),
            (3, "rejected", Some("admin_removed")),
            (4, "rejected", Some("wrong_class")),
        ];
        for (idx, want_status, want_reason) in expected {
            let Value::Map(entries) = &arr[*idx] else {
                panic!("result entry not a map");
            };
            let mut got_status: Option<String> = None;
            let mut got_reason: Option<String> = None;
            for (k, v) in entries {
                if let Value::Text(t) = k {
                    match (t.as_str(), v) {
                        ("status", Value::Text(s)) => got_status = Some(s.clone()),
                        ("reason", Value::Text(s)) => got_reason = Some(s.clone()),
                        _ => {}
                    }
                }
            }
            assert_eq!(got_status.as_deref(), Some(*want_status), "status[{idx}]");
            assert_eq!(got_reason.as_deref(), *want_reason, "reason[{idx}]");
        }
    }

    #[test]
    fn content_body_decoder_accepts_bstr_elements() {
        let body = Value::Map(vec![(
            Value::Text("objects".into()),
            Value::Array(vec![Value::Bytes(vec![0xaa, 0xbb])]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let parsed = ContentBody::decode(&buf).expect("decode");
        assert_eq!(parsed.objects.len(), 1);
        assert_eq!(parsed.objects[0], vec![0xaa, 0xbb]);
    }

    #[test]
    fn content_body_decoder_rejects_non_bstr_elements() {
        let body = Value::Map(vec![(
            Value::Text("objects".into()),
            Value::Array(vec![Value::Map(vec![])]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert!(ContentBody::decode(&buf).is_none());
    }
}
