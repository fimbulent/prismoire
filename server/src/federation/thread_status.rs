//! Thread-status push + chain-backfill handlers
//! (`docs/federation-protocol.md` §17).
//!
//! Mounts two routes under `/federation/v1`, both behind
//! `verify_known_peer`:
//!
//! ```text
//! POST /federation/v1/thread-status          (§17.1 push)
//! POST /federation/v1/thread-status/by-hash  (§17.3 chain backfill)
//! ```
//!
//! Thread-status objects are **instance-issued claims by the thread's
//! home instance** (§17). Unlike user-status, authority does NOT follow
//! user moves — the home is fixed at thread creation. They propagate by
//! **selective multi-hop gossip** (§17.2) over the §7.5 machinery, and
//! authority is anchored to the object's **inner signature** against the
//! thread's home pubkey, not the forwarding peer's envelope identity. A
//! locked status must take effect everywhere: when the thread is known
//! locally the handler mirrors the resolved lock state into
//! `threads.locked` so the existing reply-rejection path honours
//! federated locks (§17.4).
//!
//! ## Per-object state machine (§17.1)
//!
//! 1. WireFormat decode → `rejected/schema_invalid`.
//! 2. `signed_objects` dedup → `duplicate`.
//! 3. parse + class dispatch → `rejected/unknown_class` or
//!    `rejected/schema_invalid`.
//! 4. Thread-home authority: resolve the thread's home from the local
//!    `threads` row (`home_instance`, NULL = this instance). No local
//!    `threads` row → `deferred` (§17.1 missing-thread-create sub-case;
//!    autonomous backfill is the documented follow-up).
//! 5. Ed25519 verify the inner signature against the resolved home
//!    pubkey (NOT `envelope.sender` — under §17.2 gossip the sender is
//!    an arbitrary forwarding peer) → `invalid_signature`.
//! 6. Advisory `signing_instance` cross-check: if the home's domain is
//!    locally known, the declared `signing_instance` must match it →
//!    `unauthorized_signer`. For a home reached only transitively via
//!    gossip the label is accepted; the pubkey check is authoritative.
//! 7. Chain-grounding: a `Some(prior_status_hash)` must reference a
//!    stored `thread-status` predecessor, else `deferred`.
//! 8. §17.3 latest-wins (ties by canonical_hash, smaller wins) against
//!    `thread_statuses`. Winner UPSERTs the projection (`applied`) and
//!    mirrors `threads.locked`; loser is `superseded`. Both persist
//!    canonical bytes.
//! 9. Tier-2 gossip forward (§17.2): an `applied` or `superseded`
//!    object is relayed onward via [`forward_signed_object`] (key =
//!    `author(thread)`, class [`ForwardingClass::ThreadStatus`]),
//!    subject to the per-inner-signer amplification cap.

use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;
use crate::federation::envelope::{decode_signed_object, encode_signed_object};
use crate::federation::errors::{bad_request, internal_error};
use crate::federation::forwarder::forward_signed_object;
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::middleware::VerifiedBody;
use crate::federation::push_rate_limit::push_too_many_requests;
use crate::federation::routing::ForwardingClass;
use crate::federation::user_status::resolve_domain_for_key;
use crate::signed::{self, FedEnvelope, ParseError, SignedPayload, ThreadStatusKind};
use crate::signing::{sign_thread_status_with_key, store_signed_object};

/// §17.5 `MAX_THREAD_STATUS_BATCH`: per-push object-count cap.
pub const MAX_THREAD_STATUS_BATCH: usize = 256;

/// §17.5 `MAX_THREAD_STATUS_HASHES`: per-backfill hash-list cap.
pub const MAX_THREAD_STATUS_HASHES: usize = 50;

// ---------------------------------------------------------------------------
// Per-object result vocabulary (§17.1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadStatusResultKind {
    Applied,
    Duplicate,
    Deferred,
    Superseded,
    Rejected(ThreadStatusRejectReason),
}

impl ThreadStatusResultKind {
    fn status_tag(&self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Duplicate => "duplicate",
            Self::Deferred => "deferred",
            Self::Superseded => "superseded",
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

/// §17.1 enumerated `reason` vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadStatusRejectReason {
    InvalidSignature,
    SchemaInvalid,
    UnauthorizedSigner,
    UnknownClass,
}

impl ThreadStatusRejectReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid_signature",
            Self::SchemaInvalid => "schema_invalid",
            Self::UnauthorizedSigner => "unauthorized_signer",
            Self::UnknownClass => "unknown_class",
        }
    }
}

struct ThreadStatusResult {
    canonical_hash: [u8; 32],
    status: ThreadStatusResultKind,
}

// ---------------------------------------------------------------------------
// Request body decoder
// ---------------------------------------------------------------------------

/// Decoded view of the §17.1 push body: `{ "objects": [bstr, ...] }`.
struct ObjectsBody {
    objects: Vec<Vec<u8>>,
}

impl ObjectsBody {
    fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
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
// Response encoders
// ---------------------------------------------------------------------------

fn encode_results(results: &[ThreadStatusResult]) -> Vec<u8> {
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

fn cbor_ok(body: Vec<u8>) -> Response {
    let mut r = (StatusCode::OK, body).into_response();
    r.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    r
}

// ---------------------------------------------------------------------------
// Push handler (§17.1)
// ---------------------------------------------------------------------------

/// `POST /federation/v1/thread-status` handler (§17.1).
pub async fn handle_thread_status_push(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    // §17.5 per-peer per-minute request budget. Gate before any
    // decode/DB work so an over-quota peer is shed cheaply.
    if !state.thread_status_rate_limiter.try_admit(envelope.sender) {
        return push_too_many_requests();
    }
    let parsed = match ObjectsBody::decode(&body) {
        Some(p) => p,
        None => return bad_request("malformed"),
    };
    if parsed.objects.is_empty() {
        return bad_request("empty_batch");
    }
    if parsed.objects.len() > MAX_THREAD_STATUS_BATCH {
        return bad_request("batch_too_large");
    }

    let mut results: Vec<ThreadStatusResult> = Vec::with_capacity(parsed.objects.len());
    for wire_bytes in &parsed.objects {
        let result = match apply_one_thread_status(&state, wire_bytes, &envelope.sender).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "db error applying federated thread-status");
                return internal_error();
            }
        };
        results.push(result);
    }

    cbor_ok(encode_results(&results))
}

// ---------------------------------------------------------------------------
// Producer (§17 origination) — local home → gossip fabric
// ---------------------------------------------------------------------------

/// §17 producer: sign a `thread-status` for a thread **homed on this
/// instance** and inject it into the §17.2 selective-gossip fabric.
///
/// No-op (returns `Ok(())`) when the thread is unknown locally or is
/// homed elsewhere — only the thread's home may issue its status, and a
/// receiver would reject a foreign-issued one (`unauthorized_signer`).
/// The admin lock/unlock handlers that wrap this already update the
/// local `threads.locked` enforcement column; this producer only emits
/// the federated object, so it does not touch `threads.locked`.
///
/// Flow mirrors [`crate::federation::user_status::dispatch_local_user_status`]:
/// chain onto the thread's current status head, sign with the instance
/// key, persist canonical bytes, advance the `thread_statuses`
/// projection head, then [`forward_signed_object`] as originator with
/// key = `author(thread)` (the §17.2 routing key) and class
/// [`ForwardingClass::ThreadStatus`].
pub async fn dispatch_local_thread_status(
    state: &Arc<AppState>,
    thread_id: &Uuid,
    status: ThreadStatusKind,
    reason: Option<&str>,
) -> Result<(), AppError> {
    let thread_id_text = thread_id.to_string();

    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    // Resolve the OP author (the §17.2 routing key) and confirm we home
    // the thread (`home_instance IS NULL`). A foreign-homed or unknown
    // thread is not ours to issue status for.
    let thread_row = sqlx::query!(
        "SELECT t.home_instance AS \"home_instance?: Vec<u8>\", \
                u.public_key AS \"author_pubkey!: Vec<u8>\" \
         FROM threads t JOIN users u ON u.id = t.author WHERE t.id = ?",
        thread_id_text,
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(thread_row) = thread_row else {
        return Ok(());
    };
    if thread_row.home_instance.is_some() {
        // Homed elsewhere — not our status to issue.
        return Ok(());
    }
    let author_pubkey: Vec<u8> = thread_row.author_pubkey;

    let created_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Chain onto the thread's current status head, if one exists.
    let thread_id_bytes = *thread_id.as_bytes();
    let thread_id_slice: &[u8] = thread_id_bytes.as_slice();
    let prior_hash: Option<[u8; 32]> = sqlx::query!(
        "SELECT current_status_hash AS \"current_status_hash!: Vec<u8>\" \
         FROM thread_statuses WHERE thread_id = ?",
        thread_id_slice,
    )
    .fetch_optional(&mut *tx)
    .await?
    .and_then(|r| <[u8; 32]>::try_from(r.current_status_hash.as_slice()).ok());

    let signed = sign_thread_status_with_key(
        &state.instance_key,
        &thread_id_bytes,
        status,
        &state.instance_domain,
        reason,
        created_at_ms,
        prior_hash.as_ref(),
    );

    store_signed_object(
        &mut *tx,
        "thread-status",
        &signed.payload,
        &signed.signature,
        &signed.canonical_hash,
    )
    .await?;

    let status_str = status.as_str();
    let created_at_db = created_at_ms as i64;
    let canonical_hash_db: Vec<u8> = signed.canonical_hash.to_vec();
    let signing_instance_db: &str = &state.instance_domain;
    sqlx::query!(
        "INSERT INTO thread_statuses \
            (thread_id, status, signing_instance, reason, \
             current_created_at, current_status_hash) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT(thread_id) DO UPDATE SET \
            status = excluded.status, \
            signing_instance = excluded.signing_instance, \
            reason = excluded.reason, \
            current_created_at = excluded.current_created_at, \
            current_status_hash = excluded.current_status_hash, \
            updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
        thread_id_slice,
        status_str,
        signing_instance_db,
        reason,
        created_at_db,
        canonical_hash_db,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    forward_signed_object(
        Arc::clone(state),
        signed.canonical_hash,
        ForwardingClass::ThreadStatus,
        author_pubkey,
        encode_signed_object(&signed.payload, &signed.signature),
        None,
    )
    .await;
    Ok(())
}

/// §17.1 per-object state machine for a single signed `thread-status`.
///
/// `arrived_from` is the envelope sender (the transport peer that
/// pushed this batch) — the §17.2 split-horizon exclusion for the
/// tier-2 forward, not an authority input.
async fn apply_one_thread_status(
    state: &Arc<AppState>,
    wire_bytes: &[u8],
    arrived_from: &[u8; 32],
) -> Result<ThreadStatusResult, sqlx::Error> {
    // Step 1: WireFormat decode.
    let (payload_bytes, signature_bytes) = match decode_signed_object(wire_bytes) {
        Some(p) => p,
        None => {
            return Ok(reject(
                sha256(wire_bytes),
                ThreadStatusRejectReason::SchemaInvalid,
            ));
        }
    };
    let canonical_hash = sha256(&payload_bytes);

    // Step 2: dedup.
    let hash_slice: &[u8] = canonical_hash.as_slice();
    let existing = sqlx::query!(
        "SELECT (payload IS NULL) AS \"payload_null!: i64\" \
         FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_optional(&state.db)
    .await?;
    if let Some(row) = existing {
        if row.payload_null != 0 {
            return Ok(reject(
                canonical_hash,
                ThreadStatusRejectReason::SchemaInvalid,
            ));
        }
        return Ok(ThreadStatusResult {
            canonical_hash,
            status: ThreadStatusResultKind::Duplicate,
        });
    }

    // Step 3: parse + class dispatch.
    let status = match SignedPayload::parse(&payload_bytes) {
        Ok(SignedPayload::ThreadStatus(s)) => s,
        Ok(_) => {
            return Ok(reject(
                canonical_hash,
                ThreadStatusRejectReason::SchemaInvalid,
            ));
        }
        Err(ParseError::UnknownClass(_)) => {
            return Ok(reject(
                canonical_hash,
                ThreadStatusRejectReason::UnknownClass,
            ));
        }
        Err(_) => {
            return Ok(reject(
                canonical_hash,
                ThreadStatusRejectReason::SchemaInvalid,
            ));
        }
    };

    // Step 4: thread-home authority. Resolve the thread's home (and the
    // OP author, the §17.2 routing key) from the local `threads` row.
    // Open the transaction now so the authority read, chain-grounding
    // read, and UPSERTs observe one snapshot. Authority does NOT follow
    // user moves — the home is fixed at thread creation.
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    let thread_id_text = Uuid::from_bytes(status.thread_id).to_string();
    let thread_row = sqlx::query!(
        "SELECT t.home_instance AS \"home_instance?: Vec<u8>\", \
                u.public_key AS \"author_pubkey!: Vec<u8>\" \
         FROM threads t JOIN users u ON u.id = t.author WHERE t.id = ?",
        thread_id_text,
    )
    .fetch_optional(&mut *tx)
    .await?;

    // §17.1 deferred: no local `thread-create`. Reception-only —
    // autonomous backfill issuance is the documented follow-up.
    let Some(thread_row) = thread_row else {
        return Ok(ThreadStatusResult {
            canonical_hash,
            status: ThreadStatusResultKind::Deferred,
        });
    };

    let home: [u8; 32] = match &thread_row.home_instance {
        // NULL home_instance = this instance hosts the thread.
        None => *state.instance_key.public_bytes(),
        Some(h) if h.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(h);
            out
        }
        Some(_) => {
            tracing::error!(
                thread_id = %thread_id_text,
                "threads.home_instance has unexpected length",
            );
            return Ok(reject(
                canonical_hash,
                ThreadStatusRejectReason::UnauthorizedSigner,
            ));
        }
    };

    // The §17.2 routing key for the tier-2 forward is the OP author
    // pubkey (`author(thread)`), not the thread id.
    let author_pubkey: Vec<u8> = thread_row.author_pubkey;

    // Step 5: Ed25519 verify the inner signature against the resolved
    // home pubkey — NOT `envelope.sender`. Under §17.2 gossip the bytes
    // arrive from an arbitrary forwarding peer.
    let vk = match VerifyingKey::from_bytes(&home) {
        Ok(k) => k,
        Err(_) => {
            return Ok(reject(
                canonical_hash,
                ThreadStatusRejectReason::InvalidSignature,
            ));
        }
    };
    if signed::verify(&payload_bytes, &signature_bytes, &vk).is_err() {
        return Ok(reject(
            canonical_hash,
            ThreadStatusRejectReason::InvalidSignature,
        ));
    }

    // Step 6: advisory `signing_instance` cross-check against the home's
    // locally-known domain (us, or a known peer). A home reached only
    // via transitive gossip has no local mapping; the pubkey check above
    // is the authoritative gate.
    if let Some(home_domain) = resolve_domain_for_key(
        &mut tx,
        state.instance_key.public_bytes(),
        &state.instance_domain,
        &home,
    )
    .await?
        && status.signing_instance != home_domain
    {
        return Ok(reject(
            canonical_hash,
            ThreadStatusRejectReason::UnauthorizedSigner,
        ));
    }

    // Step 7: chain-grounding.
    if let Some(prior) = status.prior_status_hash {
        let prior_slice: &[u8] = prior.as_slice();
        let prior_row = sqlx::query_scalar!(
            "SELECT 1 AS \"present!: i64\" FROM signed_objects \
             WHERE canonical_hash = ? AND inner_class = 'thread-status' AND payload IS NOT NULL \
             LIMIT 1",
            prior_slice,
        )
        .fetch_optional(&mut *tx)
        .await?;
        if prior_row.is_none() {
            return Ok(ThreadStatusResult {
                canonical_hash,
                status: ThreadStatusResultKind::Deferred,
            });
        }
    }

    // Step 8: §17.3 latest-wins.
    let thread_id_slice: &[u8] = status.thread_id.as_slice();
    let existing_status = sqlx::query!(
        "SELECT current_created_at AS \"current_created_at!: i64\", \
                current_status_hash AS \"current_status_hash!: Vec<u8>\" \
         FROM thread_statuses WHERE thread_id = ?",
        thread_id_slice,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let new_wins = match &existing_status {
        None => true,
        Some(row) => {
            let prior_ts = u64::try_from(row.current_created_at).unwrap_or(0);
            if status.created_at > prior_ts {
                true
            } else if status.created_at < prior_ts {
                false
            } else {
                canonical_hash.as_slice() < row.current_status_hash.as_slice()
            }
        }
    };

    store_signed_object(
        &mut *tx,
        "thread-status",
        &payload_bytes,
        &signature_bytes,
        &canonical_hash,
    )
    .await?;

    let result_kind = if new_wins {
        let status_str = status.status.as_str();
        let canonical_hash_db: Vec<u8> = canonical_hash.to_vec();
        let created_at_db = status.created_at as i64;
        let reason: Option<&str> = status.reason.as_deref();
        // Persist the issuer's own declared `signing_instance` (the
        // home's self-label), not the transport peer's domain.
        let signing_instance_db: &str = status.signing_instance.as_str();
        sqlx::query!(
            "INSERT INTO thread_statuses \
                (thread_id, status, signing_instance, reason, \
                 current_created_at, current_status_hash) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(thread_id) DO UPDATE SET \
                status = excluded.status, \
                signing_instance = excluded.signing_instance, \
                reason = excluded.reason, \
                current_created_at = excluded.current_created_at, \
                current_status_hash = excluded.current_status_hash, \
                updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
            thread_id_slice,
            status_str,
            signing_instance_db,
            reason,
            created_at_db,
            canonical_hash_db,
        )
        .execute(&mut *tx)
        .await?;

        // §17.4 mirror: drive the local enforcement column so the
        // reply-rejection path honours the federated lock. The thread is
        // always projected locally here (step 4 returned `deferred`
        // otherwise).
        let locked = matches!(status.status, ThreadStatusKind::Locked) as i64;
        sqlx::query!(
            "UPDATE threads SET locked = ? WHERE id = ?",
            locked,
            thread_id_text,
        )
        .execute(&mut *tx)
        .await?;
        ThreadStatusResultKind::Applied
    } else {
        ThreadStatusResultKind::Superseded
    };

    tx.commit().await?;

    // Step 9: §17.2 tier-2 gossip forward. Relay verified, novel objects
    // (`applied` / `superseded`) onward toward peers interested in the OP
    // author. The per-inner-signer amplification cap (keyed on the home
    // pubkey) bounds propagation of one issuer's status stream per hour;
    // over-cap objects stay applied locally but are not forwarded.
    if matches!(
        result_kind,
        ThreadStatusResultKind::Applied | ThreadStatusResultKind::Superseded
    ) && state.status_content_rate_limiter.check_and_count(home, 1)
    {
        forward_signed_object(
            Arc::clone(state),
            canonical_hash,
            ForwardingClass::ThreadStatus,
            author_pubkey,
            encode_signed_object(&payload_bytes, &signature_bytes),
            Some(*arrived_from),
        )
        .await;
    }

    Ok(ThreadStatusResult {
        canonical_hash,
        status: result_kind,
    })
}

fn reject(canonical_hash: [u8; 32], reason: ThreadStatusRejectReason) -> ThreadStatusResult {
    ThreadStatusResult {
        canonical_hash,
        status: ThreadStatusResultKind::Rejected(reason),
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Chain backfill responder (§17.3)
// ---------------------------------------------------------------------------

/// Strictly-decoded `{ "hashes": [bstr(32), ...] }` backfill request.
struct HashesBody {
    hashes: Vec<[u8; 32]>,
}

impl HashesBody {
    fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut hashes_field: Option<Vec<Value>> = None;
        for (k, v) in entries {
            let key = match k {
                Value::Text(s) => s,
                _ => return None,
            };
            match key.as_str() {
                "hashes" => {
                    if hashes_field.is_some() {
                        return None;
                    }
                    match v {
                        Value::Array(a) => hashes_field = Some(a),
                        _ => return None,
                    }
                }
                _ => return None,
            }
        }
        let arr = hashes_field?;
        let mut hashes = Vec::with_capacity(arr.len());
        for item in arr {
            match item {
                Value::Bytes(b) if b.len() == 32 => {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&b);
                    hashes.push(h);
                }
                _ => return None,
            }
        }
        Some(Self { hashes })
    }
}

/// `POST /federation/v1/thread-status/by-hash` (§17.3).
///
/// Identical shape to §16.3: serves stored `thread-status` canonical
/// bytes by hash. `{ "objects": [...], "missing": [...] }`.
pub async fn handle_thread_status_by_hash(
    State(state): State<Arc<AppState>>,
    Extension(_envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let parsed = match HashesBody::decode(&body) {
        Some(p) => p,
        None => return bad_request("malformed"),
    };
    if parsed.hashes.is_empty() {
        return bad_request("empty_batch");
    }
    if parsed.hashes.len() > MAX_THREAD_STATUS_HASHES {
        return bad_request("too_many_hashes");
    }

    let mut objects: Vec<Value> = Vec::new();
    let mut missing: Vec<Value> = Vec::new();
    for hash in &parsed.hashes {
        let hash_slice: &[u8] = hash.as_slice();
        let row = match sqlx::query!(
            "SELECT payload AS \"payload?: Vec<u8>\", \
                    signature AS \"signature!: Vec<u8>\" \
             FROM signed_objects \
             WHERE canonical_hash = ? AND inner_class = 'thread-status'",
            hash_slice,
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "db error in thread-status by-hash backfill");
                return internal_error();
            }
        };
        match row.and_then(|r| r.payload.map(|p| (p, r.signature))) {
            Some((payload, signature)) => {
                objects.push(Value::Bytes(encode_signed_object(&payload, &signature)));
            }
            None => missing.push(Value::Bytes(hash.to_vec())),
        }
    }

    let body = Value::Map(vec![
        (Value::Text("objects".into()), Value::Array(objects)),
        (Value::Text("missing".into()), Value::Array(missing)),
    ]);
    let mut buf = Vec::with_capacity(64);
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    cbor_ok(buf)
}

// ---------------------------------------------------------------------------
// Layer-0 unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_encode_with_spec_status_tags() {
        let results = vec![
            ThreadStatusResult {
                canonical_hash: [1u8; 32],
                status: ThreadStatusResultKind::Applied,
            },
            ThreadStatusResult {
                canonical_hash: [2u8; 32],
                status: ThreadStatusResultKind::Deferred,
            },
            ThreadStatusResult {
                canonical_hash: [3u8; 32],
                status: ThreadStatusResultKind::Rejected(
                    ThreadStatusRejectReason::UnauthorizedSigner,
                ),
            },
        ];
        let bytes = encode_results(&results);
        let Value::Map(m) = ciborium::de::from_reader(bytes.as_slice()).unwrap() else {
            panic!("top-level not a map");
        };
        let Value::Array(arr) = m
            .into_iter()
            .find_map(|(k, v)| matches!(&k, Value::Text(t) if t == "results").then_some(v))
            .expect("results key")
        else {
            panic!("results not an array");
        };
        assert_eq!(arr.len(), 3);

        let expected: &[(usize, &str, Option<&str>)] = &[
            (0, "applied", None),
            (1, "deferred", None),
            (2, "rejected", Some("unauthorized_signer")),
        ];
        for (idx, want_status, want_reason) in expected {
            let Value::Map(entries) = &arr[*idx] else {
                panic!("entry not a map");
            };
            let mut got_status = None;
            let mut got_reason = None;
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
    fn objects_body_decoder_roundtrips() {
        let body = Value::Map(vec![(
            Value::Text("objects".into()),
            Value::Array(vec![Value::Bytes(vec![0x01, 0x02])]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert_eq!(
            ObjectsBody::decode(&buf).unwrap().objects,
            vec![vec![0x01, 0x02]]
        );
    }

    #[test]
    fn hashes_body_decoder_rejects_wrong_length() {
        let body = Value::Map(vec![(
            Value::Text("hashes".into()),
            Value::Array(vec![Value::Bytes(vec![0x01; 33])]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert!(HashesBody::decode(&buf).is_none());
    }

    #[test]
    fn caps_match_spec() {
        assert_eq!(MAX_THREAD_STATUS_BATCH, 256);
        assert_eq!(MAX_THREAD_STATUS_HASHES, 50);
    }
}
