//! User-status push + chain-backfill handlers
//! (`docs/federation-protocol.md` §16).
//!
//! Mounts two routes under `/federation/v1`, both behind
//! `verify_known_peer`:
//!
//! ```text
//! POST /federation/v1/user-status          (§16.1 push)
//! POST /federation/v1/user-status/by-hash  (§16.3 chain backfill)
//! ```
//!
//! User-status objects are **instance-signed evidence** (§16): the
//! subject's home instance asserts the subject is `active`,
//! `suspended`, or `banned` as of `created_at`. Authority is
//! home-scoped and follows the subject through moves (§16.1
//! `unauthorized_signer`). These objects are **direct issuer → peer
//! only** — never gossip-forwarded (§16.2), so unlike `/moves` this
//! handler does not touch the forwarder.
//!
//! ## Per-object state machine (§16.1)
//!
//! 1. WireFormat decode → `rejected/schema_invalid`.
//! 2. `signed_objects` dedup by canonical hash → `duplicate`.
//! 3. `SignedPayload::parse` + class dispatch → `rejected/unknown_class`
//!    (unrecognised `t`) or `rejected/schema_invalid` (recognised but
//!    not `user-status`).
//! 4. Ed25519 verify against the authenticated peer (`envelope.sender`)
//!    → `rejected/invalid_signature`.
//! 5. `signing_instance` must equal the sender's recorded domain →
//!    `rejected/unauthorized_signer` (§16.2 forbids forwarding, so the
//!    pusher must *be* the issuer).
//! 6. Home-at-`created_at` authority: resolve `subject`'s home key at
//!    the object's timestamp; it MUST equal `envelope.sender`. No local
//!    knowledge of the subject → `rejected/unknown_subject_home`; a
//!    different home → `rejected/unauthorized_signer`.
//! 7. Chain-grounding: a `Some(prior_status_hash)` must reference a
//!    stored `user-status` predecessor, else `deferred`.
//! 8. §16.3 latest-wins-by-`created_at` (ties broken by canonical_hash
//!    bytewise, smaller wins) against the `user_statuses` row. Winner
//!    UPSERTs the projection (`applied`); loser is `superseded`. Both
//!    persist canonical bytes for chain/audit.

use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::federation::envelope::{decode_signed_object, encode_signed_object};
use crate::federation::errors::{bad_request, internal_error};
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::middleware::VerifiedBody;
use crate::federation::push_rate_limit::push_too_many_requests;
use crate::federation::remote_users::resolve_home_at_t;
use crate::signed::{self, FedEnvelope, ParseError, SignedPayload};
use crate::signing::store_signed_object;

/// §16.5 `MAX_USER_STATUS_BATCH`: per-push object-count cap. Overflow
/// returns `400 { "error": "batch_too_large" }`.
pub const MAX_USER_STATUS_BATCH: usize = 256;

/// §16.5 `MAX_USER_STATUS_HASHES`: per-backfill hash-list cap.
pub const MAX_USER_STATUS_HASHES: usize = 50;

// ---------------------------------------------------------------------------
// Per-object result vocabulary (§16.1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserStatusResultKind {
    Applied,
    Duplicate,
    Deferred,
    Superseded,
    Rejected(UserStatusRejectReason),
}

impl UserStatusResultKind {
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

/// §16.1 enumerated `reason` vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserStatusRejectReason {
    InvalidSignature,
    SchemaInvalid,
    UnauthorizedSigner,
    UnknownSubjectHome,
    UnknownClass,
}

impl UserStatusRejectReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid_signature",
            Self::SchemaInvalid => "schema_invalid",
            Self::UnauthorizedSigner => "unauthorized_signer",
            Self::UnknownSubjectHome => "unknown_subject_home",
            Self::UnknownClass => "unknown_class",
        }
    }
}

/// One row of the §16.1 `results` array.
struct UserStatusResult {
    canonical_hash: [u8; 32],
    status: UserStatusResultKind,
}

// ---------------------------------------------------------------------------
// Request body decoder
// ---------------------------------------------------------------------------

/// Decoded view of the §16.1 push body: `{ "objects": [bstr, ...] }`.
/// Same `bstr`-per-element invariant as the other push routes — each
/// element is the raw WireFormat bytes for one signed object, re-hashed
/// verbatim by the receiver.
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

fn encode_results(results: &[UserStatusResult]) -> Vec<u8> {
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
// Push handler (§16.1)
// ---------------------------------------------------------------------------

/// `POST /federation/v1/user-status` handler (§16.1).
pub async fn handle_user_status_push(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    // §16.5 per-peer per-minute request budget. Gate before any
    // decode/DB work so an over-quota peer is shed cheaply.
    if !state.user_status_rate_limiter.try_admit(envelope.sender) {
        return push_too_many_requests();
    }
    let parsed = match ObjectsBody::decode(&body) {
        Some(p) => p,
        None => return bad_request("malformed"),
    };
    if parsed.objects.is_empty() {
        return bad_request("empty_batch");
    }
    if parsed.objects.len() > MAX_USER_STATUS_BATCH {
        return bad_request("batch_too_large");
    }

    // Resolve the sender's recorded domain once per batch. The
    // known_peer middleware already gated existence, so a missing row
    // is local-state corruption.
    let sender_domain = match resolve_sender_domain(&state, &envelope.sender).await {
        Ok(Some(d)) => d,
        Ok(None) => return internal_error(),
        Err(e) => {
            tracing::error!(error = %e, "db error resolving sender domain");
            return internal_error();
        }
    };

    let mut results: Vec<UserStatusResult> = Vec::with_capacity(parsed.objects.len());
    for wire_bytes in &parsed.objects {
        let result =
            match apply_one_user_status(&state, wire_bytes, &envelope.sender, &sender_domain).await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "db error applying federated user-status");
                    return internal_error();
                }
            };
        results.push(result);
    }

    cbor_ok(encode_results(&results))
}

/// §16.1 per-object state machine for a single signed `user-status`.
async fn apply_one_user_status(
    state: &Arc<AppState>,
    wire_bytes: &[u8],
    sender_key: &[u8; 32],
    sender_domain: &str,
) -> Result<UserStatusResult, sqlx::Error> {
    // Step 1: WireFormat decode.
    let (payload_bytes, signature_bytes) = match decode_signed_object(wire_bytes) {
        Some(p) => p,
        None => {
            return Ok(reject(
                sha256(wire_bytes),
                UserStatusRejectReason::SchemaInvalid,
            ));
        }
    };
    let canonical_hash = sha256(&payload_bytes);

    // Step 2: dedup. A live row → duplicate. A NULL-payload row means
    // our own state is corrupt for an object class that is never erased
    // → surface as schema_invalid.
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
                UserStatusRejectReason::SchemaInvalid,
            ));
        }
        return Ok(UserStatusResult {
            canonical_hash,
            status: UserStatusResultKind::Duplicate,
        });
    }

    // Step 3: parse + class dispatch.
    let status = match SignedPayload::parse(&payload_bytes) {
        Ok(SignedPayload::UserStatus(s)) => s,
        Ok(_) => {
            return Ok(reject(
                canonical_hash,
                UserStatusRejectReason::SchemaInvalid,
            ));
        }
        Err(ParseError::UnknownClass(_)) => {
            return Ok(reject(canonical_hash, UserStatusRejectReason::UnknownClass));
        }
        Err(_) => {
            return Ok(reject(
                canonical_hash,
                UserStatusRejectReason::SchemaInvalid,
            ));
        }
    };

    // Step 4: Ed25519 verify against the authenticated peer. §16.2
    // forbids forwarding, so the pusher must be the issuer — the
    // signature binds to `envelope.sender`.
    let vk = match VerifyingKey::from_bytes(sender_key) {
        Ok(k) => k,
        Err(_) => {
            return Ok(reject(
                canonical_hash,
                UserStatusRejectReason::InvalidSignature,
            ));
        }
    };
    if signed::verify(&payload_bytes, &signature_bytes, &vk).is_err() {
        return Ok(reject(
            canonical_hash,
            UserStatusRejectReason::InvalidSignature,
        ));
    }

    // Step 5: the declared `signing_instance` must match the
    // authenticated sender's domain. A mismatch means the bytes were
    // signed by this peer but claim a different issuer — not a valid
    // home authority on this direct channel.
    if status.signing_instance != sender_domain {
        return Ok(reject(
            canonical_hash,
            UserStatusRejectReason::UnauthorizedSigner,
        ));
    }

    // Step 6: home-at-T authority. Resolve `subject`'s home key as of
    // the object's `created_at`; it MUST equal the sender. Open a
    // transaction now so the authority read, chain-grounding read, and
    // the latest-wins UPSERT all observe one snapshot.
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    let self_key = *state.instance_key.public_bytes();
    let home =
        resolve_subject_home_at_t(&mut tx, &self_key, &status.subject, status.created_at).await?;
    match home {
        None => {
            return Ok(reject(
                canonical_hash,
                UserStatusRejectReason::UnknownSubjectHome,
            ));
        }
        Some(h) if &h != sender_key => {
            return Ok(reject(
                canonical_hash,
                UserStatusRejectReason::UnauthorizedSigner,
            ));
        }
        Some(_) => {}
    }

    // Step 7: chain-grounding. A non-first object must reference a
    // stored `user-status` predecessor; otherwise it is `deferred`
    // (autonomous backfill issuance is the documented Phase 11
    // follow-up — reception-only here).
    if let Some(prior) = status.prior_status_hash {
        let prior_slice: &[u8] = prior.as_slice();
        let prior_row = sqlx::query_scalar!(
            "SELECT 1 AS \"present!: i64\" FROM signed_objects \
             WHERE canonical_hash = ? AND inner_class = 'user-status' AND payload IS NOT NULL \
             LIMIT 1",
            prior_slice,
        )
        .fetch_optional(&mut *tx)
        .await?;
        if prior_row.is_none() {
            return Ok(UserStatusResult {
                canonical_hash,
                status: UserStatusResultKind::Deferred,
            });
        }
    }

    // Step 8: §16.3 latest-wins. Persist canonical bytes in either
    // branch (chain evidence); only the winner flips the projection.
    let subject_slice: &[u8] = status.subject.as_slice();
    let existing_status = sqlx::query!(
        "SELECT current_created_at AS \"current_created_at!: i64\", \
                current_status_hash AS \"current_status_hash!: Vec<u8>\" \
         FROM user_statuses WHERE subject = ?",
        subject_slice,
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
        "user-status",
        &payload_bytes,
        &signature_bytes,
        &canonical_hash,
    )
    .await?;

    let result_kind = if new_wins {
        let status_str = status.status.as_str();
        let suspended_until_db = status.suspended_until.map(|v| v as i64);
        let canonical_hash_db: Vec<u8> = canonical_hash.to_vec();
        let created_at_db = status.created_at as i64;
        let reason: Option<&str> = status.reason.as_deref();
        sqlx::query!(
            "INSERT INTO user_statuses \
                (subject, status, suspended_until, signing_instance, reason, \
                 current_created_at, current_status_hash) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(subject) DO UPDATE SET \
                status = excluded.status, \
                suspended_until = excluded.suspended_until, \
                signing_instance = excluded.signing_instance, \
                reason = excluded.reason, \
                current_created_at = excluded.current_created_at, \
                current_status_hash = excluded.current_status_hash, \
                updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
            subject_slice,
            status_str,
            suspended_until_db,
            sender_domain,
            reason,
            created_at_db,
            canonical_hash_db,
        )
        .execute(&mut *tx)
        .await?;
        UserStatusResultKind::Applied
    } else {
        UserStatusResultKind::Superseded
    };

    tx.commit().await?;

    Ok(UserStatusResult {
        canonical_hash,
        status: result_kind,
    })
}

/// Resolve `subject`'s home instance pubkey as of time `t` for the
/// §16.1 authority gate. Returns `None` when the subject is entirely
/// unknown locally (no recorded move and no `users` row → the spec's
/// `unknown_subject_home`).
///
/// Two cases:
/// - **Moves on record** → delegate to [`resolve_home_at_t`], which
///   walks `user_moves` for the latest move with `created_at ≤ t`
///   (falling back to the earliest move's `from_instance_key` when `t`
///   predates every move). We pass an all-zero sentinel as
///   `arrived_from`: with at least one move present the helper only
///   falls back on a corrupt/unparseable chain, which we surface as
///   `unknown_subject_home` rather than silently authorising the
///   sender. An all-zero key is never a valid Ed25519 instance key, so
///   the sentinel can't collide with a real home.
/// - **No moves** → the implicit registration home recorded in
///   `users.home_instance` (NULL = this instance for a local user).
async fn resolve_subject_home_at_t(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    self_key: &[u8; 32],
    subject: &[u8; 32],
    t: u64,
) -> Result<Option<[u8; 32]>, sqlx::Error> {
    let subject_slice: &[u8] = subject.as_slice();
    let has_move = sqlx::query_scalar!(
        "SELECT 1 AS \"present!: i64\" FROM user_moves WHERE user_key = ? LIMIT 1",
        subject_slice,
    )
    .fetch_optional(&mut **tx)
    .await?
    .is_some();

    if has_move {
        const SENTINEL: [u8; 32] = [0u8; 32];
        let home = resolve_home_at_t(tx, subject, t, &SENTINEL).await?;
        if home == SENTINEL {
            return Ok(None);
        }
        return Ok(Some(home));
    }

    let row = sqlx::query!(
        "SELECT home_instance AS \"home_instance?: Vec<u8>\" FROM users WHERE public_key = ?",
        subject_slice,
    )
    .fetch_optional(&mut **tx)
    .await?;
    match row {
        None => Ok(None),
        Some(r) => match r.home_instance {
            None => Ok(Some(*self_key)),
            Some(h) if h.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&h);
                Ok(Some(out))
            }
            Some(_) => {
                tracing::error!(
                    subject = ?subject,
                    "users.home_instance has unexpected length",
                );
                Ok(None)
            }
        },
    }
}

async fn resolve_sender_domain(
    state: &Arc<AppState>,
    sender_key: &[u8; 32],
) -> Result<Option<String>, sqlx::Error> {
    let sender_slice: &[u8] = sender_key.as_slice();
    let row = sqlx::query!(
        "SELECT instance_domain FROM peers WHERE instance_pubkey = ?",
        sender_slice,
    )
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|r| r.instance_domain))
}

fn reject(canonical_hash: [u8; 32], reason: UserStatusRejectReason) -> UserStatusResult {
    UserStatusResult {
        canonical_hash,
        status: UserStatusResultKind::Rejected(reason),
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Chain backfill responder (§16.3)
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

/// `POST /federation/v1/user-status/by-hash` (§16.3).
///
/// Serves stored `user-status` canonical bytes by hash. Response is
/// `{ "objects": [WireFormat, ...], "missing": [bstr(32), ...] }`.
/// User-status objects are never erased, so there is no `410 Gone`
/// branch — a hash we don't hold (or hold only as a NULL-payload row)
/// is reported in `missing`.
pub async fn handle_user_status_by_hash(
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
    if parsed.hashes.len() > MAX_USER_STATUS_HASHES {
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
             WHERE canonical_hash = ? AND inner_class = 'user-status'",
            hash_slice,
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "db error in user-status by-hash backfill");
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
            UserStatusResult {
                canonical_hash: [1u8; 32],
                status: UserStatusResultKind::Applied,
            },
            UserStatusResult {
                canonical_hash: [2u8; 32],
                status: UserStatusResultKind::Superseded,
            },
            UserStatusResult {
                canonical_hash: [3u8; 32],
                status: UserStatusResultKind::Rejected(UserStatusRejectReason::UnauthorizedSigner),
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
            (1, "superseded", None),
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
    fn objects_body_decoder_accepts_bstr_elements() {
        let body = Value::Map(vec![(
            Value::Text("objects".into()),
            Value::Array(vec![Value::Bytes(vec![0xaa, 0xbb])]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let parsed = ObjectsBody::decode(&buf).expect("decode");
        assert_eq!(parsed.objects, vec![vec![0xaa, 0xbb]]);
    }

    #[test]
    fn objects_body_decoder_rejects_unknown_key() {
        let body = Value::Map(vec![(
            Value::Text("nope".into()),
            Value::Array(vec![Value::Bytes(vec![0x01])]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert!(ObjectsBody::decode(&buf).is_none());
    }

    #[test]
    fn hashes_body_decoder_rejects_wrong_length() {
        let body = Value::Map(vec![(
            Value::Text("hashes".into()),
            Value::Array(vec![Value::Bytes(vec![0x01; 31])]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert!(HashesBody::decode(&buf).is_none());
    }

    #[test]
    fn batch_cap_matches_spec() {
        assert_eq!(MAX_USER_STATUS_BATCH, 256);
        assert_eq!(MAX_USER_STATUS_HASHES, 50);
    }
}
