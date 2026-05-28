//! Report push handler (`docs/federation-protocol.md` §18).
//!
//! Mounts one route under `/federation/v1`, behind `verify_known_peer`:
//!
//! ```text
//! POST /federation/v1/reports   (§18.1 push)
//! ```
//!
//! Reports are a **private channel from the reporter's home to the
//! target post's home** (§18). They never gossip, never backfill, and
//! are never exposed on any user-facing API (§18.3) — there is no
//! `/reports/by-hash` route. Unlike every other class, `report` is not
//! a `signed_objects` inner_class: accepted reports land directly in
//! the `federated_reports` operator-moderation queue. The §18.1 dedup
//! key is `(post_id, reporter)`.
//!
//! ## Per-object state machine (§18.1)
//!
//! Result vocabulary is `applied | duplicate | rejected{reason}` only —
//! reports do not chain, so there is no `deferred` or `superseded`.
//!
//! 1. WireFormat decode → `rejected/schema_invalid`.
//! 2. parse + class dispatch → `rejected/unknown_class` /
//!    `rejected/schema_invalid`.
//! 3. Ed25519 verify against the report's `reporter` (user-signed) →
//!    `rejected/invalid_signature`.
//! 4. `unauthorized_reporter`: the sender instance must host `reporter`
//!    (resolved via the latest move, falling back to registration
//!    home); a reporter we can't tie to the sender is rejected.
//! 5. `wrong_recipient`: `target_author` must be a user of *this*
//!    instance (we must be their current home).
//! 6. §18.1 dedup on `(post_id, reporter)` → `duplicate`; otherwise the
//!    row is queued (`applied`). Reports for posts unknown locally are
//!    still applied — the admin queue annotates "post not stored
//!    locally" (§18.1).

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
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::middleware::VerifiedBody;
use crate::federation::push_rate_limit::push_too_many_requests;
use crate::signed::{self, FedEnvelope, ParseError, SignedPayload};

/// §18.5 `MAX_REPORT_BATCH`: per-push object-count cap (smaller than the
/// other classes — reports are bursty per-incident but rarely batched).
pub const MAX_REPORT_BATCH: usize = 64;

// ---------------------------------------------------------------------------
// Per-object result vocabulary (§18.1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportResultKind {
    Applied,
    Duplicate,
    Rejected(ReportRejectReason),
}

impl ReportResultKind {
    fn status_tag(&self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Duplicate => "duplicate",
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

/// §18.1 enumerated `reason` vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportRejectReason {
    InvalidSignature,
    SchemaInvalid,
    UnauthorizedReporter,
    WrongRecipient,
    UnknownClass,
}

impl ReportRejectReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid_signature",
            Self::SchemaInvalid => "schema_invalid",
            Self::UnauthorizedReporter => "unauthorized_reporter",
            Self::WrongRecipient => "wrong_recipient",
            Self::UnknownClass => "unknown_class",
        }
    }
}

struct ReportResult {
    canonical_hash: [u8; 32],
    status: ReportResultKind,
}

// ---------------------------------------------------------------------------
// Request body decoder
// ---------------------------------------------------------------------------

/// Decoded view of the §18.1 push body: `{ "objects": [bstr, ...] }`.
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

fn encode_results(results: &[ReportResult]) -> Vec<u8> {
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
// Push handler (§18.1)
// ---------------------------------------------------------------------------

/// `POST /federation/v1/reports` handler (§18.1).
pub async fn handle_reports_push(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    // §18.5 per-peer per-minute request budget — the tightest of the
    // three Phase-11 push routes because the sender can vary `post_id`
    // to flood the moderation queue. Gate before any decode/DB work so
    // an over-quota peer is shed cheaply.
    if !state.reports_rate_limiter.try_admit(envelope.sender) {
        return push_too_many_requests();
    }
    let parsed = match ObjectsBody::decode(&body) {
        Some(p) => p,
        None => return bad_request("malformed"),
    };
    if parsed.objects.is_empty() {
        return bad_request("empty_batch");
    }
    if parsed.objects.len() > MAX_REPORT_BATCH {
        return bad_request("batch_too_large");
    }

    let mut results: Vec<ReportResult> = Vec::with_capacity(parsed.objects.len());
    for wire_bytes in &parsed.objects {
        let result = match apply_one_report(&state, wire_bytes, &envelope.sender).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "db error applying federated report");
                return internal_error();
            }
        };
        results.push(result);
    }

    cbor_ok(encode_results(&results))
}

/// §18.1 per-object state machine for a single signed `report`.
async fn apply_one_report(
    state: &Arc<AppState>,
    wire_bytes: &[u8],
    sender_key: &[u8; 32],
) -> Result<ReportResult, sqlx::Error> {
    // Step 1: WireFormat decode.
    let (payload_bytes, signature_bytes) = match decode_signed_object(wire_bytes) {
        Some(p) => p,
        None => {
            return Ok(reject(
                sha256(wire_bytes),
                ReportRejectReason::SchemaInvalid,
            ));
        }
    };
    let canonical_hash = sha256(&payload_bytes);

    // Step 2: parse + class dispatch. Reports are not stored in
    // `signed_objects`, so there is no canonical-hash dedup here; the
    // §18.1 dedup is on `(post_id, reporter)` further down.
    let report = match SignedPayload::parse(&payload_bytes) {
        Ok(SignedPayload::Report(r)) => r,
        Ok(_) => return Ok(reject(canonical_hash, ReportRejectReason::SchemaInvalid)),
        Err(ParseError::UnknownClass(_)) => {
            return Ok(reject(canonical_hash, ReportRejectReason::UnknownClass));
        }
        Err(_) => return Ok(reject(canonical_hash, ReportRejectReason::SchemaInvalid)),
    };

    // Step 3: Ed25519 verify against the report's `reporter`
    // (user-signed authority).
    let vk = match VerifyingKey::from_bytes(&report.reporter) {
        Ok(k) => k,
        Err(_) => return Ok(reject(canonical_hash, ReportRejectReason::InvalidSignature)),
    };
    if signed::verify(&payload_bytes, &signature_bytes, &vk).is_err() {
        return Ok(reject(canonical_hash, ReportRejectReason::InvalidSignature));
    }

    // Step 4: §18.1 `unauthorized_reporter`. The sender instance must
    // host `reporter`. We resolve the reporter's current home and
    // require it to equal the authenticated sender; a reporter we have
    // no record of cannot be tied to the sender and is rejected.
    match resolve_current_home(state, &report.reporter).await? {
        Some(h) if &h == sender_key => {}
        _ => {
            return Ok(reject(
                canonical_hash,
                ReportRejectReason::UnauthorizedReporter,
            ));
        }
    }

    // Step 5: §18.1 `wrong_recipient`. `target_author` must be a user
    // of *this* instance — we must be their current home.
    let self_key = *state.instance_key.public_bytes();
    match resolve_current_home(state, &report.target_author).await? {
        Some(h) if h == self_key => {}
        _ => return Ok(reject(canonical_hash, ReportRejectReason::WrongRecipient)),
    }

    // Step 6: §18.1 dedup on `(post_id, reporter)`, then queue. The
    // early SELECT returns `duplicate` cheaply; the `INSERT OR IGNORE`
    // closes the race between SELECT and INSERT (two concurrent reports
    // for the same key both pass the check; the second's insert is
    // ignored and surfaces as `duplicate` via `rows_affected`).
    let post_id_db: Vec<u8> = report.post_id.to_vec();
    let reporter_db: Vec<u8> = report.reporter.to_vec();
    let already = sqlx::query_scalar!(
        "SELECT 1 AS \"present!: i64\" FROM federated_reports \
         WHERE post_id = ? AND reporter = ? LIMIT 1",
        post_id_db,
        reporter_db,
    )
    .fetch_optional(&state.db)
    .await?;
    if already.is_some() {
        return Ok(ReportResult {
            canonical_hash,
            status: ReportResultKind::Duplicate,
        });
    }

    let id = Uuid::new_v4().to_string();
    let target_author_db: Vec<u8> = report.target_author.to_vec();
    let reason_str = report.reason.as_str();
    let detail: Option<&str> = report.detail.as_deref();
    let canonical_hash_db: Vec<u8> = canonical_hash.to_vec();
    let created_at_db = report.created_at as i64;
    let outcome = sqlx::query!(
        "INSERT OR IGNORE INTO federated_reports \
            (id, post_id, target_author, reporter, reason, detail, \
             canonical_hash, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        id,
        post_id_db,
        target_author_db,
        reporter_db,
        reason_str,
        detail,
        canonical_hash_db,
        created_at_db,
    )
    .execute(&state.db)
    .await?;

    let status = if outcome.rows_affected() == 0 {
        ReportResultKind::Duplicate
    } else {
        ReportResultKind::Applied
    };
    Ok(ReportResult {
        canonical_hash,
        status,
    })
}

/// Resolve `user`'s current home instance pubkey. Returns `None` when
/// the user is unknown locally (no move on record and no `users` row).
///
/// Resolution order mirrors `admin_rm`'s home check (§12.4 latest-wins):
/// the `user_homes` row wins when present; otherwise the implicit
/// registration home from `users.home_instance` (NULL = this instance).
async fn resolve_current_home(
    state: &Arc<AppState>,
    user: &[u8; 32],
) -> Result<Option<[u8; 32]>, sqlx::Error> {
    let user_slice: &[u8] = user.as_slice();
    let home_row = sqlx::query!(
        "SELECT current_home_key AS \"current_home_key!: Vec<u8>\" \
         FROM user_homes WHERE user_key = ?",
        user_slice,
    )
    .fetch_optional(&state.db)
    .await?;
    if let Some(row) = home_row {
        if row.current_home_key.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&row.current_home_key);
            return Ok(Some(out));
        }
        return Ok(None);
    }

    let user_row = sqlx::query!(
        "SELECT home_instance AS \"home_instance?: Vec<u8>\" FROM users WHERE public_key = ?",
        user_slice,
    )
    .fetch_optional(&state.db)
    .await?;
    match user_row {
        None => Ok(None),
        Some(r) => match r.home_instance {
            None => Ok(Some(*state.instance_key.public_bytes())),
            Some(h) if h.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&h);
                Ok(Some(out))
            }
            Some(_) => Ok(None),
        },
    }
}

fn reject(canonical_hash: [u8; 32], reason: ReportRejectReason) -> ReportResult {
    ReportResult {
        canonical_hash,
        status: ReportResultKind::Rejected(reason),
    }
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
    fn results_encode_with_spec_status_tags() {
        let results = vec![
            ReportResult {
                canonical_hash: [1u8; 32],
                status: ReportResultKind::Applied,
            },
            ReportResult {
                canonical_hash: [2u8; 32],
                status: ReportResultKind::Duplicate,
            },
            ReportResult {
                canonical_hash: [3u8; 32],
                status: ReportResultKind::Rejected(ReportRejectReason::WrongRecipient),
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
            (1, "duplicate", None),
            (2, "rejected", Some("wrong_recipient")),
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
            Value::Array(vec![Value::Bytes(vec![0x09])]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert_eq!(ObjectsBody::decode(&buf).unwrap().objects, vec![vec![0x09]]);
    }

    #[test]
    fn report_batch_cap_matches_spec() {
        assert_eq!(MAX_REPORT_BATCH, 64);
    }
}
