//! Admin-rm advisory report handler (`docs/federation-protocol.md` §10.4).
//!
//! Mounts one route under `/federation/v1`:
//!
//! ```text
//! POST /federation/v1/admin-rm-report   (§10.4 advisory)
//! ```
//!
//! Behind `verify_known_peer`. Body is `{ "object": WireFormat }` —
//! a single signed `admin-rm` whose signer is **not** the target post's
//! home (advisory removal). The receiver MUST be the current home for
//! the target post's author; if not, response is `400
//! not_authoritative_home`.
//!
//! No propagation, no on-receipt erasure. Accepted reports land in the
//! `admin_rm_reports` queue for operator review (UX is out of scope for
//! Phase 6, per the spec's "protocol does not specify the admin UX").
//!
//! ## Per-source rate limit
//!
//! `MAX_ADVISORY_REPORTS_PER_HOUR = 100` (§10.6) groups rows by
//! `signing_instance` and counts inserts in the last hour. Overflow
//! returns `400 rate_limited` per spec (we use 400 rather than 429 —
//! the spec permits either; the sender tolerates both).

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
use crate::signed::{self, FedEnvelope, SignedPayload};
use crate::signing::store_signed_object;

/// §10.6 per-source-instance rate limit on `/admin-rm-report` inserts
/// per rolling hour.
pub const MAX_ADVISORY_REPORTS_PER_HOUR: i64 = 100;

// ---------------------------------------------------------------------------
// Request body
// ---------------------------------------------------------------------------

fn decode_body(bytes: &[u8]) -> Option<Vec<u8>> {
    let value: Value = ciborium::de::from_reader(bytes).ok()?;
    let entries = match value {
        Value::Map(m) => m,
        _ => return None,
    };
    // Strict map decode: reject non-text keys, duplicate `object`
    // keys, and unknown top-level keys (matches content.rs's
    // `ContentBody::decode` and `envelope::decode_signed_object`).
    let mut object_field: Option<Vec<u8>> = None;
    for (k, v) in entries {
        let key = match k {
            Value::Text(s) => s,
            _ => return None,
        };
        match key.as_str() {
            "object" => {
                if object_field.is_some() {
                    return None;
                }
                match v {
                    Value::Bytes(b) => object_field = Some(b),
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
    object_field
}

// ---------------------------------------------------------------------------
// Response body
// ---------------------------------------------------------------------------

enum ReportStatus {
    Queued,
    Duplicate,
}

impl ReportStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Duplicate => "duplicate",
        }
    }
}

fn ok_response(canonical_hash: &[u8; 32], status: ReportStatus) -> Response {
    let body = Value::Map(vec![
        (
            Value::Text("canonical_hash".into()),
            Value::Bytes(canonical_hash.to_vec()),
        ),
        (
            Value::Text("status".into()),
            Value::Text(status.as_str().into()),
        ),
    ]);
    let mut buf = Vec::with_capacity(64);
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    let mut r = (StatusCode::OK, buf).into_response();
    r.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    r
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `POST /federation/v1/admin-rm-report` handler (§10.4).
pub async fn handle_admin_rm_report(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let wire = match decode_body(&body) {
        Some(w) => w,
        None => return bad_request("malformed"),
    };

    let (payload_bytes, signature_bytes) = match decode_signed_object(&wire) {
        Some(p) => p,
        None => return bad_request("schema_invalid"),
    };
    let canonical_hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(&payload_bytes);
        h.finalize().into()
    };

    let payload = match SignedPayload::parse(&payload_bytes) {
        Ok(p) => p,
        Err(_) => return bad_request("schema_invalid"),
    };
    let admin_rm = match payload {
        SignedPayload::AdminRemoval(a) => a,
        _ => return bad_request("schema_invalid"),
    };

    // Resolve the sender's recorded instance_domain. Known_peer
    // middleware already gated existence, so a missing row is a bug.
    let sender_slice: &[u8] = envelope.sender.as_slice();
    let sender_domain = match sqlx::query!(
        "SELECT instance_domain FROM peers WHERE instance_pubkey = ?",
        sender_slice,
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row.instance_domain,
        Ok(None) => return internal_error(),
        Err(e) => {
            tracing::error!(error = %e, "db error resolving sender domain");
            return internal_error();
        }
    };

    // Verify the inner `admin-rm` signature against the sender's
    // pubkey. The advisory route requires sender == signer (the
    // advisory signer is the moderating instance; they're the one
    // pushing the report).
    if admin_rm.signing_instance != sender_domain {
        return bad_request("invalid_signature");
    }
    let vk = match VerifyingKey::from_bytes(&envelope.sender) {
        Ok(k) => k,
        Err(_) => return bad_request("invalid_signature"),
    };
    if signed::verify(&payload_bytes, &signature_bytes, &vk).is_err() {
        return bad_request("invalid_signature");
    }

    // §10.4 receiver-side "are we the home of target_author" check.
    // The advisory route is meaningful only when we host the
    // moderated user. No local users row → return
    // not_authoritative_home.
    let target_slice: &[u8] = admin_rm.target_author.as_slice();
    let host_check = sqlx::query_scalar!(
        "SELECT 1 AS \"present!: i64\" FROM users WHERE public_key = ? LIMIT 1",
        target_slice,
    )
    .fetch_optional(&state.db)
    .await;
    let is_home = match host_check {
        Ok(opt) => opt.is_some(),
        Err(e) => {
            tracing::error!(error = %e, "db error checking home");
            return internal_error();
        }
    };
    if !is_home {
        return bad_request("not_authoritative_home");
    }

    // post_not_found: target post UUID is unknown locally. `posts`
    // stores `id` as text-uuid.
    let post_id_text = Uuid::from_bytes(admin_rm.post_id).to_string();
    let post_exists = sqlx::query_scalar!(
        "SELECT 1 AS \"present!: i64\" FROM posts WHERE id = ? LIMIT 1",
        post_id_text,
    )
    .fetch_optional(&state.db)
    .await;
    match post_exists {
        Ok(Some(_)) => {}
        Ok(None) => return bad_request("post_not_found"),
        Err(e) => {
            tracing::error!(error = %e, "db error checking post");
            return internal_error();
        }
    };

    // Per-source-instance rate limit. Counts only the rolling
    // 1-hour window, indexed by (signing_instance, received_at).
    let window_count = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"n!: i64\" FROM admin_rm_reports \
         WHERE signing_instance = ? \
           AND received_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hour')",
        sender_domain,
    )
    .fetch_one(&state.db)
    .await;
    let n = match window_count {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = %e, "db error counting reports");
            return internal_error();
        }
    };
    if n >= MAX_ADVISORY_REPORTS_PER_HOUR {
        return bad_request("rate_limited");
    }

    // Per-target-post dedup. Early SELECT lets us return `duplicate`
    // on the common case without spending a tx; the `INSERT OR IGNORE`
    // below closes the race window between this SELECT and the INSERT
    // (two concurrent reports for the same post_id would otherwise
    // both pass the check and the second would trip the UNIQUE
    // constraint, surfacing a 500 instead of `duplicate`).
    let post_id_bytes: Vec<u8> = admin_rm.post_id.to_vec();
    let already = sqlx::query_scalar!(
        "SELECT 1 AS \"present!: i64\" FROM admin_rm_reports WHERE post_id = ? LIMIT 1",
        post_id_bytes,
    )
    .fetch_optional(&state.db)
    .await;
    match already {
        Ok(Some(_)) => return ok_response(&canonical_hash, ReportStatus::Duplicate),
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "db error checking report dedup");
            return internal_error();
        }
    }

    // Persist: store canonical bytes + enqueue projection row in one
    // transaction so a crash can't leave the bytes without their
    // report (or vice versa). `INSERT OR IGNORE` keeps "first report
    // wins" race-safe — the signed-object bytes still persist for
    // audit / relay, but only the first projection row survives. We
    // detect ignored inserts via `rows_affected()` and surface
    // `duplicate` rather than `queued`.
    let tx_result: Result<u64, sqlx::Error> = async {
        let mut tx = state.db.begin().await?;
        store_signed_object(
            &mut *tx,
            "admin-rm",
            &payload_bytes,
            &signature_bytes,
            &canonical_hash,
        )
        .await?;

        let id = Uuid::new_v4().to_string();
        let target_author_db: Vec<u8> = admin_rm.target_author.to_vec();
        let canonical_hash_db: Vec<u8> = canonical_hash.to_vec();
        let reason: Option<&str> = admin_rm.reason.as_deref();
        let outcome = sqlx::query!(
            "INSERT OR IGNORE INTO admin_rm_reports \
             (id, post_id, target_author, signing_instance, reason, canonical_hash) \
             VALUES (?, ?, ?, ?, ?, ?)",
            id,
            post_id_bytes,
            target_author_db,
            sender_domain,
            reason,
            canonical_hash_db,
        )
        .execute(&mut *tx)
        .await?;
        let inserted = outcome.rows_affected();
        tx.commit().await?;
        Ok(inserted)
    }
    .await;

    match tx_result {
        Ok(0) => ok_response(&canonical_hash, ReportStatus::Duplicate),
        Ok(_) => ok_response(&canonical_hash, ReportStatus::Queued),
        Err(e) => {
            tracing::error!(error = %e, "db error inserting advisory report");
            internal_error()
        }
    }
}
