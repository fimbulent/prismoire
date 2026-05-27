//! Edge propagation push handler (`docs/federation-protocol.md` §9).
//!
//! Mounts a single route under `/federation/v1`:
//!
//! ```text
//! POST /federation/v1/edges     (§9.1 push)
//! ```
//!
//! Behind `verify_known_peer`: per §6 the sender must be an `active`
//! peer. Body is `{ "edges": [WireFormat, WireFormat, ...] }` per §9.1;
//! response is `{ "results": [{ canonical_hash, status, reason? }, ...] }`
//! in the same array order as the request (§9.1 "Senders correlate by
//! position, not by hash search").
//!
//! Per-edge state machine (§9.1, §9.4) — steps 1–7 run inside
//! `apply_one_edge`, once per edge in the request batch:
//!
//! 1. WireFormat decode → `rejected/schema_invalid` on failure.
//! 2. signed_objects lookup — `erased` row → `rejected/erased`
//!    (§9.1 erased-bit), live row → `duplicate` (§9.1 idempotency).
//! 3. SignedPayload::parse + class check — non-trust-edge →
//!    `rejected/unknown_class` (§5.3 capability-gating).
//! 4. Ed25519 verify against `from_key` → `rejected/invalid_signature`.
//! 5. BEGIN IMMEDIATE — chain-fork detection (§9.4), chain-continuity,
//!    and the projection write must observe the same snapshot.
//! 6. Projection via [`try_project_trust_edge`]
//!    (`remote_users.rs`): resolves `users.id` for both endpoints
//!    (Phase 9.5 federated stubs count, so this matches whether the
//!    endpoints are local or remote-author stubs), runs §9.4
//!    chain-fork + §9.1 chain-continuity, and (for `Projected` +
//!    `Neutral`) cascades the on-receipt erasure.
//! 7. Map the projection result to the §9.1 status vocabulary,
//!    commit the per-edge transaction:
//!    - `Projected` → `applied`, with canonical bytes persisted to
//!      `signed_objects` for dedup / relay / future audit.
//!    - `ChainFork` → `rejected/chain_fork`, with bytes persisted as
//!      §9.4 "both stored, neither active" evidence.
//!    - `Deferred` → `deferred`; do NOT persist (a re-push or §9.3
//!      backfill closes the gap and re-delivers).
//!    - `EndpointMissing` → `applied`. The Phase 9.6 sweep
//!      (`remote_users::sweep_pending_projections`) catches the
//!      projection up when the missing endpoint's profile-rev
//!      hydrates a stub for it.
//!
//! After the loop over all edges has finished, the batch-level
//! handler issues a single `trust_graph_notify` — the rebuild loop
//! coalesces, so per-edge notifications would be wasted work.
//!
//! Phase 9.6 status of historical punts:
//! - The pre-9.5 "no profile-sync yet, projection rebuilds when
//!   stubs hydrate" comment is resolved: federated stubs exist as
//!   real `users` rows from Phase 9.5 onwards, and the `EndpointMissing`
//!   branch defers projection to the sweep that runs when the
//!   missing endpoint's profile-rev arrives.
//! - Still punted: no `pending_deltas.apply` for federated edges.
//!   The rebuild loop picks the change up on its next pass; cached
//!   per-viewer trust state lags by one rebuild cycle. Originated
//!   edges keep the fast-path because the active viewer issued them.
//! - Still punted: no durable pending-orphan buffer for `deferred`.
//!   That status is a one-shot the sender sees; re-push or §9.3
//!   backfill closes the gap.

use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::federation::envelope::decode_signed_object;
use crate::federation::errors::{bad_request, internal_error};
use crate::federation::forwarder::forward_signed_object;
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::middleware::VerifiedBody;
use crate::federation::remote_users::{TrustEdgeProjection, try_project_trust_edge};
use crate::federation::routing::ForwardingClass;
use crate::signed::{self, FedEnvelope, SignedPayload};
use crate::signing::store_signed_object;

/// §9.6 `MAX_EDGE_BATCH`: receiver-enforced upper bound on
/// `len(body.edges)`. Overflow returns
/// `400 { "error": "batch_too_large" }`.
pub const MAX_EDGE_BATCH: usize = 256;

// ---------------------------------------------------------------------------
// Per-edge result vocabulary (§9.1)
// ---------------------------------------------------------------------------

/// Top-level status per the §9.1 result table. `Rejected` carries a
/// sub-reason because the spec demands per-object diagnostic detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeStatus {
    Applied,
    Duplicate,
    Deferred,
    Rejected(RejectReason),
}

impl EdgeStatus {
    /// Spec-canonical lowercase tag for the response `status` field.
    fn status_tag(&self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Duplicate => "duplicate",
            Self::Deferred => "deferred",
            Self::Rejected(_) => "rejected",
        }
    }

    /// `reason` field tag, present iff `status == "rejected"`.
    fn reason_tag(&self) -> Option<&'static str> {
        match self {
            Self::Rejected(r) => Some(r.as_str()),
            _ => None,
        }
    }
}

/// Sub-reasons attached to a `Rejected` status. Each maps verbatim
/// to a §9.1 enumerated `reason` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// WireFormat or inner payload failed structural parse, or class
    /// dispatch landed on a class this route refuses.
    SchemaInvalid,
    /// Inner class tag is unknown to this receiver. Sender violated
    /// the §5.3 capability gate.
    UnknownClass,
    /// Ed25519 signature did not verify under `from_key`.
    InvalidSignature,
    /// Canonical hash matches a locally-erased object. Re-acceptance
    /// would defeat the §3.1 erasure authority.
    Erased,
    /// Sibling edge with the same `prior_edge_hash` already applied
    /// for this pair (§9.4). Both are stored; neither is active.
    ChainFork,
}

impl RejectReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::SchemaInvalid => "schema_invalid",
            Self::UnknownClass => "unknown_class",
            Self::InvalidSignature => "invalid_signature",
            Self::Erased => "erased",
            Self::ChainFork => "chain_fork",
        }
    }
}

/// One row of the §9.1 `results` array. `canonical_hash` is the
/// SHA-256 of the verbatim payload bytes; when the WireFormat itself
/// fails to decode (no payload available), it falls back to SHA-256
/// of the raw input bytes so the sender can still correlate.
struct EdgeResult {
    canonical_hash: [u8; 32],
    status: EdgeStatus,
}

// ---------------------------------------------------------------------------
// Request body decoder
// ---------------------------------------------------------------------------

/// Decoded view of the §9.1 push body.
///
/// Each element is the raw WireFormat bytes for one edge. We do not
/// pre-decode them here — the per-edge state machine walks the
/// elements and reports a per-object `schema_invalid` for whichever
/// ones fail, so a single malformed entry does not poison the whole
/// batch.
struct EdgesBody {
    edges: Vec<Vec<u8>>,
}

impl EdgesBody {
    /// Decode `{ "edges": [bstr, bstr, ...] }`. Returns `None` on any
    /// structural deviation (extra keys are tolerated by spec
    /// silence; we just ignore them). Each list element MUST be a
    /// CBOR byte string — the request body wraps already-canonical
    /// WireFormat blobs, not nested CBOR maps.
    ///
    /// The spec writes the body as `{ "edges": [WireFormat, ...] }`
    /// without explicitly framing each WireFormat as a `bstr`. We
    /// elect to require `bstr` here because:
    /// - Senders mint canonical WireFormat bytes (`encode_signed_object`)
    ///   that the receiver MUST re-hash byte-for-byte; wrapping each
    ///   in a `bstr` preserves those bytes verbatim across re-encode
    ///   round-trips that ciborium would otherwise apply to a nested
    ///   `Value::Map`.
    /// - Forwarders relay the same opaque bytes; treating each entry
    ///   as a transparent blob avoids any temptation to re-canonicalise
    ///   on the relay path.
    fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut edges_field: Option<Vec<Value>> = None;
        for (k, v) in entries {
            let key = match k {
                Value::Text(s) => s,
                _ => continue,
            };
            if key == "edges" {
                match v {
                    Value::Array(a) => edges_field = Some(a),
                    _ => return None,
                }
            }
        }
        let arr = edges_field?;
        let mut edges = Vec::with_capacity(arr.len());
        for item in arr {
            match item {
                Value::Bytes(b) => edges.push(b),
                _ => return None,
            }
        }
        Some(Self { edges })
    }
}

// ---------------------------------------------------------------------------
// Response encoder
// ---------------------------------------------------------------------------

/// Encode `{ "results": [...] }` per §9.1.
fn encode_results(results: &[EdgeResult]) -> Vec<u8> {
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

/// Build the `200 OK` `application/cbor` response for a results array.
fn results_response(results: Vec<EdgeResult>) -> Response {
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

/// `POST /federation/v1/edges` handler (§9.1).
///
/// The `FedEnvelope` extension is present courtesy of `verify_known_peer`;
/// we don't currently key any per-edge decision off the sender, but the
/// extractor pins the middleware contract at the handler signature.
pub async fn handle_edges_push(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    // Request-level errors per §9.1: malformed body, empty batch,
    // batch_too_large. All three short-circuit before any per-edge
    // work and return a 400 with a single `{ "error": ... }` body.
    let parsed = match EdgesBody::decode(&body) {
        Some(p) => p,
        None => return bad_request("malformed"),
    };
    if parsed.edges.is_empty() {
        return bad_request("empty_batch");
    }
    if parsed.edges.len() > MAX_EDGE_BATCH {
        return bad_request("batch_too_large");
    }

    let mut results: Vec<EdgeResult> = Vec::with_capacity(parsed.edges.len());
    let mut any_applied = false;
    for wire_bytes in &parsed.edges {
        let result = match apply_one_edge(&state, wire_bytes, envelope.sender).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "db error applying federated edge");
                return internal_error();
            }
        };
        if matches!(result.status, EdgeStatus::Applied) {
            any_applied = true;
        }
        results.push(result);
    }

    if any_applied {
        // One notify per batch is sufficient — the rebuild loop coalesces.
        state.trust_graph_notify.notify_one();
    }

    results_response(results)
}

/// Apply a single signed WireFormat blob against local state.
///
/// Returns `Err` only for unexpected DB faults — every per-edge
/// rejection / deferral / duplicate path is folded into the
/// `EdgeResult.status` value so the caller can keep batch processing.
///
/// `arrived_from` is the envelope sender — passed to the §7.5
/// forwarder so we don't push the relayed edge back to the peer it
/// just arrived from.
async fn apply_one_edge(
    state: &Arc<AppState>,
    wire_bytes: &[u8],
    arrived_from: [u8; 32],
) -> Result<EdgeResult, sqlx::Error> {
    // Step 1: WireFormat decode. A failure here means we don't have a
    // canonical payload to hash for the result row's `canonical_hash`
    // field, so we fall back to hashing the raw input bytes — the
    // sender can still correlate by position (the spec promises
    // results in input order regardless).
    let (payload_bytes, signature_bytes) = match decode_signed_object(wire_bytes) {
        Some(p) => p,
        None => {
            return Ok(EdgeResult {
                canonical_hash: sha256(wire_bytes),
                status: EdgeStatus::Rejected(RejectReason::SchemaInvalid),
            });
        }
    };

    // Step 2: compute the canonical hash *of the payload*. This is
    // the dedup key in `signed_objects`; same value §9.1 says we
    // return to the sender in `canonical_hash`.
    let canonical_hash = sha256(&payload_bytes);

    // Step 3: signed_objects lookup. Two early returns:
    // - Row exists with payload NULL + erased_at set → spec §9.1
    //   `rejected/erased`: reaccepting would defeat the §3.1
    //   erasure authority.
    // - Row exists with payload still present → idempotent
    //   `duplicate` per §9.1 "redelivery is no-op".
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
            return Ok(EdgeResult {
                canonical_hash,
                status: EdgeStatus::Rejected(RejectReason::Erased),
            });
        }
        return Ok(EdgeResult {
            canonical_hash,
            status: EdgeStatus::Duplicate,
        });
    }

    // Step 4: parse the inner payload and confirm it is a trust-edge.
    // A parse failure is `schema_invalid`; a different class entirely
    // (post-rev, retract, …) is the §5.3 capability-gating violation,
    // surfaced as `unknown_class`.
    let payload = match SignedPayload::parse(&payload_bytes) {
        Ok(p) => p,
        Err(_) => {
            return Ok(EdgeResult {
                canonical_hash,
                status: EdgeStatus::Rejected(RejectReason::SchemaInvalid),
            });
        }
    };
    let trust_edge = match payload {
        SignedPayload::TrustEdge(e) => e,
        _ => {
            return Ok(EdgeResult {
                canonical_hash,
                status: EdgeStatus::Rejected(RejectReason::UnknownClass),
            });
        }
    };

    // Step 5: Ed25519 verify under the signer key (from_key).
    // `signed::verify` re-runs the identity-binding cross-check, so
    // a payload claiming a different signer than the bytes were
    // signed under fails here too.
    let verifying_key = match VerifyingKey::from_bytes(&trust_edge.from_key) {
        Ok(k) => k,
        Err(_) => {
            return Ok(EdgeResult {
                canonical_hash,
                status: EdgeStatus::Rejected(RejectReason::InvalidSignature),
            });
        }
    };
    if signed::verify(&payload_bytes, &signature_bytes, &verifying_key).is_err() {
        return Ok(EdgeResult {
            canonical_hash,
            status: EdgeStatus::Rejected(RejectReason::InvalidSignature),
        });
    }

    // Step 6: persist + project under BEGIN IMMEDIATE. Mirrors
    // users.rs::set_trust_edge — concurrent inbound pushes for the
    // same pair would otherwise both observe an empty chain head and
    // could both apply, producing a chain fork that local code missed.
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    // Steps 7-9: dispatch to the shared projection helper. It runs
    // chain-fork + chain-continuity + INSERT trust_edges + on-receipt
    // erasure (for neutral) atomically against `tx`. The signed-object
    // persistence policy below is shaped by the result: durable for
    // every status except `Deferred` (per §9.1, the orphan re-arrives
    // via re-push or §9.3 backfill).
    let projection =
        try_project_trust_edge(&mut tx, &trust_edge, &canonical_hash, &signature_bytes).await?;

    let status = match projection {
        TrustEdgeProjection::Projected => {
            store_signed_object(
                &mut *tx,
                "trust-edge",
                &payload_bytes,
                &signature_bytes,
                &canonical_hash,
            )
            .await?;
            EdgeStatus::Applied
        }
        TrustEdgeProjection::EndpointMissing => {
            // Phase 9.6: one or both endpoint stubs haven't been
            // hydrated yet (e.g., wide-scope edge arrived before the
            // matching profile-rev). Persist the canonical bytes so
            // `sweep_pending_projections` can project them when the
            // missing stub lands, and report `applied` because §9.1
            // makes no carve-out for "I don't know these users yet"
            // — durable bytes are what `applied` promises on the
            // wire.
            store_signed_object(
                &mut *tx,
                "trust-edge",
                &payload_bytes,
                &signature_bytes,
                &canonical_hash,
            )
            .await?;
            EdgeStatus::Applied
        }
        TrustEdgeProjection::ChainFork => {
            // §9.4 "both stored, neither active" — persist the new
            // bytes as evidence even though they never project.
            store_signed_object(
                &mut *tx,
                "trust-edge",
                &payload_bytes,
                &signature_bytes,
                &canonical_hash,
            )
            .await?;
            EdgeStatus::Rejected(RejectReason::ChainFork)
        }
        TrustEdgeProjection::Deferred => {
            // §9.1 deferred: orphan in the chain. We deliberately do
            // NOT persist — a re-push or §9.3 backfill re-delivers
            // the edge in a state where chain-continuity passes. A
            // durable pending-orphan buffer is a future-phase item.
            EdgeStatus::Deferred
        }
    };

    tx.commit().await?;

    // §7.5 fan the freshly-applied edge out to interested peers.
    // Originator-vs-relay is purely a matter of `arrived_from`: when
    // the envelope sender was the originator, every other interested
    // peer (capped at REDUNDANCY_K under the dedup-LRU bitset) gets
    // a copy; the originator itself is excluded because it's the
    // `arrived_from`. `Duplicate` results deliberately do NOT trigger
    // a forward — §7.5 pseudocode short-circuits "if seen_recently",
    // and the signed_objects dedup we just hit above is the local
    // equivalent.
    if matches!(status, EdgeStatus::Applied) {
        forward_signed_object(
            state.clone(),
            canonical_hash,
            ForwardingClass::TrustEdge,
            trust_edge.from_key.to_vec(),
            wire_bytes.to_vec(),
            Some(arrived_from),
        )
        .await;
    }

    Ok(EdgeResult {
        canonical_hash,
        status,
    })
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Layer-0 unit tests — local state-machine invariants
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::envelope::encode_signed_object;
    use crate::signed::TrustStance;
    use crate::signing::sign_trust_edge_with_key;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    /// Roundtrip a results body so a sender that reads the §9.1
    /// vocabulary back out gets the exact tags the spec calls for.
    #[test]
    fn results_response_uses_spec_status_tags() {
        let results = vec![
            EdgeResult {
                canonical_hash: [1u8; 32],
                status: EdgeStatus::Applied,
            },
            EdgeResult {
                canonical_hash: [2u8; 32],
                status: EdgeStatus::Duplicate,
            },
            EdgeResult {
                canonical_hash: [3u8; 32],
                status: EdgeStatus::Deferred,
            },
            EdgeResult {
                canonical_hash: [4u8; 32],
                status: EdgeStatus::Rejected(RejectReason::InvalidSignature),
            },
            EdgeResult {
                canonical_hash: [5u8; 32],
                status: EdgeStatus::Rejected(RejectReason::ChainFork),
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

        // (input-index, expected status, expected reason)
        let expected: &[(usize, &str, Option<&str>)] = &[
            (0, "applied", None),
            (1, "duplicate", None),
            (2, "deferred", None),
            (3, "rejected", Some("invalid_signature")),
            (4, "rejected", Some("chain_fork")),
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

    /// A request with a single malformed WireFormat byte string
    /// decodes at the body layer (the array element is a `bstr`) but
    /// fails the per-edge WireFormat decode, surfacing
    /// `rejected/schema_invalid` with a hash derived from the raw
    /// input bytes (the spec's order-by-position promise still holds).
    #[test]
    fn edges_body_decoder_accepts_wireformat_bstrs() {
        // Sign a real trust-edge so we have valid wire bytes to wrap.
        let signer = SigningKey::generate(&mut OsRng);
        let target = [7u8; 32];
        let out = sign_trust_edge_with_key(
            &signer,
            &target,
            TrustStance::Trust,
            1_700_000_000_000,
            None,
        );
        let wire = encode_signed_object(&out.payload, &out.signature);

        // Body shape: { "edges": [bstr] }.
        let body = Value::Map(vec![(
            Value::Text("edges".into()),
            Value::Array(vec![Value::Bytes(wire.clone())]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();

        let parsed = EdgesBody::decode(&buf).expect("decode");
        assert_eq!(parsed.edges.len(), 1);
        assert_eq!(
            parsed.edges[0], wire,
            "bstr element survives decode verbatim"
        );
    }

    /// Defensive: the body decoder rejects non-bstr array elements
    /// (e.g. a nested CBOR map) so we never accidentally round-trip
    /// a re-encoded WireFormat that no longer matches its hash.
    #[test]
    fn edges_body_decoder_rejects_non_bstr_elements() {
        let body = Value::Map(vec![(
            Value::Text("edges".into()),
            Value::Array(vec![Value::Map(vec![(
                Value::Text("p".into()),
                Value::Bytes(vec![1, 2, 3]),
            )])]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert!(EdgesBody::decode(&buf).is_none());
    }
}
