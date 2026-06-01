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
//!      `signed_objects` for dedup / relay / future audit. Phase 9.8:
//!      also drains `pending_trust_edges` for any orphan whose
//!      `prior_edge_hash` matches the just-projected `canonical_hash`,
//!      cascading through chained orphans atomically with the
//!      trigger.
//!    - `ChainFork` → `rejected/chain_fork`, with bytes persisted as
//!      §9.4 "both stored, neither active" evidence.
//!    - `Deferred` → `deferred`; Phase 9.8 enqueues the canonical
//!      bytes into `pending_trust_edges` keyed on
//!      `(source_pubkey, prior_edge_hash)`. If the row is freshly
//!      inserted (first orphan for this gap), the handler spawns an
//!      autonomous `GET /federation/v1/edges/backfill` (§9.3)
//!      against the source-key's home instance after commit. The
//!      orphan promotes to a real `signed_objects` row and a
//!      `trust_edges` projection when the predecessor lands; the
//!      pending row ages out under `DEFERRED_ORPHAN_TTL` (1h) if
//!      recovery never completes.
//!    - `EndpointMissing` → `applied`. The Phase 9.6 sweep
//!      (`remote_users::sweep_pending_projections`) catches the
//!      projection up when the missing endpoint's profile-rev
//!      hydrates a stub for it. As of §11.9.5, an `EndpointMissing`
//!      edge toward a *local* user whose *source* we've never seen is
//!      no longer purely passive: the handler spawns a §10.5
//!      by-author backfill (`prior_home_recovery::proactive_author_backfill`)
//!      after commit to pull the source's profile-rev, breaking the
//!      trust-code bootstrap deadlock where the source's content is
//!      itself gated on this edge.
//!
//! After the loop over all edges has finished, the batch-level
//! handler issues a single `trust_graph_notify` — the rebuild loop
//! coalesces, so per-edge notifications would be wasted work.
//!
//! Phase 9.8 status of historical punts:
//! - The pre-9.5 "no profile-sync yet, projection rebuilds when
//!   stubs hydrate" comment is resolved: federated stubs exist as
//!   real `users` rows from Phase 9.5 onwards, and the `EndpointMissing`
//!   branch defers projection to the sweep that runs when the
//!   missing endpoint's profile-rev arrives.
//! - Still punted: no `pending_deltas.apply` for federated edges.
//!   The rebuild loop picks the change up on its next pass; cached
//!   per-viewer trust state lags by one rebuild cycle. Originated
//!   edges keep the fast-path because the active viewer issued them.
//! - Resolved (Phase 9.8): durable pending-orphan buffer
//!   (`pending_trust_edges`) + autonomous §9.3 backfill. `Deferred`
//!   is no longer a "one-shot the sender sees" — the receiver
//!   persists the bytes and recovers the predecessor on its own.

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
use crate::federation::forwarder::forward_trust_edge;
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::middleware::VerifiedBody;
use crate::federation::remote_users::{
    TrustEdgeProjection, drain_pending_orphans_after, enqueue_pending_trust_edge,
    try_project_trust_edge,
};
use crate::signed::{self, FedEnvelope, SignedPayload};
use crate::signing::store_signed_object;

/// §9.6 `MAX_EDGE_BATCH`: receiver-enforced upper bound on
/// `len(body.edges)`. Overflow returns
/// `400 { "error": "batch_too_large" }`.
pub const MAX_EDGE_BATCH: usize = 256;

/// §9.6 `DEFERRED_ORPHAN_TTL`: receiver-local lifetime for entries in
/// the `pending_trust_edges` buffer. Default 1h per spec. After this
/// window the orphan is unrecoverable from this receiver's
/// perspective; recovery becomes the sender's problem on the next
/// push.
pub const DEFERRED_ORPHAN_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

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
pub(crate) struct EdgeResult {
    pub(crate) canonical_hash: [u8; 32],
    pub(crate) status: EdgeStatus,
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
///
/// Live-push wrapper around [`apply_one_edge_inner`]. The inner helper
/// is split out so the Phase 9.8 autonomous §9.3 backfill issuer
/// (`crate::federation::edge_backfill`) can re-feed the chain-walk
/// response through the same code path the live push uses — keeping
/// `signed_objects` writes, `try_project_trust_edge` projection,
/// pending-buffer drain, and §7.5 forwarder fan-out all on one path
/// instead of forking the receive logic.
///
/// Why the split: `apply_one_edge_inner` may signal "spawn an autonomous
/// §9.3 backfill". The spawn itself lives here in the outer wrapper, not
/// inside the inner helper, because the live-push call site is the only
/// path where firing autonomous backfill is in scope. The re-feed path
/// inside `request_edge_predecessor` deliberately suppresses recursive
/// backfill (§9.6 `MAX_BACKFILL_RATE`) by calling the inner directly
/// and discarding the signal. Keeping the spawn out of `_inner` also
/// breaks an otherwise-cyclic Send check (the spawned future calls
/// `request_edge_predecessor`, which calls `apply_one_edge_inner` —
/// putting the spawn inside the inner helper makes its own future's
/// Send-ness depend on itself).
pub(crate) async fn apply_one_edge(
    state: &Arc<AppState>,
    wire_bytes: &[u8],
    arrived_from: [u8; 32],
) -> Result<EdgeResult, sqlx::Error> {
    let (result, recovery) = apply_one_edge_inner(state, wire_bytes, arrived_from).await?;
    match recovery {
        // Phase 9.8 §9.3: a fresh orphan whose chain predecessor we
        // lack — pull the gap from the source's home. Gated behind a
        // process-wide concurrency semaphore: a burst of fresh orphans
        // (e.g. peer re-pushing a long chain from the tail) would
        // otherwise launch one outbound `GET /edges/backfill` per
        // orphan. When the cap is saturated we skip the spawn — the
        // buffered orphan stays in `pending_trust_edges`, and either the
        // next live push (which re-triggers via the `first_for_gap`
        // flag) or the §9.6 sweep tick will eventually drive recovery.
        Some(EdgeRecovery::Predecessor {
            source,
            target,
            prior,
        }) => match crate::federation::edge_backfill::try_acquire_outbound_permit() {
            Some(permit) => {
                let state_for_backfill = state.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = crate::federation::edge_backfill::request_edge_predecessor(
                        state_for_backfill,
                        source,
                        target,
                        prior,
                    )
                    .await
                    {
                        tracing::warn!(
                            source = %crate::users::hex_lower(&source),
                            target = %crate::users::hex_lower(&target),
                            error = %e,
                            "autonomous edge backfill failed; will rely on next push to retrigger",
                        );
                    }
                });
            }
            None => {
                tracing::debug!(
                    source = %crate::users::hex_lower(&source),
                    target = %crate::users::hex_lower(&target),
                    "outbound backfill concurrency cap reached; skipping spawn (orphan retains buffered, will retrigger on next push or §9.6 sweep)",
                );
            }
        },
        // §11.9.5 reverse bootstrap: an inbound trust-edge toward a local
        // user whose *source* we have never seen projects as
        // `EndpointMissing` and sits durable-but-unprojected. `Deferred`
        // actively recovers its gap; `EndpointMissing` historically did
        // not, so a trust-coded `S → local` edge would never surface in
        // the local user's "trusted by" (the source's profile-rev is
        // itself gated on this very edge — a bootstrap deadlock). Pull
        // the source's content via §10.5 by-author so its stub hydrates
        // and `sweep_pending_projections` projects the stored edge. Same
        // outbound-backfill budget as the §9.3 path above.
        Some(EdgeRecovery::UnknownSource { source }) => {
            match crate::federation::edge_backfill::try_acquire_outbound_permit() {
                Some(permit) => {
                    let state_for_backfill = state.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        crate::federation::prior_home_recovery::proactive_author_backfill(
                            &state_for_backfill,
                            source,
                        )
                        .await;
                    });
                }
                None => {
                    tracing::debug!(
                        source = %crate::users::hex_lower(&source),
                        "outbound backfill concurrency cap reached; skipping unknown-source hydration (will retrigger on next push or §9.6 sweep)",
                    );
                }
            }
        }
        None => {}
    }
    Ok(result)
}

/// Post-commit recovery the outer [`apply_one_edge`] wrapper should
/// spawn for a freshly-received edge. Carried out of
/// [`apply_one_edge_inner`] rather than spawned there because the spawned
/// future re-enters the receive path — putting the spawn inside the inner
/// helper would make its own future's Send-ness depend on itself.
pub(crate) enum EdgeRecovery {
    /// §9.3 chain-continuity: a fresh `Deferred` orphan. Fetch the
    /// missing predecessor of the `(source, target)` chain from the
    /// source's home.
    Predecessor {
        source: [u8; 32],
        target: [u8; 32],
        prior: [u8; 32],
    },
    /// §11.9.5 reverse bootstrap: an `EndpointMissing` edge toward a
    /// local user whose `source` (the signer) we have never seen. Pull
    /// the source's content via §10.5 by-author so its stub hydrates.
    UnknownSource { source: [u8; 32] },
}

/// Core per-edge state machine. Returns `(EdgeResult,
/// Option<EdgeRecovery>)` — the second element is `Some` iff the receive
/// produced an outcome the outer wrapper should fire post-commit recovery
/// for: a fresh `Deferred` orphan (→ [`EdgeRecovery::Predecessor`], §9.3
/// chain backfill) or an `EndpointMissing` edge toward a local user whose
/// source we have never seen (→ [`EdgeRecovery::UnknownSource`], §11.9.5
/// reverse bootstrap). `None` on every other outcome (and on
/// Deferred-but-duplicate, where the gap already has a buffered orphan).
pub(crate) async fn apply_one_edge_inner(
    state: &Arc<AppState>,
    wire_bytes: &[u8],
    arrived_from: [u8; 32],
) -> Result<(EdgeResult, Option<EdgeRecovery>), sqlx::Error> {
    // Step 1: WireFormat decode. A failure here means we don't have a
    // canonical payload to hash for the result row's `canonical_hash`
    // field, so we fall back to hashing the raw input bytes — the
    // sender can still correlate by position (the spec promises
    // results in input order regardless).
    let (payload_bytes, signature_bytes) = match decode_signed_object(wire_bytes) {
        Some(p) => p,
        None => {
            return Ok((
                EdgeResult {
                    canonical_hash: sha256(wire_bytes),
                    status: EdgeStatus::Rejected(RejectReason::SchemaInvalid),
                },
                None,
            ));
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
            return Ok((
                EdgeResult {
                    canonical_hash,
                    status: EdgeStatus::Rejected(RejectReason::Erased),
                },
                None,
            ));
        }
        return Ok((
            EdgeResult {
                canonical_hash,
                status: EdgeStatus::Duplicate,
            },
            None,
        ));
    }

    // Step 4: parse the inner payload and confirm it is a trust-edge.
    // A parse failure is `schema_invalid`; a different class entirely
    // (post-rev, retract, …) is the §5.3 capability-gating violation,
    // surfaced as `unknown_class`.
    let payload = match SignedPayload::parse(&payload_bytes) {
        Ok(p) => p,
        Err(_) => {
            return Ok((
                EdgeResult {
                    canonical_hash,
                    status: EdgeStatus::Rejected(RejectReason::SchemaInvalid),
                },
                None,
            ));
        }
    };
    let trust_edge = match payload {
        SignedPayload::TrustEdge(e) => e,
        _ => {
            return Ok((
                EdgeResult {
                    canonical_hash,
                    status: EdgeStatus::Rejected(RejectReason::UnknownClass),
                },
                None,
            ));
        }
    };

    // Step 5: Ed25519 verify under the signer key (from_key).
    // `signed::verify` re-runs the identity-binding cross-check, so
    // a payload claiming a different signer than the bytes were
    // signed under fails here too.
    let verifying_key = match VerifyingKey::from_bytes(&trust_edge.from_key) {
        Ok(k) => k,
        Err(_) => {
            return Ok((
                EdgeResult {
                    canonical_hash,
                    status: EdgeStatus::Rejected(RejectReason::InvalidSignature),
                },
                None,
            ));
        }
    };
    if signed::verify(&payload_bytes, &signature_bytes, &verifying_key).is_err() {
        return Ok((
            EdgeResult {
                canonical_hash,
                status: EdgeStatus::Rejected(RejectReason::InvalidSignature),
            },
            None,
        ));
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
    let projection = try_project_trust_edge(
        &mut tx,
        &trust_edge,
        &canonical_hash,
        &signature_bytes,
        &payload_bytes,
    )
    .await?;

    // Post-commit recovery signal for the outer wrapper. Set by the
    // `Deferred` branch (§9.3 predecessor backfill) and the
    // `EndpointMissing` branch (§11.9.5 unknown-source hydration); both
    // carry the keys the wrapper needs to spawn the outbound request
    // after the tx commits.
    let mut recovery: Option<EdgeRecovery> = None;

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
            // Phase 9.8: any orphans previously buffered waiting on
            // *this* edge can now project. Drain them inside the same
            // tx so the cascade is atomic with its trigger; a chain
            // of N orphans collapses in one drain pass.
            drain_pending_orphans_after(&mut tx, &canonical_hash).await?;
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

            // §11.9.5 reverse bootstrap. An `EndpointMissing` whose
            // *target* is one of our live local users but whose *source*
            // we've never seen is the trust-code deadlock: the source's
            // profile-rev (which would hydrate its stub and let
            // `sweep_pending_projections` project this edge) is itself
            // gated on a trust path that runs through this very edge.
            // Nothing else pushes the source's content our way, so the
            // local user's "trusted by" would stay empty forever. Signal
            // the outer wrapper to pull the source's content via §10.5
            // by-author. Scoped narrowly (target local + source unknown)
            // so stranger→stranger edges stay passive and we don't
            // amplify backfill for edges that can't touch a local view.
            let to_slice: &[u8] = &trust_edge.to_key;
            let from_slice: &[u8] = &trust_edge.from_key;
            let target_is_local = sqlx::query_scalar!(
                "SELECT 1 AS \"x!: i64\" FROM users \
                 WHERE public_key = ? AND home_instance IS NULL AND status = 'active' LIMIT 1",
                to_slice,
            )
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
            let source_known = sqlx::query_scalar!(
                "SELECT 1 AS \"x!: i64\" FROM users WHERE public_key = ? LIMIT 1",
                from_slice,
            )
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
            if target_is_local && !source_known {
                recovery = Some(EdgeRecovery::UnknownSource {
                    source: trust_edge.from_key,
                });
            }
            // No frontier_edges insert here: an `EndpointMissing` edge is
            // not yet active in `trust_edges`, so it has no business in
            // the reverse-frontier store. It projects (and lands in the
            // store) via `try_project_trust_edge` on the §9.6 sweep once
            // the missing stub hydrates.
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
            // `try_project_trust_edge` only returns `Deferred` from
            // inside the `if let Some(prior)` branch, so by
            // construction `prior_edge_hash` is `Some` here. Pull it
            // out explicitly: a `None` means projection logic and the
            // caller have desynchronised, and we must not lie
            // "deferred" to the sender for an edge we can never
            // recover (the pending row would be silently dropped by
            // `enqueue_pending_trust_edge`'s defensive NULL guard).
            let Some(prior) = trust_edge.prior_edge_hash else {
                tracing::error!(
                    canonical_hash = %crate::users::hex_lower(&canonical_hash),
                    "try_project_trust_edge returned Deferred for an edge with NULL prior_edge_hash; rejecting as schema_invalid"
                );
                return Ok((
                    EdgeResult {
                        canonical_hash,
                        status: EdgeStatus::Rejected(RejectReason::SchemaInvalid),
                    },
                    None,
                ));
            };

            // Phase 9.8: durable buffer for orphan edges. `INSERT OR
            // IGNORE` keyed on `(source_pubkey, prior_edge_hash)`
            // returns `true` iff this is the first orphan for this
            // gap — i.e. the one that should trigger the autonomous
            // §9.3 backfill. Subsequent re-pushes / siblings for the
            // same gap collapse into the existing buffered row and
            // don't re-fire the request.
            //
            // We deliberately do NOT call `store_signed_object` here:
            // the pending buffer is the sole durable layer for
            // orphans, and double-storing would let the §9.1 dedup
            // check observe the bytes and return `Duplicate` on
            // re-push before the predecessor lands (which would
            // confuse the sender about whether their chain has been
            // accepted).
            let now_ms = chrono::Utc::now().timestamp_millis();
            let first_for_gap = enqueue_pending_trust_edge(
                &mut tx,
                &trust_edge,
                &canonical_hash,
                &payload_bytes,
                &signature_bytes,
                now_ms,
            )
            .await?;
            if first_for_gap {
                recovery = Some(EdgeRecovery::Predecessor {
                    source: trust_edge.from_key,
                    target: trust_edge.to_key,
                    prior,
                });
            }
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
        forward_trust_edge(
            state.clone(),
            canonical_hash,
            trust_edge.from_key,
            trust_edge.to_key,
            wire_bytes.to_vec(),
            Some(arrived_from),
        )
        .await;
    }

    Ok((
        EdgeResult {
            canonical_hash,
            status,
        },
        recovery,
    ))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Cadence for the Phase 9.8 TTL sweep. Polls every 5 minutes —
/// `DEFERRED_ORPHAN_TTL` is 1h, so a row ages out within at most
/// `TTL + 5min ≈ 65 min` after enqueue. Fast enough that a stuck
/// orphan doesn't pin a pubkey row indefinitely; slow enough that
/// idle instances don't churn the DB.
const PENDING_ORPHAN_TTL_TICK: std::time::Duration = std::time::Duration::from_secs(300);

/// Background loop for Phase 9.8 `pending_trust_edges` TTL eviction.
///
/// Runs forever (spawned from `main`). On each tick, calls
/// [`crate::federation::remote_users::evict_expired_pending_trust_edges`]
/// with the current wall clock and the [`DEFERRED_ORPHAN_TTL`] window
/// as `ttl_ms`. A non-zero eviction count is surfaced at `info!` so
/// operators can spot a stuck-sender pattern (chronic eviction means
/// somebody is pushing orphan chains whose root never arrives via
/// any channel).
pub async fn pending_orphan_ttl_loop(db: sqlx::SqlitePool) {
    let ttl_ms = DEFERRED_ORPHAN_TTL.as_millis() as i64;
    loop {
        tokio::time::sleep(PENDING_ORPHAN_TTL_TICK).await;
        let now_ms = chrono::Utc::now().timestamp_millis();
        match crate::federation::remote_users::evict_expired_pending_trust_edges(
            &db, now_ms, ttl_ms,
        )
        .await
        {
            Ok(0) => {}
            Ok(n) => tracing::info!(evicted = n, "pending_trust_edges TTL sweep"),
            Err(e) => tracing::warn!(error = %e, "pending_trust_edges TTL sweep failed"),
        }
    }
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
