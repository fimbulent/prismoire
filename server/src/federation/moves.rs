//! Move declaration push handler (`docs/federation-protocol.md` §12).
//!
//! Mounts two routes under `/federation/v1`:
//!
//! ```text
//! POST /federation/v1/moves           (§12.1 push)
//! GET  /federation/v1/moves/backfill  (§12.3 chain-continuity recovery)
//! ```
//!
//! Both behind `verify_known_peer`: per §6 the sender must be an
//! `active` peer. The backfill GET handler lives in
//! [`super::backfill`] to keep all `/backfill` routes co-located.
//!
//! ## Per-object state machine (§12.1)
//!
//! 1. WireFormat decode → `rejected/schema_invalid` on failure.
//! 2. `signed_objects` lookup — live row → `duplicate`. (Moves
//!    are never erased, so no `Erased` branch is needed; the
//!    `payload IS NULL` defensive check still surfaces as
//!    `schema_invalid` if it ever fires, since a NULL-payload move
//!    means our own state is corrupt.)
//! 3. `SignedPayload::parse` + class dispatch — non-move accepted
//!    class → `rejected/wrong_class`; unrecognised class →
//!    `rejected/unknown_class`.
//! 4. Ed25519 verify against `Move.key`.
//! 5. `MAX_CLOCK_SKEW` check against receiver wall clock.
//! 6. Chain-grounding: if `prior_move_hash` is `Some(h)`, that hash
//!    MUST be present in `signed_objects` as a move; otherwise the
//!    object is `deferred` (no persist, no forward — Phase 8 lands
//!    the pending-validation buffer + autonomous backfill issuance).
//! 7. §12.4 latest-wins-by-timestamp resolution: compare against the
//!    existing `user_homes` row for `Move.key` (if any). The winner
//!    UPSERTs `user_homes`; the loser is `superseded`. In both cases
//!    the canonical bytes are persisted to `signed_objects` so
//!    backfill and audit chains stay intact.
//! 8. Persisted (applied OR superseded) → forward via §12.2 with
//!    `REDUNDANCY_K_MOVE = 5`. `duplicate` is **also forwarded once**
//!    under the redundancy budget (the unconditional-flood property
//!    of §12.2 means truncating on first-duplicate would defeat
//!    discoverability — that branch is wired by Phase 7's forwarder
//!    extension in [`super::forwarder`] / [`super::routing`]).
//!
//! ## Result vocabulary
//!
//! `applied | duplicate | deferred | superseded | rejected{reason}` per
//! §12.1; `reason ∈ { invalid_signature, schema_invalid, skew_exceeded,
//! unknown_key, unknown_class, wrong_class, other }`. `wrong_class` is
//! kept for symmetry with `/content` and `/edges` so a peer that
//! misroutes a non-move signed-object gets a consistent diagnostic
//! across all push routes.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
use crate::federation::routing::ForwardingClass;
use crate::signed::{self, FedEnvelope, Move, SignedPayload};
use crate::signing::store_signed_object;

/// Per-source rolling-hour Move-object cap (mirrors the §10.6 fold-in
/// for `/content`). Closes the equivalent abuse window flagged for
/// `/federation/v1/moves`: with `MAX_MOVE_BATCH = 64`,
/// `bypasses_filters = true`, and `REDUNDANCY_K_MOVE = 5`, a hostile
/// peer could sustain steady-state DB write pressure plus 5× outbound
/// fanout. The cap is tighter than the `/content` ceiling
/// (`MAX_CONTENT_OBJECTS_PER_HOUR = 10_000`) because moves are rare
/// (one per user per identity transition, indefinitely retained per
/// §12.5) and the unconditional-flood fanout amplifies abuse cost
/// proportionally.
pub const MAX_MOVE_OBJECTS_PER_HOUR: u32 = 1_000;

/// §12.7 `MAX_MOVE_BATCH`: receiver-enforced object-count cap.
/// Overflow returns `400 { "error": "batch_too_large" }`.
pub const MAX_MOVE_BATCH: usize = 64;

/// §12.7 `MAX_CLOCK_SKEW`: tolerance for `move.created_at` vs.
/// receiver wall clock. Bounds the forge-replay window on a
/// compromised key.
pub const MAX_CLOCK_SKEW_MS: u64 = 300_000;

// ---------------------------------------------------------------------------
// Per-object result vocabulary (§12.1)
// ---------------------------------------------------------------------------

/// Top-level status per the §12.1 result table. `Superseded` is the
/// move-specific variant absent from `/content` and `/edges` — the
/// object is persisted (chain evidence per §12.5) but does not flip
/// `user_homes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoveStatus {
    Applied,
    Duplicate,
    Deferred,
    Superseded,
    Rejected(MoveRejectReason),
}

impl MoveStatus {
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

/// The §12.1 enumerated `reason` vocabulary, plus `wrong_class` kept
/// for parity with `/content` and `/edges` (a peer that misroutes a
/// non-move signed object gets a consistent diagnostic across push
/// routes; §12.1's `unknown_class` is reserved for genuinely
/// unrecognised classes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoveRejectReason {
    InvalidSignature,
    SchemaInvalid,
    SkewExceeded,
    UnknownClass,
    WrongClass,
}

impl MoveRejectReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid_signature",
            Self::SchemaInvalid => "schema_invalid",
            Self::SkewExceeded => "skew_exceeded",
            Self::UnknownClass => "unknown_class",
            Self::WrongClass => "wrong_class",
        }
    }
}

/// One row of the §12.1 `results` array.
struct MoveResult {
    canonical_hash: [u8; 32],
    status: MoveStatus,
}

// ---------------------------------------------------------------------------
// Request body decoder
// ---------------------------------------------------------------------------

/// Decoded view of the §12.1 push body.
///
/// Same `bstr`-per-element invariant as `content.rs::ContentBody` and
/// `edges.rs::EdgesBody`: each element is the raw WireFormat bytes for
/// one signed move. The receiver re-hashes those bytes verbatim, so
/// wrapping each as `bstr` preserves them across re-encode round-trips.
struct MovesBody {
    moves: Vec<Vec<u8>>,
}

impl MovesBody {
    fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut moves_field: Option<Vec<Value>> = None;
        for (k, v) in entries {
            let key = match k {
                Value::Text(s) => s,
                _ => return None,
            };
            match key.as_str() {
                "moves" => {
                    if moves_field.is_some() {
                        return None;
                    }
                    match v {
                        Value::Array(a) => moves_field = Some(a),
                        _ => return None,
                    }
                }
                _ => return None,
            }
        }
        let arr = moves_field?;
        let mut moves = Vec::with_capacity(arr.len());
        for item in arr {
            match item {
                Value::Bytes(b) => moves.push(b),
                _ => return None,
            }
        }
        Some(Self { moves })
    }
}

// ---------------------------------------------------------------------------
// Response encoder
// ---------------------------------------------------------------------------

fn encode_results(results: &[MoveResult]) -> Vec<u8> {
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

fn results_response(results: Vec<MoveResult>) -> Response {
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

/// `POST /federation/v1/moves` handler (§12.1).
pub async fn handle_moves_push(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let parsed = match MovesBody::decode(&body) {
        Some(p) => p,
        None => return bad_request("malformed"),
    };
    if parsed.moves.is_empty() {
        return bad_request("empty_batch");
    }
    if parsed.moves.len() > MAX_MOVE_BATCH {
        return bad_request("batch_too_large");
    }
    // Per-source rolling-hour cap (see [`MAX_MOVE_OBJECTS_PER_HOUR`]).
    // Whole-batch reject on overflow is the same backpressure shape
    // as `/content` — a well-behaved sender drops into backoff rather
    // than retrying object-by-object. A rejected batch does not burn
    // budget.
    if !state
        .move_rate_limiter
        .check_and_count(envelope.sender, parsed.moves.len() as u32)
    {
        return bad_request("rate_limited");
    }

    let now_ms = now_ms();
    let mut results: Vec<MoveResult> = Vec::with_capacity(parsed.moves.len());
    for wire_bytes in &parsed.moves {
        let result = match apply_one_move(&state, wire_bytes, envelope.sender, now_ms).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "db error applying federated move");
                return internal_error();
            }
        };
        results.push(result);
    }

    results_response(results)
}

/// §12.1 / §12.4 per-object state machine for a single signed move.
async fn apply_one_move(
    state: &Arc<AppState>,
    wire_bytes: &[u8],
    arrived_from: [u8; 32],
    now_ms: u64,
) -> Result<MoveResult, sqlx::Error> {
    // Step 1: WireFormat decode.
    let (payload_bytes, signature_bytes) = match decode_signed_object(wire_bytes) {
        Some(p) => p,
        None => {
            return Ok(MoveResult {
                canonical_hash: sha256(wire_bytes),
                status: MoveStatus::Rejected(MoveRejectReason::SchemaInvalid),
            });
        }
    };
    let canonical_hash = sha256(&payload_bytes);

    // Step 2: signed_objects dedup. Moves are §12.5-indefinite-retention;
    // there's no `erased` branch like content/edges. A `payload IS NULL`
    // row here would mean our local state was corrupted by another path
    // (no spec path erases a move), so surface as schema_invalid.
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
            return Ok(MoveResult {
                canonical_hash,
                status: MoveStatus::Rejected(MoveRejectReason::SchemaInvalid),
            });
        }
        // §12.2: `duplicate` moves are still candidates for one
        // forward under the redundancy budget (the unconditional
        // flood property). We hand the bytes to the forwarder; the
        // dedup-LRU's REDUNDANCY_K_MOVE budget bounds the actual
        // fanout. Forwarding-class wiring lands alongside Task #5.
        //
        // Important: `Move` bypasses §7.4 routing-key dispatch
        // (`peers_interested_in` returns every active peer when
        // `bypasses_filters()`), so an empty routing key does NOT
        // no-op — it would still flood. If the inbound bytes don't
        // re-parse as a Move (only possible if the prior accept's
        // bytes were valid but these new wire bytes are not, which
        // by hash collision-resistance shouldn't happen), skip the
        // forward rather than relay nonsense to peers.
        if let Some(key) = move_routing_key_from_bytes(&payload_bytes) {
            forward_signed_object(
                state.clone(),
                canonical_hash,
                ForwardingClass::Move,
                key,
                wire_bytes.to_vec(),
                Some(arrived_from),
            )
            .await;
        } else {
            tracing::warn!(
                hash_prefix = ?&canonical_hash[..4],
                "duplicate move payload failed to re-parse; suppressing forward to avoid relaying corrupt bytes"
            );
        }
        return Ok(MoveResult {
            canonical_hash,
            status: MoveStatus::Duplicate,
        });
    }

    // Step 3: parse + class dispatch. Non-move accepted classes are
    // `wrong_class`; unrecognised classes are `unknown_class`.
    let payload = match SignedPayload::parse(&payload_bytes) {
        Ok(p) => p,
        Err(_) => {
            return Ok(MoveResult {
                canonical_hash,
                status: MoveStatus::Rejected(MoveRejectReason::SchemaInvalid),
            });
        }
    };
    let mv: Move = match payload {
        SignedPayload::Move(m) => m,
        SignedPayload::TrustEdge(_)
        | SignedPayload::PostRevision(_)
        | SignedPayload::Retraction(_)
        | SignedPayload::AdminRemoval(_)
        | SignedPayload::ProfileRevision(_)
        | SignedPayload::ThreadCreate(_)
        | SignedPayload::Deactivation(_)
        | SignedPayload::UserStatus(_)
        | SignedPayload::ThreadStatus(_)
        | SignedPayload::Report(_)
        | SignedPayload::Attestation(_) => {
            return Ok(MoveResult {
                canonical_hash,
                status: MoveStatus::Rejected(MoveRejectReason::WrongClass),
            });
        }
        SignedPayload::FedEnvelope(_)
        | SignedPayload::RegistrationChallenge(_)
        | SignedPayload::PriorHomeChallenge(_)
        | SignedPayload::PriorHomeResponse(_) => {
            return Ok(MoveResult {
                canonical_hash,
                status: MoveStatus::Rejected(MoveRejectReason::UnknownClass),
            });
        }
    };

    // Step 4: Ed25519 verify against the moving identity K.
    let vk = match VerifyingKey::from_bytes(&mv.key) {
        Ok(k) => k,
        Err(_) => {
            return Ok(MoveResult {
                canonical_hash,
                status: MoveStatus::Rejected(MoveRejectReason::InvalidSignature),
            });
        }
    };
    if signed::verify(&payload_bytes, &signature_bytes, &vk).is_err() {
        return Ok(MoveResult {
            canonical_hash,
            status: MoveStatus::Rejected(MoveRejectReason::InvalidSignature),
        });
    }

    // Step 5: §12.7 `MAX_CLOCK_SKEW` check. `now_ms` is captured once
    // per batch in the handler so a long batch can't drift across
    // entries; `|now - move.created_at| > MAX_CLOCK_SKEW` is terminal
    // (`skew_exceeded`; senders MUST NOT retry).
    let skew = now_ms.abs_diff(mv.created_at);
    if skew > MAX_CLOCK_SKEW_MS {
        return Ok(MoveResult {
            canonical_hash,
            status: MoveStatus::Rejected(MoveRejectReason::SkewExceeded),
        });
    }

    // Step 6: chain-grounding. If `prior_move_hash` is set the
    // predecessor MUST be in `signed_objects` (as a move) — otherwise
    // `deferred`. Phase 7 returns `deferred` as a one-shot status
    // without persisting; Phase 8 lands the pending-validation buffer
    // and autonomous `/moves/backfill` issuance.
    if let Some(prior) = mv.prior_move_hash {
        let prior_slice: &[u8] = prior.as_slice();
        let prior_row = sqlx::query_scalar!(
            "SELECT 1 AS \"present!: i64\" FROM signed_objects \
             WHERE canonical_hash = ? AND inner_class = 'move' AND payload IS NOT NULL \
             LIMIT 1",
            prior_slice,
        )
        .fetch_optional(&state.db)
        .await?;
        if prior_row.is_none() {
            return Ok(MoveResult {
                canonical_hash,
                status: MoveStatus::Deferred,
            });
        }
    }

    // Step 7: §12.4 latest-wins-by-timestamp resolution under
    // BEGIN IMMEDIATE so the existing `user_homes` row read and the
    // UPSERT observe one snapshot (two concurrent inbound moves for
    // the same K would otherwise both observe the prior winner and
    // race to UPSERT).
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    let key_slice: &[u8] = mv.key.as_slice();
    let existing_home = sqlx::query!(
        "SELECT current_created_at AS \"current_created_at!: i64\", \
                current_move_hash AS \"current_move_hash!: Vec<u8>\" \
         FROM user_homes WHERE user_key = ?",
        key_slice,
    )
    .fetch_optional(&mut *tx)
    .await?;

    // §12.4 winner determination. Latest `created_at` wins; ties broken
    // by canonical_hash bytewise compare (smaller wins — picking
    // *some* deterministic rule both peers can agree on; the spec
    // leaves the direction unspecified, so we pin "smaller wins"
    // here and rely on cross-instance convergence tests to enforce it).
    let new_wins = match &existing_home {
        None => true,
        Some(row) => {
            // `current_created_at` is INTEGER NOT NULL in `user_homes`; the
            // schema doesn't enforce non-negative, but every write path
            // here populates it from `mv.created_at: u64`. A negative
            // value would mean our row was corrupted (or a future
            // migration changed semantics); treat it as if the prior
            // move was at the epoch so any inbound move with a sensible
            // timestamp supersedes — losing-direction is the safer
            // failure mode than letting a corrupted row pin the home.
            let prior_ts = u64::try_from(row.current_created_at).unwrap_or(0);
            let new_ts = mv.created_at;
            if new_ts > prior_ts {
                true
            } else if new_ts < prior_ts {
                false
            } else {
                // Tie on timestamp: smaller canonical_hash wins.
                let prior_hash = row.current_move_hash.as_slice();
                canonical_hash.as_slice() < prior_hash
            }
        }
    };

    // Persist canonical bytes in either branch (chain evidence
    // per §12.5). store_signed_object is `INSERT OR IGNORE`, so the
    // concurrent-race case where another path already inserted is
    // a no-op.
    store_signed_object(
        &mut *tx,
        "move",
        &payload_bytes,
        &signature_bytes,
        &canonical_hash,
    )
    .await?;

    // Project into `user_moves` for §12.3 backfill. Both `applied`
    // and `superseded` populate this index — both are chain evidence
    // per §12.5 and both must be reachable via §12.3 so a peer
    // rebuilding the chain sees the full fork. `INSERT OR IGNORE`
    // makes a concurrent-double-insert a no-op (the same canonical
    // hash can never validly insert twice; the dedup short-circuit
    // at Step 2 catches it on the second push).
    let canonical_hash_db: Vec<u8> = canonical_hash.to_vec();
    let created_at_db = mv.created_at as i64;
    sqlx::query!(
        "INSERT OR IGNORE INTO user_moves (user_key, canonical_hash, created_at) \
         VALUES (?, ?, ?)",
        key_slice,
        canonical_hash_db,
        created_at_db,
    )
    .execute(&mut *tx)
    .await?;

    let status = if new_wins {
        // UPSERT user_homes with the winning move's fields. Verbatim
        // copy of `to_instance_key` / `to_instance` from the move
        // (no domain re-derivation) per §12 joint-binding rule.
        let to_key_db: Vec<u8> = mv.to_instance_key.to_vec();
        sqlx::query!(
            "INSERT INTO user_homes \
                (user_key, current_home_key, current_home_domain, \
                 current_move_hash, current_created_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(user_key) DO UPDATE SET \
                current_home_key = excluded.current_home_key, \
                current_home_domain = excluded.current_home_domain, \
                current_move_hash = excluded.current_move_hash, \
                current_created_at = excluded.current_created_at, \
                updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
            key_slice,
            to_key_db,
            mv.to_instance,
            canonical_hash_db,
            created_at_db,
        )
        .execute(&mut *tx)
        .await?;

        // Phase 9.5 retrofit: keep the `users.home_instance` projection
        // in sync with `user_homes.current_home_key`. Stub rows carry
        // their home in `users.home_instance` for visibility/dedup
        // filters; without this UPDATE the stub drifts and reads
        // disagree with the chain-grounded resolution. Convention:
        // NULL means "lives here" (local), matching how local-user
        // signups leave `home_instance` NULL — so when the move
        // targets *our* instance key, we write NULL. The UPDATE is
        // a no-op when no stub row exists yet (e.g., move arrived
        // before any signed object referenced the user); a later
        // hydrate_stub_user pass will read user_homes and seed the
        // correct home_instance at insert time.
        let local_key: &[u8] = state.instance_key.public_bytes().as_slice();
        if mv.to_instance_key.as_slice() == local_key {
            sqlx::query!(
                "UPDATE users SET home_instance = NULL WHERE public_key = ?",
                key_slice,
            )
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query!(
                "UPDATE users SET home_instance = ? WHERE public_key = ?",
                to_key_db,
                key_slice,
            )
            .execute(&mut *tx)
            .await?;
        }
        MoveStatus::Applied
    } else {
        // §12.1: loser is stored (already done above) and reported
        // as `superseded`. No `user_homes` mutation.
        MoveStatus::Superseded
    };

    // §12.6 source-instance key disposal. A move whose
    // `from_instance_key == self` is the user's own signed attestation
    // that we are no longer their home. Destroy any local
    // private-signing-key material and revoke active sessions inside
    // the same transaction as the home update so a crash mid-apply
    // commits both or neither — there is no half-state where the user
    // has been re-homed but the private key still lingers.
    //
    // Trigger applies on both `Applied` and `Superseded`: a
    // `Superseded` outbound-from-self move still proves the user
    // intended to leave us (the §12.4 winner just happens to determine
    // *where* they ended up). The receiver-side authority disposal is
    // independent of which branch wins on the wire.
    let local_key: &[u8] = state.instance_key.public_bytes().as_slice();
    let outbound_from_self =
        mv.from_instance_key.as_slice() == local_key && mv.to_instance_key.as_slice() != local_key;
    if outbound_from_self && matches!(status, MoveStatus::Applied | MoveStatus::Superseded) {
        dispose_local_user_authority(&mut tx, &mv.key).await?;
    }

    tx.commit().await?;

    // Step 8: §12.2 unconditional flood. Both `applied` and
    // `superseded` forward — `superseded` still forwards because peers
    // further from the origin may need the bytes to repair their own
    // chains. `deferred` already short-circuited above (chain not yet
    // contiguous, nothing to forward).
    forward_signed_object(
        state.clone(),
        canonical_hash,
        ForwardingClass::Move,
        mv.key.to_vec(),
        wire_bytes.to_vec(),
        Some(arrived_from),
    )
    .await;

    Ok(MoveResult {
        canonical_hash,
        status,
    })
}

/// §12.6 source-instance key disposal. Called when a move with
/// `from_instance_key == self` and `to_instance_key != self` is
/// applied or superseded — the user has signed that we are no longer
/// their home, so any local authority we retain to act as them is
/// stale.
///
/// Scope:
/// - **MUST** delete `signing_keys` row(s) for `K` (the protocol
///   requirement: the private seed we held would otherwise let us
///   mint a fresh "move back to me" with a later timestamp and
///   re-claim the user under §12.4 latest-wins).
/// - **MUST** delete `sessions` rows so any still-open browser tab
///   on this instance loses its login.
/// - **SHOULD** delete `credentials` rows so passkey login is no
///   longer possible. The credential identifier is not secret
///   material (it's a public WebAuthn handle), but its continued
///   presence has no protocol meaning after the move.
/// - **SHOULD** flip `users.signup_method` to `federated` so the
///   row's classification matches how it would appear had it been
///   hydrated as a stub rather than locally registered. The display
///   name, public key, and authored content remain — the row is
///   downgraded, not erased.
///
/// Authored content (post revisions, trust-edges, profile revisions)
/// is **retained** per §10.5.3. Moves do not erase.
///
/// Idempotent: a no-op when no local `users` row matches `K`, when
/// the row is already `signup_method = 'federated'`, or when a prior
/// disposal already cleared the auth rows.
async fn dispose_local_user_authority(
    tx: &mut sqlx::SqliteConnection,
    user_key: &[u8; 32],
) -> Result<(), sqlx::Error> {
    let key_slice: &[u8] = user_key.as_slice();

    // Locate the local user row. A federated stub (signup_method =
    // 'federated') has no local authority to dispose — it was never
    // ours; the row is just a projection of the remote identity. A
    // missing row means the move arrived before any local registration
    // ever happened; also a no-op.
    let row = sqlx::query!(
        "SELECT id FROM users WHERE public_key = ? AND signup_method != 'federated'",
        key_slice,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        return Ok(());
    };
    let user_id = row.id;

    // MUST: destroy private signing-key material. This is the
    // load-bearing line for §12.6 — without it, a source instance
    // retains the ability to forge a counter-move and re-home the
    // user under §12.4 latest-wins.
    sqlx::query!("DELETE FROM signing_keys WHERE user_id = ?", user_id)
        .execute(&mut *tx)
        .await?;

    // MUST: revoke active sessions. A user whose home moved should
    // not continue to have logged-in tabs on the old home behaving
    // as though nothing changed.
    sqlx::query!("DELETE FROM sessions WHERE user_id = ?", user_id)
        .execute(&mut *tx)
        .await?;

    // SHOULD: drop credentials. Holds no secret material (only the
    // public WebAuthn credential id + counter), but leaving them in
    // place would let the user re-authenticate locally even though
    // their authority has moved.
    sqlx::query!("DELETE FROM credentials WHERE user_id = ?", user_id)
        .execute(&mut *tx)
        .await?;

    // SHOULD: flip classification. The row stays so authored content
    // keeps resolving to a known identity, but its `signup_method`
    // now matches how peers without prior local registration would
    // represent the same identity.
    sqlx::query!(
        "UPDATE users SET signup_method = 'federated' WHERE id = ?",
        user_id,
    )
    .execute(&mut *tx)
    .await?;

    tracing::info!(
        user_id = %user_id,
        user_key_prefix = ?&user_key[..4],
        "§12.6 disposal: dropped local signing authority for moved-away user"
    );

    Ok(())
}

/// Best-effort routing-key extraction from already-stored canonical
/// CBOR. Used on the `duplicate` path where we want to forward without
/// re-running the full validation state machine.
///
/// Returns `None` on parse failure so the caller can suppress the
/// forward entirely. An empty-vector fallback is unsafe here because
/// `Move` bypasses §7.4 filter dispatch (`peers_interested_in`
/// returns every active peer when [`ForwardingClass::bypasses_filters`]
/// is true), so a zero-length routing key would still trigger a
/// full flood rather than the desired no-op.
fn move_routing_key_from_bytes(payload_bytes: &[u8]) -> Option<Vec<u8>> {
    match SignedPayload::parse(payload_bytes) {
        Ok(SignedPayload::Move(m)) => Some(m.key.to_vec()),
        _ => None,
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Receiver wall clock in Unix milliseconds. Captured once per batch
/// in the handler so a long batch can't see entries drift across the
/// `MAX_CLOCK_SKEW` boundary mid-loop. Falls back to 0 if the system
/// clock is somehow set before UNIX_EPOCH; a 0 clock surfaces every
/// future-timestamped move as `skew_exceeded`, which is the safe
/// rejection.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
            MoveResult {
                canonical_hash: [1u8; 32],
                status: MoveStatus::Applied,
            },
            MoveResult {
                canonical_hash: [2u8; 32],
                status: MoveStatus::Duplicate,
            },
            MoveResult {
                canonical_hash: [3u8; 32],
                status: MoveStatus::Deferred,
            },
            MoveResult {
                canonical_hash: [4u8; 32],
                status: MoveStatus::Superseded,
            },
            MoveResult {
                canonical_hash: [5u8; 32],
                status: MoveStatus::Rejected(MoveRejectReason::SkewExceeded),
            },
            MoveResult {
                canonical_hash: [6u8; 32],
                status: MoveStatus::Rejected(MoveRejectReason::WrongClass),
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
        assert_eq!(arr.len(), 6);

        let expected: &[(usize, &str, Option<&str>)] = &[
            (0, "applied", None),
            (1, "duplicate", None),
            (2, "deferred", None),
            (3, "superseded", None),
            (4, "rejected", Some("skew_exceeded")),
            (5, "rejected", Some("wrong_class")),
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
    fn moves_body_decoder_accepts_bstr_elements() {
        let body = Value::Map(vec![(
            Value::Text("moves".into()),
            Value::Array(vec![Value::Bytes(vec![0xaa, 0xbb])]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let parsed = MovesBody::decode(&buf).expect("decode");
        assert_eq!(parsed.moves.len(), 1);
        assert_eq!(parsed.moves[0], vec![0xaa, 0xbb]);
    }

    #[test]
    fn moves_body_decoder_rejects_non_bstr_elements() {
        let body = Value::Map(vec![(
            Value::Text("moves".into()),
            Value::Array(vec![Value::Map(vec![])]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert!(MovesBody::decode(&buf).is_none());
    }

    #[test]
    fn moves_body_decoder_rejects_unknown_top_level_key() {
        let body = Value::Map(vec![
            (
                Value::Text("moves".into()),
                Value::Array(vec![Value::Bytes(vec![0x01])]),
            ),
            (Value::Text("extra".into()), Value::Bytes(vec![0xff])),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert!(MovesBody::decode(&buf).is_none());
    }

    #[test]
    fn max_clock_skew_matches_spec() {
        // Pin the §12.7 resolved default. Changes here go alongside
        // a protocol-spec amendment.
        assert_eq!(MAX_CLOCK_SKEW_MS, 300_000);
    }
}
