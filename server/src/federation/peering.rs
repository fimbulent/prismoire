//! §5.4 peering handshake: peer-request + peer-response.
//!
//! Two POST routes form the entire wire surface of Phase 2's peer
//! lifecycle:
//!
//! ```text
//! POST /federation/v1/peer-request   (initiator → target)
//! POST /federation/v1/peer-response  (target    → initiator)
//! ```
//!
//! On top of those, this module exposes two operator-facing helpers
//! that the harness drives directly (and that a Phase 3+ admin
//! surface will eventually call from the admin API):
//!
//! - [`operator_initiate_peer_request`] — operator on instance A
//!   types instance B's domain and pubkey; we build the body, wrap
//!   it in an envelope, dispatch via [`FederationTransport`], and
//!   record `pending_outbound`.
//! - [`operator_accept_peer_request`] — operator on instance B sees
//!   the queued `pending_inbound` row, clicks accept; we flip the
//!   row to `active`, build the peer-response body, sign+dispatch
//!   the callback, and the initiator's handler flips its own row to
//!   `active` upon receipt.
//!
//! `DELETE /federation/v1/peer-relationship` and the §6.6 rotation
//! routes are deferred to Phase 3+.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ciborium::value::{Integer, Value};
use http::HeaderValue;
use rand::RngCore;
use rand::rngs::OsRng;
use sqlx::SqlitePool;

use crate::AppState;
use crate::federation::domain::parse_instance_domain;
use crate::federation::envelope::{self, AUTH_HEADER};
use crate::federation::errors::{bad_request, conflict, internal_error, not_found, unauthorized};
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::instance_key::InstanceKey;
use crate::federation::middleware::VerifiedBody;
use crate::federation::transport::{FederationTransport, PeerId, TransportError};
use crate::signed::FedEnvelope;

/// Hard cap on persisted `terminator_domain` length. DNS allows up
/// to 253 chars; rounding to 255 leaves slack for transitional
/// punycode variants without inviting "domain" fields the size of a
/// novel into the audit row.
const MAX_DOMAIN_LEN: usize = 255;

/// Hard cap on persisted operator messages (`message` /
/// `decision_message`). 4 KiB is more than any human-typed welcome
/// or termination note will reach; the middleware's 64 KiB body cap
/// is too permissive for a column the admin UI will routinely
/// display verbatim.
const MAX_MESSAGE_LEN: usize = 4096;

/// §5.4 peer-request body (initiator → target).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRequestBody {
    /// Initiator's bare canonical domain.
    pub initiator_domain: String,
    /// Initiator's instance signing pubkey. MUST equal the envelope
    /// `sender` field; the verifier's bootstrap check (§6.5 step 5,
    /// §5.4) enforces this self-consistency.
    pub initiator_instance_pubkey: [u8; 32],
    /// Capabilities the initiator wants to use.
    pub proposed_capabilities: Vec<String>,
    /// Optional operator-set introduction message.
    pub introduction: Option<String>,
    /// UUID v4-shaped 16 random bytes that both sides reference
    /// through the handshake lifecycle.
    pub request_id: [u8; 16],
    /// Unix milliseconds, UTC.
    pub created_at: u64,
}

/// §5.4 peer-response body (target → initiator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerResponseBody {
    /// The request being responded to.
    pub request_id: [u8; 16],
    /// Responder's bare canonical domain.
    pub responder_domain: String,
    /// Responder's instance pubkey (= signer of this callback's
    /// envelope, AND must equal the value the initiator first saw
    /// via `GET /identity`).
    pub responder_instance_pubkey: [u8; 32],
    /// `"accept"` or `"reject"`.
    pub decision: PeerDecision,
    /// Capabilities both sides agreed to. Present iff accept.
    pub agreed_capabilities: Option<Vec<String>>,
    /// Optional operator-set message (welcome / rejection reason).
    pub decision_message: Option<String>,
    /// Unix milliseconds, UTC.
    pub created_at: u64,
}

/// `decision` field of [`PeerResponseBody`]. Spec-restricted to
/// exactly two values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDecision {
    Accept,
    Reject,
}

impl PeerDecision {
    fn as_str(self) -> &'static str {
        match self {
            PeerDecision::Accept => "accept",
            PeerDecision::Reject => "reject",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "accept" => Some(PeerDecision::Accept),
            "reject" => Some(PeerDecision::Reject),
            _ => None,
        }
    }
}

/// §5.4 `DELETE /peer-relationship` body. Either side of an active
/// peering can send this to wind the relationship down. The peer row
/// flips to `terminated` (audit-retained) on both sides; subsequent
/// envelope-signed traffic from the now-terminated peer 401s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRelationshipDeleteBody {
    /// The terminating side's bare canonical domain.
    pub terminator_domain: String,
    /// Reason tag as defined by §5.4.
    pub reason: TerminationReason,
    /// Optional operator-set explanation. Stored on both sides in
    /// the existing `decision_message` column.
    pub message: Option<String>,
    /// Unix milliseconds, UTC.
    pub created_at: u64,
}

/// `reason` field of [`PeerRelationshipDeleteBody`]. Spec-restricted
/// to exactly three tokens; the wire string is preserved verbatim in
/// the `termination_reason` column so a future protocol revision can
/// add values as data, not as a schema migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationReason {
    OperatorInitiated,
    CompromiseResponse,
    PolicyViolation,
}

impl TerminationReason {
    fn as_str(self) -> &'static str {
        match self {
            TerminationReason::OperatorInitiated => "operator_initiated",
            TerminationReason::CompromiseResponse => "compromise_response",
            TerminationReason::PolicyViolation => "policy_violation",
        }
    }

    /// Parse a wire / operator-supplied reason token. Returns `None`
    /// on any value outside the spec-restricted three.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "operator_initiated" => Some(TerminationReason::OperatorInitiated),
            "compromise_response" => Some(TerminationReason::CompromiseResponse),
            "policy_violation" => Some(TerminationReason::PolicyViolation),
            _ => None,
        }
    }
}

// --- CBOR encoders / decoders ----------------------------------------

impl PeerRequestBody {
    /// Encode to wire CBOR. Spec table order (not canonical) — the
    /// body is not a signed payload; CBOR map ordering is irrelevant
    /// to the receiver, which uses key lookup.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries: Vec<(Value, Value)> = vec![
            (
                Value::Text("initiator_domain".into()),
                Value::Text(self.initiator_domain.clone()),
            ),
            (
                Value::Text("initiator_instance_pubkey".into()),
                Value::Bytes(self.initiator_instance_pubkey.to_vec()),
            ),
            (
                Value::Text("proposed_capabilities".into()),
                Value::Array(
                    self.proposed_capabilities
                        .iter()
                        .map(|s| Value::Text(s.clone()))
                        .collect(),
                ),
            ),
            (
                Value::Text("request_id".into()),
                Value::Bytes(self.request_id.to_vec()),
            ),
            (
                Value::Text("created_at".into()),
                Value::Integer(Integer::from(self.created_at)),
            ),
        ];
        if let Some(intro) = &self.introduction {
            entries.push((
                Value::Text("introduction".into()),
                Value::Text(intro.clone()),
            ));
        }
        let mut buf = Vec::with_capacity(128);
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf)
            .expect("ciborium ser is infallible into Vec");
        buf
    }

    /// Decode from wire CBOR. Returns `None` on structural deviation.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut domain: Option<String> = None;
        let mut pubkey: Option<[u8; 32]> = None;
        let mut caps: Option<Vec<String>> = None;
        let mut intro: Option<String> = None;
        let mut request_id: Option<[u8; 16]> = None;
        let mut created_at: Option<u64> = None;
        for (k, v) in entries {
            let key = match k {
                Value::Text(s) => s,
                _ => continue,
            };
            match key.as_str() {
                "initiator_domain" => {
                    domain = Some(text_required(v)?);
                }
                "initiator_instance_pubkey" => {
                    pubkey = Some(fixed_bytes::<32>(v)?);
                }
                "proposed_capabilities" => {
                    caps = Some(text_array(v)?);
                }
                "introduction" => {
                    intro = Some(text_required(v)?);
                }
                "request_id" => {
                    request_id = Some(fixed_bytes::<16>(v)?);
                }
                "created_at" => {
                    created_at = Some(uint_required(v)?);
                }
                _ => {}
            }
        }
        Some(PeerRequestBody {
            initiator_domain: domain?,
            initiator_instance_pubkey: pubkey?,
            proposed_capabilities: caps?,
            introduction: intro,
            request_id: request_id?,
            created_at: created_at?,
        })
    }
}

impl PeerResponseBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut entries: Vec<(Value, Value)> = vec![
            (
                Value::Text("request_id".into()),
                Value::Bytes(self.request_id.to_vec()),
            ),
            (
                Value::Text("responder_domain".into()),
                Value::Text(self.responder_domain.clone()),
            ),
            (
                Value::Text("responder_instance_pubkey".into()),
                Value::Bytes(self.responder_instance_pubkey.to_vec()),
            ),
            (
                Value::Text("decision".into()),
                Value::Text(self.decision.as_str().to_string()),
            ),
            (
                Value::Text("created_at".into()),
                Value::Integer(Integer::from(self.created_at)),
            ),
        ];
        if let Some(caps) = &self.agreed_capabilities {
            entries.push((
                Value::Text("agreed_capabilities".into()),
                Value::Array(caps.iter().map(|s| Value::Text(s.clone())).collect()),
            ));
        }
        if let Some(msg) = &self.decision_message {
            entries.push((
                Value::Text("decision_message".into()),
                Value::Text(msg.clone()),
            ));
        }
        let mut buf = Vec::with_capacity(128);
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf)
            .expect("ciborium ser is infallible into Vec");
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut request_id: Option<[u8; 16]> = None;
        let mut domain: Option<String> = None;
        let mut pubkey: Option<[u8; 32]> = None;
        let mut decision: Option<PeerDecision> = None;
        let mut caps: Option<Vec<String>> = None;
        let mut msg: Option<String> = None;
        let mut created_at: Option<u64> = None;
        for (k, v) in entries {
            let key = match k {
                Value::Text(s) => s,
                _ => continue,
            };
            match key.as_str() {
                "request_id" => {
                    request_id = Some(fixed_bytes::<16>(v)?);
                }
                "responder_domain" => {
                    domain = Some(text_required(v)?);
                }
                "responder_instance_pubkey" => {
                    pubkey = Some(fixed_bytes::<32>(v)?);
                }
                "decision" => {
                    let s = text_required(v)?;
                    decision = Some(PeerDecision::parse(&s)?);
                }
                "agreed_capabilities" => {
                    caps = Some(text_array(v)?);
                }
                "decision_message" => {
                    msg = Some(text_required(v)?);
                }
                "created_at" => {
                    created_at = Some(uint_required(v)?);
                }
                _ => {}
            }
        }
        Some(PeerResponseBody {
            request_id: request_id?,
            responder_domain: domain?,
            responder_instance_pubkey: pubkey?,
            decision: decision?,
            agreed_capabilities: caps,
            decision_message: msg,
            created_at: created_at?,
        })
    }
}

impl PeerRelationshipDeleteBody {
    /// Encode to wire CBOR. Spec table order; `message` is omitted
    /// from the map entirely when `None` so a missing key on the
    /// wire round-trips as `None` on decode.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries: Vec<(Value, Value)> = vec![
            (
                Value::Text("terminator_domain".into()),
                Value::Text(self.terminator_domain.clone()),
            ),
            (
                Value::Text("reason".into()),
                Value::Text(self.reason.as_str().to_string()),
            ),
            (
                Value::Text("created_at".into()),
                Value::Integer(Integer::from(self.created_at)),
            ),
        ];
        if let Some(msg) = &self.message {
            entries.push((Value::Text("message".into()), Value::Text(msg.clone())));
        }
        let mut buf = Vec::with_capacity(64);
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf)
            .expect("ciborium ser is infallible into Vec");
        buf
    }

    /// Decode from wire CBOR. Returns `None` on structural
    /// deviation (missing required field, unknown `reason` token,
    /// wrong type for a known key).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut domain: Option<String> = None;
        let mut reason: Option<TerminationReason> = None;
        let mut message: Option<String> = None;
        let mut created_at: Option<u64> = None;
        for (k, v) in entries {
            let key = match k {
                Value::Text(s) => s,
                _ => continue,
            };
            match key.as_str() {
                "terminator_domain" => {
                    domain = Some(text_required(v)?);
                }
                "reason" => {
                    let s = text_required(v)?;
                    reason = Some(TerminationReason::parse(&s)?);
                }
                "message" => {
                    message = Some(text_required(v)?);
                }
                "created_at" => {
                    created_at = Some(uint_required(v)?);
                }
                _ => {}
            }
        }
        Some(PeerRelationshipDeleteBody {
            terminator_domain: domain?,
            reason: reason?,
            message,
            created_at: created_at?,
        })
    }
}

fn text_required(v: Value) -> Option<String> {
    match v {
        Value::Text(s) => Some(s),
        _ => None,
    }
}

fn fixed_bytes<const N: usize>(v: Value) -> Option<[u8; N]> {
    match v {
        Value::Bytes(b) => <[u8; N]>::try_from(b.as_slice()).ok(),
        _ => None,
    }
}

fn uint_required(v: Value) -> Option<u64> {
    match v {
        Value::Integer(i) => i.try_into().ok(),
        _ => None,
    }
}

fn text_array(v: Value) -> Option<Vec<String>> {
    let items = match v {
        Value::Array(a) => a,
        _ => return None,
    };
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match it {
            Value::Text(s) => out.push(s),
            _ => return None,
        }
    }
    Some(out)
}

// --- Capability intersection -----------------------------------------

/// Intersect two capability lists, preserving the order of `ours`.
/// Used by the responder to compute `agreed_capabilities` against
/// the initiator's `proposed_capabilities`.
fn intersect_caps(ours: &[String], proposed: &[String]) -> Vec<String> {
    ours.iter()
        .filter(|c| proposed.iter().any(|p| p == *c))
        .cloned()
        .collect()
}

// --- Operator-facing flow --------------------------------------------

/// Outcome of [`operator_initiate_peer_request`].
#[derive(Debug)]
pub enum InitiateError {
    /// Transport failed to deliver the peer-request to the target.
    Transport(TransportError),
    /// Target accepted the wire payload but returned a non-202 status.
    UnexpectedStatus(StatusCode),
    /// Local database error while recording the `pending_outbound` row.
    Db(sqlx::Error),
    /// Operator tried to peer with this instance itself. The §5.1
    /// trust model assumes two distinct origins; self-peering is a
    /// configuration error caught before any wire traffic.
    SelfPeering,
    /// Another peer row already binds this `instance_domain` to a
    /// different `instance_pubkey`. Surfaced before the INSERT to
    /// avoid a misleading 500 from the `UNIQUE(instance_domain)`
    /// constraint; operator must remove the existing row (or fix the
    /// typed domain/pubkey pair) before retrying.
    DomainConflict,
    /// Operator-supplied `target_domain` failed
    /// [`parse_instance_domain`] (path/query/userinfo characters,
    /// scheme prefix, empty, oversize, etc.). Caught at the operator
    /// boundary so a typo can't poison `peers.instance_domain` with a
    /// value the transport would refuse later.
    InvalidTargetDomain,
}

impl From<sqlx::Error> for InitiateError {
    fn from(value: sqlx::Error) -> Self {
        InitiateError::Db(value)
    }
}

/// Operator-initiated start of a peering handshake.
///
/// Builds and signs a peer-request, dispatches it to the target's
/// `/federation/v1/peer-request` via the supplied transport, then
/// records a `pending_outbound` row keyed on the target's pubkey.
/// Returns the freshly-minted `request_id` so the caller (admin UI
/// in production, harness in tests) can correlate the callback
/// when it arrives.
///
/// The target's pubkey is assumed to have been fetched out-of-band
/// via `GET /federation/v1/identity` and operator-confirmed against
/// the typed domain (§5.2). Phase 3 will likely add a thin
/// "fetch-and-confirm" helper around this; for now the caller is
/// responsible for obtaining and verifying the pubkey before
/// invoking this function.
#[allow(clippy::too_many_arguments)]
pub async fn operator_initiate_peer_request(
    db: &SqlitePool,
    instance_key: &InstanceKey,
    initiator_domain: &str,
    transport: &Arc<dyn FederationTransport>,
    target_pubkey: [u8; 32],
    target_domain: &str,
    proposed_capabilities: Vec<String>,
    introduction: Option<String>,
) -> Result<[u8; 16], InitiateError> {
    // §5.1: peering is between *two distinct* instances. A
    // self-peering attempt is an operator-side configuration error;
    // reject before signing anything.
    if target_pubkey == *instance_key.public_bytes() {
        return Err(InitiateError::SelfPeering);
    }

    // SSRF defence at the operator boundary: reject typo'd or
    // malicious `target_domain` values before they reach the peers
    // table. The same check runs against `initiator_domain` in
    // `handle_peer_request` for inbound traffic; this is the
    // outbound equivalent. The transport re-validates as defence
    // in depth.
    if parse_instance_domain(target_domain).is_err() {
        return Err(InitiateError::InvalidTargetDomain);
    }

    // Pre-check `instance_domain` uniqueness against existing rows.
    // The UPSERT below collides on `instance_pubkey`; the *separate*
    // `UNIQUE(instance_domain)` constraint would surface a different-
    // pubkey-same-domain conflict as a raw 500 otherwise.
    let target_pubkey_slice: &[u8] = &target_pubkey;
    let existing = sqlx::query!(
        "SELECT instance_pubkey FROM peers \
         WHERE instance_domain = ? AND instance_pubkey != ? LIMIT 1",
        target_domain,
        target_pubkey_slice,
    )
    .fetch_optional(db)
    .await?;
    if existing.is_some() {
        return Err(InitiateError::DomainConflict);
    }

    let mut request_id = [0u8; 16];
    OsRng.fill_bytes(&mut request_id);

    let body = PeerRequestBody {
        initiator_domain: initiator_domain.to_string(),
        initiator_instance_pubkey: *instance_key.public_bytes(),
        proposed_capabilities: proposed_capabilities.clone(),
        introduction,
        request_id,
        created_at: envelope::now_unix_ms(),
    };
    let body_bytes = body.encode();

    let path = "/federation/v1/peer-request";
    let header_value = envelope::sign_outbound(
        instance_key,
        target_pubkey,
        &Method::POST,
        path,
        &body_bytes,
    );

    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .header(AUTH_HEADER, header_value)
        .body(Bytes::from(body_bytes))
        .expect("request builder");

    // Record pending_outbound *before* dispatching. If transport
    // fails after this, the operator simply re-invokes; the UPSERT
    // on `instance_pubkey` refreshes the row's request_id and
    // capabilities in place. The opposite ordering would leave the
    // peer with a pending_inbound row pointing at a request_id we
    // had not persisted, so their later accept callback would 404
    // against our pending_outbound lookup.
    let request_id_slice: &[u8] = &request_id;
    let proposed_cbor = encode_text_array(&proposed_capabilities);
    let proposed_cbor_slice: &[u8] = &proposed_cbor;
    sqlx::query!(
        "INSERT INTO peers (instance_pubkey, instance_domain, status, direction, \
                            request_id, capabilities, last_handshake) \
         VALUES (?, ?, 'pending_outbound', 'outbound', ?, ?, \
                 strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) \
         ON CONFLICT(instance_pubkey) DO UPDATE SET \
             status = 'pending_outbound', \
             direction = 'outbound', \
             request_id = excluded.request_id, \
             capabilities = excluded.capabilities, \
             last_handshake = excluded.last_handshake",
        target_pubkey_slice,
        target_domain,
        request_id_slice,
        proposed_cbor_slice,
    )
    .execute(db)
    .await?;

    let response = transport
        .request(&PeerId::from_bytes(target_pubkey), request)
        .await
        .map_err(InitiateError::Transport)?;

    if response.status() != StatusCode::ACCEPTED && response.status() != StatusCode::OK {
        return Err(InitiateError::UnexpectedStatus(response.status()));
    }

    Ok(request_id)
}

/// Operator-side accept on an inbound peer-request.
///
/// Looks up the `pending_inbound` row by `request_id`, intersects
/// the proposed capabilities with our advertised set, flips the row
/// to `active`, then signs and dispatches the peer-response
/// callback back to the initiator. The peer-response handler on
/// their side updates their own `pending_outbound` → `active`.
pub async fn operator_accept_peer_request(
    db: &SqlitePool,
    instance_key: &InstanceKey,
    responder_domain: &str,
    transport: &Arc<dyn FederationTransport>,
    request_id: [u8; 16],
) -> Result<(), InitiateError> {
    let request_id_slice: &[u8] = &request_id;
    let row = sqlx::query!(
        "SELECT instance_pubkey, capabilities \
         FROM peers \
         WHERE request_id = ? AND status = 'pending_inbound' LIMIT 1",
        request_id_slice,
    )
    .fetch_one(db)
    .await?;

    let initiator_pubkey: [u8; 32] =
        row.instance_pubkey.as_slice().try_into().map_err(|_| {
            InitiateError::Db(sqlx::Error::Decode("peer pubkey not 32 bytes".into()))
        })?;
    let proposed_caps: Vec<String> = row
        .capabilities
        .as_ref()
        .and_then(|b| decode_text_array(b))
        .unwrap_or_default();

    let our_caps: Vec<String> = crate::federation::identity::CAPABILITIES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let agreed = intersect_caps(&our_caps, &proposed_caps);

    // Encode agreed caps once: we need them in both the callback
    // body and the local UPDATE that follows on success.
    let agreed_cbor = encode_text_array(&agreed);

    // Build and dispatch the callback *before* flipping our local
    // row to active. If dispatch fails, our row stays
    // `pending_inbound` and the operator simply retries; the
    // alternative (flip-then-dispatch) leaves a stuck half-handshake
    // (B=active, A=pending_outbound) that has no clean recovery
    // path because the next accept attempt no longer finds a
    // pending_inbound row to operate on.
    let body = PeerResponseBody {
        request_id,
        responder_domain: responder_domain.to_string(),
        responder_instance_pubkey: *instance_key.public_bytes(),
        decision: PeerDecision::Accept,
        agreed_capabilities: Some(agreed),
        decision_message: None,
        created_at: envelope::now_unix_ms(),
    };
    let body_bytes = body.encode();

    let path = "/federation/v1/peer-response";
    let header_value = envelope::sign_outbound(
        instance_key,
        initiator_pubkey,
        &Method::POST,
        path,
        &body_bytes,
    );

    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .header(AUTH_HEADER, header_value)
        .body(Bytes::from(body_bytes))
        .expect("request builder");

    let response = transport
        .request(&PeerId::from_bytes(initiator_pubkey), request)
        .await
        .map_err(InitiateError::Transport)?;

    if response.status() != StatusCode::OK {
        return Err(InitiateError::UnexpectedStatus(response.status()));
    }

    // Callback delivered. Flip our side to active. The WHERE clause
    // matches `pending_inbound` (normal case) and `active`
    // (idempotent retry: a previous attempt's callback succeeded
    // but its response was lost, so the operator re-issued accept
    // and `handle_peer_response` over there is also idempotent).
    let agreed_cbor_slice: &[u8] = &agreed_cbor;
    let update = sqlx::query!(
        "UPDATE peers \
         SET status = 'active', \
             agreed_capabilities = ?, \
             last_handshake = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE request_id = ? AND status IN ('pending_inbound', 'active')",
        agreed_cbor_slice,
        request_id_slice,
    )
    .execute(db)
    .await;
    if let Err(e) = update {
        // Callback already landed on the initiator, so the *other*
        // half-handshake (A=active, B=pending_inbound) is now
        // possible if this UPDATE failed. Local DB error here is
        // rare; log loudly so an operator can reconcile.
        tracing::warn!(
            error = %e,
            request_id = ?request_id,
            "half-handshake: peer accept callback succeeded but local commit failed; \
             peer is active, we remain pending_inbound — operator must reconcile",
        );
        return Err(InitiateError::Db(e));
    }

    Ok(())
}

/// Encode a CBOR array-of-tstr. Used for the `capabilities` and
/// `agreed_capabilities` columns on `peers`.
fn encode_text_array(items: &[String]) -> Vec<u8> {
    let value = Value::Array(items.iter().map(|s| Value::Text(s.clone())).collect());
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&value, &mut buf).expect("ciborium ser is infallible");
    buf
}

/// Decode a CBOR array-of-tstr. Returns `None` on any deviation.
pub(crate) fn decode_text_array(bytes: &[u8]) -> Option<Vec<String>> {
    let value: Value = ciborium::de::from_reader(bytes).ok()?;
    text_array(value)
}

// --- HTTP handlers ---------------------------------------------------

/// `POST /federation/v1/peer-request` handler.
///
/// Bootstrap-exception verifier: the §6 middleware (mounted in
/// `federation::router`) runs `VerifyMode::Bootstrap` so §6.5 step 5
/// is skipped; this handler enforces the spec-mandated
/// self-consistency check (`envelope.sender ==
/// body.initiator_instance_pubkey`) that bootstrap mode leaves to
/// the caller. On success, records a `pending_inbound` row visible to
/// the operator's admin UI.
pub async fn handle_peer_request(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let parsed = match PeerRequestBody::decode(&body) {
        Some(p) => p,
        None => return bad_request("invalid_body"),
    };

    // Bootstrap self-consistency: envelope.sender MUST match the
    // body's claimed pubkey. The §6 verifier left this to us
    // because in bootstrap mode it has no peer row to consult.
    if parsed.initiator_instance_pubkey != envelope.sender {
        return unauthorized();
    }

    // SSRF defence: `initiator_domain` is wire-supplied and will be
    // persisted into `peers.instance_domain`, where every outbound
    // federation request will subsequently `format!` it into a URL.
    // Reject anything that is not a clean `host[:port]` here so the
    // database never accepts a value the transport would have to
    // refuse later (and so the operator's `/peers` UI doesn't show
    // injection payloads as legitimate-looking peer rows). The
    // transport re-validates as defence in depth.
    if parse_instance_domain(&parsed.initiator_domain).is_err() {
        return bad_request("invalid_initiator_domain");
    }

    // Pre-check `instance_domain` uniqueness: if another peer row
    // already binds this domain to a *different* pubkey, return
    // 409 rather than letting the INSERT below surface the
    // UNIQUE(instance_domain) violation as a 500.
    let pubkey_slice: &[u8] = &parsed.initiator_instance_pubkey;
    let request_id_slice: &[u8] = &parsed.request_id;
    let domain_conflict = sqlx::query!(
        "SELECT instance_pubkey FROM peers \
         WHERE instance_domain = ? AND instance_pubkey != ? LIMIT 1",
        parsed.initiator_domain,
        pubkey_slice,
    )
    .fetch_optional(&state.db)
    .await;
    match domain_conflict {
        Ok(Some(_)) => return conflict("domain_taken"),
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "db error during instance_domain pre-check");
            return internal_error();
        }
    }

    // Record pending_inbound. UPSERT keyed on pubkey so a duplicate
    // peer-request (operator re-issuing after the original timed
    // out) refreshes the row in place rather than failing on the
    // PRIMARY KEY collision. Dedupe by `(initiator_domain,
    // initiator_instance_pubkey)` per §5.4 callback retry note.
    let caps_cbor = encode_text_array(&parsed.proposed_capabilities);
    let caps_cbor_slice: &[u8] = &caps_cbor;
    let insert_result = sqlx::query!(
        "INSERT INTO peers (instance_pubkey, instance_domain, status, direction, \
                            request_id, capabilities, last_handshake) \
         VALUES (?, ?, 'pending_inbound', 'inbound', ?, ?, \
                 strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) \
         ON CONFLICT(instance_pubkey) DO UPDATE SET \
             status = 'pending_inbound', \
             direction = 'inbound', \
             instance_domain = excluded.instance_domain, \
             request_id = excluded.request_id, \
             capabilities = excluded.capabilities, \
             last_handshake = excluded.last_handshake",
        pubkey_slice,
        parsed.initiator_domain,
        request_id_slice,
        caps_cbor_slice,
    )
    .execute(&state.db)
    .await;
    if let Err(e) = insert_result {
        tracing::error!(error = %e, "failed to record pending_inbound peer");
        return internal_error();
    }

    // §5.4 response: 202 Accepted with `{"request_id":..., "status":"pending"}`.
    let response_value = Value::Map(vec![
        (
            Value::Text("request_id".into()),
            Value::Bytes(parsed.request_id.to_vec()),
        ),
        (Value::Text("status".into()), Value::Text("pending".into())),
    ]);
    let mut buf = Vec::with_capacity(64);
    ciborium::ser::into_writer(&response_value, &mut buf).expect("ser infallible");

    let mut response = (StatusCode::ACCEPTED, buf).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    response
}

/// `POST /federation/v1/peer-response` handler.
///
/// Receives the callback from the responder. The §6 middleware runs
/// `VerifyMode::Bootstrap` for this route — the responder is in our
/// `pending_outbound` set, not `active`, so the verifier's step-5
/// peers lookup would reject otherwise. Bootstrap also means
/// `envelope.sender == body.responder_instance_pubkey` must be
/// enforced here; the verifier didn't do it. On accept, the
/// matching `pending_outbound` row flips to `active` with the agreed
/// capability set.
pub async fn handle_peer_response(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let parsed = match PeerResponseBody::decode(&body) {
        Some(p) => p,
        None => return bad_request("invalid_body"),
    };

    // Bootstrap self-consistency: see `handle_peer_request` for the
    // rationale. Without this check the responder could plausibly
    // claim any pubkey in the body while signing with another.
    if parsed.responder_instance_pubkey != envelope.sender {
        return unauthorized();
    }

    // Look up the row by request_id. We match both `pending_outbound`
    // (normal first-delivery case) and `active` (idempotent retry:
    // the responder's first dispatch reached us and we flipped to
    // active, but our 200 response was lost, so the responder
    // operator retried accept and we're now seeing the callback a
    // second time). Matching `active` keeps the retry returning 200
    // rather than 404, which is what the responder needs to commit
    // its own local flip.
    let request_id_slice: &[u8] = &parsed.request_id;
    let row = match sqlx::query!(
        "SELECT instance_pubkey FROM peers \
         WHERE request_id = ? AND status IN ('pending_outbound', 'active') LIMIT 1",
        request_id_slice,
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("unknown_request"),
        Err(e) => {
            tracing::error!(error = %e, "db error looking up pending_outbound");
            return internal_error();
        }
    };

    let recorded_pubkey: [u8; 32] = match row.instance_pubkey.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return internal_error(),
    };
    // §5.4 step 2: the responder pubkey on the callback MUST equal
    // the one we recorded at peer-request initiation time.
    if recorded_pubkey != parsed.responder_instance_pubkey {
        return unauthorized();
    }

    let decision_message = parsed.decision_message.as_deref();
    match parsed.decision {
        PeerDecision::Accept => {
            let agreed = parsed.agreed_capabilities.unwrap_or_default();
            let agreed_cbor = encode_text_array(&agreed);
            let agreed_cbor_slice: &[u8] = &agreed_cbor;
            // WHERE clause matches `pending_outbound` (normal) and
            // `active` (idempotent retry; re-sets agreed_capabilities
            // to the same value the responder sent the first time).
            let update_result = sqlx::query!(
                "UPDATE peers \
                 SET status = 'active', \
                     agreed_capabilities = ?, \
                     decision_message = ?, \
                     last_handshake = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
                 WHERE request_id = ? AND status IN ('pending_outbound', 'active')",
                agreed_cbor_slice,
                decision_message,
                request_id_slice,
            )
            .execute(&state.db)
            .await;
            if let Err(e) = update_result {
                tracing::error!(error = %e, "failed to flip peer to active on accept");
                return internal_error();
            }
            // §8.6 first-contact: our outbound request was accepted and
            // the peer is now active on our side, so announce our
            // frontier (the responder announces from its own accept
            // path). Spawn-and-forget so we still return 200 promptly.
            crate::federation::frontier::spawn_first_contact_announce(
                state.clone(),
                recorded_pubkey,
            );
            // §7.3 step 2: also pull the peer's frontier so our own
            // routing leaves empty-filter mode even if their announce
            // never reaches us — the redundant backstop for a lost push.
            crate::federation::frontier::spawn_bootstrap_frontier_pull(
                state.clone(),
                recorded_pubkey,
            );
        }
        PeerDecision::Reject => {
            // Terminal `rejected` per §5.4 ("rejected (archive)"); the
            // operator UI surfaces `decision_message` alongside the
            // row. The previous `closed` value is reserved for cases
            // neither `rejected` nor `terminated` covers.
            let update_result = sqlx::query!(
                "UPDATE peers \
                 SET status = 'rejected', \
                     decision_message = ?, \
                     last_handshake = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
                 WHERE request_id = ? AND status = 'pending_outbound'",
                decision_message,
                request_id_slice,
            )
            .execute(&state.db)
            .await;
            if let Err(e) = update_result {
                tracing::error!(error = %e, "failed to archive rejected peer");
                return internal_error();
            }
        }
    }

    StatusCode::OK.into_response()
}

/// `GET /federation/v1/peers` handler (§5.5).
///
/// Returns this instance's *active* peer list so the caller's
/// operator UI can suggest "peers of your peers" as candidates for
/// new peerings. Mounted behind `verify_known_peer`, so the §6
/// middleware has already enforced that the requester is in
/// `peers WHERE status = 'active'`; default visibility per §5.5 is
/// peers-only, which is exactly what `KnownPeer` enforces.
///
/// The protocol's "hide from discovery" flag is local policy (§5.5).
/// No column for it exists yet, so every active peer is returned for
/// now; once the admin surface lets operators flip the flag per row,
/// the `WHERE status = 'active'` clause will pick up an extra
/// `AND discoverable = 1` predicate.
pub async fn handle_peers_list(State(state): State<Arc<AppState>>) -> Response {
    // `first_seen` is the closest stand-in for the spec's `since`
    // (when peering became active). The schema stores it as an ISO-
    // 8601 string defaulted at row creation; we re-parse it to unix
    // milliseconds for the wire payload so the requester doesn't
    // need a chrono dependency to consume the field.
    let rows = match sqlx::query!(
        "SELECT instance_pubkey, instance_domain, first_seen, \
                COALESCE(agreed_capabilities, capabilities) AS \"caps?\" \
         FROM peers WHERE status = 'active'",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "db error listing peers for /peers");
            return internal_error();
        }
    };

    let mut peer_entries: Vec<Value> = Vec::with_capacity(rows.len());
    for row in rows {
        let since_ms = iso8601_to_unix_ms(&row.first_seen).unwrap_or_else(|| {
            // Only reachable if something rewrote `first_seen` to a
            // shape `strftime('%Y-%m-%dT%H:%M:%SZ', 'now')` would
            // never emit. Emit a warning so operators notice rather
            // than silently shipping epoch-0 to peers.
            tracing::warn!(
                first_seen = %row.first_seen,
                "peers.first_seen failed ISO 8601 parse; reporting since=0 to caller"
            );
            0
        });
        let caps: Vec<String> = row
            .caps
            .as_ref()
            .and_then(|b| decode_text_array(b))
            .unwrap_or_default();
        peer_entries.push(Value::Map(vec![
            (
                Value::Text("domain".into()),
                Value::Text(row.instance_domain),
            ),
            (
                Value::Text("instance_pubkey".into()),
                Value::Bytes(row.instance_pubkey),
            ),
            (
                Value::Text("since".into()),
                Value::Integer(Integer::from(since_ms)),
            ),
            (
                Value::Text("capabilities".into()),
                Value::Array(caps.into_iter().map(Value::Text).collect()),
            ),
        ]));
    }

    let body_value = Value::Map(vec![(
        Value::Text("peers".into()),
        Value::Array(peer_entries),
    )]);
    let mut buf = Vec::with_capacity(128);
    ciborium::ser::into_writer(&body_value, &mut buf).expect("ser infallible");

    let mut response = (StatusCode::OK, buf).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    response
}

/// `DELETE /federation/v1/peer-relationship` handler (§5.4).
///
/// Either side of an active peering can wind it down. Mounted behind
/// `verify_known_peer`, so the §6 middleware has already proved the
/// caller is currently an `active` peer. This handler flips that row
/// to `terminated`, persists the wire-supplied reason and optional
/// message, and 200s. Per §5.4 the row is retained for audit.
///
/// Termination is idempotent: a duplicate request from the same peer
/// (e.g. a retry of a network-fumbled DELETE) re-200s without
/// changing the row — the UPDATE's `WHERE status = 'active'` makes
/// the second call a no-op rather than an error, which is what the
/// peer needs to commit its own local flip.
pub async fn handle_peer_relationship_delete(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let parsed = match PeerRelationshipDeleteBody::decode(&body) {
        Some(p) => p,
        None => return bad_request("invalid_body"),
    };

    // Length caps on the two free-text fields. A peer is free to
    // send 64 KiB of garbage (the middleware's body cap), but we
    // refuse to *persist* unbounded text into the audit row.
    if parsed.terminator_domain.len() > MAX_DOMAIN_LEN
        || parsed
            .message
            .as_deref()
            .is_some_and(|m| m.len() > MAX_MESSAGE_LEN)
    {
        return bad_request("invalid_body");
    }

    // Cross-check that `terminator_domain` matches what we recorded
    // for this sender. The envelope already proved the sender owns
    // the signing key; this guards against a peer suddenly claiming
    // a different domain in the audit log without going through a
    // rotation/re-peering flow.
    let sender_slice: &[u8] = &envelope.sender;
    let known_domain = match sqlx::query!(
        "SELECT instance_domain FROM peers WHERE instance_pubkey = ? AND status = 'active'",
        sender_slice,
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row.instance_domain,
        // No active row means the verifier middleware shouldn't have
        // let this through. Treat as unauthorized rather than 500.
        Ok(None) => return unauthorized(),
        Err(e) => {
            tracing::error!(error = %e, "db error looking up sender for terminator-domain check");
            return internal_error();
        }
    };
    if parsed.terminator_domain != known_domain {
        return bad_request("invalid_body");
    }

    // The UPDATE is scoped to the sender's pubkey so a malicious
    // peer cannot terminate someone *else's* relationship. Per the
    // migration's documented contract, `decision_message` always
    // moves to the most recent lifecycle event — overwrite any
    // welcome note from the original handshake with the termination
    // message (or with NULL if none supplied).
    let reason_str = parsed.reason.as_str();
    let message = parsed.message.as_deref();
    let update_result = sqlx::query!(
        "UPDATE peers \
         SET status = 'terminated', \
             termination_reason = ?, \
             decision_message = ?, \
             last_handshake = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE instance_pubkey = ? AND status = 'active'",
        reason_str,
        message,
        sender_slice,
    )
    .execute(&state.db)
    .await;
    match update_result {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "failed to terminate peer relationship");
            internal_error()
        }
    }
}

/// Operator-side termination of an active peering.
///
/// Builds and signs the §5.4 DELETE payload, dispatches it to the
/// peer, then flips our local row to `terminated`. Local flip
/// happens *after* dispatch so a transport failure leaves the row
/// `active` and the operator can retry; the alternative ordering
/// would leave us terminated and the peer still talking to us
/// (post-DELETE 401s on their side, half-handshake on ours).
///
/// Idempotent if the peer's response is lost mid-flight: the second
/// call hits a no-longer-`active` row locally and falls through to a
/// no-op UPDATE; the peer's idempotent handler also no-ops.
pub async fn operator_terminate_peer_relationship(
    db: &SqlitePool,
    instance_key: &InstanceKey,
    terminator_domain: &str,
    transport: &Arc<dyn FederationTransport>,
    peer_pubkey: [u8; 32],
    reason: TerminationReason,
    message: Option<String>,
) -> Result<(), InitiateError> {
    let body = PeerRelationshipDeleteBody {
        terminator_domain: terminator_domain.to_string(),
        reason,
        message,
        created_at: envelope::now_unix_ms(),
    };
    let body_bytes = body.encode();

    let path = "/federation/v1/peer-relationship";
    let header_value = envelope::sign_outbound(
        instance_key,
        peer_pubkey,
        &Method::DELETE,
        path,
        &body_bytes,
    );

    let request = Request::builder()
        .method(Method::DELETE)
        .uri(path)
        .header(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .header(AUTH_HEADER, header_value)
        .body(Bytes::from(body_bytes))
        .expect("request builder");

    let response = transport
        .request(&PeerId::from_bytes(peer_pubkey), request)
        .await
        .map_err(InitiateError::Transport)?;

    if response.status() != StatusCode::OK {
        return Err(InitiateError::UnexpectedStatus(response.status()));
    }

    let peer_slice: &[u8] = &peer_pubkey;
    let reason_str = reason.as_str();
    sqlx::query!(
        "UPDATE peers \
         SET status = 'terminated', \
             termination_reason = ?, \
             last_handshake = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE instance_pubkey = ? AND status = 'active'",
        reason_str,
        peer_slice,
    )
    .execute(db)
    .await?;

    Ok(())
}

/// Parse an ISO 8601 `YYYY-MM-DDTHH:MM:SSZ` string (the shape
/// `strftime('%Y-%m-%dT%H:%M:%SZ', 'now')` emits into the
/// `first_seen` column) into unix milliseconds. Returns `None` on
/// any deviation; the §5.5 caller logs a warning and treats that as
/// a missing field.
fn iso8601_to_unix_ms(s: &str) -> Option<u64> {
    let dt = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ").ok()?;
    let ms = dt.and_utc().timestamp_millis();
    if ms < 0 { None } else { Some(ms as u64) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> PeerRequestBody {
        PeerRequestBody {
            initiator_domain: "alpha.example".into(),
            initiator_instance_pubkey: [9u8; 32],
            proposed_capabilities: vec!["edge-sync".into(), "content-sync".into()],
            introduction: Some("hi".into()),
            request_id: [0xab; 16],
            created_at: 1_700_000_000_000,
        }
    }

    fn sample_response() -> PeerResponseBody {
        PeerResponseBody {
            request_id: [0xab; 16],
            responder_domain: "beta.example".into(),
            responder_instance_pubkey: [7u8; 32],
            decision: PeerDecision::Accept,
            agreed_capabilities: Some(vec!["edge-sync".into()]),
            decision_message: Some("welcome".into()),
            created_at: 1_700_000_001_000,
        }
    }

    #[test]
    fn peer_request_round_trips() {
        let r = sample_request();
        let bytes = r.encode();
        let decoded = PeerRequestBody::decode(&bytes).expect("decode");
        assert_eq!(decoded, r);
    }

    #[test]
    fn peer_request_round_trips_without_introduction() {
        let mut r = sample_request();
        r.introduction = None;
        let bytes = r.encode();
        let decoded = PeerRequestBody::decode(&bytes).expect("decode");
        assert_eq!(decoded, r);
    }

    #[test]
    fn peer_response_round_trips() {
        let r = sample_response();
        let bytes = r.encode();
        let decoded = PeerResponseBody::decode(&bytes).expect("decode");
        assert_eq!(decoded, r);
    }

    #[test]
    fn peer_response_reject_without_agreed_caps() {
        let mut r = sample_response();
        r.decision = PeerDecision::Reject;
        r.agreed_capabilities = None;
        r.decision_message = Some("not at this time".into());
        let bytes = r.encode();
        let decoded = PeerResponseBody::decode(&bytes).expect("decode");
        assert_eq!(decoded, r);
    }

    #[test]
    fn intersect_caps_preserves_our_order_and_filters() {
        let ours = vec!["a".into(), "b".into(), "c".into()];
        let proposed = vec!["c".into(), "b".into(), "z".into()];
        let got = intersect_caps(&ours, &proposed);
        assert_eq!(got, vec!["b".to_string(), "c".to_string()]);
    }

    fn sample_delete() -> PeerRelationshipDeleteBody {
        PeerRelationshipDeleteBody {
            terminator_domain: "gamma.example".into(),
            reason: TerminationReason::PolicyViolation,
            message: Some("abuse policy §3".into()),
            created_at: 1_700_000_002_000,
        }
    }

    #[test]
    fn peer_relationship_delete_round_trips() {
        let r = sample_delete();
        let bytes = r.encode();
        let decoded = PeerRelationshipDeleteBody::decode(&bytes).expect("decode");
        assert_eq!(decoded, r);
    }

    #[test]
    fn peer_relationship_delete_round_trips_without_message() {
        let mut r = sample_delete();
        r.message = None;
        r.reason = TerminationReason::OperatorInitiated;
        let bytes = r.encode();
        let decoded = PeerRelationshipDeleteBody::decode(&bytes).expect("decode");
        assert_eq!(decoded, r);
    }

    #[test]
    fn peer_relationship_delete_rejects_unknown_reason() {
        // Hand-craft a body with an out-of-spec `reason` token.
        let value = Value::Map(vec![
            (
                Value::Text("terminator_domain".into()),
                Value::Text("x".into()),
            ),
            (Value::Text("reason".into()), Value::Text("bored".into())),
            (
                Value::Text("created_at".into()),
                Value::Integer(Integer::from(1u64)),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf).unwrap();
        assert!(PeerRelationshipDeleteBody::decode(&buf).is_none());
    }

    #[test]
    fn iso8601_to_unix_ms_handles_epoch_and_known_dates() {
        assert_eq!(iso8601_to_unix_ms("1970-01-01T00:00:00Z"), Some(0));
        // 2021-01-01T00:00:00Z is 1_609_459_200 unix seconds.
        assert_eq!(
            iso8601_to_unix_ms("2021-01-01T00:00:00Z"),
            Some(1_609_459_200_000)
        );
    }

    #[test]
    fn iso8601_to_unix_ms_rejects_wrong_shape() {
        assert!(iso8601_to_unix_ms("not-a-date").is_none());
        assert!(iso8601_to_unix_ms("2021-01-01T00:00:00").is_none());
        assert!(iso8601_to_unix_ms("2021/01/01T00:00:00Z").is_none());
    }
}
