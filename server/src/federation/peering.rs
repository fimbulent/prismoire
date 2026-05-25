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
use axum::extract::State;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ciborium::value::{Integer, Value};
use http::HeaderValue;
use rand::RngCore;
use rand::rngs::OsRng;
use sqlx::SqlitePool;

use crate::AppState;
use crate::federation::envelope::{self, AUTH_HEADER, VerifyError, VerifyMode};
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::instance_key::InstanceKey;
use crate::federation::transport::{FederationTransport, PeerId, TransportError};

/// Maximum CBOR body size for either handshake POST. The protocol's
/// peer-request / peer-response bodies are bounded by a small handful
/// of fixed fields plus the proposed-capabilities array (a few short
/// tokens), so 64 KiB is a generous cap that still keeps the handler
/// from being a memory-amplification vector.
const PEER_HANDSHAKE_MAX_BODY: usize = 64 * 1024;

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
fn decode_text_array(bytes: &[u8]) -> Option<Vec<String>> {
    let value: Value = ciborium::de::from_reader(bytes).ok()?;
    text_array(value)
}

// --- HTTP handlers ---------------------------------------------------

/// `POST /federation/v1/peer-request` handler.
///
/// Bootstrap-exception verifier: §6.5 step 5 lookup is skipped and
/// instead this handler enforces self-consistency (`envelope.sender
/// == body.initiator_instance_pubkey`). On success, records a
/// `pending_inbound` row visible to the operator's admin UI.
pub async fn handle_peer_request(
    State(state): State<Arc<AppState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let (parts, body) = req.into_parts();
    if let Some(resp) = require_cbor_content_type(&parts.headers) {
        return resp;
    }
    let body = match axum::body::to_bytes(body, PEER_HANDSHAKE_MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return unauthorized(),
    };

    let auth_header = parts.headers.get(AUTH_HEADER);
    let envelope = match envelope::verify_inbound(
        &state.db,
        state.instance_key.public_bytes(),
        &state.federation_nonce_lru,
        VerifyMode::Bootstrap,
        &Method::POST,
        "/federation/v1/peer-request",
        &body,
        auth_header,
    )
    .await
    {
        Ok(e) => e,
        Err(_) => return unauthorized(),
    };

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
/// Receives the callback from the responder. The envelope is
/// verified in `KnownPeer` mode against the `pending_outbound` row
/// we recorded when our operator hit "Request"; on accept, the row
/// flips to `active` with the agreed capability set.
pub async fn handle_peer_response(
    State(state): State<Arc<AppState>>,
    req: Request<axum::body::Body>,
) -> Response {
    let (parts, body) = req.into_parts();
    if let Some(resp) = require_cbor_content_type(&parts.headers) {
        return resp;
    }
    let body = match axum::body::to_bytes(body, PEER_HANDSHAKE_MAX_BODY).await {
        Ok(b) => b,
        Err(_) => return unauthorized(),
    };

    let auth_header = parts.headers.get(AUTH_HEADER);
    // The peer-response envelope is signed by the responder, who is
    // *not yet* in our `active` peers table — they're in
    // `pending_outbound` from our point of view. Use Bootstrap mode
    // for the envelope verify and then do the lookup ourselves
    // below, scoped to `pending_outbound` rows specifically.
    let envelope = match envelope::verify_inbound(
        &state.db,
        state.instance_key.public_bytes(),
        &state.federation_nonce_lru,
        VerifyMode::Bootstrap,
        &Method::POST,
        "/federation/v1/peer-response",
        &body,
        auth_header,
    )
    .await
    {
        Ok(e) => e,
        Err(VerifyError::MissingHeader)
        | Err(VerifyError::BadBase64)
        | Err(VerifyError::BadWireFormat)
        | Err(VerifyError::BadPayload)
        | Err(VerifyError::NotFedEnvelope)
        | Err(VerifyError::SignatureFailed)
        | Err(VerifyError::WrongReceiver)
        | Err(VerifyError::MethodMismatch)
        | Err(VerifyError::PathMismatch)
        | Err(VerifyError::BodyHashMismatch)
        | Err(VerifyError::ClockSkew)
        | Err(VerifyError::Replay) => return unauthorized(),
        // Bootstrap mode never produces `UnknownSender` (the verifier
        // skips its step-5 peers lookup), so this arm is structurally
        // unreachable today. It is enumerated explicitly to keep the
        // match exhaustive against the `VerifyError` enum. Once §20
        // anomaly counters land, an inbound peer-response with a key
        // that doesn't match our recorded `pending_outbound` row is a
        // separately-interesting signal (MITM vs. mid-flight key
        // rotation) and will want its own counter rather than being
        // folded into the generic `unauthorized` bucket below.
        Err(VerifyError::UnknownSender) => return unauthorized(),
        Err(VerifyError::Db(e)) => {
            tracing::error!(error = %e, "db error during peer-response envelope verify");
            return internal_error();
        }
    };

    let parsed = match PeerResponseBody::decode(&body) {
        Some(p) => p,
        None => return bad_request("invalid_body"),
    };

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

/// CBOR-encode an error body of shape `{ "error": <code> }` per
/// `federation-protocol.md` §1.7 (the `/federation/v1/*` surface is
/// CBOR-only — no JSON anywhere, including error responses).
fn cbor_error_body(code: &str) -> Vec<u8> {
    let value = Value::Map(vec![(
        Value::Text("error".into()),
        Value::Text(code.into()),
    )]);
    let mut buf = Vec::with_capacity(32);
    ciborium::ser::into_writer(&value, &mut buf).expect("ciborium ser is infallible");
    buf
}

fn error_response(status: StatusCode, code: &str) -> Response {
    let mut r = (status, cbor_error_body(code)).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    r
}

fn unauthorized() -> Response {
    error_response(StatusCode::UNAUTHORIZED, "unauthorized")
}

fn unsupported_media_type() -> Response {
    error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
}

/// Reject the request if its `Content-Type` is not `application/cbor`.
/// Returns `None` when the header is acceptable; `Some(response)` to
/// short-circuit the handler with 415. Peers that send JSON would
/// otherwise reach the CBOR decoder and fail at parse rather than at
/// content negotiation, which is harder to diagnose.
fn require_cbor_content_type(headers: &http::HeaderMap) -> Option<Response> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    if ct == Some(CBOR_CONTENT_TYPE) {
        None
    } else {
        Some(unsupported_media_type())
    }
}

fn bad_request(code: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, code)
}

fn not_found(code: &str) -> Response {
    error_response(StatusCode::NOT_FOUND, code)
}

fn conflict(code: &str) -> Response {
    error_response(StatusCode::CONFLICT, code)
}

fn internal_error() -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal")
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
}
