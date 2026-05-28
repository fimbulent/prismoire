//! §14.1 / §14.2 client-side primitives.
//!
//! The server-side counterparts live in
//! [`crate::federation::prior_home`] (challenge mint + probe handler).
//! This module is what the §13 cross-instance registration handler
//! calls when it needs to probe a candidate prior home for activity
//! on the migrating user's pubkey K.
//!
//! ## Wire shape (`docs/federation-protocol.md` §14.1 step 1, §14.2)
//!
//! 1. `POST /federation/v1/prior-home/challenge` with
//!    `{ "key": bstr(K) }`. Response is
//!    `{ "challenge": bstr(WireFormat) }` — a §5.6 `prior-home-challenge`
//!    signed by the responding peer's instance key.
//! 2. Sign a §5.7 `prior-home-response` under K binding
//!    `challenge_hash = SHA256(challenge.payload)` and a fresh
//!    `created_at` ms timestamp.
//! 3. `POST /federation/v1/prior-home/probe` with
//!    `{ "challenge": bstr, "response": bstr }`. Response is
//!    `{ "has_activity": bool, "earliest_seen"?: uint }`.
//!
//! Both POSTs ride the §6 envelope KnownPeer tier — the requesting
//! peer (this destination instance) must be in `peers` as `active` on
//! the receiver's side. That is the normal precondition for federation
//! traffic; in tests we set it up via `establish_active_peering`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use http::{Method, Request, StatusCode};
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::federation::envelope::{
    AUTH_HEADER, decode_signed_object, encode_signed_object, sign_outbound,
};
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::transport::{PeerId, TransportError};
use crate::signed::{PriorHomeResponse, SignedPayload};

/// §14.1 step-1 endpoint path.
pub const CHALLENGE_PATH: &str = "/federation/v1/prior-home/challenge";

/// §14.2 probe endpoint path.
pub const PROBE_PATH: &str = "/federation/v1/prior-home/probe";

/// §14.2 probe outcome — the 1-bit `has_activity` answer plus the
/// optional Unix-ms timestamp present when the answer is `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// `true` iff the responding peer holds a live local credential
    /// for K (and no observed move-out per §14.2 semantics).
    pub has_activity: bool,
    /// §14.2 `earliest_seen` — Unix-ms timestamp of the peer's local
    /// `users.created_at` for K. Present iff `has_activity == true`.
    pub earliest_seen: Option<u64>,
}

/// Failure modes for [`probe_peer_for_key`]. Coarse on purpose: callers
/// (today, the §13.3 fan-out orchestrator in
/// [`crate::federation::registration`]) only branch on "definitive hit"
/// vs "could not determine" — the latter is treated as a probe miss.
#[derive(Debug)]
pub enum ProbeError {
    /// Transport refused or failed to dispatch. Includes
    /// [`TransportError`] verbatim for tracing; callers treat this
    /// the same as a network outage.
    Transport(TransportError),
    /// Peer returned a non-success HTTP status. The §14 wire shape
    /// uses 400 for malformed / `wrong_responder` / `subject_mismatch`,
    /// 403 for `subject_deactivated`, 429 for `Retry-After`-bearing
    /// rate-limit overflow. Callers don't currently differentiate.
    Status(StatusCode),
    /// Response body did not match the expected wire shape.
    Decode(&'static str),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "prior-home probe transport error: {e}"),
            Self::Status(s) => write!(f, "prior-home probe status {s}"),
            Self::Decode(why) => write!(f, "prior-home probe decode error: {why}"),
        }
    }
}

impl std::error::Error for ProbeError {}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build `{ "key": bstr(K) }` per §14.1 step-1 request shape.
///
/// `pub(crate)` so the §13.3 step-4 recovery flow can mint the
/// challenge request body itself (it reuses the same §14.1 step-1
/// surface that [`probe_peer_for_key`] does, just to drive §14.5 /
/// §14.6 bulk-fetch instead of §14.2 probe).
pub(crate) fn encode_challenge_request(key: &[u8; 32]) -> Vec<u8> {
    let body = Value::Map(vec![(
        Value::Text("key".into()),
        Value::Bytes(key.to_vec()),
    )]);
    let mut buf = Vec::with_capacity(64);
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    buf
}

/// Build `{ "challenge": bstr, "response": bstr }` per §14.2 probe body.
fn encode_probe_request(challenge_wire: &[u8], response_wire: &[u8]) -> Vec<u8> {
    // Canonical map-key order: bytewise-lex on CBOR-encoded keys.
    // "challenge" (`c` = 0x63) < "response" (`r` = 0x72), so the order
    // we emit here matches the receiver's strict-decoder expectation.
    let body = Value::Map(vec![
        (
            Value::Text("challenge".into()),
            Value::Bytes(challenge_wire.to_vec()),
        ),
        (
            Value::Text("response".into()),
            Value::Bytes(response_wire.to_vec()),
        ),
    ]);
    let mut buf = Vec::with_capacity(challenge_wire.len() + response_wire.len() + 32);
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    buf
}

/// Pull the `"challenge"` bstr field out of the §14.1 step-1 response.
///
/// `pub(crate)` so the §13.3 step-4 recovery flow can reuse the same
/// parser when it mints a challenge for §14.5 / §14.6 pagination.
pub(crate) fn parse_challenge_response(body: &[u8]) -> Option<Vec<u8>> {
    let value: Value = ciborium::de::from_reader(body).ok()?;
    let entries = match value {
        Value::Map(m) => m,
        _ => return None,
    };
    let mut challenge: Option<Vec<u8>> = None;
    for (k, v) in entries {
        let name = match k {
            Value::Text(s) => s,
            _ => return None,
        };
        match name.as_str() {
            "challenge" => {
                if challenge.is_some() {
                    return None;
                }
                match v {
                    Value::Bytes(b) => challenge = Some(b),
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
    challenge
}

/// Parse the §14.2 probe response into `{ has_activity, earliest_seen }`.
fn parse_probe_response(body: &[u8]) -> Option<ProbeOutcome> {
    let value: Value = ciborium::de::from_reader(body).ok()?;
    let entries = match value {
        Value::Map(m) => m,
        _ => return None,
    };
    let mut has_activity: Option<bool> = None;
    let mut earliest_seen: Option<u64> = None;
    for (k, v) in entries {
        let name = match k {
            Value::Text(s) => s,
            _ => return None,
        };
        match name.as_str() {
            "has_activity" => match v {
                Value::Bool(b) => has_activity = Some(b),
                _ => return None,
            },
            "earliest_seen" => match v {
                Value::Integer(i) => {
                    let n: i128 = i.into();
                    earliest_seen = Some(u64::try_from(n).ok()?);
                }
                _ => return None,
            },
            _ => return None,
        }
    }
    Some(ProbeOutcome {
        has_activity: has_activity?,
        earliest_seen,
    })
}

/// Mint a §5.7 `prior-home-response` signed by `signing_key`, binding
/// `challenge_hash = SHA256(challenge_payload)` per §14.1 step-5 prose
/// ("pin the response to the bytes we just verified, so an attacker
/// cannot pair a fresh response with someone else's challenge"). The
/// returned bytes are the §6.3 WireFormat blob the probe endpoint
/// expects as its `response` field.
///
/// `pub(crate)` so the §13.3 step-4 recovery flow can mint a *fresh*
/// response per §14.5 / §14.6 page within the cached challenge's TTL
/// (the spec keeps `challenge` reusable across pages but requires a
/// new `response` per call to keep `created_at` inside
/// `MAX_FEDERATION_CLOCK_SKEW`).
pub(crate) fn mint_response(
    signing_key: &SigningKey,
    subject_key: &[u8; 32],
    challenge_payload: &[u8],
) -> Vec<u8> {
    let response = PriorHomeResponse {
        subject_key: *subject_key,
        challenge_hash: Sha256::digest(challenge_payload).into(),
        created_at: now_ms(),
    };
    let payload = SignedPayload::PriorHomeResponse(response).encode();
    let signature = signing_key.sign(&payload).to_bytes();
    encode_signed_object(&payload, &signature)
}

/// Dispatch one envelope-signed POST against `peer` and return the
/// response status + body. Envelope is signed with the destination's
/// own `instance_key`, addressed to `peer.as_bytes()` — the §6 verifier
/// on the receiving side requires this destination to appear in their
/// `peers` table as `status = 'active'`.
///
/// `pub(crate)` so the §13.3 step-4 recovery flow can dispatch its
/// §14.5 / §14.6 bulk-fetch POSTs through the same envelope-signing
/// path (challenge / probe / bulk-fetch all share the §6 KnownPeer
/// tier).
pub(crate) async fn signed_post(
    state: &Arc<AppState>,
    peer: &PeerId,
    path: &str,
    body: Vec<u8>,
) -> Result<(StatusCode, Bytes), ProbeError> {
    let header = sign_outbound(
        &state.instance_key,
        *peer.as_bytes(),
        &Method::POST,
        path,
        &body,
    );
    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(AUTH_HEADER, header)
        .header(http::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .body(Bytes::from(body))
        .map_err(|_| ProbeError::Decode("request build failed"))?;
    let response = state
        .federation_transport
        .request(peer, req)
        .await
        .map_err(ProbeError::Transport)?;
    let status = response.status();
    let body = response.into_body();
    Ok((status, body))
}

/// Run the §14.1 challenge / §14.2 probe ceremony against `peer` for
/// `subject_key`. Returns the §14.2 `has_activity` + optional
/// `earliest_seen`.
///
/// `signing_key` must hold the private half of `subject_key` — the
/// §14.1 step-4 verifier on the peer's side rejects any response
/// whose signature does not verify under the response's declared
/// `subject_key`.
///
/// Failure modes (all expressed as [`ProbeError`]):
/// - Transport refusal or network failure.
/// - Non-2xx status from either endpoint (typically `400` /
///   `403 subject_deactivated` / `429`).
/// - Malformed response body (e.g. peer running an incompatible
///   protocol revision).
///
/// Callers in the §13.3 fan-out treat any `Err` the same as
/// `Ok(ProbeOutcome { has_activity: false, .. })` — a probe miss.
pub async fn probe_peer_for_key(
    state: &Arc<AppState>,
    peer: &PeerId,
    subject_key: [u8; 32],
    signing_key: &SigningKey,
) -> Result<ProbeOutcome, ProbeError> {
    // §14.1 step 1 — challenge mint.
    let (status, body) = signed_post(
        state,
        peer,
        CHALLENGE_PATH,
        encode_challenge_request(&subject_key),
    )
    .await?;
    if !status.is_success() {
        return Err(ProbeError::Status(status));
    }
    let challenge_wire = parse_challenge_response(&body)
        .ok_or(ProbeError::Decode("challenge response missing `challenge`"))?;
    // Peel the WireFormat to get the §5.6 canonical bytes we need to
    // hash for the §5.7 `challenge_hash` binding.
    let (challenge_payload, _) = decode_signed_object(&challenge_wire)
        .ok_or(ProbeError::Decode("challenge wire is not a SignedObject"))?;

    // Sign the §5.7 response under K against the peer's challenge.
    let response_wire = mint_response(signing_key, &subject_key, &challenge_payload);

    // §14.2 probe.
    let (status, body) = signed_post(
        state,
        peer,
        PROBE_PATH,
        encode_probe_request(&challenge_wire, &response_wire),
    )
    .await?;
    if !status.is_success() {
        return Err(ProbeError::Status(status));
    }
    parse_probe_response(&body).ok_or(ProbeError::Decode("probe response missing `has_activity`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_request_encodes_canonically() {
        let key = [0xab; 32];
        let body = encode_challenge_request(&key);
        // Round-trip via ciborium and check the single `key` field.
        let value: Value = ciborium::de::from_reader(body.as_slice()).expect("cbor");
        let Value::Map(entries) = value else {
            panic!("not a map")
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, Value::Text("key".into()));
        assert_eq!(entries[0].1, Value::Bytes(key.to_vec()));
    }

    #[test]
    fn probe_request_encodes_canonically() {
        let ch = vec![0xc1, 0xc2, 0xc3];
        let resp = vec![0xd1, 0xd2];
        let body = encode_probe_request(&ch, &resp);
        let value: Value = ciborium::de::from_reader(body.as_slice()).expect("cbor");
        let Value::Map(entries) = value else {
            panic!("not a map")
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, Value::Text("challenge".into()));
        assert_eq!(entries[1].0, Value::Text("response".into()));
    }

    #[test]
    fn parse_challenge_response_round_trips() {
        let wire = vec![0xa0, 0xa1, 0xa2, 0xa3];
        let body = Value::Map(vec![(
            Value::Text("challenge".into()),
            Value::Bytes(wire.clone()),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let parsed = parse_challenge_response(&buf).expect("parse");
        assert_eq!(parsed, wire);
    }

    #[test]
    fn parse_challenge_response_rejects_extra_keys() {
        let body = Value::Map(vec![
            (Value::Text("challenge".into()), Value::Bytes(vec![1, 2])),
            (Value::Text("extra".into()), Value::Bool(true)),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert!(parse_challenge_response(&buf).is_none());
    }

    #[test]
    fn parse_probe_response_active() {
        let body = Value::Map(vec![
            (
                Value::Text("earliest_seen".into()),
                Value::Integer(1_700_000_000_000u64.into()),
            ),
            (Value::Text("has_activity".into()), Value::Bool(true)),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let parsed = parse_probe_response(&buf).expect("parse");
        assert!(parsed.has_activity);
        assert_eq!(parsed.earliest_seen, Some(1_700_000_000_000));
    }

    #[test]
    fn parse_probe_response_inactive_omits_earliest() {
        let body = Value::Map(vec![(
            Value::Text("has_activity".into()),
            Value::Bool(false),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let parsed = parse_probe_response(&buf).expect("parse");
        assert!(!parsed.has_activity);
        assert!(parsed.earliest_seen.is_none());
    }

    #[test]
    fn parse_probe_response_requires_has_activity() {
        let body = Value::Map(vec![(
            Value::Text("earliest_seen".into()),
            Value::Integer(1u64.into()),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert!(parse_probe_response(&buf).is_none());
    }
}
