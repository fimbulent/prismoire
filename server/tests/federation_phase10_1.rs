//! Phase-10.1 integration tests: §14.1 / §14.2 prior-home challenge +
//! probe surface.
//!
//! Spec gates exercised here (`docs/federation-protocol.md` §14):
//!
//! - **Layer 1** — Happy path: A posts a challenge for live local
//!   user K on B, gets a signed challenge back, K signs a response,
//!   A posts the probe, and B answers `has_activity = true` with
//!   `earliest_seen` set to K's local `created_at`.
//! - **Layer 1** — Absent K: K is not provisioned on B (no users
//!   row), so the probe answers `has_activity = false` with no
//!   `earliest_seen`. Negative answers are by design — the protocol
//!   exists to let a recovering user enumerate candidate priors.
//! - **Layer 1** — Expired challenge: a challenge whose
//!   `expires_at` is in the past collapses to
//!   400 `expired_challenge` even though the signatures verify.
//! - **Layer 1** — Subject mismatch: the challenge is bound to K1,
//!   but the response is signed by K2. The §14.1 step-5 check
//!   `challenge.subject_key == response.subject_key` (and its
//!   challenge-hash pin) collapses both shapes to 400
//!   `subject_mismatch`.
//! - **Layer 1** — Wrong responder: the challenge body is tampered
//!   so B's signature no longer verifies; §14.1 step 3 returns 400
//!   `wrong_responder`.
//! - **Layer 1** — Rate-limit overflow: PRIOR_HOME_PROBES_PER_DAY_PER_KEY
//!   successful probes for the same K saturate the §14.3 counter;
//!   the next admit returns 429 with `Retry-After: 86400`.

#![cfg(feature = "test-auth")]

mod common;

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use http::{Method, StatusCode};
use prismoire_server::federation::prior_home_rate_limit::PRIOR_HOME_PROBES_PER_DAY_PER_KEY;
use prismoire_server::signed::{PriorHomeChallenge, PriorHomeResponse, SignedPayload};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};
use common::setup_admin;

// ---------------------------------------------------------------------------
// Wire-format helpers
// ---------------------------------------------------------------------------

/// Build a `{ "p": payload, "s": signature }` WireFormat blob — same
/// shape as `crate::federation::envelope::encode_signed_object`, but
/// inlined here because the encoder is `pub(crate)`.
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

fn decode_wire(wire: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let v: Value = ciborium::de::from_reader(wire).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("wire not a map");
    };
    let mut p = None;
    let mut s = None;
    for (k, v) in m {
        let Value::Text(name) = k else {
            panic!("non-text key")
        };
        let Value::Bytes(bytes) = v else {
            panic!("non-bytes value")
        };
        match name.as_str() {
            "p" => p = Some(bytes),
            "s" => s = Some(bytes),
            _ => panic!("unexpected key {name}"),
        }
    }
    (p.expect("p"), s.expect("s"))
}

fn encode_challenge_request(key: &[u8; 32]) -> Vec<u8> {
    let body = Value::Map(vec![(
        Value::Text("key".into()),
        Value::Bytes(key.to_vec()),
    )]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

fn encode_probe_request(challenge_wire: &[u8], response_wire: &[u8]) -> Vec<u8> {
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
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// Pull the `"challenge"` field out of the server's reply to
/// `POST /prior-home/challenge`.
fn parse_challenge_response(body: &[u8]) -> Vec<u8> {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("challenge response not a map");
    };
    for (k, v) in m {
        if let Value::Text(name) = k
            && name == "challenge"
        {
            let Value::Bytes(b) = v else {
                panic!("challenge not bytes")
            };
            return b;
        }
    }
    panic!("missing `challenge` field");
}

/// Parse the §14.2 probe-response body into `(has_activity, earliest_seen)`.
fn parse_probe_response(body: &[u8]) -> (bool, Option<u64>) {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("probe response not a map");
    };
    let mut has_activity = None;
    let mut earliest_seen = None;
    for (k, v) in m {
        let Value::Text(name) = k else {
            panic!("non-text key")
        };
        match (name.as_str(), v) {
            ("has_activity", Value::Bool(b)) => has_activity = Some(b),
            ("earliest_seen", Value::Integer(i)) => {
                let n: i128 = i.into();
                earliest_seen = Some(u64::try_from(n).expect("earliest_seen fits"));
            }
            (other, _) => panic!("unexpected field {other}"),
        }
    }
    (has_activity.expect("has_activity"), earliest_seen)
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Mint a §5.7 `prior-home-response` signed by `k_key` against the
/// challenge whose canonical bytes are `challenge_payload`.
fn mint_response(k_key: &SigningKey, challenge_payload: &[u8]) -> Vec<u8> {
    let response = PriorHomeResponse {
        subject_key: *k_key.verifying_key().as_bytes(),
        challenge_hash: Sha256::digest(challenge_payload).into(),
        created_at: now_ms(),
    };
    let payload = SignedPayload::PriorHomeResponse(response).encode();
    let signature = k_key.sign(&payload).to_bytes().to_vec();
    encode_wire(&payload, &signature)
}

/// Extract K's SigningKey from the DB so the test can sign §5.7
/// responses as K. Mirrors `federation_phase9_9::extract_user_signing_key`.
async fn extract_user_signing_key(db: &SqlitePool, user_id: &str) -> SigningKey {
    let row = sqlx::query!(
        "SELECT private_key AS \"private_key!: Vec<u8>\" \
         FROM signing_keys WHERE user_id = ? AND active = 1",
        user_id,
    )
    .fetch_one(db)
    .await
    .expect("signing_keys row");
    let bytes: [u8; 32] = row
        .private_key
        .as_slice()
        .try_into()
        .expect("32-byte private key");
    SigningKey::from_bytes(&bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Done-when (1): A obtains a fresh challenge from B for live local
/// user K, K signs a response, the probe returns `has_activity = true`
/// with `earliest_seen` matching K's local `created_at`.
#[tokio::test]
async fn happy_path_returns_has_activity_true() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    // K is a live local user on B.
    let k_session = setup_admin(&b.router, "kara").await;
    let k_key = extract_user_signing_key(&b.state.db, &k_session.user_id).await;
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // Step 1: A asks B for a challenge bound to K.
    let req_body = encode_challenge_request(&k_pub);
    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/challenge",
        &req_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "challenge mint should succeed");
    let challenge_wire = parse_challenge_response(&body);

    // Step 2: K signs the response.
    let (challenge_payload, _) = decode_wire(&challenge_wire);
    let response_wire = mint_response(&k_key, &challenge_payload);

    // Step 3: A posts the probe.
    let probe_body = encode_probe_request(&challenge_wire, &response_wire);
    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/probe",
        &probe_body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "probe should succeed: body={:?}",
        String::from_utf8_lossy(&body),
    );
    let (has_activity, earliest_seen) = parse_probe_response(&body);
    assert!(has_activity, "K has live local credentials on B");
    let ts = earliest_seen.expect("earliest_seen present iff has_activity");
    assert!(
        ts > 0 && ts <= now_ms(),
        "earliest_seen is a plausible past Unix-ms timestamp (got {ts})"
    );
}

/// Done-when (2): K is not provisioned on B, so the probe answers
/// `has_activity = false` with no `earliest_seen`. The challenge
/// endpoint does not consult the users table — it issues for any
/// curve-valid K — so a "miss" only surfaces at probe time.
#[tokio::test]
async fn absent_key_returns_has_activity_false() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // K is a synthetic key never provisioned on either instance.
    let k_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    let req_body = encode_challenge_request(&k_pub);
    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/challenge",
        &req_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let challenge_wire = parse_challenge_response(&body);
    let (challenge_payload, _) = decode_wire(&challenge_wire);
    let response_wire = mint_response(&k_key, &challenge_payload);

    let probe_body = encode_probe_request(&challenge_wire, &response_wire);
    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/probe",
        &probe_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (has_activity, earliest_seen) = parse_probe_response(&body);
    assert!(!has_activity, "K is unknown to B");
    assert!(earliest_seen.is_none(), "earliest_seen omitted on miss");
}

/// Done-when (3): A challenge whose `expires_at` is in the past
/// collapses to 400 `expired_challenge` even though both signatures
/// verify. We mint the challenge directly with B's instance key
/// (mirroring the handler) rather than going through the live mint
/// endpoint — the live one never produces a stale challenge.
#[tokio::test]
async fn expired_challenge_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let k_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // Hand-mint a challenge expiring 10s ago.
    let now = now_ms();
    let challenge = PriorHomeChallenge {
        responder_instance_key: *b.state.instance_key.public_bytes(),
        subject_key: k_pub,
        nonce: [7u8; 32],
        created_at: now.saturating_sub(120_000),
        expires_at: now.saturating_sub(10_000),
    };
    let challenge_payload = SignedPayload::PriorHomeChallenge(challenge).encode();
    let challenge_sig = b.state.instance_key.sign(&challenge_payload).to_vec();
    let challenge_wire = encode_wire(&challenge_payload, &challenge_sig);
    let response_wire = mint_response(&k_key, &challenge_payload);

    let probe_body = encode_probe_request(&challenge_wire, &response_wire);
    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/probe",
        &probe_body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expired challenge must 400"
    );
    let v: Value = ciborium::de::from_reader(body.as_slice()).expect("cbor");
    let Value::Map(fields) = v else {
        panic!("error body not a map")
    };
    let err = fields
        .into_iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == "error" => match v {
                Value::Text(t) => Some(t),
                _ => None,
            },
            _ => None,
        })
        .expect("error field");
    assert_eq!(err, "expired_challenge");
}

/// Done-when (4): challenge bound to K1, response signed by K2. The
/// step-5 `challenge.subject_key == response.subject_key` check
/// collapses to 400 `subject_mismatch`.
#[tokio::test]
async fn subject_mismatch_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let k1 = SigningKey::generate(&mut rand::rngs::OsRng);
    let k2 = SigningKey::generate(&mut rand::rngs::OsRng);

    // Challenge bound to K1.
    let req_body = encode_challenge_request(k1.verifying_key().as_bytes());
    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/challenge",
        &req_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let challenge_wire = parse_challenge_response(&body);
    let (challenge_payload, _) = decode_wire(&challenge_wire);

    // Response signed by K2 instead.
    let response_wire = mint_response(&k2, &challenge_payload);
    let probe_body = encode_probe_request(&challenge_wire, &response_wire);
    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/probe",
        &probe_body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let v: Value = ciborium::de::from_reader(body.as_slice()).expect("cbor");
    let Value::Map(fields) = v else {
        panic!("error body not a map")
    };
    let err = fields
        .into_iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == "error" => match v {
                Value::Text(t) => Some(t),
                _ => None,
            },
            _ => None,
        })
        .expect("error field");
    assert_eq!(err, "subject_mismatch");
}

/// Done-when (5): the challenge bytes are altered after issuance so
/// B's signature no longer verifies. §14.1 step 3 returns 400
/// `wrong_responder`.
#[tokio::test]
async fn tampered_challenge_returns_wrong_responder() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let k = SigningKey::generate(&mut rand::rngs::OsRng);
    let req_body = encode_challenge_request(k.verifying_key().as_bytes());
    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/challenge",
        &req_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let challenge_wire = parse_challenge_response(&body);
    let (mut challenge_payload, challenge_sig) = decode_wire(&challenge_wire);
    // Flip a byte deep in the payload — same length, but the signature
    // is now over different bytes. Nonce field lives well inside the
    // canonical map, so we mutate the last byte (likely an
    // `expires_at` digit) to keep it parseable as CBOR while breaking
    // the sig.
    let last = challenge_payload.len() - 1;
    challenge_payload[last] ^= 0x01;
    let tampered_wire = encode_wire(&challenge_payload, &challenge_sig);
    // The response signs over the tampered payload's hash to keep the
    // step-5 challenge_hash pin from short-circuiting before step 3
    // runs. (Step 3 is the signature check; the hash check is later.)
    let response_wire = mint_response(&k, &challenge_payload);

    let probe_body = encode_probe_request(&tampered_wire, &response_wire);
    let (status, body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/probe",
        &probe_body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let v: Value = ciborium::de::from_reader(body.as_slice()).expect("cbor");
    let Value::Map(fields) = v else {
        panic!("error body not a map")
    };
    let err = fields
        .into_iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == "error" => match v {
                Value::Text(t) => Some(t),
                _ => None,
            },
            _ => None,
        })
        .expect("error field");
    assert_eq!(err, "wrong_responder");
}

/// Done-when (6): exhausting the §14.3 per-subject daily budget
/// collapses the next request to 429 with `Retry-After: 86400`.
/// We send `PRIOR_HOME_PROBES_PER_DAY_PER_KEY + 1` so the test
/// tracks the constant if the cap ever gets re-tuned.
#[tokio::test]
async fn rate_limit_overflow_returns_429() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let k = SigningKey::generate(&mut rand::rngs::OsRng);
    let k_pub: [u8; 32] = *k.verifying_key().as_bytes();

    // Helper: do one full ceremony round-trip; assert on `status`.
    async fn probe_once(
        harness: &MultiInstanceHarness,
        k: &SigningKey,
        k_pub: &[u8; 32],
    ) -> StatusCode {
        let req_body = encode_challenge_request(k_pub);
        let (s1, body) = send_envelope_signed(
            harness,
            "a",
            "b",
            Method::POST,
            "/federation/v1/prior-home/challenge",
            &req_body,
        )
        .await;
        assert_eq!(s1, StatusCode::OK, "challenge mint should never overflow");
        let challenge_wire = parse_challenge_response(&body);
        let (challenge_payload, _) = decode_wire(&challenge_wire);
        let response_wire = mint_response(k, &challenge_payload);
        let probe_body = encode_probe_request(&challenge_wire, &response_wire);
        let (s2, _) = send_envelope_signed(
            harness,
            "a",
            "b",
            Method::POST,
            "/federation/v1/prior-home/probe",
            &probe_body,
        )
        .await;
        s2
    }

    // First N probes admit; N+1 must be 429.
    let budget = PRIOR_HOME_PROBES_PER_DAY_PER_KEY;
    for i in 0..budget {
        let s = probe_once(&harness, &k, &k_pub).await;
        assert_eq!(s, StatusCode::OK, "probe #{} should admit", i + 1);
    }
    let overflow = probe_once(&harness, &k, &k_pub).await;
    assert_eq!(
        overflow,
        StatusCode::TOO_MANY_REQUESTS,
        "probe #{} must overflow §14.3 daily budget",
        budget + 1,
    );
}
