#![cfg(feature = "test-auth")]
//! Prior-home / post-move recovery integration tests (§13.3 / §14).
//!
//! Consolidates five formerly-separate phase files into the single
//! protocol surface they all exercise — a user's prior-home instance
//! answering identity probes and serving back the user's content/edges
//! after the user has moved (or is recovering credentials on a new
//! home):
//!
//! - **§14.1 / §14.2 challenge + probe.** A asks B to mint a challenge
//!   bound to subject-key K; K signs a §5.7 response; A posts the probe
//!   and B answers `has_activity` (+ `earliest_seen` on a hit). A live
//!   local K answers `true`; an unprovisioned K answers `false`. The
//!   reject classes all 400: an expired challenge (`expired_challenge`),
//!   a K1-bound challenge answered by K2 (`subject_mismatch`), and a
//!   tampered challenge whose responder signature no longer verifies
//!   (`wrong_responder`). The §14.3 per-K daily probe budget 429s on
//!   overflow with `Retry-After: 86400`.
//! - **§14.3 challenge-mint rate limits.** The per-K per-minute cap
//!   (`PRIOR_HOME_CHALLENGE_RPM_PER_KEY`) 429s the (N+1)th mint with
//!   `Retry-After: 60`; distinct K values keep independent buckets; a
//!   curve-invalid K 400s `invalid_key` *before* the limiter is charged,
//!   so it cannot deplete a neighbouring real K's budget.
//! - **§14.5 / §14.6 bulk fetch.** `content-by-key` serves K-authored
//!   objects only — an outbound trust-edge (K→X) and a profile revision
//!   surface; an inbound edge (X→K) does not; an unknown K yields an
//!   empty `complete` page; the walk keyset-paginates. `inbound-edges-by-key`
//!   is the mirror surface: it serves inbound edges (X→K, Y→K) and omits
//!   outbound.
//! - **§13.3 step-1 prior-home discovery.** `discover_prior_home`
//!   resolves strategy 1 (user-declared peer), strategy 2 (local
//!   `users.home_instance` hint), and strategy 3 (bounded fan-out across
//!   active peers). A declared hit short-circuits; a declared
//!   *authoritative* miss is terminal even when another peer holds K; a
//!   declared peer that is unreachable or unknown falls through to
//!   fan-out; fan-out honours `PRIOR_HOME_PROBE_FANOUT_MAX`; and a
//!   moved-out peer (`home_instance` set) answers `false` and is never
//!   surfaced.
//! - **§14.5 / §14.6 / §14.7 step-4 data recovery.** `drive_recovery`
//!   walks the §14.5 + §14.6 surfaces against the confirmed prior home
//!   (primary), landing the recovered bytes in the registering instance's
//!   `signed_objects`; when the prior home is offline it falls back to
//!   the §10.5.1 `edges-by-key` route against an active peer; the
//!   `RecoveryStats` flags distinguish primary-complete, fallback-complete,
//!   and the `best_effort_incomplete` posture where neither layer produced
//!   bytes.
//!
//! Every scenario here either drives the function under test directly
//! (`discover_prior_home`, `drive_recovery`) or probes a handler via a
//! signed envelope, so none use the [`settle`](common::federation::settle)
//! convergence driver — there is no `frontier_fanout_loop` + poll race to
//! replace.

mod common;

use axum::body::Bytes;
use base64::Engine;
use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use http::{Method, StatusCode, header};
use prismoire_server::federation::prior_home_challenge_rate_limit::PRIOR_HOME_CHALLENGE_RPM_PER_KEY;
use prismoire_server::federation::prior_home_rate_limit::PRIOR_HOME_PROBES_PER_DAY_PER_KEY;
use prismoire_server::federation::prior_home_recovery::{RecoveryStats, drive_recovery};
use prismoire_server::federation::registration::{
    PRIOR_HOME_PROBE_FANOUT_MAX, discover_prior_home,
};
use prismoire_server::federation::transport::FederationTransport;
use prismoire_server::signed::{PriorHomeChallenge, PriorHomeResponse, SignedPayload, TrustStance};
use prismoire_server::signing::{SigningOutput, sign_trust_edge_with_key};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};
use common::setup_admin;

// ===========================================================================
// Shared helpers
// ===========================================================================

/// Build a `{ "p": payload, "s": signature }` §6.3 WireFormat blob —
/// same shape as `federation::envelope::encode_signed_object`, but
/// inlined because the encoder is `pub(crate)`.
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

/// Decode a §6.3 WireFormat blob back into `(payload, signature)`.
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

/// `POST /federation/v1/prior-home/challenge` body: `{ "key": bstr(32) }`.
fn encode_challenge_request(key: &[u8; 32]) -> Vec<u8> {
    let body = Value::Map(vec![(
        Value::Text("key".into()),
        Value::Bytes(key.to_vec()),
    )]);
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

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Mint a §5.7 `prior-home-response` signed by `k_key` against the
/// canonical bytes of `challenge_payload`.
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

/// Drive the §14.1 challenge mint against B and sign a fresh response.
/// Returns `(challenge_wire, response_wire)` for the bulk-fetch / probe
/// request bodies.
async fn mint_challenge_and_response(
    harness: &MultiInstanceHarness,
    k_key: &SigningKey,
) -> (Vec<u8>, Vec<u8>) {
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    let req_body = encode_challenge_request(&k_pub);
    let (status, body) = send_envelope_signed(
        harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/challenge",
        &req_body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "challenge mint must succeed: body={:?}",
        String::from_utf8_lossy(&body),
    );
    let challenge_wire = parse_challenge_response(&body);
    let (challenge_payload, _) = decode_wire(&challenge_wire);
    let response_wire = mint_response(k_key, &challenge_payload);
    (challenge_wire, response_wire)
}

/// Pull the `"error"` text field out of a CBOR error body.
fn parse_error_tag(body: &[u8]) -> String {
    let v: Value = ciborium::de::from_reader(body).expect("cbor");
    let Value::Map(fields) = v else {
        panic!("error body not a map")
    };
    fields
        .into_iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == "error" => match v {
                Value::Text(t) => Some(t),
                _ => None,
            },
            _ => None,
        })
        .expect("error field")
}

/// Extract K's active `SigningKey` from the DB so a test can sign §5.7
/// responses as a real provisioned user K.
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

/// Insert a `users` row whose `public_key` is `pubkey`. The user counts
/// as "local" for the probe / §14.5 / §14.6 surfaces (`signup_method !=
/// 'federated' AND home_instance IS NULL`). Returns the generated UUID.
async fn insert_local_user(db: &SqlitePool, display_name: &str, pubkey: &[u8; 32]) -> String {
    let id = Uuid::new_v4().to_string();
    let skeleton = display_name.to_lowercase();
    let pubkey_slice: &[u8] = pubkey.as_slice();
    sqlx::query!(
        "INSERT INTO users (id, display_name, signup_method, public_key, display_name_skeleton) \
         VALUES (?, ?, 'admin', ?, ?)",
        id,
        display_name,
        pubkey_slice,
        skeleton,
    )
    .execute(db)
    .await
    .expect("insert user");
    id
}

/// Sign + seed a trust edge from `signer` to `target_pub`, inserting both
/// the `signed_objects` row and the `trust_edges` projection (keyed by
/// the canonical_hash the §14.5 / §14.6 joins use). `received_at` is fixed
/// to a deterministic ISO timestamp derived from `ts_ms` so the keyset
/// pagination order is stable across runs. Returns the [`SigningOutput`]
/// so the caller can compare its WireFormat against the served bytes.
#[allow(clippy::too_many_arguments)]
async fn seed_signed_edge(
    db: &SqlitePool,
    signer: &SigningKey,
    source_user_id: &str,
    target_user_id: &str,
    target_pub: &[u8; 32],
    stance: TrustStance,
    ts_ms: u64,
    prior: Option<[u8; 32]>,
) -> SigningOutput {
    let signed = sign_trust_edge_with_key(signer, target_pub, stance, ts_ms, prior);

    let secs = (ts_ms / 1000) as i64;
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .expect("timestamp in range")
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let payload_slice: &[u8] = signed.payload.as_slice();
    let signature_slice: &[u8] = signed.signature.as_slice();
    sqlx::query!(
        "INSERT INTO signed_objects \
            (canonical_hash, inner_class, payload, signature, received_at) \
         VALUES (?, 'trust-edge', ?, ?, ?)",
        hash_slice,
        payload_slice,
        signature_slice,
        dt,
    )
    .execute(db)
    .await
    .expect("insert signed_objects (trust-edge)");

    let edge_id = Uuid::new_v4().to_string();
    let trust_type = match stance {
        TrustStance::Trust => "trust",
        TrustStance::Distrust => "distrust",
        TrustStance::Neutral => "neutral",
    };
    sqlx::query(
        "INSERT INTO trust_edges \
            (id, source_user, target_user, trust_type, canonical_hash, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&edge_id)
    .bind(source_user_id)
    .bind(target_user_id)
    .bind(trust_type)
    .bind(hash_slice)
    .bind(&dt)
    .execute(db)
    .await
    .expect("insert trust_edges");
    signed
}

// ===========================================================================
// §14.1 / §14.2 — challenge + probe surface
// ===========================================================================

/// Build the §14.2 probe request body `{ challenge, response }`.
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

/// Happy path: A obtains a fresh challenge from B for live local user K,
/// K signs a response, the probe returns `has_activity = true` with
/// `earliest_seen` matching K's local `created_at`.
#[tokio::test]
async fn happy_path_returns_has_activity_true() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    // K is a live local user on B.
    let k_session = setup_admin(&b.router, "kara").await;
    let k_key = extract_user_signing_key(&b.state.db, &k_session.user_id).await;
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
    assert_eq!(status, StatusCode::OK, "challenge mint should succeed");
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

/// K is not provisioned on B, so the probe answers `has_activity = false`
/// with no `earliest_seen`. The challenge endpoint issues for any
/// curve-valid K, so a "miss" only surfaces at probe time.
#[tokio::test]
async fn absent_key_returns_has_activity_false() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let k_key = SigningKey::generate(&mut OsRng);
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

/// A challenge whose `expires_at` is in the past collapses to 400
/// `expired_challenge` even though both signatures verify. We hand-mint
/// the challenge with B's instance key (the live mint never produces a
/// stale challenge).
#[tokio::test]
async fn expired_challenge_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

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
    assert_eq!(parse_error_tag(&body), "expired_challenge");
}

/// Challenge bound to K1, response signed by K2. The §14.1 step-5
/// `challenge.subject_key == response.subject_key` check (and its
/// challenge-hash pin) collapses to 400 `subject_mismatch`.
#[tokio::test]
async fn subject_mismatch_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let k1 = SigningKey::generate(&mut OsRng);
    let k2 = SigningKey::generate(&mut OsRng);

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
    assert_eq!(parse_error_tag(&body), "subject_mismatch");
}

/// The challenge bytes are altered after issuance so B's signature no
/// longer verifies. §14.1 step 3 returns 400 `wrong_responder`.
#[tokio::test]
async fn tampered_challenge_returns_wrong_responder() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let k = SigningKey::generate(&mut OsRng);
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
    // Flip the last byte — same length, but the signature is now over
    // different bytes. The response signs over the tampered payload's
    // hash so the step-5 challenge_hash pin doesn't short-circuit before
    // step 3 (the signature check) runs.
    let last = challenge_payload.len() - 1;
    challenge_payload[last] ^= 0x01;
    let tampered_wire = encode_wire(&challenge_payload, &challenge_sig);
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
    assert_eq!(parse_error_tag(&body), "wrong_responder");
}

/// Exhausting the §14.3 per-subject daily probe budget collapses the
/// next probe to 429 with `Retry-After: 86400`. We send
/// `PRIOR_HOME_PROBES_PER_DAY_PER_KEY + 1` so the test tracks the
/// constant if the cap is re-tuned.
#[tokio::test]
async fn probe_rate_limit_overflow_returns_429() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let k = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k.verifying_key().as_bytes();

    // One full ceremony round-trip; returns the probe's status.
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

// ===========================================================================
// §14.3 — challenge-mint rate limits
// ===========================================================================

/// Mint one challenge for `k_pub` against B and return the HTTP status
/// plus the `Retry-After` header (if present). Re-issues via the
/// transport directly so the test can read response headers (the
/// `send_envelope_signed` helper drops them).
async fn mint_challenge(
    harness: &MultiInstanceHarness,
    k_pub: &[u8; 32],
) -> (StatusCode, Option<String>) {
    let req_body = encode_challenge_request(k_pub);
    let from_h = harness.instance("a");
    let to_h = harness.instance("b");
    let header_val = prismoire_server::federation::envelope::sign_outbound(
        &from_h.state.instance_key,
        *to_h.state.instance_key.public_bytes(),
        &Method::POST,
        "/federation/v1/prior-home/challenge",
        &req_body,
    );
    let req = http::Request::builder()
        .method(Method::POST)
        .uri("/federation/v1/prior-home/challenge")
        .header(
            prismoire_server::federation::envelope::AUTH_HEADER,
            header_val,
        )
        .header(
            http::header::CONTENT_TYPE,
            prismoire_server::federation::identity::CBOR_CONTENT_TYPE,
        )
        .body(Bytes::from(req_body))
        .expect("build request");
    let response = from_h
        .transport
        .request(
            &prismoire_server::federation::transport::PeerId::from_bytes(
                *to_h.state.instance_key.public_bytes(),
            ),
            req,
        )
        .await
        .expect("transport dispatch");
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    (status, retry_after)
}

/// Saturate the per-K minute budget at the spec default and confirm the
/// next mint returns 429 with `Retry-After: 60`.
#[tokio::test]
async fn per_key_minute_cap_returns_429_with_retry_after() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    // Lock B's challenge limiter to the spec defaults. The harness
    // default is `u32::MAX` so unrelated tests aren't throttled; this
    // test specifically asserts on the production cap.
    harness
        .instance("b")
        .state
        .prior_home_challenge_rate_limiter
        .set_caps(
            u32::MAX, // per-IP unused under the in-process transport
            PRIOR_HOME_CHALLENGE_RPM_PER_KEY,
        );

    let k_pub: [u8; 32] = *SigningKey::generate(&mut OsRng).verifying_key().as_bytes();

    for i in 0..PRIOR_HOME_CHALLENGE_RPM_PER_KEY {
        let (status, _) = mint_challenge(&harness, &k_pub).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "challenge #{} should admit (cap = {})",
            i + 1,
            PRIOR_HOME_CHALLENGE_RPM_PER_KEY,
        );
    }
    let (status, retry_after) = mint_challenge(&harness, &k_pub).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "challenge #{} must overflow §14.3 per-K minute cap",
        PRIOR_HOME_CHALLENGE_RPM_PER_KEY + 1,
    );
    assert_eq!(
        retry_after.as_deref(),
        Some("60"),
        "429 must carry Retry-After: 60 per §14.3",
    );
}

/// Two distinct K values keep independent per-minute buckets — a K1 that
/// has saturated does not block a fresh K2 mint.
#[tokio::test]
async fn per_key_cap_does_not_cross_subject_keys() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    harness
        .instance("b")
        .state
        .prior_home_challenge_rate_limiter
        .set_caps(u32::MAX, PRIOR_HOME_CHALLENGE_RPM_PER_KEY);

    let k1_pub: [u8; 32] = *SigningKey::generate(&mut OsRng).verifying_key().as_bytes();
    let k2_pub: [u8; 32] = *SigningKey::generate(&mut OsRng).verifying_key().as_bytes();

    for _ in 0..PRIOR_HOME_CHALLENGE_RPM_PER_KEY {
        let (status, _) = mint_challenge(&harness, &k1_pub).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _) = mint_challenge(&harness, &k1_pub).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "K1 saturated");

    let (status, _) = mint_challenge(&harness, &k2_pub).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "fresh K2 must not be blocked by K1's exhausted bucket",
    );
}

/// A 32-byte blob that fails the §14.1 step-1 curve check returns 400
/// `invalid_key` and does NOT burn the per-K counter. After the
/// rejection a *real* K can still draw its full budget.
#[tokio::test]
async fn invalid_key_does_not_consume_per_key_budget() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    // Tight per-K cap so we can prove "1 garbage mint did not eat our
    // only slot."
    harness
        .instance("b")
        .state
        .prior_home_challenge_rate_limiter
        .set_caps(u32::MAX, 1);

    // A 32-byte blob that's not a valid Ed25519 pubkey: encoded y=2
    // (sign=0) has no curve point, so the §14.1 step-1 check collapses
    // to 400 `invalid_key` before the limiter is consulted.
    let mut bad_k = [0u8; 32];
    bad_k[0] = 0x02;
    assert!(
        VerifyingKey::from_bytes(&bad_k).is_err(),
        "test premise broken: {bad_k:?} unexpectedly decodes as a curve point — \
         pick another curve-invalid blob",
    );
    let req_body = encode_challenge_request(&bad_k);
    let (status, _) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/challenge",
        &req_body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "non-curve K must collapse to 400 invalid_key",
    );

    // The garbage attempt did not enter the per-K counter, so a real K
    // with cap=1 still has its full budget.
    let real_k_pub: [u8; 32] = *SigningKey::generate(&mut OsRng).verifying_key().as_bytes();
    let (status, _) = mint_challenge(&harness, &real_k_pub).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real K's first mint should admit; garbage K did not consume budget",
    );
    let (status, _) = mint_challenge(&harness, &real_k_pub).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "real K's second mint overflows at cap=1, confirming garbage K did \
         not steal the only slot",
    );
}

// ===========================================================================
// §14.5 / §14.6 — bulk fetch (content-by-key + inbound-edges-by-key)
// ===========================================================================

/// Build the §14.5 / §14.6 request body
/// `{ challenge, response, [since], [limit] }`.
fn encode_bulk_fetch_body(
    challenge_wire: &[u8],
    response_wire: &[u8],
    since: Option<&[u8]>,
    limit: Option<u32>,
) -> Vec<u8> {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(4);
    entries.push((
        Value::Text("challenge".into()),
        Value::Bytes(challenge_wire.to_vec()),
    ));
    entries.push((
        Value::Text("response".into()),
        Value::Bytes(response_wire.to_vec()),
    ));
    if let Some(s) = since {
        entries.push((Value::Text("since".into()), Value::Bytes(s.to_vec())));
    }
    if let Some(l) = limit {
        entries.push((Value::Text("limit".into()), Value::Integer(l.into())));
    }
    let body = Value::Map(entries);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// Parsed §14.5 / §14.6 page body `{ objects, [next_cursor], complete }`.
struct BulkBody {
    objects: Vec<Vec<u8>>,
    next_cursor: Option<Vec<u8>>,
    complete: bool,
}

fn parse_bulk_body(bytes: &[u8]) -> BulkBody {
    let v: Value = ciborium::de::from_reader(bytes).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("body not a map");
    };
    let mut objects: Option<Vec<Vec<u8>>> = None;
    let mut next_cursor: Option<Vec<u8>> = None;
    let mut complete: Option<bool> = None;
    for (k, v) in m {
        if let Value::Text(t) = &k {
            match (t.as_str(), v) {
                ("objects", Value::Array(arr)) => {
                    let mut out = Vec::with_capacity(arr.len());
                    for entry in arr {
                        let Value::Bytes(b) = entry else {
                            panic!("objects entry must be bstr");
                        };
                        out.push(b);
                    }
                    objects = Some(out);
                }
                ("next_cursor", Value::Bytes(b)) => next_cursor = Some(b),
                ("complete", Value::Bool(b)) => complete = Some(b),
                _ => {}
            }
        }
    }
    BulkBody {
        objects: objects.expect("missing `objects`"),
        next_cursor,
        complete: complete.expect("missing `complete`"),
    }
}

/// content-by-key returns K's outbound trust-edge (K→X) with
/// `complete: true`. Pins the §14.5 outbound-edge join
/// (`trust_edges.source_user == K`).
///
/// Carve-out: this test pins the byte-exact §14.5 emission and an
/// `objects.len() == 1` count over a K that authored *exactly one* object.
/// A real local K would also carry a genesis profile (and any invite
/// edges), and no real handler lets a test choose an edge's canonical
/// bytes — so the seeded edge is the legitimate input and the real handler
/// under test is the content-by-key endpoint driven below.
#[tokio::test]
async fn content_by_key_returns_outbound_edge() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    let k_uid = insert_local_user(&b.state.db, "kara", &k_pub).await;

    let x_key = SigningKey::generate(&mut OsRng);
    let x_pub: [u8; 32] = *x_key.verifying_key().as_bytes();
    let x_uid = insert_local_user(&b.state.db, "xeno", &x_pub).await;

    let edge = seed_signed_edge(
        &b.state.db,
        &k_key,
        &k_uid,
        &x_uid,
        &x_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    )
    .await;

    let (challenge_wire, response_wire) = mint_challenge_and_response(&harness, &k_key).await;
    let body = encode_bulk_fetch_body(&challenge_wire, &response_wire, None, None);
    let (status, resp) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/content-by-key",
        &body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "content-by-key happy path must 200: body={:?}",
        String::from_utf8_lossy(&resp),
    );

    let parsed = parse_bulk_body(&resp);
    assert!(parsed.complete, "single page completes the walk");
    assert!(parsed.next_cursor.is_none());
    assert_eq!(parsed.objects.len(), 1, "exactly K's outbound edge");
    assert_eq!(
        parsed.objects[0],
        encode_wire(&edge.payload, &edge.signature),
        "object[0] must be the signed bytes wrapped as §6.3 WireFormat",
    );
}

/// content-by-key returns a K-authored profile revision. Pins the §14.5
/// profile-author join (`profile_revisions.user_id`).
///
/// Driven through real APIs: K is a live local user, so its §12.8 genesis
/// profile revision (minted by `complete_local_user_birth`) is the only
/// K-authored object on B. content-by-key must surface exactly that
/// profile, and the served bytes must round-trip to the stored
/// `signed_objects` row for K's profile.
#[tokio::test]
async fn content_by_key_returns_profile_revision() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let k_session = setup_admin(&b.router, "kara").await;
    let k_key = extract_user_signing_key(&b.state.db, &k_session.user_id).await;

    // The genesis profile's stored bytes — the §14.5 profile branch joins
    // `profile_revisions.user_id == K` to `signed_objects.canonical_hash`
    // and emits these verbatim, so they are what the served object must equal.
    let (exp_payload, exp_signature) = {
        let row = sqlx::query!(
            "SELECT so.payload AS \"payload!: Vec<u8>\", \
                    so.signature AS \"signature!: Vec<u8>\" \
             FROM profile_revisions pr \
             JOIN signed_objects so ON so.canonical_hash = pr.canonical_hash \
             WHERE pr.user_id = ?",
            k_session.user_id,
        )
        .fetch_one(&b.state.db)
        .await
        .expect("K's genesis profile signed_objects row");
        (row.payload, row.signature)
    };

    let (challenge_wire, response_wire) = mint_challenge_and_response(&harness, &k_key).await;
    let body = encode_bulk_fetch_body(&challenge_wire, &response_wire, None, None);
    let (status, resp) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/content-by-key",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed = parse_bulk_body(&resp);
    assert!(parsed.complete);
    assert_eq!(
        parsed.objects.len(),
        1,
        "a fresh local user authors exactly its genesis profile; got {}",
        parsed.objects.len(),
    );
    let (payload, signature) = decode_wire(&parsed.objects[0]);
    assert_eq!(
        payload, exp_payload,
        "served payload matches stored genesis profile"
    );
    assert_eq!(signature, exp_signature);
}

/// content-by-key omits inbound edges (X→K) — the §14.5 "K-authored
/// only" carve-out keeps §14.5 + §14.6 non-overlapping.
///
/// Carve-out: needs an X→K edge whose canonical bytes the assertion can
/// pin and which must be the *only* inbound edge; the seeded edge is the
/// legitimate input and content-by-key is the real handler under test.
#[tokio::test]
async fn content_by_key_omits_inbound_edges() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    let k_uid = insert_local_user(&b.state.db, "kara", &k_pub).await;

    let x_key = SigningKey::generate(&mut OsRng);
    let x_pub: [u8; 32] = *x_key.verifying_key().as_bytes();
    let x_uid = insert_local_user(&b.state.db, "xeno", &x_pub).await;

    // INBOUND edge: X trusts K. Must NOT appear in content-by-key.
    let _ = seed_signed_edge(
        &b.state.db,
        &x_key,
        &x_uid,
        &k_uid,
        &k_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    )
    .await;

    let (challenge_wire, response_wire) = mint_challenge_and_response(&harness, &k_key).await;
    let body = encode_bulk_fetch_body(&challenge_wire, &response_wire, None, None);
    let (status, resp) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/content-by-key",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed = parse_bulk_body(&resp);
    assert!(parsed.complete);
    assert!(
        parsed.objects.is_empty(),
        "content-by-key must omit inbound edges; got {} objects",
        parsed.objects.len(),
    );
}

/// content-by-key for an unknown K returns `200 OK` with an empty
/// `objects` array and `complete: true` — same carve-out as
/// `/backfill/by-author` for remote-only keys.
#[tokio::test]
async fn content_by_key_unknown_subject_returns_empty_complete() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let k_key = SigningKey::generate(&mut OsRng);

    let (challenge_wire, response_wire) = mint_challenge_and_response(&harness, &k_key).await;
    let body = encode_bulk_fetch_body(&challenge_wire, &response_wire, None, None);
    let (status, resp) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/content-by-key",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed = parse_bulk_body(&resp);
    assert!(parsed.complete);
    assert!(parsed.objects.is_empty());
    assert!(parsed.next_cursor.is_none());
}

/// inbound-edges-by-key returns both inbound edges (X→K, Y→K) with
/// `complete: true`. Pins the §14.6 target-direction join
/// (`trust_edges.target_user == K`).
///
/// Carve-out: pins byte-exact emission *and* a `received_at` ordering
/// (X→K before Y→K) that the assertion depends on; a real handler stamps
/// `received_at = now` for every edge, so the deterministic ordering and
/// canonical bytes can only come from seeded objects. The real handler
/// under test is the inbound-edges-by-key endpoint driven below.
#[tokio::test]
async fn inbound_edges_by_key_returns_two_inbound() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    let k_uid = insert_local_user(&b.state.db, "kara", &k_pub).await;

    let x_key = SigningKey::generate(&mut OsRng);
    let x_pub: [u8; 32] = *x_key.verifying_key().as_bytes();
    let x_uid = insert_local_user(&b.state.db, "xeno", &x_pub).await;

    let y_key = SigningKey::generate(&mut OsRng);
    let y_pub: [u8; 32] = *y_key.verifying_key().as_bytes();
    let y_uid = insert_local_user(&b.state.db, "yarrow", &y_pub).await;

    // X→K at t=...000, Y→K at t=...001 so ordering is deterministic.
    let edge_xk = seed_signed_edge(
        &b.state.db,
        &x_key,
        &x_uid,
        &k_uid,
        &k_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    )
    .await;
    let edge_yk = seed_signed_edge(
        &b.state.db,
        &y_key,
        &y_uid,
        &k_uid,
        &k_pub,
        TrustStance::Trust,
        1_700_000_001_000,
        None,
    )
    .await;

    let (challenge_wire, response_wire) = mint_challenge_and_response(&harness, &k_key).await;
    let body = encode_bulk_fetch_body(&challenge_wire, &response_wire, None, None);
    let (status, resp) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/inbound-edges-by-key",
        &body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "inbound-edges-by-key happy path must 200: body={:?}",
        String::from_utf8_lossy(&resp),
    );

    let parsed = parse_bulk_body(&resp);
    assert!(parsed.complete);
    assert_eq!(parsed.objects.len(), 2, "exactly the two inbound edges");
    // Ordering: trust_edges.created_at ASC, so X→K precedes Y→K.
    assert_eq!(
        parsed.objects[0],
        encode_wire(&edge_xk.payload, &edge_xk.signature)
    );
    assert_eq!(
        parsed.objects[1],
        encode_wire(&edge_yk.payload, &edge_yk.signature)
    );
}

/// inbound-edges-by-key omits K→X (outbound). The §14.6 "target only"
/// carve-out keeps inbound + outbound non-overlapping.
///
/// Carve-out: needs a K→X edge that must be the *only* edge in the fixture
/// so the empty inbound result is unambiguous; the seeded edge is the
/// legitimate input and inbound-edges-by-key is the real handler under test.
#[tokio::test]
async fn inbound_edges_by_key_omits_outbound() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    let k_uid = insert_local_user(&b.state.db, "kara", &k_pub).await;

    let x_key = SigningKey::generate(&mut OsRng);
    let x_pub: [u8; 32] = *x_key.verifying_key().as_bytes();
    let x_uid = insert_local_user(&b.state.db, "xeno", &x_pub).await;

    // OUTBOUND edge: K trusts X. Must NOT appear in inbound-edges-by-key.
    let _ = seed_signed_edge(
        &b.state.db,
        &k_key,
        &k_uid,
        &x_uid,
        &x_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    )
    .await;

    let (challenge_wire, response_wire) = mint_challenge_and_response(&harness, &k_key).await;
    let body = encode_bulk_fetch_body(&challenge_wire, &response_wire, None, None);
    let (status, resp) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/inbound-edges-by-key",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed = parse_bulk_body(&resp);
    assert!(parsed.complete);
    assert!(
        parsed.objects.is_empty(),
        "inbound-edges-by-key must omit outbound; got {} objects",
        parsed.objects.len(),
    );
}

/// With 3 outbound edges and `limit = 2`, page 1 returns 2 objects +
/// cursor + `complete: false`; resuming with the cursor (and a fresh
/// per-page response) returns the third object + `complete: true`.
///
/// Carve-out: the whole point is `(received_at, canonical_hash)` keyset
/// pagination across three strictly-ascending `received_at` values, and a
/// real handler stamps `received_at = now` for every edge — so the
/// deterministic page boundaries can only come from seeded objects with
/// chosen timestamps. content-by-key (with its cursor) is the real handler
/// under test.
#[tokio::test]
async fn content_by_key_paginates() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    let k_uid = insert_local_user(&b.state.db, "kara", &k_pub).await;

    let x1_key = SigningKey::generate(&mut OsRng);
    let x1_pub: [u8; 32] = *x1_key.verifying_key().as_bytes();
    let x1_uid = insert_local_user(&b.state.db, "x1", &x1_pub).await;
    let x2_key = SigningKey::generate(&mut OsRng);
    let x2_pub: [u8; 32] = *x2_key.verifying_key().as_bytes();
    let x2_uid = insert_local_user(&b.state.db, "x2", &x2_pub).await;
    let x3_key = SigningKey::generate(&mut OsRng);
    let x3_pub: [u8; 32] = *x3_key.verifying_key().as_bytes();
    let x3_uid = insert_local_user(&b.state.db, "x3", &x3_pub).await;

    // Strictly-ascending timestamps so the (received_at, canonical_hash)
    // keyset pagination is deterministic.
    let e1 = seed_signed_edge(
        &b.state.db,
        &k_key,
        &k_uid,
        &x1_uid,
        &x1_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    )
    .await;
    let e2 = seed_signed_edge(
        &b.state.db,
        &k_key,
        &k_uid,
        &x2_uid,
        &x2_pub,
        TrustStance::Trust,
        1_700_000_001_000,
        None,
    )
    .await;
    let e3 = seed_signed_edge(
        &b.state.db,
        &k_key,
        &k_uid,
        &x3_uid,
        &x3_pub,
        TrustStance::Trust,
        1_700_000_002_000,
        None,
    )
    .await;

    // Page 1: limit=2 → 2 objects + cursor + complete=false.
    let (challenge_wire, response_wire) = mint_challenge_and_response(&harness, &k_key).await;
    let body = encode_bulk_fetch_body(&challenge_wire, &response_wire, None, Some(2));
    let (status, resp) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/content-by-key",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let page1 = parse_bulk_body(&resp);
    assert!(!page1.complete, "page 1 must have more");
    let cursor = page1.next_cursor.expect("page 1 carries a cursor");
    assert_eq!(page1.objects.len(), 2);
    assert_eq!(page1.objects[0], encode_wire(&e1.payload, &e1.signature));
    assert_eq!(page1.objects[1], encode_wire(&e2.payload, &e2.signature));
    assert!(!cursor.is_empty(), "cursor must carry the page-1 tail row");
    // The on-wire cursor is raw bytes; the server re-encodes to base64
    // internally. Round-trip it through the codec as a smoke check.
    let _ = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cursor);

    // Page 2: same challenge (within TTL) but a fresh response per §14.5.
    let (challenge_payload, _) = decode_wire(&challenge_wire);
    let response2 = mint_response(&k_key, &challenge_payload);
    let body2 = encode_bulk_fetch_body(&challenge_wire, &response2, Some(&cursor), Some(2));
    let (status, resp) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/prior-home/content-by-key",
        &body2,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let page2 = parse_bulk_body(&resp);
    assert!(page2.complete, "page 2 finishes the walk");
    assert!(page2.next_cursor.is_none());
    assert_eq!(page2.objects.len(), 1);
    assert_eq!(page2.objects[0], encode_wire(&e3.payload, &e3.signature));
}

// ===========================================================================
// §13.3 step-1 — prior-home discovery (declared / local-lookup / fan-out)
// ===========================================================================

/// Insert a user row for K with `home_instance` set, simulating a peer
/// that *was* K's home but K has since moved out. The §14.2 probe
/// handler filters on `home_instance IS NULL`, so this row answers
/// `has_activity = false`.
async fn insert_moved_out_user(
    db: &SqlitePool,
    display_name: &str,
    pubkey: &[u8; 32],
    new_home_pubkey: &[u8; 32],
) -> String {
    let id = Uuid::new_v4().to_string();
    let skeleton = display_name.to_lowercase();
    let pubkey_slice: &[u8] = pubkey.as_slice();
    let new_home_slice: &[u8] = new_home_pubkey.as_slice();
    sqlx::query!(
        "INSERT INTO users \
            (id, display_name, signup_method, public_key, display_name_skeleton, home_instance) \
         VALUES (?, ?, 'admin', ?, ?, ?)",
        id,
        display_name,
        pubkey_slice,
        skeleton,
        new_home_slice,
    )
    .execute(db)
    .await
    .expect("insert moved-out user");
    id
}

/// Insert a `signup_method = 'federated'` stub with `home_instance =
/// home_pubkey`. Phase 9.5 hydration produces rows in this shape; the
/// §13.3 strategy-2 lookup in `discover_prior_home` keys on this column.
async fn insert_federated_stub_with_home(
    db: &SqlitePool,
    display_name: &str,
    pubkey: &[u8; 32],
    home_pubkey: &[u8; 32],
) -> String {
    let id = Uuid::new_v4().to_string();
    let skeleton = display_name.to_lowercase();
    let pubkey_slice: &[u8] = pubkey.as_slice();
    let home_slice: &[u8] = home_pubkey.as_slice();
    sqlx::query!(
        "INSERT INTO users \
            (id, display_name, signup_method, public_key, display_name_skeleton, home_instance) \
         VALUES (?, ?, 'federated', ?, ?, ?)",
        id,
        display_name,
        pubkey_slice,
        skeleton,
        home_slice,
    )
    .execute(db)
    .await
    .expect("insert federated stub");
    id
}

/// Strategy-1 happy path: D declares B as the prior home, B holds K (and
/// so does C). `discover_prior_home` surfaces B — the declared-peer
/// short-circuit wins over the fan-out alternative.
///
/// Carve-out: the scenario requires the *same* key K to be a live local
/// (non-federated, `home_instance IS NULL`) user on B *and* C at once.
/// Local signup mints a fresh server-side keypair per instance, so a
/// single shared K cannot be born locally on both via real APIs; the
/// seeded local users are the legitimate input and discover_prior_home is
/// the function under test.
#[tokio::test]
async fn declared_hit_surfaces_declared_peer() {
    let harness = MultiInstanceHarness::new(3).await; // D=a, B=b, C=c
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    let b = harness.instance("b");
    let c = harness.instance("c");
    insert_local_user(&b.state.db, "kara", &k_pub).await;
    insert_local_user(&c.state.db, "kara", &k_pub).await;

    let d = harness.instance("a");
    let hit = discover_prior_home(&d.state, &k_pub, &k_key, Some(&b.state.instance_domain)).await;
    let (hit_key, hit_domain) = hit.expect("declared hit must surface");
    assert_eq!(
        hit_key,
        *b.state.instance_key.public_bytes(),
        "declared peer (B) must win, not the fan-out alt (C)",
    );
    assert_eq!(hit_domain, b.state.instance_domain);
}

/// Strategy-1 authoritative miss: declared peer B answers
/// `has_activity = false`. Even though C holds K, `discover_prior_home`
/// must NOT surface C — B's "no" is authoritative.
#[tokio::test]
async fn declared_authoritative_miss_is_terminal() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    // K is NOT on B (B answers false) but IS a live local user on C.
    let c = harness.instance("c");
    let k_session = setup_admin(&c.router, "kara").await;
    let k_key = extract_user_signing_key(&c.state.db, &k_session.user_id).await;
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    let d = harness.instance("a");
    let b = harness.instance("b");
    let hit = discover_prior_home(&d.state, &k_pub, &k_key, Some(&b.state.instance_domain)).await;
    assert!(
        hit.is_none(),
        "declared authoritative miss must terminate, even if another peer holds K",
    );
}

/// Strategy-1 unreachable peer falls through to fan-out. D declares B,
/// but B is disconnected from the transport before the probe runs, so
/// the probe errors (Unreachable) rather than answering false. C holds K
/// and is reachable; fan-out surfaces C.
#[tokio::test]
async fn declared_unreachable_falls_through_to_fanout() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    let c = harness.instance("c");
    let k_session = setup_admin(&c.router, "kara").await;
    let k_key = extract_user_signing_key(&c.state.db, &k_session.user_id).await;
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    let b_domain = harness.instance("b").state.instance_domain.clone();
    harness.disconnect("b").await;

    let d = harness.instance("a");
    let hit = discover_prior_home(&d.state, &k_pub, &k_key, Some(&b_domain)).await;
    let (hit_key, hit_domain) = hit.expect("fan-out must locate K on C after B is unreachable");
    assert_eq!(
        hit_key,
        *c.state.instance_key.public_bytes(),
        "unreachable declared peer (B) must not block surfacing C",
    );
    assert_eq!(hit_domain, c.state.instance_domain);
}

/// Strategy-1 unknown domain falls through to fan-out. The declared
/// domain isn't in D's `peers` table, so `resolve_peer_by_domain`
/// returns `Ok(None)` and discovery falls through to strategy 3, which
/// surfaces the K-holder C. Also covers the bare strategy-3 fan-out hit.
#[tokio::test]
async fn declared_unknown_domain_falls_through_to_fanout() {
    // D="a", C="b". The declared domain is never registered as a peer.
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let c = harness.instance("b");
    let k_session = setup_admin(&c.router, "kara").await;
    let k_key = extract_user_signing_key(&c.state.db, &k_session.user_id).await;
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    let d = harness.instance("a");
    let hit = discover_prior_home(&d.state, &k_pub, &k_key, Some("ghost.example.invalid")).await;
    let (hit_key, _) = hit.expect("fan-out must run when declared domain isn't peered");
    assert_eq!(hit_key, *c.state.instance_key.public_bytes());
}

/// Strategy-2 happy path: D holds a Phase-9.5 federated stub for K with
/// `home_instance = pubkey(B)`. With no declared domain,
/// `discover_prior_home` probes B and finds K via the
/// `users.home_instance` shortcut.
#[tokio::test]
async fn local_lookup_uses_home_instance_pointer() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    // K is a live local user on B only — the strategy must steer the probe
    // at B. The §13.3 strategy-2 input is the Phase-9.5 federated stub on
    // D (`users.home_instance = pubkey(B)`); driving the hydration pipeline
    // that mints that stub is out of scope here, so it is the one seeded
    // input. K itself, and B's `has_activity` answer, are fully real.
    let b = harness.instance("b");
    let k_session = setup_admin(&b.router, "kara").await;
    let k_key = extract_user_signing_key(&b.state.db, &k_session.user_id).await;
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    let d = harness.instance("a");
    insert_federated_stub_with_home(
        &d.state.db,
        "kara",
        &k_pub,
        b.state.instance_key.public_bytes(),
    )
    .await;

    let hit = discover_prior_home(&d.state, &k_pub, &k_key, None).await;
    let (hit_key, _) = hit.expect("local home_instance lookup must succeed");
    assert_eq!(hit_key, *b.state.instance_key.public_bytes());
}

/// Fan-out cap: with `PRIOR_HOME_PROBE_FANOUT_MAX + 2` active peers but
/// the K-holder forced to sort *past* the cap (oldest `last_handshake`
/// under `ORDER BY ... DESC`), `discover_prior_home` returns `None`.
#[tokio::test]
async fn fanout_respects_cap() {
    // 1 registering (D) + (cap + 2) candidates.
    let n_candidates = PRIOR_HOME_PROBE_FANOUT_MAX + 2;
    let harness = MultiInstanceHarness::new(1 + n_candidates).await;

    for i in 0..n_candidates {
        let label = char::from(b'b' + i as u8).to_string();
        establish_active_peering(&harness, "a", &label).await;
    }

    // Place K as a live local user on a candidate beyond the cap, then
    // force that candidate to sort last (the `UPDATE peers` below is
    // deterministic-ordering control over D's own peer table, not a
    // fabricated K precondition).
    let holder_label = char::from(b'b' + (n_candidates - 1) as u8).to_string();
    let holder = harness.instance(&holder_label);
    let k_session = setup_admin(&holder.router, "kara").await;
    let k_key = extract_user_signing_key(&holder.state.db, &k_session.user_id).await;
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // holder = OLDEST, everyone else = NEWEST. ORDER BY DESC visits
    // non-holders first; the holder lands beyond the cap.
    let d = harness.instance("a");
    let holder_pubkey: &[u8] = holder.state.instance_key.public_bytes().as_slice();
    sqlx::query!(
        "UPDATE peers SET last_handshake = '2000-01-01T00:00:00Z' \
         WHERE instance_pubkey = ?",
        holder_pubkey,
    )
    .execute(&d.state.db)
    .await
    .expect("UPDATE holder last_handshake");
    sqlx::query!(
        "UPDATE peers SET last_handshake = '2030-01-01T00:00:00Z' \
         WHERE instance_pubkey != ?",
        holder_pubkey,
    )
    .execute(&d.state.db)
    .await
    .expect("UPDATE non-holder last_handshake");

    // Sanity-check the ordering assumption before probing.
    let limit = PRIOR_HOME_PROBE_FANOUT_MAX as i64;
    let head: Vec<Vec<u8>> = sqlx::query_scalar!(
        "SELECT instance_pubkey AS \"instance_pubkey!: Vec<u8>\" \
         FROM peers WHERE status = 'active' \
         ORDER BY COALESCE(last_handshake, first_seen) DESC \
         LIMIT ?",
        limit,
    )
    .fetch_all(&d.state.db)
    .await
    .expect("SELECT head of peers fan-out");
    assert!(
        !head.iter().any(|p| p.as_slice() == holder_pubkey),
        "test mis-set-up: holder leaked into the first {} peers",
        PRIOR_HOME_PROBE_FANOUT_MAX,
    );

    let hit = discover_prior_home(&d.state, &k_pub, &k_key, None).await;
    assert!(
        hit.is_none(),
        "K-holder past the fan-out cap must NOT be surfaced \
         (cap = {}, candidates = {})",
        PRIOR_HOME_PROBE_FANOUT_MAX,
        n_candidates,
    );
}

/// A peer that used to hold K but has since seen K move out
/// (`home_instance` set) answers `has_activity = false`, so
/// `discover_prior_home` must not surface it even as the sole candidate.
///
/// Carve-out: the input is a *local* row (`signup_method != 'federated'`)
/// whose `home_instance` is set — the post-move shape. Producing it would
/// mean driving a full §12 move ceremony, out of scope here; the seeded
/// moved-out row is the legitimate input and discover_prior_home is the
/// function under test.
#[tokio::test]
async fn stale_home_is_not_surfaced() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // B has a row for K but K moved out — home_instance points elsewhere
    // (a synthetic placeholder; the probe only checks IS NULL).
    let b = harness.instance("b");
    let elsewhere_key: [u8; 32] = [0x77; 32];
    insert_moved_out_user(&b.state.db, "kara", &k_pub, &elsewhere_key).await;

    let d = harness.instance("a");
    let hit = discover_prior_home(&d.state, &k_pub, &k_key, None).await;
    assert!(
        hit.is_none(),
        "moved-out peer must answer has_activity=false; \
         discover_prior_home must not surface it",
    );
}

// ===========================================================================
// §14.5 / §14.6 / §14.7 step-4 — post-move data recovery (drive_recovery)
// ===========================================================================

/// Count `signed_objects` rows matching `hash`. Recovery is best-effort
/// and additive, so the success signal is "the bytes are now on D".
async fn count_signed_object(db: &SqlitePool, hash: &[u8; 32]) -> i64 {
    let hash_slice: &[u8] = hash.as_slice();
    sqlx::query_scalar!(
        "SELECT COUNT(*) FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(db)
    .await
    .expect("count signed_objects")
}

/// Primary happy path: D=a, A=b (prior home). A holds one K-authored
/// outbound edge (K→X, §14.5) and one inbound edge (X→K, §14.6).
/// `drive_recovery` walks both surfaces, reaches `complete: true` on
/// each, and the bytes land in D's `signed_objects`.
///
/// Carve-out: the success signal is "these specific canonical hashes
/// landed on D", which requires byte-controlled edges on A; the seeded
/// edges are the legitimate input and `drive_recovery` is the function
/// under test.
#[tokio::test]
async fn primary_path_recovers_content_and_inbound_edges() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let d = harness.instance("a");
    let a = harness.instance("b");

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    let k_uid = insert_local_user(&a.state.db, "kara", &k_pub).await;

    let x_key = SigningKey::generate(&mut OsRng);
    let x_pub: [u8; 32] = *x_key.verifying_key().as_bytes();
    let x_uid = insert_local_user(&a.state.db, "xeno", &x_pub).await;

    let edge_kx = seed_signed_edge(
        &a.state.db,
        &k_key,
        &k_uid,
        &x_uid,
        &x_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    )
    .await;
    let edge_xk = seed_signed_edge(
        &a.state.db,
        &x_key,
        &x_uid,
        &k_uid,
        &k_pub,
        TrustStance::Trust,
        1_700_000_001_000,
        None,
    )
    .await;

    let confirmed = Some((
        *a.state.instance_key.public_bytes(),
        a.state.instance_domain.clone(),
    ));
    let stats: RecoveryStats =
        drive_recovery(d.state.clone(), k_pub, k_key.clone(), confirmed).await;

    assert!(stats.primary_attempted, "confirmed peer was Some");
    assert!(
        stats.primary_complete,
        "both §14.5 + §14.6 should reach complete:true on a 1-row surface; stats={stats:?}",
    );
    assert!(
        !stats.fallback_attempted,
        "fallback must skip when primary completed; stats={stats:?}",
    );
    assert!(
        stats.objects_seen >= 2,
        "at least the K→X content + X→K edge bytes were piped through ingest; stats={stats:?}",
    );

    assert_eq!(
        count_signed_object(&d.state.db, &edge_kx.canonical_hash).await,
        1,
        "K→X (§14.5) should have landed on D",
    );
    assert_eq!(
        count_signed_object(&d.state.db, &edge_xk.canonical_hash).await,
        1,
        "X→K (§14.6) should have landed on D",
    );
}

/// A-offline fallback: D=a, A=b, peer=c. A is disconnected before
/// recovery, so the §14.5 / §14.6 calls fail at transport. C holds an
/// X→K edge served by the §10.5.1 `edges-by-key?direction=both` route.
/// Recovery surfaces those bytes on D and reports
/// `primary_attempted && !primary_complete && fallback_attempted`.
///
/// Carve-out: asserts a specific X→K canonical hash landed on D via the
/// §10.5.1 fallback route; that requires a byte-controlled edge on peer C,
/// so the seeded edge is the legitimate input and `drive_recovery` is the
/// function under test.
#[tokio::test]
async fn fallback_recovers_from_peer_when_prior_home_offline() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    // K and X both have rows on C — §10.5.1 resolves `key` against C's
    // `users` table before walking trust_edges.
    let c = harness.instance("c");
    let k_uid = insert_local_user(&c.state.db, "kara", &k_pub).await;
    let x_key = SigningKey::generate(&mut OsRng);
    let x_pub: [u8; 32] = *x_key.verifying_key().as_bytes();
    let x_uid = insert_local_user(&c.state.db, "xeno", &x_pub).await;
    let edge_xk = seed_signed_edge(
        &c.state.db,
        &x_key,
        &x_uid,
        &k_uid,
        &k_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    )
    .await;

    // Snapshot A's identity before disconnecting so recovery still
    // believes A is the confirmed prior home.
    let a = harness.instance("b");
    let a_key = *a.state.instance_key.public_bytes();
    let a_domain = a.state.instance_domain.clone();
    harness.disconnect("b").await;

    let d = harness.instance("a");
    let stats: RecoveryStats = drive_recovery(
        d.state.clone(),
        k_pub,
        k_key.clone(),
        Some((a_key, a_domain)),
    )
    .await;

    assert!(stats.primary_attempted);
    assert!(
        !stats.primary_complete,
        "A is disconnected; §14.5/§14.6 calls must fail at transport; stats={stats:?}",
    );
    assert!(
        stats.fallback_attempted,
        "primary incomplete must trigger fallback; stats={stats:?}",
    );
    assert!(
        stats.objects_seen >= 1,
        "fallback should pipe at least the X→K bytes through ingest; stats={stats:?}",
    );
    assert_eq!(
        count_signed_object(&d.state.db, &edge_xk.canonical_hash).await,
        1,
        "X→K (§10.5.1 edges-by-key) should have landed on D via peer C",
    );
}

/// Zero-active-peers: D=a stands up alone with no peering and no
/// confirmed prior home. Primary is skipped; the fallback runs but
/// `list_active_peers` is empty, so it reports
/// `fallback_attempted = true && fallback_complete = false` (operators
/// see `best_effort_incomplete`, not "all swept peers completed").
#[tokio::test]
async fn fallback_with_zero_active_peers_reports_incomplete() {
    let harness = MultiInstanceHarness::new(1).await;
    let d = harness.instance("a");

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    let stats: RecoveryStats = drive_recovery(d.state.clone(), k_pub, k_key, None).await;

    assert!(!stats.primary_attempted, "no confirmed peer was provided");
    assert!(
        stats.fallback_attempted,
        "fallback always runs when primary didn't complete"
    );
    assert!(
        !stats.fallback_complete,
        "zero active peers must NOT be reported as 'all peers swept complete'; stats={stats:?}",
    );
    assert_eq!(stats.objects_seen, 0);
}

/// best_effort_incomplete telemetry: D=a, A=b, peer=c. BOTH A and the
/// only peer C are disconnected before recovery, so neither surface can
/// produce bytes. `drive_recovery` still returns (best-effort posture)
/// but the stats reflect
/// `primary_attempted && !primary_complete && fallback_attempted &&
/// !fallback_complete` — the `recovery: best_effort_incomplete` combo.
#[tokio::test]
async fn best_effort_incomplete_when_neither_layer_completes() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();

    let a = harness.instance("b");
    let a_key = *a.state.instance_key.public_bytes();
    let a_domain = a.state.instance_domain.clone();
    harness.disconnect("b").await;
    harness.disconnect("c").await;

    let d = harness.instance("a");
    let stats: RecoveryStats =
        drive_recovery(d.state.clone(), k_pub, k_key, Some((a_key, a_domain))).await;

    assert!(stats.primary_attempted);
    assert!(!stats.primary_complete);
    assert!(stats.fallback_attempted);
    assert!(
        !stats.fallback_complete,
        "C disconnected → §10.5.1 GET fails → fallback_all_complete=false; stats={stats:?}",
    );
    let primary_ok = stats.primary_attempted && stats.primary_complete;
    let fallback_ok = stats.fallback_attempted && stats.fallback_complete;
    assert!(
        !(primary_ok || fallback_ok),
        "neither layer succeeded → recovery: best_effort_incomplete; stats={stats:?}",
    );
}
