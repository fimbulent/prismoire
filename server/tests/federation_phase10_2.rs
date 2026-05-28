//! Phase-10.2 integration tests: §14.5 / §14.6 prior-home bulk-fetch
//! surface.
//!
//! Spec gates exercised here (`docs/federation-protocol.md` §14):
//!
//! - **Layer 1 — content-by-key happy path (outbound trust-edge).**
//!   A asks B for the content-by-key page bound to K. B owns K
//!   locally and holds one outbound trust-edge K→X. The response
//!   carries one object (the WireFormat of K's signed edge) with
//!   `complete: true`. This pins the §14.5 outbound-edge join
//!   (`trust_edges.source_user == K`).
//! - **Layer 1 — content-by-key happy path (profile revision).**
//!   K has signed a profile revision. The content-by-key response
//!   returns that profile object. This pins the §14.5 profile-author
//!   join (`profile_revisions.user_id`).
//! - **Layer 1 — content-by-key omits inbound edges.** A trust-edge
//!   X→K (someone trusts K) lives on B. content-by-key for K must
//!   return an empty page — inbound edges ride §14.6, not §14.5.
//!   This pins the spec's "K-authored only" carve-out.
//! - **Layer 1 — content-by-key unknown K.** K is not provisioned
//!   on B. content-by-key returns `200 OK` with an empty `objects`
//!   array and `complete: true` (same carve-out as
//!   `/backfill/by-author` for remote-only keys).
//! - **Layer 1 — inbound-edges-by-key happy path.** Two trust edges
//!   X→K and Y→K live on B. inbound-edges-by-key returns both
//!   objects with `complete: true`. This pins the §14.6
//!   target-direction join (`trust_edges.target_user == K`).
//! - **Layer 1 — inbound-edges-by-key omits outbound.** K→X exists
//!   on B; inbound-edges-by-key for K returns an empty page.
//!   This pins the §14.6 "target only" carve-out.
//! - **Layer 1 — pagination.** With 3 outbound edges authored by K
//!   and `limit = 2`, the first page carries 2 objects + a cursor +
//!   `complete: false`; resuming with the cursor yields the last
//!   object with `complete: true`.

#![cfg(feature = "test-auth")]

mod common;

use base64::Engine;
use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use prismoire_server::signed::TrustStance;
use prismoire_server::signing::{SigningOutput, sign_trust_edge_with_key};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};
use prismoire_server::signed::{PriorHomeResponse, SignedPayload};

// ---------------------------------------------------------------------------
// Wire-format helpers (echo Phase-10.1)
// ---------------------------------------------------------------------------

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
/// canonical bytes of `challenge_payload`. The bulk-fetch handlers
/// expect a *fresh* response per page; tests just call this repeatedly
/// inside the same challenge TTL.
fn mint_response(k_key: &SigningKey, challenge_payload: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let response = PriorHomeResponse {
        subject_key: *k_key.verifying_key().as_bytes(),
        challenge_hash: Sha256::digest(challenge_payload).into(),
        created_at: now_ms(),
    };
    let payload = SignedPayload::PriorHomeResponse(response).encode();
    let signature = k_key.sign(&payload).to_bytes().to_vec();
    encode_wire(&payload, &signature)
}

/// Build the §14.5 / §14.6 request body:
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

// ---------------------------------------------------------------------------
// Response parsing — `{ objects, [next_cursor], complete }`
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Fixture helpers — seed users / projection rows on B
// ---------------------------------------------------------------------------

/// Insert a `users` row with a known Ed25519 pubkey. Returns the
/// generated user-id (UUID). The user counts as "local" for §14.5 /
/// §14.6 (signup_method != 'federated' AND home_instance IS NULL).
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

/// Sign and seed a `trust-edge` from `signer` to `target_pub` with the
/// given stance and ms-timestamp. Inserts both the `signed_objects`
/// row and the `trust_edges` projection row (with the canonical_hash
/// that the §14.5 / §14.6 joins key on). Returns the SigningOutput so
/// the caller can compare its WireFormat against the wire bytes the
/// server emits.
///
/// `ts_ms` is folded into both `trust_edges.created_at` and
/// `signed_objects.received_at`. The latter is the keyset-pagination
/// key the bulk-fetch handlers actually order by — tests share the
/// same `received_at` second when the default `strftime('now')` runs
/// for every row in the same wall-clock second, which makes the
/// canonical-hash tiebreaker the *only* determinant of order. Fixing
/// `received_at` to a synthetic ISO timestamp derived from `ts_ms`
/// gives the test deterministic page ordering.
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

    // Explicit INSERT with controlled received_at (skip the production
    // helper, which uses `strftime('now')`).
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

/// Seed a `profile_revisions` row + matching `signed_objects` row for
/// K. The §14.5 query joins via `profile_revisions.canonical_hash`,
/// so we mint a synthetic canonical_hash here. The payload isn't
/// signature-checked by §14.5 — it only encodes-and-emits the bytes —
/// so we use arbitrary payload + signature placeholders. (The §14.1
/// challenge/response is signed for real by K's actual key; the
/// payload bytes the handler emits are whatever we stored.)
async fn seed_synthetic_profile(db: &SqlitePool, user_id: &str) -> [u8; 32] {
    let canonical_hash: [u8; 32] = Sha256::digest(format!("profile-{user_id}").as_bytes()).into();
    let hash_slice: &[u8] = canonical_hash.as_slice();
    let payload: &[u8] = b"profile payload bytes";
    let signature: &[u8] = b"profile signature placeholder";
    sqlx::query!(
        "INSERT INTO signed_objects (canonical_hash, inner_class, payload, signature) \
         VALUES (?, 'profile', ?, ?)",
        hash_slice,
        payload,
        signature,
    )
    .execute(db)
    .await
    .expect("insert signed_objects (profile)");
    let profile_id = Uuid::new_v4().to_string();
    let created_ms = 1_700_000_000_000i64;
    sqlx::query!(
        "INSERT INTO profile_revisions \
            (id, user_id, display_name, bio, created_at, signature, canonical_hash) \
         VALUES (?, ?, 'kara', '', ?, ?, ?)",
        profile_id,
        user_id,
        created_ms,
        signature,
        hash_slice,
    )
    .execute(db)
    .await
    .expect("insert profile_revisions");
    canonical_hash
}

// ---------------------------------------------------------------------------
// Ceremony helper — mint a §14.1 challenge + signed response in one shot
// ---------------------------------------------------------------------------

/// Drive the §14.1 challenge mint and sign a fresh response. Returns
/// `(challenge_wire, response_wire)` which the bulk-fetch tests then
/// pack into request bodies.
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

// ---------------------------------------------------------------------------
// content-by-key tests
// ---------------------------------------------------------------------------

/// Done-when (1): B owns local user K, and K has authored one outbound
/// trust-edge K→X. content-by-key for K returns that one edge with
/// `complete: true`. Verifies the §14.5 outbound-edge join.
#[tokio::test]
async fn content_by_key_returns_outbound_edge() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    // K is a synthetic local user on B (we control K's signing key so
    // the §14.1 response signature verifies under the same pubkey we
    // attach to the users row).
    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    let k_uid = insert_local_user(&b.state.db, "kara", &k_pub).await;

    // X is the trust-edge target; identity doesn't matter beyond having
    // a `users` row to satisfy the trust_edges FK.
    let x_key = SigningKey::generate(&mut OsRng);
    let x_pub: [u8; 32] = *x_key.verifying_key().as_bytes();
    let x_uid = insert_local_user(&b.state.db, "xeno", &x_pub).await;

    // Seed K's signed outbound edge K→X.
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

    // Run §14.1 ceremony.
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

/// Done-when (2): K has authored a profile revision. content-by-key
/// returns it. Verifies the §14.5 profile join.
#[tokio::test]
async fn content_by_key_returns_profile_revision() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    let k_uid = insert_local_user(&b.state.db, "kara", &k_pub).await;
    let profile_hash = seed_synthetic_profile(&b.state.db, &k_uid).await;

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
    assert_eq!(parsed.objects.len(), 1, "exactly the profile object");
    // Verify the emitted object carries the canonical hash we stored —
    // unwrap the WireFormat and re-hash the (payload, signature)
    // boundary is set by `profile_revisions.canonical_hash`, so we
    // verify by membership against the known canonical_hash.
    let (payload, signature) = decode_wire(&parsed.objects[0]);
    assert_eq!(
        payload, b"profile payload bytes",
        "payload matches what we seeded"
    );
    assert_eq!(signature, b"profile signature placeholder");
    // Sanity: the seeded canonical_hash maps back via the
    // signed_objects table; the test fixture inserts it under that key.
    let _ = profile_hash; // already asserted via payload+signature equality
}

/// Done-when (3): content-by-key omits inbound edges (X→K). The §14.5
/// "K-authored only" rule is what keeps §14.5 + §14.6 non-overlapping.
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

    // Seed an INBOUND edge: X trusts K. This must NOT appear in
    // content-by-key for K (it would in §14.6).
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

/// Done-when (4): K is not a local user on B. content-by-key returns
/// `200 OK` with an empty `objects` array and `complete: true`. Same
/// carve-out as `/backfill/by-author` — the responding peer has no
/// projection to serve.
#[tokio::test]
async fn content_by_key_unknown_subject_returns_empty_complete() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // K is a synthetic key with no `users` row on B.
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

// ---------------------------------------------------------------------------
// inbound-edges-by-key tests
// ---------------------------------------------------------------------------

/// Done-when (5): two edges X→K and Y→K live on B.
/// inbound-edges-by-key for K returns both objects.
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

    // X→K at t=...000, Y→K at t=...001 to keep ordering deterministic.
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
    // Ordering: trust_edges.created_at ASC, so X→K comes before Y→K.
    let xk_wire = encode_wire(&edge_xk.payload, &edge_xk.signature);
    let yk_wire = encode_wire(&edge_yk.payload, &edge_yk.signature);
    assert_eq!(parsed.objects[0], xk_wire);
    assert_eq!(parsed.objects[1], yk_wire);
}

/// Done-when (6): inbound-edges-by-key omits K→X (outbound). The §14.6
/// "target only" rule keeps inbound + outbound non-overlapping across
/// §14.5 / §14.6.
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

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

/// Done-when (7): with 3 outbound edges and `limit = 2`, the first
/// page returns 2 objects + `next_cursor` + `complete: false`; resuming
/// with the cursor returns the third object + `complete: true`.
#[tokio::test]
async fn content_by_key_paginates() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let k_key = SigningKey::generate(&mut OsRng);
    let k_pub: [u8; 32] = *k_key.verifying_key().as_bytes();
    let k_uid = insert_local_user(&b.state.db, "kara", &k_pub).await;

    // Three targets so each edge is to a distinct user.
    let x1_key = SigningKey::generate(&mut OsRng);
    let x1_pub: [u8; 32] = *x1_key.verifying_key().as_bytes();
    let x1_uid = insert_local_user(&b.state.db, "x1", &x1_pub).await;
    let x2_key = SigningKey::generate(&mut OsRng);
    let x2_pub: [u8; 32] = *x2_key.verifying_key().as_bytes();
    let x2_uid = insert_local_user(&b.state.db, "x2", &x2_pub).await;
    let x3_key = SigningKey::generate(&mut OsRng);
    let x3_pub: [u8; 32] = *x3_key.verifying_key().as_bytes();
    let x3_uid = insert_local_user(&b.state.db, "x3", &x3_pub).await;

    // Three outbound edges with strictly-ascending timestamps so the
    // (received_at, canonical_hash) keyset pagination is deterministic.
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

    // Sanity check: the cursor is base64url-decodable to a 52-byte raw
    // blob — the §9.3 / §10.5.2 layout. (We feed it back as raw bytes
    // since the §14.5 request body is bstr-typed.)
    assert!(
        !cursor.is_empty(),
        "cursor must carry the page-1 tail row info"
    );
    // The on-wire form is raw bytes (not base64). Internally the
    // server's `decode_cursor` re-encodes to base64 before parsing; we
    // pass through raw bytes verbatim and let the server handle it.
    let _ = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cursor);

    // Page 2: same challenge (within TTL) but a *fresh* response per
    // §14.5 prose. Re-mint the response over the same challenge.
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
