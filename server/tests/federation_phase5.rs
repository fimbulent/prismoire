//! Phase-5 Layer-1 integration tests: §9 edge propagation push.
//!
//! Pins Task #15's done-when criteria from
//! `docs/federation-impl-plan.md`:
//!
//! - `POST /federation/v1/edges` accepts a §9.1 body from an active
//!   peer and (when both endpoints are local users) projects the
//!   incoming signed trust-edge into `trust_edges`.
//! - Same bytes replayed return `duplicate` for every edge in the
//!   batch.
//! - A WireFormat that decodes but whose Ed25519 signature is bad
//!   surfaces as `rejected/invalid_signature` — and is not persisted.
//! - Request-level failure modes — malformed body, empty batch,
//!   batch_too_large — produce a 400 with a single `{ "error": ... }`
//!   body (no per-edge results array).
//!
//! Task #16 adds the 3-instance multi-hop (A → B → C) scenario:
//! the forwarder behind §7.5 now exists, so an edge A pushes to B
//! gets re-emitted to C whenever C's `edge_origin_filter` says C is
//! interested. See [`forwarder_relays_applied_edge_to_interested_peer`]
//! below.
//!
//! Layer-0 invariants (decoder rejects non-bstr elements, response
//! tags match the spec) live in the in-module `#[cfg(test)]` block in
//! `src/federation/edges.rs`. The two layers split along the usual
//! "in-process state machine" / "end-to-end through the router"
//! seam.

#![cfg(feature = "test-auth")]

mod common;

use axum::body::Bytes;
use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use prismoire_server::federation::bloom::BloomFilter;
use prismoire_server::federation::edges::MAX_EDGE_BATCH;
use prismoire_server::federation::envelope;
use prismoire_server::federation::frontier::{FilterSpec, FrontierAnnounce};
use prismoire_server::signed::TrustStance;
use prismoire_server::signing::sign_trust_edge_with_key;
use rand::rngs::OsRng;
use sqlx::SqlitePool;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};

/// Push body builder: wrap each `(payload, signature)` pair into a
/// canonical WireFormat blob and pack the lot under `{ "edges": [bstr, ...] }`.
fn encode_edges_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("edges".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + wires.iter().map(|w| w.len()).sum::<usize>());
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// Encode a §6.3 WireFormat `{ "p", "s" }`. Mirrors the in-module
/// `envelope::encode_signed_object` helper without exposing it as
/// `pub`-on-the-wire: tests build wire bytes the same way senders do.
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

/// Decode `{ "results": [{ canonical_hash, status, reason? }, ...] }`
/// into a flat vector of `(canonical_hash, status, reason)`.
fn parse_results_body(body: &[u8]) -> Vec<([u8; 32], String, Option<String>)> {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("results body is not a map");
    };
    let Some(results) = m.into_iter().find_map(|(k, v)| match k {
        Value::Text(t) if t == "results" => Some(v),
        _ => None,
    }) else {
        panic!("missing `results` field");
    };
    let Value::Array(arr) = results else {
        panic!("`results` is not an array");
    };
    arr.into_iter()
        .map(|entry| {
            let Value::Map(fields) = entry else {
                panic!("result entry not a map");
            };
            let mut hash: Option<[u8; 32]> = None;
            let mut status: Option<String> = None;
            let mut reason: Option<String> = None;
            for (k, v) in fields {
                if let Value::Text(name) = k {
                    match (name.as_str(), v) {
                        ("canonical_hash", Value::Bytes(b)) => {
                            hash = Some(b.as_slice().try_into().expect("32 bytes"));
                        }
                        ("status", Value::Text(s)) => status = Some(s),
                        ("reason", Value::Text(s)) => reason = Some(s),
                        _ => {}
                    }
                }
            }
            (hash.expect("hash"), status.expect("status"), reason)
        })
        .collect()
}

/// Pull the `error` field from a request-level 400 body.
fn parse_error_body(body: &[u8]) -> String {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("error body is not a map");
    };
    for (k, v) in m {
        if let (Value::Text(t), Value::Text(s)) = (&k, v)
            && t == "error"
        {
            return s;
        }
    }
    panic!("missing `error` field");
}

/// Insert a `users` row with a known Ed25519 public key on the
/// receiver, so an inbound edge naming that key as an endpoint
/// projects into `trust_edges`. Mirrors the minimum-columns INSERT
/// the signup path uses for the non-PII fixture.
async fn insert_user_with_pubkey(db: &SqlitePool, id: &str, display_name: &str, pubkey: &[u8; 32]) {
    let pubkey_slice: &[u8] = pubkey.as_slice();
    let skeleton = display_name.to_lowercase();
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
}

/// Done-when (Task #15): a single push from active-peer A reaches B,
/// the canonical bytes land in `signed_objects`, the projection lands
/// in `trust_edges`, and the response carries `applied`.
#[tokio::test]
async fn push_applies_signed_edge_into_local_projection() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    // Fixture: B knows two local users whose public keys match the
    // signed edge's `from_key` / `to_key`. The signer of the trust
    // edge is the source user — its private key never lives in B's
    // signing_keys table (it's a hypothetical remote user we're
    // standing in for).
    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;

    // Sign a trust edge alice -> bob and push it from A to B.
    let signed = sign_trust_edge_with_key(
        &alice_key,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let wire = encode_wire(&signed.payload, &signed.signature);
    let body = encode_edges_body(&[wire]);

    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "200 OK (body: {:?})", resp_body);

    let results = parse_results_body(&resp_body);
    assert_eq!(results.len(), 1, "one result per input");
    assert_eq!(results[0].0, signed.canonical_hash);
    assert_eq!(results[0].1, "applied");
    assert!(results[0].2.is_none(), "no reason for applied");

    // signed_objects row exists with the verbatim canonical bytes.
    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let stored = sqlx::query!(
        "SELECT inner_class, payload FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("signed_objects row");
    assert_eq!(stored.inner_class, "trust-edge");
    assert_eq!(
        stored.payload.as_deref(),
        Some(signed.payload.as_slice()),
        "payload bytes stored verbatim",
    );

    // trust_edges projection landed.
    let projection = sqlx::query!(
        "SELECT trust_type FROM trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&b.state.db)
    .await
    .expect("trust_edges projection");
    assert_eq!(projection.trust_type, "trust");
}

/// Done-when (Task #15): replaying the exact same bytes returns
/// `duplicate` per §9.1 "redelivery is no-op". The receiver does not
/// distinguish duplicate-from-resend vs duplicate-from-gossip-relay.
#[tokio::test]
async fn push_replay_returns_duplicate() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    insert_user_with_pubkey(
        &b.state.db,
        "user-alice",
        "alice",
        &alice_key.verifying_key().to_bytes(),
    )
    .await;
    insert_user_with_pubkey(
        &b.state.db,
        "user-bob",
        "bob",
        &bob_key.verifying_key().to_bytes(),
    )
    .await;

    let signed = sign_trust_edge_with_key(
        &alice_key,
        &bob_key.verifying_key().to_bytes(),
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let wire = encode_wire(&signed.payload, &signed.signature);
    let body = encode_edges_body(&[wire]);

    let (status1, b1) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(parse_results_body(&b1)[0].1, "applied");

    let (status2, b2) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status2, StatusCode::OK);
    let results2 = parse_results_body(&b2);
    assert_eq!(results2[0].1, "duplicate");
    assert!(results2[0].2.is_none());

    // Only one row in signed_objects + trust_edges — INSERT OR
    // IGNORE on the canonical-hash PK is what makes redelivery safe.
    let count_signed: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE inner_class = 'trust-edge'",
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count");
    assert_eq!(count_signed, 1);
    let count_edges: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count");
    assert_eq!(count_edges, 1);
}

/// A WireFormat that decodes but whose signature does not verify
/// under `from_key` surfaces as `rejected/invalid_signature` and is
/// NOT persisted to `signed_objects`. This is the spec's main defence
/// against a peer-relayed forgery: §9.1 expressly requires per-object
/// signature verification.
#[tokio::test]
async fn push_with_bad_signature_is_rejected_and_not_persisted() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    insert_user_with_pubkey(
        &b.state.db,
        "user-alice",
        "alice",
        &alice_key.verifying_key().to_bytes(),
    )
    .await;
    insert_user_with_pubkey(
        &b.state.db,
        "user-bob",
        "bob",
        &bob_key.verifying_key().to_bytes(),
    )
    .await;

    let signed = sign_trust_edge_with_key(
        &alice_key,
        &bob_key.verifying_key().to_bytes(),
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    // Flip a byte in the signature.
    let mut tampered = signed.signature.clone();
    tampered[0] ^= 0xFF;
    let wire = encode_wire(&signed.payload, &tampered);
    let body = encode_edges_body(&[wire]);

    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "request-level OK; per-edge reject");

    let results = parse_results_body(&resp_body);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("invalid_signature"));

    // Not persisted: the rejection happens before the BEGIN
    // IMMEDIATE store, so signed_objects stays empty for this hash.
    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count");
    assert_eq!(count, 0, "tampered edge must not be persisted");
}

/// A valid edge with an unknown `prior_edge_hash` (chain orphan) is
/// `deferred` per §9.1 and not persisted to `trust_edges` — the
/// sender or §9.3 backfill is expected to close the gap.
#[tokio::test]
async fn push_with_unknown_prior_hash_is_deferred() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    insert_user_with_pubkey(
        &b.state.db,
        "user-alice",
        "alice",
        &alice_key.verifying_key().to_bytes(),
    )
    .await;
    insert_user_with_pubkey(
        &b.state.db,
        "user-bob",
        "bob",
        &bob_key.verifying_key().to_bytes(),
    )
    .await;

    // Sign with a prior_edge_hash B has never seen → orphan.
    let bogus_prior = [0x42u8; 32];
    let signed = sign_trust_edge_with_key(
        &alice_key,
        &bob_key.verifying_key().to_bytes(),
        TrustStance::Trust,
        1_700_000_000_000,
        Some(bogus_prior),
    );
    let wire = encode_wire(&signed.payload, &signed.signature);
    let body = encode_edges_body(&[wire]);

    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let results = parse_results_body(&resp_body);
    assert_eq!(results[0].1, "deferred");

    let count_edges: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count");
    assert_eq!(count_edges, 0, "deferred edges do not project");
}

/// Edges between two keys the receiver has never seen still
/// `applied`: the canonical bytes are durable in `signed_objects` so
/// gossip relay + Phase-6 stub hydration both keep working, but no
/// `trust_edges` projection rows are produced. This is the Phase-5
/// carve-out documented in `edges.rs`.
#[tokio::test]
async fn push_between_unknown_users_persists_signed_object_only() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let stranger1 = SigningKey::generate(&mut OsRng);
    let stranger2_pub = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let signed = sign_trust_edge_with_key(
        &stranger1,
        &stranger2_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let wire = encode_wire(&signed.payload, &signed.signature);
    let body = encode_edges_body(&[wire]);

    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse_results_body(&resp_body)[0].1, "applied");

    // signed_objects: present.
    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let count_signed: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count");
    assert_eq!(count_signed, 1);

    // trust_edges: zero rows for the no-local-user pair (we can't
    // FK to users(id) we don't have). The signed bytes are the
    // authoritative record; the projection rebuilds when Phase 6
    // hydrates remote-user stubs.
    let count_edges: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM trust_edges WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("count");
    assert_eq!(count_edges, 0);
}

/// Request-level error: body that isn't a CBOR map with an `edges`
/// field. Returns 400 with `{ "error": "malformed" }` per §9.1.
#[tokio::test]
async fn push_with_malformed_body_returns_400_malformed() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // Garbage bytes that aren't valid CBOR.
    let body = vec![0xffu8; 16];
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&resp_body), "malformed");
}

/// Request-level error: a syntactically valid body with an empty
/// `edges` array. Per §9.1 the receiver returns
/// `{ "error": "empty_batch" }` so the sender doesn't loop on noise.
#[tokio::test]
async fn push_with_empty_batch_returns_400_empty_batch() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let body = encode_edges_body(&[]);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&resp_body), "empty_batch");
}

/// Request-level error: more than `MAX_EDGE_BATCH` entries. The
/// entries here are not signed (the receiver short-circuits on
/// length before per-edge validation runs), so we can fill the
/// array cheaply with dummy bstrs.
#[tokio::test]
async fn push_exceeding_batch_returns_400_batch_too_large() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let dummy = vec![0u8; 4];
    let body = encode_edges_body(&vec![dummy; MAX_EDGE_BATCH + 1]);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&resp_body), "batch_too_large");
}

/// Mixed-result batches are normal per §9.1: one good edge + one
/// bad-signature edge produce a 200 with `applied` and `rejected`
/// in input order. Senders correlate by position, not by hash.
#[tokio::test]
async fn push_mixed_batch_returns_per_edge_results_in_input_order() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    insert_user_with_pubkey(
        &b.state.db,
        "user-alice",
        "alice",
        &alice_key.verifying_key().to_bytes(),
    )
    .await;
    insert_user_with_pubkey(
        &b.state.db,
        "user-bob",
        "bob",
        &bob_key.verifying_key().to_bytes(),
    )
    .await;

    let good = sign_trust_edge_with_key(
        &alice_key,
        &bob_key.verifying_key().to_bytes(),
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let mut bad_sig = good.signature.clone();
    bad_sig[0] ^= 0xFF;
    let good_wire = encode_wire(&good.payload, &good.signature);
    let bad_wire = encode_wire(&good.payload, &bad_sig);

    // Different payload so the bad entry doesn't dedup against the
    // good one — sign a second valid edge then tamper the signature
    // of the second.
    let other_target = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let other = sign_trust_edge_with_key(
        &alice_key,
        &other_target,
        TrustStance::Trust,
        1_700_000_000_001,
        None,
    );
    let mut other_bad_sig = other.signature.clone();
    other_bad_sig[0] ^= 0xFF;
    let other_bad_wire = encode_wire(&other.payload, &other_bad_sig);

    let body = encode_edges_body(&[good_wire, other_bad_wire, bad_wire]);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let results = parse_results_body(&resp_body);
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].1, "applied");
    assert_eq!(results[1].1, "rejected");
    assert_eq!(results[1].2.as_deref(), Some("invalid_signature"));
    // Third entry: same payload as the first (already applied above),
    // bad sig — even so, it short-circuits on the `signed_objects`
    // lookup and reports `duplicate`. That's the correct §9.1
    // behaviour: duplicate detection is by canonical hash and runs
    // before signature verification, so a peer who replays a valid
    // edge with a corrupted signature still gets `duplicate`.
    assert_eq!(results[2].1, "duplicate");
}

/// Unauthenticated requests (no envelope header) hit the
/// `verify_known_peer` middleware first and collapse to 401 per §6.5
/// before any §9.1 logic runs. Pins that the route is mounted behind
/// the middleware rather than on the public path.
#[tokio::test]
async fn push_without_envelope_header_is_401() {
    use http::Request;
    use tower::ServiceExt;

    let harness = MultiInstanceHarness::new(1).await;
    let a = harness.instance("a");

    let body = encode_edges_body(&[vec![1u8; 8]]);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/federation/v1/edges")
        .header(
            http::header::CONTENT_TYPE,
            prismoire_server::federation::identity::CBOR_CONTENT_TYPE,
        )
        .body(axum::body::Body::from(body))
        .expect("build req");
    let response = a.router.clone().oneshot(req).await.expect("dispatch");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Reference the import so unused-import lints don't trip if we
    // restructure later. The `envelope` import documents that the
    // 401 here is the same code path as a verifier-rejection above.
    let _ = envelope::AUTH_HEADER;
}

/// The §6 envelope verifier accepts only `application/cbor` (§1.7).
/// This pins that the request-Content-Type guard runs before the
/// per-edge state machine — feeding JSON yields a 415, not a 400.
#[tokio::test]
async fn push_with_wrong_content_type_is_415() {
    use http::Request;
    use tower::ServiceExt;

    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let body = encode_edges_body(&[vec![1u8; 8]]);
    let header = envelope::sign_outbound(
        &a.state.instance_key,
        *b.state.instance_key.public_bytes(),
        &Method::POST,
        "/federation/v1/edges",
        &body,
    );
    let req = Request::builder()
        .method(Method::POST)
        .uri("/federation/v1/edges")
        .header(envelope::AUTH_HEADER, header)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(Bytes::from(body)))
        .expect("build req");
    let response = b.router.clone().oneshot(req).await.expect("dispatch");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

/// Build a minimal §8.3 `FrontierAnnounce` whose `edge_origin_filter`
/// is populated with `interested_keys`. The `content_filter` is the
/// `all_ones_sentinel` so it cannot accidentally route an `Authored`
/// object — this test only exercises the trust-edge path, and using
/// the sentinel keeps the receiver's filter-bytes validation happy
/// without us computing a real closure.
fn announce_with_edge_origin_keys(interested_keys: &[&[u8; 32]]) -> FrontierAnnounce {
    // 1024-bit filter is the smallest in-spec size that comfortably
    // holds a handful of keys at the reference 1% FPR. k=7 matches
    // bloom::recommend_k for tiny key counts and stays inside [MIN_K,
    // MAX_K].
    let mut edge = BloomFilter::new_empty(7, 1024, interested_keys.len() as u64, 0.01)
        .expect("build edge filter");
    for k in interested_keys {
        edge.insert(k.as_slice());
    }
    FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        content_filter: FilterSpec::from_bloom(&BloomFilter::all_ones_sentinel()),
        edge_origin_filter: FilterSpec::from_bloom(&edge),
    }
}

/// Wait up to `timeout_ms` for `predicate` to return `true`. Phase
/// 6.4 moved per-peer dispatch off `tokio::spawn` and onto a per-peer
/// drain worker, but the egress is still asynchronous from the
/// upstream push's perspective — the downstream peer's DB does not
/// have the projected row by the time `send_envelope_signed` returns.
/// Polling with a short backoff (rather than a single `sleep`) keeps
/// the test fast in the happy case and only burns the full budget on
/// a real failure. Phase-6 tests prefer `wait_outbound_idle` via the
/// `OutboundQueues::idle_notify` signal; this Phase-5 helper predates
/// that and is kept as-is to avoid churn.
async fn poll_until<F, Fut>(timeout_ms: u64, mut predicate: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        if predicate().await {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Done-when (Task #16): A pushes a signed trust-edge to B, B applies
/// it locally, and the §7.5 forwarder relays it on to C because C's
/// `edge_origin_filter` says C is interested in edges signed by
/// alice. The arrival path on C is the same `/federation/v1/edges`
/// handler the originator push uses — the forwarder is just another
/// active peer to C — so we assert convergence by polling C's
/// `trust_edges` projection.
#[tokio::test]
async fn forwarder_relays_applied_edge_to_interested_peer() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "b", "c").await;
    let b = harness.instance("b");
    let c = harness.instance("c");

    // Both B and C need local user rows for (alice, bob) so the
    // §9.1 projection lands on both ends. The signed edge is
    // alice → bob; whichever instance receives it must already know
    // who alice and bob are to write into `trust_edges`.
    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;
    insert_user_with_pubkey(&c.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&c.state.db, "user-bob", "bob", &bob_pub).await;

    // C announces a frontier to B whose `edge_origin_filter` contains
    // alice's pubkey. This makes B's `peers_interested_in` return C
    // for any `ForwardingClass::TrustEdge` keyed on alice.
    let announce_body = announce_with_edge_origin_keys(&[&alice_pub]).encode();
    let (status, _) = send_envelope_signed(
        &harness,
        "c",
        "b",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "C → B announce must apply");

    // A pushes the signed edge to B.
    let signed = sign_trust_edge_with_key(
        &alice_key,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let wire = encode_wire(&signed.payload, &signed.signature);
    let body = encode_edges_body(&[wire]);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "A → B push must apply");
    assert_eq!(parse_results_body(&resp_body)[0].1, "applied");

    // B's `forward_signed_object` enqueues onto B's per-peer outbound
    // queue (Phase 6.4) and the drain worker dispatches to C
    // asynchronously, so C's row appears after this push returns. Poll
    // for up to 2s before failing — happy path resolves in single-digit ms.
    let c_db = c.state.db.clone();
    let hash_slice = signed.canonical_hash.to_vec();
    let arrived = poll_until(2_000, || {
        let c_db = c_db.clone();
        let hash_slice = hash_slice.clone();
        async move {
            let hash_slice_ref: &[u8] = &hash_slice;
            let row = sqlx::query!(
                "SELECT 1 AS \"n!: i64\" FROM signed_objects WHERE canonical_hash = ?",
                hash_slice_ref,
            )
            .fetch_optional(&c_db)
            .await
            .expect("query signed_objects on c");
            row.is_some()
        }
    })
    .await;
    assert!(arrived, "forwarder did not deliver signed object to C");

    // Projection landed on C too — confirms the forwarded copy went
    // through the full §9.1 push pipeline on the receiving end, not
    // just `signed_objects`.
    let projection = sqlx::query!(
        "SELECT trust_type FROM trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&c.state.db)
    .await
    .expect("trust_edges projection on c");
    assert_eq!(projection.trust_type, "trust");

    // §7.5: arrived_from suppression. The forwarder must not push
    // back to A (the peer it arrived from). A is not in C's interest
    // set anyway, but the more direct check is that A's own DB still
    // has no `signed_objects` row for this hash — A originated the
    // push so nothing was ever persisted there.
    let a = harness.instance("a");
    let hash_slice_a: &[u8] = signed.canonical_hash.as_slice();
    let count_on_a: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        hash_slice_a,
    )
    .fetch_one(&a.state.db)
    .await
    .expect("count on a");
    assert_eq!(
        count_on_a, 0,
        "originator A must not receive its own object back via gossip",
    );
}
