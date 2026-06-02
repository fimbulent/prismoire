#![cfg(feature = "test-auth")]
//! Cross-instance trust-edge propagation integration tests (§9).
//!
//! Consolidates four formerly-separate phase files into the single
//! protocol surface they all exercise — signed trust-edges crossing the
//! instance boundary and converging into each receiver's local
//! projection:
//!
//! - **§9.1 edge-push receive path.** An active peer's
//!   `POST /federation/v1/edges` applies a signed edge into
//!   `signed_objects` + `trust_edges` when both endpoints are local
//!   users; replays return `duplicate`; a bad signature is `rejected`
//!   and not persisted; an edge between two strangers persists the
//!   bytes only (no projection). Request-level failure modes (malformed
//!   body, empty batch, batch-too-large) 400 with a single `{ error }`
//!   body; mixed batches return per-edge results in input order;
//!   missing envelope is 401, wrong content-type is 415.
//! - **§7.4 / §7.5 / §8.10 forwarder relay.** B applies an edge from A
//!   and re-emits it to an interested peer C (target-keyed routing);
//!   a peer interested only in the edge *source* is not a forward
//!   target; §8.10 source-side shedding cleaves a relay whose source is
//!   younger than the peer's advertised root ceiling.
//! - **§11.9.5 unknown-source recovery.** An edge whose *source* is a
//!   never-seen remote key but whose home peer delivered it gets its
//!   source hydrated from that peer and the edge projects; the recovery
//!   also backfills the source's pre-existing by-author content.
//! - **§9.3 chain-continuity backfill.** `GET /edges/backfill` returns a
//!   chain oldest-first, paginates via an opaque `since` cursor, 400s on
//!   an unknown chain / invalid cursor / out-of-range limit, and powers
//!   an end-to-end partition heal (late joiner pulls + replays to
//!   converge).
//! - **§9.6 Layer-0 sweep projection.** `sweep_pending_projections`
//!   projects a stored-but-unprojected edge once both endpoint stubs
//!   hydrate, leaves it unprojected while a stub is missing, projects
//!   exactly one of two chain-fork siblings, projects an out-of-order
//!   chain via its fixed-point loop, and defers an orphan whose
//!   predecessor was never stored.
//! - **§9.8 pending orphan buffer.** TTL eviction prunes stale rows;
//!   the sweep drain extension promotes a buffered orphan atomically
//!   with its predecessor; a `deferred` push buffers the orphan in
//!   `pending_trust_edges` (deduped per `(source, prior)` gap) without
//!   double-landing in `signed_objects`; a subsequent root push drains
//!   the buffer; and the first orphan for a gap fires an autonomous
//!   §9.3 backfill against the source's home that closes the chain.
//!
//! Convergence-driven scenarios use the [`settle`] harness driver rather
//! than spawning `frontier_fanout_loop` + polling. The one exception is
//! the autonomous-backfill round-trip, whose recovery rides a raw
//! `tokio::spawn` of `request_edge_predecessor` that `settle` does not
//! drive — that test keeps a bounded `poll_until`.

mod common;

use axum::body::Bytes;
use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use prismoire_server::federation::backfill::MAX_EDGE_BACKFILL_PAGE;
use prismoire_server::federation::bloom::BloomFilter;
use prismoire_server::federation::edges::{DEFERRED_ORPHAN_TTL, MAX_EDGE_BATCH};
use prismoire_server::federation::envelope;
use prismoire_server::federation::frontier::{FilterSpec, FrontierAnnounce};
use prismoire_server::federation::remote_users::{
    evict_expired_pending_trust_edges, hydrate_stub_user, sweep_pending_projections,
};
use prismoire_server::federation::routing::Mode;
use prismoire_server::signed::TrustStance;
use prismoire_server::signing::{SigningOutput, sign_trust_edge_with_key, store_signed_object};
use rand::SeedableRng;
use rand::rngs::{OsRng, StdRng};
use sqlx::SqlitePool;

use common::federation::{
    MultiInstanceHarness, establish_active_peering, send_envelope_signed,
    send_envelope_signed_split, settle,
};
use common::{body_json, get_request, json_request, send, setup_admin, test_app};
use serde_json::json;

// ===========================================================================
// §9.1 — edge-push receive path
// ===========================================================================

/// Done-when: a single push from active-peer A reaches B, the canonical
/// bytes land in `signed_objects`, the projection lands in `trust_edges`,
/// and the response carries `applied`.
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

/// Replaying the exact same bytes returns `duplicate` per §9.1
/// "redelivery is no-op". The receiver does not distinguish
/// duplicate-from-resend vs duplicate-from-gossip-relay.
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

/// A WireFormat that decodes but whose signature does not verify under
/// `from_key` surfaces as `rejected/invalid_signature` and is NOT
/// persisted to `signed_objects`. The spec's main defence against a
/// peer-relayed forgery: §9.1 requires per-object signature
/// verification.
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

/// Edges between two keys the receiver has never seen still `applied`:
/// the canonical bytes are durable in `signed_objects` so gossip relay +
/// stub hydration both keep working, but no `trust_edges` projection
/// rows are produced.
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
    // authoritative record; the projection rebuilds when a later
    // sweep hydrates remote-user stubs.
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

/// Request-level error: a syntactically valid body with an empty `edges`
/// array. Per §9.1 the receiver returns `{ "error": "empty_batch" }` so
/// the sender doesn't loop on noise.
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

/// Request-level error: more than `MAX_EDGE_BATCH` entries. The entries
/// here are not signed (the receiver short-circuits on length before
/// per-edge validation runs), so we can fill the array cheaply with
/// dummy bstrs.
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
/// bad-signature edge produce a 200 with `applied` and `rejected` in
/// input order. Senders correlate by position, not by hash.
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
/// before any §9.1 logic runs. Pins that the route is mounted behind the
/// middleware rather than on the public path.
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

/// The §6 envelope verifier accepts only `application/cbor` (§1.7). This
/// pins that the request-Content-Type guard runs before the per-edge
/// state machine — feeding JSON yields a 415, not a 400.
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

// ===========================================================================
// §7.4 / §7.5 / §8.10 — forwarder relay
// ===========================================================================

/// A pushes a signed trust-edge to B, B applies it locally, and the §7.5
/// forwarder relays it on to C because C's `expansion_filter` says C is
/// interested in edges targeting bob. The arrival path on C is the same
/// `/federation/v1/edges` handler the originator push uses — the
/// forwarder is just another active peer to C — so we assert convergence
/// (via [`settle`]) on C's `trust_edges` projection.
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

    // C announces a frontier to B whose `expansion_filter` contains
    // bob's pubkey (the edge target). This makes B's
    // `peers_interested_in` return C for any `ForwardingClass::TrustEdge`
    // keyed on bob, the §7.4 trust-edge routing key.
    let announce_body = announce_with_edge_origin_keys(&[&bob_pub]).encode();
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
    // queue; the drain worker dispatches to C. We drain B's queue
    // directly rather than `settle` here: these fixtures use synthetic
    // non-UUID user ids that the trust-graph rebuild `settle` runs
    // cannot parse, so we wait on the outbound-idle signal instead.
    assert!(
        b.state
            .outbound_queues
            .wait_idle(std::time::Duration::from_secs(2))
            .await,
        "B outbound queue did not drain within 2s",
    );

    // signed_objects on C: the forwarded copy arrived.
    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let count_on_c: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&c.state.db)
    .await
    .expect("count on c");
    assert_eq!(
        count_on_c, 1,
        "forwarder did not deliver signed object to C"
    );

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
    // back to A (the peer it arrived from). A originated the push so
    // nothing was ever persisted there.
    let a = harness.instance("a");
    let count_on_a: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&a.state.db)
    .await
    .expect("count on a");
    assert_eq!(
        count_on_a, 0,
        "originator A must not receive its own object back via gossip",
    );
}

/// §8.10 source-side shedding: when a peer advertises an age ceiling for
/// the edge's *root* (`to_key`) and the forwarder holds an
/// instance-attested `genesis_at` for the *source* (`from_key`) strictly
/// younger than that cutoff, the relay is shed before enqueue — the peer
/// would reject it on receipt (§8.10), so the round-trip is saved. The
/// negative companion to
/// [`forwarder_relays_applied_edge_to_interested_peer`]: C IS otherwise
/// interested (its `expansion_filter` carries the target bob), so the
/// only thing keeping the edge from C is the §8.10 cleave.
#[tokio::test]
async fn forwarder_sheds_relay_when_source_younger_than_peer_ceiling() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "b", "c").await;
    let b = harness.instance("b");
    let c = harness.instance("c");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;
    insert_user_with_pubkey(&c.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&c.state.db, "user-bob", "bob", &bob_pub).await;

    // C announces to B: interested in edges targeting bob, AND a §8.3
    // age ceiling for root bob at cutoff T. B records both — the
    // `expansion_filter` into `peer_frontiers` (so C is a candidate) and
    // the ceiling into `peer_frontier_age_ceilings` (so the §8.10
    // pre-filter has a cutoff to test the source's age against).
    let cutoff = 1_600_000_000_000u64;
    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(bob_pub, cutoff);
    let announce_body = announce_with_edge_keys_and_ceilings(&[&bob_pub], ceilings).encode();
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

    // B holds an instance-attested genesis for the SOURCE alice that is
    // strictly younger than the cutoff → `ceiling_admits` is false → C
    // is shed. (`genesis_at <= cutoff` would admit; we go above it.)
    insert_user_genesis(&b.state.db, &alice_pub, (cutoff + 100_000_000) as i64).await;

    // A pushes the signed alice → bob edge to B.
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

    // Drain B's outbound queue (not `settle`: synthetic non-UUID user
    // ids break the trust-graph rebuild `settle` runs). C never
    // received the object — the shed dropped C before enqueue, so
    // nothing was ever queued for it.
    assert!(
        b.state
            .outbound_queues
            .wait_idle(std::time::Duration::from_secs(2))
            .await,
        "B outbound queue did not drain within 2s",
    );
    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let count_on_c: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&c.state.db)
    .await
    .expect("count on c");
    assert_eq!(
        count_on_c, 0,
        "§8.10: B must shed the relay to C (source younger than C's ceiling for the root)",
    );
}

/// §7.4 trust-edge routing direction: a peer interested ONLY in the
/// edge's *source* (`from_key`) is NOT a forward target — trust edges
/// route by their *target* (`to_key`), so a filter that matches alice
/// (source) but not bob (target) does not pull the alice → bob edge.
/// Mirror-negative of
/// [`forwarder_relays_applied_edge_to_interested_peer`], which puts the
/// target bob in C's filter and asserts arrival.
#[tokio::test]
async fn forwarder_does_not_relay_to_peer_interested_only_in_edge_source() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "b", "c").await;
    let b = harness.instance("b");
    let c = harness.instance("c");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;
    insert_user_with_pubkey(&c.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&c.state.db, "user-bob", "bob", &bob_pub).await;

    // C announces to B with the edge's SOURCE alice in its
    // `expansion_filter` — and NOT the target bob. Under §7.4
    // target-routing, B's `peers_interested_in` keyed on bob does not
    // return C, so the edge is never forwarded.
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

    // Drain B's outbound queue (not `settle`: synthetic non-UUID user
    // ids break the trust-graph rebuild `settle` runs). C was never a
    // candidate (its filter matches the source, not the §7.4 target
    // key), so nothing was enqueued for it; assert absence after drain.
    assert!(
        b.state
            .outbound_queues
            .wait_idle(std::time::Duration::from_secs(2))
            .await,
        "B outbound queue did not drain within 2s",
    );
    let hash_slice: &[u8] = signed.canonical_hash.as_slice();
    let count_on_c: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        hash_slice,
    )
    .fetch_one(&c.state.db)
    .await
    .expect("count on c");
    assert_eq!(
        count_on_c, 0,
        "§7.4: edge targeting bob must not reach a peer interested only in source alice",
    );
}

// ===========================================================================
// §11.9.5 — unknown-source recovery
// ===========================================================================

/// §11.9.5 cross-instance bootstrap, target's-home side. A homes sam1, B
/// homes sam2, and B's sam2 redeems sam1's trust code — minting a signed
/// `sam2 -> sam1` trust-edge on B. The edge is target-routed (§7.4) to A
/// (sam1's home). On A the edge *source* sam2 is a never-seen remote key,
/// so the receive path persists the bytes but writes no `trust_edges`
/// row until the unknown-source recovery hydrates sam2 from the
/// delivering peer B and projects the edge into sam1's "trusted by".
#[tokio::test]
async fn unknown_source_edge_to_local_target_recovers_and_projects() {
    let harness = MultiInstanceHarness::new(2).await;
    // Mutual active peering: B pushes the edge to A, and A must be able
    // to pull sam2's profile back from B to recover the missing source.
    establish_active_peering(&harness, "a", "b").await;

    let a = harness.instance("a");
    let b = harness.instance("b");

    // sam1: real local user on A (edge target, sam1's home).
    let sam1 = setup_admin(&a.router, "sam1").await;
    // sam2: real local user on B (edge source, sam2's home).
    let sam2 = setup_admin(&b.router, "sam2").await;

    // Give sam2 a published profile-rev on B. A real signup mints a
    // genesis revision; the test bypass route does not, so without this
    // the by-author backfill A runs to recover the unknown source would
    // find no content to hydrate sam2's stub from.
    let sam2_profile = send(
        &b.router,
        json_request(
            Method::PATCH,
            &format!("/api/users/{}", sam2.public_key_hex),
            Some(&sam2.cookie),
            &json!({ "bio": "sam2 on instance b" }),
        ),
    )
    .await;
    assert_eq!(
        sam2_profile.status(),
        StatusCode::NO_CONTENT,
        "sam2 publishes a profile revision on B",
    );

    // sam1 mints a trust code on A; sam2 redeems it on B. Redemption
    // seeds a sam1 stub on B and signs a `sam2 -> sam1` trust-edge with
    // sam2's key, storing the canonical bytes in B's `signed_objects`.
    let mint = send(
        &a.router,
        get_request("/api/me/trust-code", Some(&sam1.cookie)),
    )
    .await;
    assert_eq!(mint.status(), StatusCode::OK, "mint sam1's trust code");
    let code = body_json(mint).await["code"]
        .as_str()
        .expect("code field")
        .to_string();

    let redeem = send(
        &b.router,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&sam2.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(redeem.status(), StatusCode::OK, "sam2 redeems sam1's code");

    // Pull the canonical `sam2 -> sam1` edge bytes B just signed and
    // deliver them to A straight from B, mirroring the §7.4 forward.
    let (payload, signature): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT payload, signature FROM signed_objects \
         WHERE inner_class = 'trust-edge' AND payload IS NOT NULL LIMIT 1",
    )
    .fetch_one(&b.state.db)
    .await
    .expect("sam2 -> sam1 edge bytes on B");
    let body = encode_edges_body(&[encode_wire(&payload, &signature)]);

    let (status, resp_body) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        parse_results_body(&resp_body)[0].1,
        "applied",
        "§9.1 promises `applied` (durable bytes) even for an unknown-source edge",
    );

    // A recovers the unknown source sam2 from peer B and projects the
    // edge, so sam1's "trusted by" shows sam2. The recovery rides
    // `spawn_unknown_source_backfill`, which `settle` waits out via its
    // by-author-backfill drain.
    settle(&harness).await;

    let sam1_pub = hex32(&sam1.public_key_hex);
    let sam2_pub = hex32(&sam2.public_key_hex);
    let projected: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM current_trust_edges cte \
           JOIN users su ON su.id = cte.source_user \
           JOIN users tu ON tu.id = cte.target_user \
          WHERE su.public_key = ? AND tu.public_key = ? \
            AND cte.trust_type = 'trust'",
    )
    .bind(&sam2_pub[..])
    .bind(&sam1_pub[..])
    .fetch_one(&a.state.db)
    .await
    .expect("count sam2 -> sam1 on A");
    assert!(
        projected > 0,
        "A must hydrate the unknown source sam2 from peer B and project \
         the edge into sam1's trusted-by",
    );
}

/// Second gap (§11.9.5 follow-on): once A learns the unknown source sam2,
/// sam2's *pre-existing* thread (authored on B before A had any interest)
/// must also surface on A. The unknown-source recovery pulls sam2's
/// by-author content; asserting on the OP `posts` row is the stronger
/// check — a `posts` row FK-requires its `threads` row, so it proves both
/// the thread-create and the OP post-rev converged.
#[tokio::test]
async fn unknown_source_recovery_backfills_authors_existing_thread() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let a = harness.instance("a");
    let b = harness.instance("b");

    let sam1 = setup_admin(&a.router, "sam1").await;
    let sam2 = setup_admin(&b.router, "sam2").await;

    // sam2 publishes a profile-rev (stub hydration) and a thread on B,
    // both BEFORE A learns sam2 exists.
    let sam2_profile = send(
        &b.router,
        json_request(
            Method::PATCH,
            &format!("/api/users/{}", sam2.public_key_hex),
            Some(&sam2.cookie),
            &json!({ "bio": "sam2 on instance b" }),
        ),
    )
    .await;
    assert_eq!(sam2_profile.status(), StatusCode::NO_CONTENT);

    let thread = send(
        &b.router,
        json_request(
            Method::POST,
            "/api/threads",
            Some(&sam2.cookie),
            &json!({
                "room": "lounge",
                "title": "sam2's pre-existing thread",
                "body": "kumquat tangerine — authored before A knew sam2",
            }),
        ),
    )
    .await;
    assert_eq!(
        thread.status(),
        StatusCode::CREATED,
        "sam2 creates a thread on B"
    );
    let thread_id = body_json(thread).await["id"]
        .as_str()
        .expect("thread.id")
        .to_string();

    // Trust-code edge sam2 -> sam1, delivered to A. Recovery pulls
    // sam2's by-author content as a side effect.
    let mint = send(
        &a.router,
        get_request("/api/me/trust-code", Some(&sam1.cookie)),
    )
    .await;
    assert_eq!(mint.status(), StatusCode::OK);
    let code = body_json(mint).await["code"]
        .as_str()
        .expect("code field")
        .to_string();

    let redeem = send(
        &b.router,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&sam2.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(redeem.status(), StatusCode::OK);

    let (payload, signature): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT payload, signature FROM signed_objects \
         WHERE inner_class = 'trust-edge' AND payload IS NOT NULL LIMIT 1",
    )
    .fetch_one(&b.state.db)
    .await
    .expect("sam2 -> sam1 edge bytes on B");
    let body = encode_edges_body(&[encode_wire(&payload, &signature)]);

    let (status, _resp_body) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // A backfills sam2's thread-create AND OP post and projects both.
    // The thread id is content-derived, so it matches B's id
    // byte-for-byte. Asserting on the OP `posts` row is the stronger
    // check — a `posts` row FK-requires its `threads` row.
    settle(&harness).await;
    let projected_post: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM posts WHERE thread = ?")
        .bind(&thread_id)
        .fetch_one(&a.state.db)
        .await
        .expect("count sam2's OP post on A");
    assert!(
        projected_post > 0,
        "A must backfill and project sam2's pre-existing thread (and its \
         OP post) once it learns sam2 via the unknown-source recovery",
    );
}

// ===========================================================================
// §9.3 — chain-continuity backfill
// ===========================================================================

/// A holds a 3-mutation chain on (alice, bob). A late-joining D peers
/// with A, GETs `/edges/backfill`, and receives all three signed objects
/// in oldest-first order with `complete: true` and no `next_cursor`.
/// Pins the unpaginated happy path.
#[tokio::test]
async fn backfill_returns_chain_oldest_first_complete() {
    let harness = MultiInstanceHarness::new(4).await;
    // A receives the chain from B (the originator stand-in); D pulls
    // from A. A is the only instance whose DB we walk on the GET side.
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&a.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&a.state.db, "user-bob", "bob", &bob_pub).await;

    // Seed A with a chained history. Distinct ms-precision timestamps
    // keep the (created_at, canonical_hash) keyset pagination
    // unambiguous; the timestamps round to whole-second ISO strings on
    // store, so they only need to differ at the second level.
    let chain = sign_chain(
        &alice_key,
        &bob_pub,
        &[
            (TrustStance::Trust, 1_700_000_000_000),
            (TrustStance::Distrust, 1_700_000_001_000),
            (TrustStance::Trust, 1_700_000_002_000),
        ],
    );
    push_chain(&harness, "b", "a", &chain).await;

    // D joins late and peers with A.
    establish_active_peering(&harness, "a", "d").await;

    let alice_hex = to_hex(&alice_pub);
    let bob_hex = to_hex(&bob_pub);
    let (status, body) = get_backfill(&harness, "d", "a", &alice_hex, &bob_hex, None, None).await;
    assert_eq!(status, StatusCode::OK, "happy backfill must be 200");

    let parsed = parse_backfill_body(&body);
    assert!(parsed.complete, "single page must report complete=true");
    assert!(
        parsed.next_cursor.is_none(),
        "complete=true must omit next_cursor (§10.5.2)",
    );
    assert_eq!(parsed.objects.len(), 3, "all 3 chained edges returned");

    // Oldest-first: the order returned must thread by prior_edge_hash —
    // i.e. equal the order we seeded.
    for (i, signed) in chain.iter().enumerate() {
        let expected = encode_wire(&signed.payload, &signed.signature);
        assert_eq!(
            parsed.objects[i], expected,
            "object[{i}] must be the chained signed bytes verbatim",
        );
    }
}

/// Pagination round-trip: 4-mutation chain, page size 2. First GET
/// returns 2 objects + `next_cursor` + `complete: false`; the resume GET
/// with that cursor returns the final 2 with `complete: true`.
#[tokio::test]
async fn backfill_paginates_with_limit_and_next_cursor() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&a.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&a.state.db, "user-bob", "bob", &bob_pub).await;

    let chain = sign_chain(
        &alice_key,
        &bob_pub,
        &[
            (TrustStance::Trust, 1_700_000_000_000),
            (TrustStance::Distrust, 1_700_000_001_000),
            (TrustStance::Trust, 1_700_000_002_000),
            (TrustStance::Distrust, 1_700_000_003_000),
        ],
    );
    push_chain(&harness, "b", "a", &chain).await;

    establish_active_peering(&harness, "a", "d").await;

    let alice_hex = to_hex(&alice_pub);
    let bob_hex = to_hex(&bob_pub);

    // Page 1: limit=2 → first two objects + next_cursor.
    let (s1, b1) = get_backfill(&harness, "d", "a", &alice_hex, &bob_hex, Some(2), None).await;
    assert_eq!(s1, StatusCode::OK);
    let p1 = parse_backfill_body(&b1);
    assert_eq!(p1.objects.len(), 2);
    assert!(!p1.complete, "more rows remain — must be incomplete");
    let next_cursor = p1.next_cursor.expect("incomplete page must carry cursor");
    assert_eq!(
        p1.objects[0],
        encode_wire(&chain[0].payload, &chain[0].signature)
    );
    assert_eq!(
        p1.objects[1],
        encode_wire(&chain[1].payload, &chain[1].signature)
    );

    // Page 2: resume with the cursor → final two objects + complete:true.
    let cursor_b64 = URL_SAFE_NO_PAD.encode(&next_cursor);
    let (s2, b2) = get_backfill(
        &harness,
        "d",
        "a",
        &alice_hex,
        &bob_hex,
        Some(2),
        Some(&cursor_b64),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    let p2 = parse_backfill_body(&b2);
    assert_eq!(p2.objects.len(), 2, "remaining tail of the chain");
    assert!(p2.complete, "tail page completes the walk");
    assert!(p2.next_cursor.is_none(), "complete=true omits cursor");
    assert_eq!(
        p2.objects[0],
        encode_wire(&chain[2].payload, &chain[2].signature)
    );
    assert_eq!(
        p2.objects[1],
        encode_wire(&chain[3].payload, &chain[3].signature)
    );
}

/// Both endpoints unknown to A → `400 unknown_chain`. Distinguished from
/// `invalid_key` (which is a malformed hex string).
#[tokio::test]
async fn backfill_unknown_chain_returns_400() {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;

    // Random keys A has never seen — no users rows, no signed_objects.
    let stranger1 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let stranger2 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let (status, body) = get_backfill(
        &harness,
        "d",
        "a",
        &to_hex(&stranger1),
        &to_hex(&stranger2),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&body), "unknown_chain");
}

/// Garbage `since` cursor (right base64 alphabet, wrong length) →
/// `400 invalid_cursor`. The spec mandates this collapse so a client
/// retries without `since` rather than looping on a stale cursor.
#[tokio::test]
async fn backfill_invalid_cursor_returns_400() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;
    let a = harness.instance("a");

    // Need both endpoints to be known users so we get past the
    // `unknown_chain` check and reach the cursor parser. The chain
    // itself can be empty — invalid_cursor fires before the SQL walk.
    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&a.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&a.state.db, "user-bob", "bob", &bob_pub).await;

    // 10 bytes — not the 52-byte cursor layout the handler expects.
    let garbage = URL_SAFE_NO_PAD.encode([0u8; 10]);
    let (status, body) = get_backfill(
        &harness,
        "d",
        "a",
        &to_hex(&alice_pub),
        &to_hex(&bob_pub),
        None,
        Some(&garbage),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&body), "invalid_cursor");
}

/// `limit=0` and `limit=MAX_EDGE_BACKFILL_PAGE + 1` both collapse to
/// `400 limit_out_of_range`. Pins the §9.6 cap.
#[tokio::test]
async fn backfill_limit_out_of_range_returns_400() {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;
    let a = harness.instance("a");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&a.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&a.state.db, "user-bob", "bob", &bob_pub).await;

    for bad_limit in [0u32, MAX_EDGE_BACKFILL_PAGE + 1] {
        let (status, body) = get_backfill(
            &harness,
            "d",
            "a",
            &to_hex(&alice_pub),
            &to_hex(&bob_pub),
            Some(bad_limit),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "limit={bad_limit}");
        assert_eq!(parse_error_body(&body), "limit_out_of_range");
    }
}

/// **End-to-end partition heal.** A holds a 3-mutation chain. D joins
/// late, walks `/edges/backfill` against A, and replays each returned
/// signed object into its own `/edges` handler. After the replay, D's
/// `current_trust_edges` view matches A's latest stance — the exact
/// convergence guarantee §9.3 sells.
#[tokio::test]
async fn partition_heal_via_backfill_and_replay() {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&a.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&a.state.db, "user-bob", "bob", &bob_pub).await;

    let chain = sign_chain(
        &alice_key,
        &bob_pub,
        &[
            // Each step flips the stance so the projection's final
            // value is non-trivial — if D drops any object in transit,
            // the convergence assert below catches it.
            (TrustStance::Trust, 1_700_000_000_000),
            (TrustStance::Distrust, 1_700_000_001_000),
            (TrustStance::Trust, 1_700_000_002_000),
        ],
    );
    push_chain(&harness, "b", "a", &chain).await;

    // D joins. D needs its own alice/bob rows so the §9.1 projection
    // lands on D's side too — projection only fires when both endpoints
    // are local users.
    let d = harness.instance("d");
    insert_user_with_pubkey(&d.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&d.state.db, "user-bob", "bob", &bob_pub).await;
    establish_active_peering(&harness, "a", "d").await;

    // D pulls the chain from A.
    let alice_hex = to_hex(&alice_pub);
    let bob_hex = to_hex(&bob_pub);
    let (status, body) = get_backfill(&harness, "d", "a", &alice_hex, &bob_hex, None, None).await;
    assert_eq!(status, StatusCode::OK);
    let parsed = parse_backfill_body(&body);
    assert!(parsed.complete);
    assert_eq!(parsed.objects.len(), 3);

    // D replays each backfilled object through its own `/edges` push
    // handler, with A as the upstream sender (A is the active peer D
    // knows, and `/edges` only cares that *some* active peer pushed
    // the bytes). After this round-trip, D's tables hold the same
    // chain A's do.
    let replay_body = encode_edges_body(&parsed.objects);
    let (replay_status, _) = send_envelope_signed(
        &harness,
        "a",
        "d",
        Method::POST,
        "/federation/v1/edges",
        &replay_body,
    )
    .await;
    assert_eq!(replay_status, StatusCode::OK, "replay must succeed");

    // Convergence: every signed object A has, D now has too.
    for signed in &chain {
        let hash_slice: &[u8] = signed.canonical_hash.as_slice();
        let present_on_d: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
            hash_slice,
        )
        .fetch_one(&d.state.db)
        .await
        .expect("count signed_objects on d");
        assert_eq!(
            present_on_d, 1,
            "d must hold every backfilled signed object verbatim",
        );
    }

    // Projection: the final stance on D's `current_trust_edges` view
    // matches A's — both `trust`, the last entry in the chain. The
    // view picks the latest non-neutral row per pair, so this single
    // assertion validates the full chain landed in the right order.
    let stance_on_a: String = sqlx::query_scalar!(
        "SELECT trust_type FROM current_trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&a.state.db)
    .await
    .expect("current stance on a");
    let stance_on_d: String = sqlx::query_scalar!(
        "SELECT trust_type FROM current_trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&d.state.db)
    .await
    .expect("current stance on d");
    assert_eq!(stance_on_a, "trust", "A's latest stance is trust");
    assert_eq!(
        stance_on_d, stance_on_a,
        "after backfill+replay, D converges on A's stance",
    );

    // Row counts match too — the projection table on D has the same
    // 3 historical entries as A. This guards against the "view picks
    // the right latest row, but the underlying log is missing entries"
    // failure mode.
    let count_on_a: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&a.state.db)
    .await
    .expect("count on a");
    let count_on_d: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&d.state.db)
    .await
    .expect("count on d");
    assert_eq!(count_on_a, 3);
    assert_eq!(count_on_d, count_on_a, "log lengths converge");
}

// ===========================================================================
// §9.6 — Layer-0 sweep projection
// ===========================================================================

/// Both endpoint stubs exist when sweep runs → stored edge projects.
#[tokio::test]
async fn sweep_projects_stored_edge_after_both_stubs_hydrate() {
    let (_app, state) = test_app().await;

    let from_signer = seeded_signer(0x11);
    let to_signer = seeded_signer(0x22);
    let from_key = pubkey_of(&from_signer);
    let to_key = pubkey_of(&to_signer);
    let home = [0x33u8; 32];

    // Hydrate stubs for both endpoints first, *then* land the stored
    // edge. (The order doesn't matter for sweep correctness — sweep
    // looks for not-yet-projected signed_objects — but staging the
    // stubs first lets us assert that the stored edge truly was the
    // only blocker.)
    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &from_key, "remote_alice", &home)
            .await
            .expect("from stub");
        hydrate_stub_user(&mut tx, &to_key, "remote_bob", &home)
            .await
            .expect("to stub");
        tx.commit().await.expect("commit");
    }

    let edge_hash = store_unprojected_edge(
        &state.db,
        &from_signer,
        &to_key,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    )
    .await;
    assert!(
        !trust_edge_projected(&state.db, &edge_hash).await,
        "precondition: edge stored but not yet projected"
    );

    // Sweep keyed on the source — the just-hydrated stub triggers
    // the call site in production (via project_remote_profile), but
    // for Layer-0 we drive it directly.
    {
        let mut tx = state.db.begin().await.expect("begin");
        sweep_pending_projections(&mut tx, &from_key)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
    }

    assert!(
        trust_edge_projected(&state.db, &edge_hash).await,
        "sweep should project the stored edge once both stubs exist"
    );
}

/// Only one endpoint stub exists → stored edge stays unprojected. Models
/// the wide-scope-edge case where the author has hydrated (their
/// profile-rev arrived) but the target hasn't yet. Hydrating the target
/// later lets a sweep keyed on the target project the stored edge.
#[tokio::test]
async fn sweep_leaves_edge_unprojected_when_target_stub_missing() {
    let (_app, state) = test_app().await;

    let from_signer = seeded_signer(0x44);
    let to_signer = seeded_signer(0x55);
    let from_key = pubkey_of(&from_signer);
    let to_key = pubkey_of(&to_signer);
    let home = [0x66u8; 32];

    // Hydrate only the source stub.
    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &from_key, "remote_alice", &home)
            .await
            .expect("from stub");
        tx.commit().await.expect("commit");
    }

    let edge_hash = store_unprojected_edge(
        &state.db,
        &from_signer,
        &to_key,
        TrustStance::Trust,
        1_700_000_000_001,
        None,
    )
    .await;

    {
        let mut tx = state.db.begin().await.expect("begin");
        sweep_pending_projections(&mut tx, &from_key)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
    }

    assert!(
        !trust_edge_projected(&state.db, &edge_hash).await,
        "edge must stay unprojected while target stub is missing"
    );

    // Later: hydrating the target should let a sweep (now keyed on
    // the target) project the previously-stored edge.
    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &to_key, "remote_bob", &home)
            .await
            .expect("to stub");
        sweep_pending_projections(&mut tx, &to_key)
            .await
            .expect("sweep on target");
        tx.commit().await.expect("commit");
    }

    assert!(
        trust_edge_projected(&state.db, &edge_hash).await,
        "sweep keyed on target should project once both stubs exist"
    );
}

/// Two siblings (same prior_edge_hash, same source/target) → sweep
/// projects exactly one of them, not both. Models §9.4 "both stored as
/// evidence" at the receive-path level: the canonical bytes for both
/// siblings remain durable in `signed_objects` regardless of which one
/// wins projection.
#[tokio::test]
async fn sweep_chain_fork_projects_exactly_one_sibling() {
    let (_app, state) = test_app().await;

    let from_signer = seeded_signer(0x77);
    let to_signer = seeded_signer(0x88);
    let from_key = pubkey_of(&from_signer);
    let to_key = pubkey_of(&to_signer);
    let home = [0x99u8; 32];

    // Pre-hydrate so the missing-stub branch is out of the picture.
    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &from_key, "alice", &home)
            .await
            .expect("from stub");
        hydrate_stub_user(&mut tx, &to_key, "bob", &home)
            .await
            .expect("to stub");
        tx.commit().await.expect("commit");
    }

    // Two siblings: both prior_edge_hash = None (i.e. both claim to
    // be the first mutation in the chain), distinct canonical_hashes
    // because stance differs. Real-world this models two devices
    // racing a first-mutation issuance.
    let hash_a = store_unprojected_edge(
        &state.db,
        &from_signer,
        &to_key,
        TrustStance::Trust,
        1_700_000_000_010,
        None,
    )
    .await;
    let hash_b = store_unprojected_edge(
        &state.db,
        &from_signer,
        &to_key,
        TrustStance::Distrust,
        1_700_000_000_011,
        None,
    )
    .await;
    assert_ne!(
        hash_a, hash_b,
        "siblings must have distinct canonical hashes"
    );

    {
        let mut tx = state.db.begin().await.expect("begin");
        sweep_pending_projections(&mut tx, &from_key)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
    }

    // The fixed-point loop sees both candidates with `prior_edge_hash
    // = NULL` (NULL-matches-NULL via the chain-fork OR clause). The
    // first-considered candidate projects; the second hits the
    // chain-fork check and is rejected. Which one wins depends on
    // `signed_objects` row order, but exactly one of the two must
    // project — not zero, not both.
    let a_in = trust_edge_projected(&state.db, &hash_a).await;
    let b_in = trust_edge_projected(&state.db, &hash_b).await;
    assert!(
        a_in ^ b_in,
        "exactly one sibling should project; saw a={a_in} b={b_in}"
    );

    // Both canonical bytes remain durable in signed_objects regardless
    // — the §9.4 evidence requirement.
    let surviving_bytes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM signed_objects \
         WHERE inner_class = 'trust-edge' AND payload IS NOT NULL \
           AND canonical_hash IN (?, ?)",
    )
    .bind(&hash_a[..])
    .bind(&hash_b[..])
    .fetch_one(&state.db)
    .await
    .expect("count signed_objects");
    assert_eq!(
        surviving_bytes, 2,
        "both sibling payloads remain stored as §9.4 evidence",
    );
}

/// Chain E1 → E2 stored out of order (E2 first in row order, E1 second).
/// The fixed-point loop should project E1 in pass 1 and then E2 in pass 2
/// — exercising the loop's progress condition.
#[tokio::test]
async fn sweep_projects_ordered_chain_via_fixed_point() {
    let (_app, state) = test_app().await;

    let from_signer = seeded_signer(0xaa);
    let to_signer = seeded_signer(0xbb);
    let from_key = pubkey_of(&from_signer);
    let to_key = pubkey_of(&to_signer);
    let home = [0xccu8; 32];

    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &from_key, "alice", &home)
            .await
            .expect("from stub");
        hydrate_stub_user(&mut tx, &to_key, "bob", &home)
            .await
            .expect("to stub");
        tx.commit().await.expect("commit");
    }

    // E1: first mutation (prior_edge_hash = None). E2 chains off it.
    let e1 = sign_trust_edge_with_key(
        &from_signer,
        &to_key,
        TrustStance::Trust,
        1_700_000_000_020,
        None,
    );
    let e2 = sign_trust_edge_with_key(
        &from_signer,
        &to_key,
        TrustStance::Distrust,
        1_700_000_000_021,
        Some(e1.canonical_hash),
    );

    // Store E2 *first* so the row order in signed_objects has the
    // chain successor ahead of its predecessor. Without the
    // fixed-point loop, a single pass would project E1 but leave E2
    // as Deferred.
    {
        let mut tx = state.db.begin().await.expect("begin");
        store_signed_object(
            &mut *tx,
            "trust-edge",
            &e2.payload,
            &e2.signature,
            &e2.canonical_hash,
        )
        .await
        .expect("store e2");
        store_signed_object(
            &mut *tx,
            "trust-edge",
            &e1.payload,
            &e1.signature,
            &e1.canonical_hash,
        )
        .await
        .expect("store e1");
        tx.commit().await.expect("commit");
    }

    {
        let mut tx = state.db.begin().await.expect("begin");
        sweep_pending_projections(&mut tx, &from_key)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
    }

    assert!(
        trust_edge_projected(&state.db, &e1.canonical_hash).await,
        "E1 (chain head) must project",
    );
    assert!(
        trust_edge_projected(&state.db, &e2.canonical_hash).await,
        "E2 (chain successor) must project in the same sweep call via fixed-point",
    );
}

/// Orphan edge: E2 has prior=E1.hash but E1 was never stored. Sweep must
/// NOT project E2 (chain-continuity); the bytes remain stored for a
/// future §9.3 backfill or re-push.
#[tokio::test]
async fn sweep_defers_orphan_edge_with_missing_predecessor() {
    let (_app, state) = test_app().await;

    let from_signer = seeded_signer(0xdd);
    let to_signer = seeded_signer(0xee);
    let from_key = pubkey_of(&from_signer);
    let to_key = pubkey_of(&to_signer);
    let home = [0xffu8; 32];

    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &from_key, "alice", &home)
            .await
            .expect("from stub");
        hydrate_stub_user(&mut tx, &to_key, "bob", &home)
            .await
            .expect("to stub");
        tx.commit().await.expect("commit");
    }

    // Phantom predecessor: a hash that no signed_object carries.
    let phantom_prior = [0x42u8; 32];
    let orphan_hash = store_unprojected_edge(
        &state.db,
        &from_signer,
        &to_key,
        TrustStance::Trust,
        1_700_000_000_030,
        Some(phantom_prior),
    )
    .await;

    {
        let mut tx = state.db.begin().await.expect("begin");
        sweep_pending_projections(&mut tx, &from_key)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
    }

    assert!(
        !trust_edge_projected(&state.db, &orphan_hash).await,
        "orphan with missing predecessor must not project",
    );

    // But the bytes are still durable — a later §9.3 backfill that
    // delivers the missing predecessor can re-trigger projection.
    let slice: &[u8] = orphan_hash.as_slice();
    let still_stored: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM signed_objects \
         WHERE canonical_hash = ? AND payload IS NOT NULL",
    )
    .bind(slice)
    .fetch_one(&state.db)
    .await
    .expect("count");
    assert_eq!(
        still_stored, 1,
        "orphan bytes remain durable in signed_objects"
    );
}

// ===========================================================================
// §9.8 — pending orphan buffer
// ===========================================================================

/// `evict_expired_pending_trust_edges` deletes only rows whose
/// `received_at` is more than `ttl_ms` behind `now_ms`. Fresh rows
/// survive. Drives §9.6 `DEFERRED_ORPHAN_TTL` directly.
#[tokio::test]
async fn evict_drops_expired_pending_rows_and_preserves_fresh() {
    let (_app, state) = test_app().await;

    // Two synthetic pending rows: one ancient (received 2h ago), one
    // fresh (received "now"). Insert via raw SQL — the public surface
    // doesn't expose the enqueue path directly, and we only need the
    // row shape, not the receive-path machinery, for this test.
    let now_ms: i64 = chrono::Utc::now().timestamp_millis();
    let two_hours_ago = now_ms - 2 * 3600 * 1000;
    let source_old = [0x11u8; 32];
    let source_new = [0x22u8; 32];
    let target = [0x33u8; 32];
    let prior_old = [0x44u8; 32];
    let prior_new = [0x55u8; 32];
    let canonical_old = [0x66u8; 32];
    let canonical_new = [0x77u8; 32];

    for (source, prior, canonical, received_at) in [
        (&source_old, &prior_old, &canonical_old, two_hours_ago),
        (&source_new, &prior_new, &canonical_new, now_ms),
    ] {
        let s: &[u8] = source.as_slice();
        let t: &[u8] = target.as_slice();
        let p: &[u8] = prior.as_slice();
        let c: &[u8] = canonical.as_slice();
        let payload: &[u8] = &[0xAB, 0xCD];
        let signature: &[u8] = &[0xEF, 0x01];
        sqlx::query!(
            "INSERT INTO pending_trust_edges \
                (source_pubkey, target_pubkey, prior_edge_hash, canonical_hash, \
                 payload, signature, received_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            s,
            t,
            p,
            c,
            payload,
            signature,
            received_at,
        )
        .execute(&state.db)
        .await
        .expect("insert pending");
    }

    let ttl_ms = DEFERRED_ORPHAN_TTL.as_millis() as i64;
    let evicted = evict_expired_pending_trust_edges(&state.db, now_ms, ttl_ms)
        .await
        .expect("evict");
    assert_eq!(evicted, 1, "exactly the ancient row should be evicted");

    assert_eq!(
        pending_row_count(&state.db, &source_old, &prior_old).await,
        0,
        "ancient row gone",
    );
    assert_eq!(
        pending_row_count(&state.db, &source_new, &prior_new).await,
        1,
        "fresh row preserved",
    );
}

/// `sweep_pending_projections` projects a stored predecessor edge and —
/// via the §9.8 drain extension — promotes the orphan that was buffered
/// against that predecessor in the same transaction. Verifies the
/// cascade closes atomically: E1 lands in `trust_edges`, E2 promotes from
/// `pending_trust_edges` into `trust_edges` + `signed_objects`, and the
/// pending row is deleted.
#[tokio::test]
async fn sweep_projection_drains_buffered_orphan_chain() {
    let (_app, state) = test_app().await;

    let from_signer = seeded_signer(0xa1);
    let to_signer = seeded_signer(0xa2);
    let from_key = pubkey_of(&from_signer);
    let to_key = pubkey_of(&to_signer);
    let home = [0xa3u8; 32];

    // Both endpoints get federated stubs so the projection's FK
    // resolution finds users rows.
    {
        let mut tx = state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &from_key, "alice", &home)
            .await
            .expect("from stub");
        hydrate_stub_user(&mut tx, &to_key, "bob", &home)
            .await
            .expect("to stub");
        tx.commit().await.expect("commit");
    }

    // Build E1 (root, prior=None) and E2 (chains off E1).
    let e1 = sign_trust_edge_with_key(
        &from_signer,
        &to_key,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let e2 = sign_trust_edge_with_key(
        &from_signer,
        &to_key,
        TrustStance::Distrust,
        1_700_000_000_001,
        Some(e1.canonical_hash),
    );

    // Stage E1 in `signed_objects` *unprojected* — sweep is supposed
    // to find it. Stage E2 in `pending_trust_edges` keyed on
    // `(from_key, e1.canonical_hash)` — the drain trigger.
    {
        let mut tx = state.db.begin().await.expect("begin");
        store_signed_object(
            &mut *tx,
            "trust-edge",
            &e1.payload,
            &e1.signature,
            &e1.canonical_hash,
        )
        .await
        .expect("store e1");

        // Direct INSERT into pending_trust_edges — `enqueue_pending_trust_edge`
        // is pub(crate), but the row shape is stable and the test
        // exercises the projection-cascade contract, not the enqueue
        // wire path (covered at Layer 1).
        let now_ms = chrono::Utc::now().timestamp_millis();
        let source_slice: &[u8] = from_key.as_slice();
        let target_slice: &[u8] = to_key.as_slice();
        let prior_slice: &[u8] = e1.canonical_hash.as_slice();
        let canonical_slice: &[u8] = e2.canonical_hash.as_slice();
        let payload_slice: &[u8] = e2.payload.as_slice();
        let signature_slice: &[u8] = e2.signature.as_slice();
        sqlx::query!(
            "INSERT INTO pending_trust_edges \
                (source_pubkey, target_pubkey, prior_edge_hash, canonical_hash, \
                 payload, signature, received_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            source_slice,
            target_slice,
            prior_slice,
            canonical_slice,
            payload_slice,
            signature_slice,
            now_ms,
        )
        .execute(&mut *tx)
        .await
        .expect("insert pending");

        tx.commit().await.expect("commit");
    }

    // Pre-sweep: E1 stored, E2 only in pending, neither in trust_edges.
    assert!(signed_object_live(&state.db, &e1.canonical_hash).await);
    assert!(!signed_object_live(&state.db, &e2.canonical_hash).await);
    assert!(!trust_edge_present(&state.db, &e1.canonical_hash).await);
    assert!(!trust_edge_present(&state.db, &e2.canonical_hash).await);
    assert_eq!(
        pending_row_count(&state.db, &from_key, &e1.canonical_hash).await,
        1,
    );

    // Run the sweep. E1 projects via the §9.6 fixed-point loop; the
    // §9.8 drain extension then promotes E2 from the pending buffer.
    {
        let mut tx = state.db.begin().await.expect("begin");
        sweep_pending_projections(&mut tx, &from_key)
            .await
            .expect("sweep");
        tx.commit().await.expect("commit");
    }

    assert!(
        trust_edge_present(&state.db, &e1.canonical_hash).await,
        "E1 must project via the sweep",
    );
    assert!(
        trust_edge_present(&state.db, &e2.canonical_hash).await,
        "E2 must promote from pending via the drain extension",
    );
    assert!(
        signed_object_live(&state.db, &e2.canonical_hash).await,
        "promoted orphan's bytes must land in signed_objects too",
    );
    assert_eq!(
        pending_row_count(&state.db, &from_key, &e1.canonical_hash).await,
        0,
        "pending row deleted after drain",
    );
}

/// A `deferred` push response is backed by a freshly-inserted row in
/// `pending_trust_edges` keyed on `(source, prior)`. The phantom
/// predecessor never arrives, so the row stays put. Deferred
/// specifically does NOT store the bytes in `signed_objects` — the
/// pending buffer is the sole durable layer until promotion. (Subsumes
/// the old `push_with_unknown_prior_hash_is_deferred`: that test only
/// asserted `deferred` + no projection; this one additionally pins the
/// pending-row buffer and the no-double-land invariant.)
#[tokio::test]
async fn deferred_push_buffers_orphan_in_pending_table() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice = SigningKey::generate(&mut OsRng);
    let bob = SigningKey::generate(&mut OsRng);
    let alice_pub = alice.verifying_key().to_bytes();
    let bob_pub = bob.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;

    let phantom_prior = [0x42u8; 32];
    let signed = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        Some(phantom_prior),
    );
    let body = encode_edges_body(&[encode_wire(&signed.payload, &signed.signature)]);

    let (status, resp_body) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "request-level OK");
    let results = parse_results_body(&resp_body);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, "deferred", "orphan must defer");

    // Pending row landed under the spec-mandated key shape.
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &phantom_prior).await,
        1,
        "single pending row keyed on (source, prior)",
    );

    // Deferred specifically does NOT store the bytes in signed_objects
    // — the pending buffer is the sole durable layer until promotion.
    assert!(
        !signed_object_live(&b.state.db, &signed.canonical_hash).await,
        "deferred bytes must not double-land in signed_objects",
    );
    assert!(
        !trust_edge_present(&b.state.db, &signed.canonical_hash).await,
        "deferred orphan must not project",
    );
}

/// Re-pushing the same orphan (or pushing a sibling with the same
/// `(source, prior)` gap) does NOT double-enqueue — `INSERT OR IGNORE`
/// on the pending PK collapses retries into the existing row. Both
/// responses are `deferred`.
#[tokio::test]
async fn duplicate_orphan_for_same_gap_does_not_double_enqueue() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice = SigningKey::generate(&mut OsRng);
    let bob = SigningKey::generate(&mut OsRng);
    let alice_pub = alice.verifying_key().to_bytes();
    let bob_pub = bob.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;

    let phantom_prior = [0x42u8; 32];
    let signed = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        Some(phantom_prior),
    );
    let body = encode_edges_body(&[encode_wire(&signed.payload, &signed.signature)]);

    // First push: enqueues, status `deferred`.
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
    assert_eq!(parse_results_body(&b1)[0].1, "deferred");
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &phantom_prior).await,
        1,
    );

    // Second push of the exact same bytes: still `deferred`, still
    // exactly one row buffered.
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
    assert_eq!(parse_results_body(&b2)[0].1, "deferred");
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &phantom_prior).await,
        1,
        "INSERT OR IGNORE collapses retries to one pending row",
    );

    // Sibling with the same prior but a different stance — still
    // shares the gap, still does not double-enqueue. (The dedup is
    // keyed on (source, prior), not on canonical_hash.)
    let sibling = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Distrust,
        1_700_000_000_001,
        Some(phantom_prior),
    );
    let body2 = encode_edges_body(&[encode_wire(&sibling.payload, &sibling.signature)]);
    let (status3, b3) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body2,
    )
    .await;
    assert_eq!(status3, StatusCode::OK);
    assert_eq!(parse_results_body(&b3)[0].1, "deferred");
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &phantom_prior).await,
        1,
        "sibling for same gap collapses into the existing pending row",
    );
}

/// E2 arrives first (orphan, deferred); E1 arrives second. The
/// receive-path drain extension projects E2 atomically with E1's
/// projection, deletes the pending row, and persists E2's canonical
/// bytes in `signed_objects` for future relay / audit.
#[tokio::test]
async fn root_push_drains_buffered_orphan_chain() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let b = harness.instance("b");

    let alice = SigningKey::generate(&mut OsRng);
    let bob = SigningKey::generate(&mut OsRng);
    let alice_pub = alice.verifying_key().to_bytes();
    let bob_pub = bob.verifying_key().to_bytes();
    insert_user_with_pubkey(&b.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;

    let e1 = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let e2 = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Distrust,
        1_700_000_000_001,
        Some(e1.canonical_hash),
    );

    // Push E2 first — orphan, defers.
    let body_e2 = encode_edges_body(&[encode_wire(&e2.payload, &e2.signature)]);
    let (s1, b1) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body_e2,
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(parse_results_body(&b1)[0].1, "deferred");
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &e1.canonical_hash).await,
        1,
    );
    assert!(!trust_edge_present(&b.state.db, &e2.canonical_hash).await);
    assert!(!signed_object_live(&b.state.db, &e2.canonical_hash).await);

    // Push E1 — applies, and the same-tx drain promotes E2.
    let body_e1 = encode_edges_body(&[encode_wire(&e1.payload, &e1.signature)]);
    let (s2, b2) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body_e1,
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(parse_results_body(&b2)[0].1, "applied");

    assert!(
        trust_edge_present(&b.state.db, &e1.canonical_hash).await,
        "E1 projects on E1's own push",
    );
    assert!(
        trust_edge_present(&b.state.db, &e2.canonical_hash).await,
        "E2 promotes from pending via drain on E1's projection",
    );
    assert!(
        signed_object_live(&b.state.db, &e2.canonical_hash).await,
        "drain persists the orphan's bytes into signed_objects",
    );
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &e1.canonical_hash).await,
        0,
        "pending row deleted after promotion",
    );
}

/// Autonomous §9.3 backfill: B receives an orphan whose source key has
/// its home_instance pointing at A. B fires `request_edge_predecessor`
/// after the receive tx commits, A serves the predecessor over
/// `/edges/backfill`, B feeds it back through the receive path, and the
/// buffered orphan promotes — without an additional sender push.
///
/// Keeps a bounded `poll_until`: the recovery rides a raw `tokio::spawn`
/// of `request_edge_predecessor` that `settle` does not drive.
#[tokio::test]
async fn autonomous_backfill_recovers_chain_from_source_home() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_peer = *a.peer_id.as_bytes();

    // Both alice and bob exist as local users on A so A's
    // /edges/backfill handler can join trust_edges + signed_objects
    // and serve the chain.
    let alice = SigningKey::generate(&mut OsRng);
    let bob = SigningKey::generate(&mut OsRng);
    let alice_pub = alice.verifying_key().to_bytes();
    let bob_pub = bob.verifying_key().to_bytes();
    insert_user_with_pubkey(&a.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&a.state.db, "user-bob", "bob", &bob_pub).await;

    let e1 = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let e2 = sign_trust_edge_with_key(
        &alice,
        &bob_pub,
        TrustStance::Distrust,
        1_700_000_000_001,
        Some(e1.canonical_hash),
    );

    // Bring A to a state where it has E1 and E2 both projected:
    // push both from B → A (B is the active peer, envelope sender).
    let body_both = encode_edges_body(&[
        encode_wire(&e1.payload, &e1.signature),
        encode_wire(&e2.payload, &e2.signature),
    ]);
    let (sa, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/edges",
        &body_both,
    )
    .await;
    assert_eq!(sa, StatusCode::OK, "seed push to A");
    assert!(trust_edge_present(&a.state.db, &e1.canonical_hash).await);
    assert!(trust_edge_present(&a.state.db, &e2.canonical_hash).await);

    // On B: bob is a local user; alice is a federated stub whose
    // home_instance points at A, so B's autonomous backfill issuer
    // resolves alice's home to A's peer_id.
    insert_user_with_pubkey(&b.state.db, "user-bob", "bob", &bob_pub).await;
    {
        let mut tx = b.state.db.begin().await.expect("begin");
        hydrate_stub_user(&mut tx, &alice_pub, "alice", &a_peer)
            .await
            .expect("alice stub");
        tx.commit().await.expect("commit");
    }

    // Push only E2 to B. B sees the orphan, defers, enqueues, and
    // spawns the autonomous backfill aimed at A.
    let body_e2 = encode_edges_body(&[encode_wire(&e2.payload, &e2.signature)]);
    let (sb, body_b) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/edges",
        &body_e2,
    )
    .await;
    assert_eq!(sb, StatusCode::OK);
    assert_eq!(parse_results_body(&body_b)[0].1, "deferred");
    assert_eq!(
        pending_row_count(&b.state.db, &alice_pub, &e1.canonical_hash).await,
        1,
        "orphan buffered before the backfill round-trips",
    );

    // The spawned backfill task: GET /edges/backfill?source=alice&target=bob
    // → A returns E1 → B re-feeds → E1 projects on B → drain promotes E2.
    // Asynchronous from the push's perspective; poll with a bounded
    // wait. 2s is generous for in-process transport.
    let db = b.state.db.clone();
    let e1_hash = e1.canonical_hash;
    let e2_hash = e2.canonical_hash;
    let alice_pub_copy = alice_pub;
    let e1_hash_copy = e1.canonical_hash;
    let ok = poll_until(2000, move || {
        let db = db.clone();
        async move {
            trust_edge_present(&db, &e1_hash).await
                && trust_edge_present(&db, &e2_hash).await
                && pending_row_count(&db, &alice_pub_copy, &e1_hash_copy).await == 0
        }
    })
    .await;
    assert!(
        ok,
        "autonomous backfill did not close the chain within deadline: \
         E1 projected={} E2 projected={} pending={}",
        trust_edge_present(&b.state.db, &e1.canonical_hash).await,
        trust_edge_present(&b.state.db, &e2.canonical_hash).await,
        pending_row_count(&b.state.db, &alice_pub, &e1.canonical_hash).await,
    );

    // After the round-trip, E1's bytes are stored on B and E2's
    // bytes were promoted out of pending into signed_objects.
    assert!(signed_object_live(&b.state.db, &e1.canonical_hash).await);
    assert!(signed_object_live(&b.state.db, &e2.canonical_hash).await);
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Decode 64-char lowercase hex into 32 bytes.
fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "pubkey hex must be 64 chars");
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    out
}

/// Lowercase hex of a 32-byte pubkey. Matches the format
/// `backfill::decode_hex_pubkey` accepts.
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("hi nibble"));
        s.push(char::from_digit((b & 0x0F) as u32, 16).expect("lo nibble"));
    }
    s
}

/// Push body builder: wrap each `(payload, signature)` pair into a
/// canonical WireFormat blob and pack the lot under
/// `{ "edges": [bstr, ...] }`.
fn encode_edges_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("edges".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + wires.iter().map(|w| w.len()).sum::<usize>());
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// Encode a §6.3 WireFormat `{ "p", "s" }`. Mirrors the in-module
/// `envelope::encode_signed_object` helper: tests build wire bytes the
/// same way senders do.
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

/// Insert a `users` row with a known Ed25519 public key on the receiver,
/// so an inbound edge naming that key as an endpoint projects into
/// `trust_edges`. Mirrors the minimum-columns INSERT the signup path uses
/// for the non-PII fixture.
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

/// Deterministic Ed25519 signer from a seed byte. Real signers (not raw
/// pubkeys) so the canonical_hash chain across siblings is meaningful.
fn seeded_signer(seed: u8) -> SigningKey {
    let mut rng = StdRng::seed_from_u64(seed as u64);
    SigningKey::generate(&mut rng)
}

fn pubkey_of(k: &SigningKey) -> [u8; 32] {
    *k.verifying_key().as_bytes()
}

/// Sign a chain of `(stance, created_at_ms)` mutations, threading each
/// row's `canonical_hash` into the next as `prior_edge_hash`. The
/// bare-bones equivalent of what `set_trust_edge` does inside the server,
/// but without touching any DB.
fn sign_chain(
    signer: &SigningKey,
    target_pub: &[u8; 32],
    stances: &[(TrustStance, u64)],
) -> Vec<SigningOutput> {
    let mut chain = Vec::with_capacity(stances.len());
    let mut prior: Option<[u8; 32]> = None;
    for (stance, ts) in stances {
        let signed = sign_trust_edge_with_key(signer, target_pub, *stance, *ts, prior);
        prior = Some(signed.canonical_hash);
        chain.push(signed);
    }
    chain
}

/// Push every signed edge in `chain` to `receiver` (one edge per
/// request, mirroring the typical real-world flow where edges land over
/// time). Returns when every push has been acknowledged.
async fn push_chain(
    harness: &MultiInstanceHarness,
    sender: &str,
    receiver: &str,
    chain: &[SigningOutput],
) {
    for signed in chain {
        let wire = encode_wire(&signed.payload, &signed.signature);
        let body = encode_edges_body(&[wire]);
        let (status, _resp) = send_envelope_signed(
            harness,
            sender,
            receiver,
            Method::POST,
            "/federation/v1/edges",
            &body,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "push setup must succeed");
    }
}

/// Decoded `{ objects, [next_cursor], complete }` body from
/// `/federation/v1/edges/backfill`.
struct BackfillBody {
    /// Each entry is the raw bytes of one §6.3 WireFormat blob — the same
    /// shape the §9.1 push body expects, so replay is a direct
    /// `encode_edges_body(&objects)`.
    objects: Vec<Vec<u8>>,
    /// Opaque cursor for the next page, present iff `complete = false`.
    next_cursor: Option<Vec<u8>>,
    complete: bool,
}

fn parse_backfill_body(bytes: &[u8]) -> BackfillBody {
    let v: Value = ciborium::de::from_reader(bytes).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("backfill body is not a map");
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
    BackfillBody {
        objects: objects.expect("missing `objects`"),
        next_cursor,
        complete: complete.expect("missing `complete`"),
    }
}

/// Issue `GET /federation/v1/edges/backfill?...` from `from` to `to`,
/// signing under the empty body and the query-less path per §6.5 step 9.
/// Returns `(status, body)`.
async fn get_backfill(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    source_hex: &str,
    target_hex: &str,
    limit: Option<u32>,
    since_b64: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let mut query = format!("source={source_hex}&target={target_hex}");
    if let Some(n) = limit {
        query.push_str(&format!("&limit={n}"));
    }
    if let Some(c) = since_b64 {
        query.push_str(&format!("&since={c}"));
    }
    let signed_path = "/federation/v1/edges/backfill";
    let dispatch_uri = format!("{signed_path}?{query}");
    send_envelope_signed_split(
        harness,
        from,
        to,
        Method::GET,
        signed_path,
        &dispatch_uri,
        b"",
    )
    .await
}

/// Build a minimal §8.3 `FrontierAnnounce` whose `expansion_filter` is
/// populated with `interested_keys` and whose `visible_filter` is empty.
///
/// The empty `visible_filter` is load-bearing. `classify_mode` (§7.2)
/// measures the receiver's coverage of the *announcer's* visible filter
/// to decide the sender→announcer `outbound_mode`: an `all_ones_sentinel`
/// here scores 100% coverage and promotes the pair to `Mode::All`, which
/// floods every object past the per-class bloom check. Under `All` the
/// trust-edge `expansion_filter` is never consulted, so a routing-key
/// assertion would pass regardless of source-vs-target. A non-covering
/// (empty) visible filter keeps the pair in `Mode::Filtered` so the
/// expansion-membership test actually decides delivery.
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
    let visible = BloomFilter::new_empty(7, 1024, 0, 0.01).expect("build empty visible filter");
    FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: FilterSpec::from_bloom(&visible),
        expansion_filter: FilterSpec::from_bloom(&edge),
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
}

/// Like [`announce_with_edge_origin_keys`] but also carries §8.3
/// `age_ceilings`, so the receiver advertises a per-root age cutoff — the
/// input the forwarder's §8.10 source-side shedding pre-filter consults
/// before relaying a trust-edge keyed on that root.
fn announce_with_edge_keys_and_ceilings(
    interested_keys: &[&[u8; 32]],
    ceilings: std::collections::BTreeMap<[u8; 32], u64>,
) -> FrontierAnnounce {
    let mut announce = announce_with_edge_origin_keys(interested_keys);
    announce.age_ceilings = ceilings;
    announce
}

/// Insert a `user_genesis` attestation row so the forwarder's §8.10
/// pre-filter can read an instance-attested `genesis_at` for `key`. The
/// `birth_instance_key` / `attestation_sig` are correct-length
/// placeholders — the shedding resolver only reads `genesis_at`.
async fn insert_user_genesis(db: &SqlitePool, key: &[u8; 32], genesis_at: i64) {
    let key_slice: &[u8] = key.as_slice();
    let birth_instance: &[u8] = &[0u8; 32];
    let sig: &[u8] = &[0u8; 64];
    sqlx::query!(
        "INSERT INTO user_genesis (user_key, genesis_at, birth_instance_key, attestation_sig) \
         VALUES (?, ?, ?, ?)",
        key_slice,
        genesis_at,
        birth_instance,
        sig,
    )
    .execute(db)
    .await
    .expect("insert user_genesis");
}

/// Store the signed payload + signature in `signed_objects` without
/// projecting into `trust_edges`. Mirrors what `apply_one_edge` does in
/// the `EndpointMissing` branch — sets up the "stored-but-unprojected"
/// precondition for the Layer-0 sweep tests.
async fn store_unprojected_edge(
    db: &SqlitePool,
    signing_key: &SigningKey,
    to_key: &[u8; 32],
    stance: TrustStance,
    created_at_ms: u64,
    prior_edge_hash: Option<[u8; 32]>,
) -> [u8; 32] {
    let out = sign_trust_edge_with_key(signing_key, to_key, stance, created_at_ms, prior_edge_hash);
    let mut tx = db.begin().await.expect("begin tx");
    store_signed_object(
        &mut *tx,
        "trust-edge",
        &out.payload,
        &out.signature,
        &out.canonical_hash,
    )
    .await
    .expect("store signed_object");
    tx.commit().await.expect("commit");
    out.canonical_hash
}

/// Count rows in `trust_edges` matching `canonical_hash`. true =
/// projected, false = not projected.
async fn trust_edge_projected(db: &SqlitePool, canonical_hash: &[u8; 32]) -> bool {
    let slice: &[u8] = canonical_hash.as_slice();
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trust_edges WHERE canonical_hash = ?")
        .bind(slice)
        .fetch_one(db)
        .await
        .expect("count trust_edges");
    n > 0
}

/// Count rows in `pending_trust_edges` keyed on `(source, prior)`.
async fn pending_row_count(db: &SqlitePool, source: &[u8; 32], prior: &[u8; 32]) -> i64 {
    let s: &[u8] = source.as_slice();
    let p: &[u8] = prior.as_slice();
    sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM pending_trust_edges \
         WHERE source_pubkey = ? AND prior_edge_hash = ?",
        s,
        p,
    )
    .fetch_one(db)
    .await
    .expect("pending count")
}

/// Count rows in `trust_edges` matching `canonical_hash`.
async fn trust_edge_present(db: &SqlitePool, canonical_hash: &[u8; 32]) -> bool {
    let h: &[u8] = canonical_hash.as_slice();
    let n: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM trust_edges WHERE canonical_hash = ?",
        h,
    )
    .fetch_one(db)
    .await
    .expect("trust_edges count");
    n > 0
}

/// `signed_objects` payload present (live row, not erased).
async fn signed_object_live(db: &SqlitePool, canonical_hash: &[u8; 32]) -> bool {
    let h: &[u8] = canonical_hash.as_slice();
    let n: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects \
         WHERE canonical_hash = ? AND payload IS NOT NULL",
        h,
    )
    .fetch_one(db)
    .await
    .expect("signed_objects count");
    n > 0
}

/// Poll `predicate` up to `timeout_ms`. Used only by
/// `autonomous_backfill_recovers_chain_from_source_home`, whose recovery
/// rides a raw `tokio::spawn` of `request_edge_predecessor` that `settle`
/// does not drive.
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
