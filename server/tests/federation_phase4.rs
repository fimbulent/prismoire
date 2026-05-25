//! Phase-4 Layer-1 integration tests: §8 frontier sync.
//!
//! Pins the Phase-4 done-when criteria from
//! `docs/federation-impl-plan.md`:
//!
//! - `POST /federation/v1/frontier/announce` accepts a §8.3 body from
//!   an active peer and persists a `peer_frontiers` row.
//! - The same announce replayed at the same `version` is idempotent
//!   (200 with the same cursor; no extra row).
//! - `POST /federation/v1/frontier/delta` applies the §8.4 OR-mask to
//!   the stored bytes when `prev_version` matches.
//! - A delta with a stale `prev_version` returns 409 with the stored
//!   `current_version`; a delta when no prior announce exists returns
//!   409 with `current_version = 0`.
//! - `GET /federation/v1/frontier` returns the *local* frontier
//!   snapshot, and short-circuits to 304 when the supplied `since`
//!   cursor matches what we'd return.
//! - The §7.2 mode classifier flips between `Filtered` and `All` when
//!   coverage crosses the HIGH / LOW thresholds.
//!
//! All tests use the existing `MultiInstanceHarness` so the
//! envelope-verifier (Phase 3) middleware sits in front of every
//! handler the way it does in production.
//!
//! The §7.4 `peers_interested_in` routing path itself is covered by
//! the unit tests in `src/federation/routing.rs` — they don't need a
//! multi-instance harness to exercise the filter-dispatch logic, and
//! the round-trip through `peer_frontiers` is asserted here via the
//! direct DB read in the announce / delta tests below.

#![cfg(feature = "test-auth")]

mod common;

use std::sync::Arc;

use axum::body::Bytes;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::Value;
use http::{Method, Request, StatusCode};
use prismoire_server::federation::bloom::BloomFilter;
use prismoire_server::federation::envelope;
use prismoire_server::federation::frontier::{
    FilterSpec, FrontierAnnounce, FrontierDelta, FrontierSnapshot, operator_announce_frontier,
};
use prismoire_server::federation::identity::CBOR_CONTENT_TYPE;
use prismoire_server::federation::peering::{
    operator_accept_peer_request, operator_initiate_peer_request,
};
use prismoire_server::federation::routing::{HIGH_THRESHOLD, Mode, classify_mode};
use prismoire_server::federation::transport::{FederationTransport, PeerId};

use common::federation::MultiInstanceHarness;

/// Drive A through the initiate → B accepts dance so the test starts
/// from "mutual active peering". Mirrors the helper in
/// `federation_phase3.rs` so we don't depend on its module being
/// importable across test crates.
async fn establish_active_peering(harness: &MultiInstanceHarness, initiator: &str, target: &str) {
    let i = harness.instance(initiator);
    let t = harness.instance(target);
    let i_transport: Arc<dyn FederationTransport> = i.transport.clone();
    let request_id = operator_initiate_peer_request(
        &i.state.db,
        &i.state.instance_key,
        &i.state.instance_domain,
        &i_transport,
        *t.state.instance_key.public_bytes(),
        &t.state.instance_domain,
        vec!["edge-sync".into(), "content-sync".into()],
        None,
    )
    .await
    .expect("operator_initiate_peer_request");
    let t_transport: Arc<dyn FederationTransport> = t.transport.clone();
    operator_accept_peer_request(
        &t.state.db,
        &t.state.instance_key,
        &t.state.instance_domain,
        &t_transport,
        request_id,
    )
    .await
    .expect("operator_accept_peer_request");
}

/// Done-when (1) of Phase 4: announce reaches the handler, the
/// envelope-verifier accepts it because the sender is an active peer,
/// and the row lands in `peer_frontiers` keyed by the sender's pubkey.
#[tokio::test]
async fn announce_persists_a_peer_frontiers_row() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let a = harness.instance("a");
    let b = harness.instance("b");
    let b_pub = *b.state.instance_key.public_bytes();

    // A announces *its own* frontier to B. The operator helper
    // refreshes the local snapshot before dispatch, so this also
    // exercises the BFS / bloom path end-to-end (empty trust graph
    // here → empty bloom but a valid wire body).
    let version = operator_announce_frontier(
        &a.state,
        &a.state.instance_key,
        &(a.transport.clone() as Arc<dyn FederationTransport>),
        b_pub,
    )
    .await
    .expect("operator_announce_frontier");

    // The row B persisted should be keyed by A's pubkey, not B's.
    let a_pub_bytes: &[u8] = a.state.instance_key.public_bytes();
    let row = sqlx::query!(
        "SELECT applied_version, cf_family, ef_family FROM peer_frontiers WHERE peer_pubkey = ?",
        a_pub_bytes,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("peer_frontiers row");
    assert_eq!(row.applied_version as u64, version);
    assert_eq!(row.cf_family, "prismoire-bloom-v1");
    assert_eq!(row.ef_family, "prismoire-bloom-v1");
}

/// Done-when (2) of Phase 4: a same-version replay of the announce is
/// idempotent (200 OK, same cursor) and does not bump the stored
/// version. The §8.3 spec requires "same `version` is a no-op".
#[tokio::test]
async fn announce_at_same_version_is_idempotent() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Hand-roll the announce body so we can dispatch the *exact same
    // wire bytes* twice (the operator helper would refresh and
    // potentially bump the version between calls).
    let body = FrontierAnnounce {
        version: 1_000,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        content_filter: empty_filter_spec(),
        edge_origin_filter: empty_filter_spec(),
    }
    .encode();

    let resp1 = send_announce_envelope(&harness, "a", "b", &body).await;
    assert_eq!(resp1.status, StatusCode::OK);
    let resp2 = send_announce_envelope(&harness, "a", "b", &body).await;
    assert_eq!(resp2.status, StatusCode::OK);
    assert_eq!(
        resp1.cursor, resp2.cursor,
        "same-version replay returns the same cursor"
    );

    // And the row's applied_version is still 1000, not bumped.
    let a_pub: &[u8] = a.state.instance_key.public_bytes();
    let stored = sqlx::query_scalar!(
        "SELECT applied_version FROM peer_frontiers WHERE peer_pubkey = ?",
        a_pub,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("applied_version");
    assert_eq!(stored as u64, 1_000);
}

/// Done-when (3) of Phase 4: a delta OR-masked on top of an existing
/// announce updates the stored bytes and bumps `applied_version`.
#[tokio::test]
async fn delta_or_mask_updates_filter_bytes_and_version() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Announce a baseline at version 5.
    let baseline = FrontierAnnounce {
        version: 5,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        content_filter: empty_filter_spec(),
        edge_origin_filter: empty_filter_spec(),
    }
    .encode();
    let announce_resp = send_announce_envelope(&harness, "a", "b", &baseline).await;
    assert_eq!(announce_resp.status, StatusCode::OK);

    // Send a delta at version 6 that flips one byte in the content
    // mask. Filter shape is m=64 → 8 bytes; mask shape matches.
    let mut mask = vec![0u8; 8];
    mask[3] = 0b1010_1010;
    let delta_body = FrontierDelta {
        prev_version: 5,
        new_version: 6,
        content_mask: Some(mask.clone()),
        edge_origin_mask: None,
    }
    .encode();
    let delta_resp = send_delta_envelope(&harness, "a", "b", &delta_body).await;
    assert_eq!(delta_resp.status, StatusCode::OK);

    let a_pub: &[u8] = a.state.instance_key.public_bytes();
    let row = sqlx::query!(
        "SELECT applied_version, cf_bytes FROM peer_frontiers WHERE peer_pubkey = ?",
        a_pub,
    )
    .fetch_one(&b.state.db)
    .await
    .expect("peer_frontiers row");
    assert_eq!(row.applied_version as u64, 6, "version bumped to 6");
    assert_eq!(
        row.cf_bytes[3], 0b1010_1010,
        "byte index 3 reflects the OR-mask"
    );
}

/// Done-when (4) of Phase 4: a delta whose `prev_version` does not
/// match the stored `applied_version` returns 409 with a
/// `current_version` field set to what we *do* have.
#[tokio::test]
async fn delta_with_stale_prev_version_returns_409_with_current() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // Establish a baseline at version 10.
    let body = FrontierAnnounce {
        version: 10,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        content_filter: empty_filter_spec(),
        edge_origin_filter: empty_filter_spec(),
    }
    .encode();
    assert_eq!(
        send_announce_envelope(&harness, "a", "b", &body)
            .await
            .status,
        StatusCode::OK
    );

    // Now send a delta claiming prev=7 (stale).
    let delta = FrontierDelta {
        prev_version: 7,
        new_version: 11,
        content_mask: Some(vec![0u8; 8]),
        edge_origin_mask: None,
    }
    .encode();
    let resp = send_delta_envelope(&harness, "a", "b", &delta).await;
    assert_eq!(resp.status, StatusCode::CONFLICT);

    let body: Value = ciborium::de::from_reader(resp.body.as_slice()).expect("cbor parse");
    let map = match body {
        Value::Map(m) => m,
        _ => panic!("expected CBOR map"),
    };
    let current_version = map
        .iter()
        .find_map(|(k, v)| match k {
            Value::Text(t) if t == "current_version" => match v {
                Value::Integer(i) => Some(u64::try_from(*i).expect("u64 cast")),
                _ => None,
            },
            _ => None,
        })
        .expect("current_version field");
    assert_eq!(
        current_version, 10,
        "409 carries our actual applied_version"
    );
}

/// Done-when (5) of Phase 4: a delta with no prior announce returns
/// 409 with `current_version = 0` so the sender knows it must
/// re-announce.
#[tokio::test]
async fn delta_without_prior_announce_returns_409_with_zero() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    let delta = FrontierDelta {
        prev_version: 0,
        new_version: 1,
        content_mask: Some(vec![0u8; 8]),
        edge_origin_mask: None,
    }
    .encode();
    let resp = send_delta_envelope(&harness, "a", "b", &delta).await;
    assert_eq!(resp.status, StatusCode::CONFLICT);
    let body: Value = ciborium::de::from_reader(resp.body.as_slice()).expect("cbor parse");
    let map = match body {
        Value::Map(m) => m,
        _ => panic!("expected CBOR map"),
    };
    let current = map
        .iter()
        .find_map(|(k, v)| match k {
            Value::Text(t) if t == "current_version" => match v {
                Value::Integer(i) => Some(u64::try_from(*i).expect("u64 cast")),
                _ => None,
            },
            _ => None,
        })
        .expect("current_version field");
    assert_eq!(current, 0);
}

/// Done-when (6) of Phase 4: a peer pulling `GET /frontier` receives
/// the responder's *own* current snapshot, then a follow-up GET with
/// the returned cursor short-circuits to 304.
#[tokio::test]
async fn get_frontier_returns_snapshot_then_304_on_matching_cursor() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // First GET: cold cursor, returns the snapshot.
    let resp = send_frontier_get(&harness, "a", "b", None).await;
    assert_eq!(resp.status, StatusCode::OK);
    let snapshot = FrontierSnapshot::decode(&resp.body).expect("decode snapshot");
    let cursor = snapshot.cursor.clone();
    assert!(!cursor.is_empty(), "snapshot carries a cursor");

    // Second GET with the cursor encoded base64-url: 304.
    let cursor_b64 = URL_SAFE_NO_PAD.encode(&cursor);
    let resp2 = send_frontier_get(&harness, "a", "b", Some(&cursor_b64)).await;
    assert_eq!(resp2.status, StatusCode::NOT_MODIFIED);
}

/// Mode classifier flips Filtered → All when coverage crosses
/// HIGH_THRESHOLD. The wire promote/demote protocol is Phase 5+; this
/// test pins only the *decision* function so the routing layer is
/// ready to consume the wire signal when it lands.
#[tokio::test]
async fn classify_mode_promotes_at_high_coverage() {
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    let mut peer_filter = BloomFilter::new_empty(7, 1024, 2, 0.01).unwrap();
    peer_filter.insert(&alice);
    peer_filter.insert(&bob);
    // Local user set is exactly {alice, bob}; peer filter covers both
    // → coverage = 1.0 ≥ HIGH_THRESHOLD.
    const _: () = assert!(HIGH_THRESHOLD <= 1.0);
    let next = classify_mode(Mode::Filtered, &peer_filter, &[alice, bob]);
    assert_eq!(next, Mode::All);
}

// ---------------------------------------------------------------------------
// Helpers — envelope-signed dispatch + small wire-shape utilities
// ---------------------------------------------------------------------------

/// Minimal empty FilterSpec compatible with the announce CHECK
/// constraints. Uses `bloom::recommend_k(m, 0)` so the fixture
/// matches the `k` value production-side `build_bloom_from_keys`
/// would emit for an empty user set (otherwise reviewer-spotted
/// divergence: `m = 64, n = 0` clamps to `MIN_K = 1`, not the
/// arbitrary 7 the original fixture used).
fn empty_filter_spec() -> FilterSpec {
    let m: u32 = 64;
    let k = prismoire_server::federation::bloom::recommend_k(m, 0);
    let bloom = BloomFilter::new_empty(k, m, 0, 0.01).unwrap();
    FilterSpec::from_bloom(&bloom)
}

/// Tuple of `(status, body, cursor?)` from an envelope-signed
/// announce dispatch.
struct AnnounceResponse {
    status: StatusCode,
    #[allow(dead_code)]
    body: Vec<u8>,
    cursor: Vec<u8>,
}

async fn send_announce_envelope(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    body: &[u8],
) -> AnnounceResponse {
    let resp = send_envelope_signed(
        harness,
        from,
        to,
        Method::POST,
        "/federation/v1/frontier/announce",
        body,
    )
    .await;
    let cursor = if resp.0 == StatusCode::OK {
        extract_cursor_from_announce_ok(&resp.1)
    } else {
        Vec::new()
    };
    AnnounceResponse {
        status: resp.0,
        body: resp.1,
        cursor,
    }
}

struct DeltaResponse {
    status: StatusCode,
    body: Vec<u8>,
}

async fn send_delta_envelope(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    body: &[u8],
) -> DeltaResponse {
    let (status, body) = send_envelope_signed(
        harness,
        from,
        to,
        Method::POST,
        "/federation/v1/frontier/delta",
        body,
    )
    .await;
    DeltaResponse { status, body }
}

struct GetResponse {
    status: StatusCode,
    body: Vec<u8>,
}

async fn send_frontier_get(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    since: Option<&str>,
) -> GetResponse {
    // The envelope is signed over the path *without* the query string
    // (§6.5 step 9 normalises to `req.uri().path()`); the dispatched
    // URI carries the query so the `since` param reaches the handler.
    let signed_path = "/federation/v1/frontier";
    let dispatch_uri = match since {
        Some(s) => format!("/federation/v1/frontier?since={}", s),
        None => signed_path.to_string(),
    };
    let (status, body) = send_envelope_signed_split(
        harness,
        from,
        to,
        Method::GET,
        signed_path,
        &dispatch_uri,
        &[],
    )
    .await;
    GetResponse { status, body }
}

/// Sign an envelope from `from` to `to`, dispatch via the shared
/// transport, and return `(status, body_bytes)`. Mirrors the
/// envelope-build / dispatch dance used in `federation_phase3.rs`
/// without re-importing its private helpers.
async fn send_envelope_signed(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    method: Method,
    path: &str,
    body: &[u8],
) -> (StatusCode, Vec<u8>) {
    send_envelope_signed_split(harness, from, to, method, path, path, body).await
}

/// Like [`send_envelope_signed`] but lets the caller sign over one
/// path and dispatch against a different URI. The split is needed for
/// GET routes that take query parameters: §6.5 step 9 normalises the
/// signed path to `req.uri().path()` (no query), but the dispatched
/// URI must carry the query so the handler's `Query` extractor sees it.
async fn send_envelope_signed_split(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    method: Method,
    signed_path: &str,
    dispatch_uri: &str,
    body: &[u8],
) -> (StatusCode, Vec<u8>) {
    let from_h = harness.instance(from);
    let to_h = harness.instance(to);

    let header = envelope::sign_outbound(
        &from_h.state.instance_key,
        *to_h.state.instance_key.public_bytes(),
        &method,
        signed_path,
        body,
    );

    let mut builder = Request::builder()
        .method(method.clone())
        .uri(dispatch_uri)
        .header(envelope::AUTH_HEADER, header);
    if method == Method::POST {
        builder = builder.header(http::header::CONTENT_TYPE, CBOR_CONTENT_TYPE);
    }
    let req = builder
        .body(Bytes::from(body.to_vec()))
        .expect("build request");

    let response = from_h
        .transport
        .request(
            &PeerId::from_bytes(*to_h.state.instance_key.public_bytes()),
            req,
        )
        .await
        .expect("transport dispatch");
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body().into(), usize::MAX)
        .await
        .expect("body bytes")
        .to_vec();
    (status, body_bytes)
}

/// Pull the cursor field out of an announce 200 body
/// (`{ applied_version, cursor }`).
fn extract_cursor_from_announce_ok(body: &[u8]) -> Vec<u8> {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse announce body");
    let Value::Map(m) = v else {
        panic!("expected CBOR map");
    };
    for (k, v) in m {
        if let Value::Text(t) = &k
            && t == "cursor"
            && let Value::Bytes(b) = v
        {
            return b;
        }
    }
    panic!("no cursor field in announce body");
}
