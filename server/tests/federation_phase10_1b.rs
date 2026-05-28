//! Phase-10.1b integration tests: §14.3 challenge-endpoint rate limits.
//!
//! Spec gates exercised here (`docs/federation-protocol.md` §14.3):
//!
//! - **Layer 1** — per-subject-key per-minute cap
//!   (`PRIOR_HOME_CHALLENGE_RPM_PER_KEY = 10`). After 10 admitted
//!   challenge mints for the same K within the rolling 60s window,
//!   the 11th request returns `429 Too Many Requests` with
//!   `Retry-After: 60`. The cap is charged only after the §14.1
//!   step-1 curve check, so garbage K values cannot deplete a real
//!   K's bucket.
//! - **Layer 1** — separate K values keep separate per-minute
//!   buckets. K2's first mint admits even after K1 has saturated.
//! - **Layer 1** — a curve-invalid K (a 32-byte blob whose y-coord
//!   has no curve point) is rejected with `400 invalid_key` and does
//!   *not* burn the per-K counter for any neighboring real K.
//!
//! The per-source-IP cap is verified by unit tests in
//! `prior_home_challenge_rate_limit` rather than here, because the
//! in-process test transport dispatches via `router.oneshot` instead
//! of a TcpListener, so `ConnectInfo<SocketAddr>` is not populated
//! and the handler's IP branch is unreachable in this harness.

#![cfg(feature = "test-auth")]

mod common;

use axum::body::Bytes;
use ciborium::value::Value;
use ed25519_dalek::{SigningKey, VerifyingKey};
use http::{Method, StatusCode, header};
use prismoire_server::federation::prior_home_challenge_rate_limit::PRIOR_HOME_CHALLENGE_RPM_PER_KEY;
use prismoire_server::federation::transport::FederationTransport;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};

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

/// Mint one challenge for `k_pub` against B and return the HTTP
/// status plus the `Retry-After` header (if present, as a string).
async fn mint_challenge(
    harness: &MultiInstanceHarness,
    k_pub: &[u8; 32],
) -> (StatusCode, Option<String>) {
    let req_body = encode_challenge_request(k_pub);
    // The harness helper returns (status, body). For 429s we want the
    // Retry-After header, so we re-issue via the router directly to
    // get the full response.
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

/// Saturate the per-K minute budget at the spec default and confirm
/// the next mint returns 429 with `Retry-After: 60`.
#[tokio::test]
async fn per_key_minute_cap_returns_429_with_retry_after() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    // Lock B's challenge limiter to the spec defaults. The harness
    // default is `u32::MAX` so unrelated tests don't get throttled;
    // this test specifically asserts on the production cap.
    harness
        .instance("b")
        .state
        .prior_home_challenge_rate_limiter
        .set_caps(
            u32::MAX, // per-IP unused under the in-process transport
            PRIOR_HOME_CHALLENGE_RPM_PER_KEY,
        );

    let k_pub: [u8; 32] = *SigningKey::generate(&mut rand::rngs::OsRng)
        .verifying_key()
        .as_bytes();

    // First N mints all admit.
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
    // N+1 overflows.
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

/// Two distinct K values keep independent per-minute buckets — a K1
/// that has saturated does not block a fresh K2 mint.
#[tokio::test]
async fn per_key_cap_does_not_cross_subject_keys() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    harness
        .instance("b")
        .state
        .prior_home_challenge_rate_limiter
        .set_caps(u32::MAX, PRIOR_HOME_CHALLENGE_RPM_PER_KEY);

    let k1_pub: [u8; 32] = *SigningKey::generate(&mut rand::rngs::OsRng)
        .verifying_key()
        .as_bytes();
    let k2_pub: [u8; 32] = *SigningKey::generate(&mut rand::rngs::OsRng)
        .verifying_key()
        .as_bytes();

    // Saturate K1.
    for _ in 0..PRIOR_HOME_CHALLENGE_RPM_PER_KEY {
        let (status, _) = mint_challenge(&harness, &k1_pub).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _) = mint_challenge(&harness, &k1_pub).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "K1 saturated",);

    // K2's first mint still admits — separate bucket per spec §14.3.
    let (status, _) = mint_challenge(&harness, &k2_pub).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "fresh K2 must not be blocked by K1's exhausted bucket",
    );
}

/// A 32-byte blob that fails the §14.1 step-1 curve check returns
/// `400 invalid_key` and does NOT burn the per-K counter. After the
/// rejection, a *real* K can still draw its full budget.
#[tokio::test]
async fn invalid_key_does_not_consume_per_key_budget() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    // Tight per-K cap so we can prove "1 garbage mint did not eat
    // our only slot."
    harness
        .instance("b")
        .state
        .prior_home_challenge_rate_limiter
        .set_caps(u32::MAX, 1);

    // A 32-byte blob that's not a valid Ed25519 pubkey. Encoded y=2
    // (sign=0) has no curve point — `VerifyingKey::from_bytes` returns
    // `Err`, so the §14.1 step-1 check at the top of `handle_challenge`
    // collapses to `400 invalid_key` before the limiter is consulted.
    let mut bad_k = [0u8; 32];
    bad_k[0] = 0x02;
    // Guard the premise: if a future `ed25519-dalek` revision starts
    // accepting this encoding, fail loudly here rather than have the
    // test silently degenerate into "200 OK was returned, which is
    // also < 400" green-on-bug.
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

    // The garbage attempt did not enter the per-K counter (it can't
    // — the curve check rejects before the limiter is consulted).
    // A *real* K with cap=1 still has its full budget available.
    let real_k_pub: [u8; 32] = *SigningKey::generate(&mut rand::rngs::OsRng)
        .verifying_key()
        .as_bytes();
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
