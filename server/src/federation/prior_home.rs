//! §14 prior-home discovery surface — challenge issuance + probe.
//!
//! Mounts two routes under `/federation/v1/prior-home/*`. Both ride
//! the §6 envelope KnownPeer tier (the requesting peer is the *carrier*
//! of a user-signed exchange), with an additional user-auth layer
//! per `docs/federation-protocol.md` §14.1:
//!
//! - `POST /federation/v1/prior-home/challenge` — receiver mints a
//!   stateless §5.6 `prior-home-challenge` bound to `(self, K)` and
//!   returns it as a WireFormat-framed signed object.
//! - `POST /federation/v1/prior-home/probe` — redeem the challenge
//!   with a §5.7 `prior-home-response` signed by K; on success serve
//!   the §14.2 1-bit `has_activity` + optional `earliest_seen`.
//! - `POST /federation/v1/prior-home/content-by-key` (§14.5) — bulk
//!   paginated transfer of signed objects authored by K (`post-rev`,
//!   `retract`, `profile`, outbound `trust-edge`). Same auth surface
//!   as the probe.
//! - `POST /federation/v1/prior-home/inbound-edges-by-key` (§14.6) —
//!   bulk paginated transfer of signed `trust-edge` objects where K
//!   appears as the *target*. Fixed direction by spec — outbound
//!   edges ride §14.5.
//!
//! ## Auth model recap (§14.1)
//!
//! The two-step challenge/response is the defence against captured-
//! signature replay: any user-signed payload at rest would replay
//! across peers and across time. Binding the response to a fresh
//! receiver-issued challenge with a 60-second TTL eliminates both.
//!
//! The challenge is *stateless* on the receiver — the instance signs
//! its own minted nonce, then verifies its own signature at redeem
//! time. No challenge LRU is required, which is what keeps the
//! ceremony resilient across receiver restarts and load-balanced
//! replicas (§14.1 prose).
//!
//! ## §14.1 verification step layout
//!
//! [`verify_prior_home_request`] is the shared helper for steps 2–9
//! (step 1 is the envelope middleware; step 10 is the per-endpoint
//! serve step). The probe handler calls it, then folds in the §14.3
//! rate-limit admit and the §14.2 has_activity computation.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Extension, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::federation::backfill::{
    MAX_BACKFILL_PAGE, PullChainRow, decode_cursor, encode_cursor, encode_pull_backfill_body,
    ok_response,
};
use crate::federation::envelope::{MAX_CLOCK_SKEW_MS, encode_signed_object};
use crate::federation::errors::{bad_request, forbidden, internal_error};
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::middleware::VerifiedBody;
use crate::federation::prior_home_challenge_rate_limit::prior_home_challenge_too_many_requests;
use crate::federation::prior_home_rate_limit::prior_home_too_many_requests;
use crate::signed::{self, PriorHomeChallenge, SignedPayload, TAG_DEACTIVATION};

/// §14.3 `PRIOR_HOME_CHALLENGE_TTL`: 60 s issuance-to-redeem window
/// for §5.6 `prior-home-challenge` payloads. The challenge carries
/// `expires_at = created_at + this`; step 6 of §14.1 enforces
/// `now ≤ expires_at`.
pub const PRIOR_HOME_CHALLENGE_TTL_MS: u64 = 60_000;

/// §14.3 `PRIOR_HOME_NONCE_BYTES`: 32-byte CSPRNG nonce per minted
/// challenge. Matches `PRIOR_HOME_NONCE_BYTES` in the §14.3 table
/// and the §13.5 registration nonce width.
pub const PRIOR_HOME_NONCE_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// Request body decoders
// ---------------------------------------------------------------------------

/// `POST /federation/v1/prior-home/challenge` body: `{ "key": bstr(32) }`.
struct ChallengeReq {
    key: [u8; 32],
}

impl ChallengeReq {
    fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut key_field: Option<Vec<u8>> = None;
        for (k, v) in entries {
            let key_name = match k {
                Value::Text(s) => s,
                _ => return None,
            };
            match key_name.as_str() {
                "key" => {
                    if key_field.is_some() {
                        return None;
                    }
                    match v {
                        Value::Bytes(b) => key_field = Some(b),
                        _ => return None,
                    }
                }
                _ => return None,
            }
        }
        let bytes = key_field?;
        let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
        Some(Self { key: arr })
    }
}

/// `POST /federation/v1/prior-home/probe` body shape, shared with
/// the §14.5 / §14.6 bulk-fetch endpoints' `challenge` + `response`
/// pair (those add `since` / `limit`, decoded in their own modules).
///
/// Both fields are the raw WireFormat bytes (`{ "p", "s" }` CBOR map)
/// for one signed payload. We carry the verbatim bytes through to the
/// signature check so the hashed/verified bytes match the wire bytes
/// exactly — same invariant as the §6 envelope verifier.
pub(crate) struct ProbeReq {
    pub(crate) challenge: Vec<u8>,
    pub(crate) response: Vec<u8>,
}

impl ProbeReq {
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut challenge_field: Option<Vec<u8>> = None;
        let mut response_field: Option<Vec<u8>> = None;
        for (k, v) in entries {
            let key_name = match k {
                Value::Text(s) => s,
                _ => return None,
            };
            match key_name.as_str() {
                "challenge" => {
                    if challenge_field.is_some() {
                        return None;
                    }
                    match v {
                        Value::Bytes(b) => challenge_field = Some(b),
                        _ => return None,
                    }
                }
                "response" => {
                    if response_field.is_some() {
                        return None;
                    }
                    match v {
                        Value::Bytes(b) => response_field = Some(b),
                        _ => return None,
                    }
                }
                _ => return None,
            }
        }
        Some(Self {
            challenge: challenge_field?,
            response: response_field?,
        })
    }
}

// ---------------------------------------------------------------------------
// Response encoders
// ---------------------------------------------------------------------------

/// Encode `{ "challenge": bstr(WireFormat) }` per §14.1 step-1
/// success response.
fn encode_challenge_body(wire: &[u8]) -> Vec<u8> {
    let body = Value::Map(vec![(
        Value::Text("challenge".into()),
        Value::Bytes(wire.to_vec()),
    )]);
    let mut buf = Vec::with_capacity(wire.len() + 32);
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    buf
}

/// Encode the §14.2 probe response: `{ "has_activity": bool,
/// "earliest_seen"?: uint }`. `earliest_seen` is omitted when
/// `has_activity == false` per §14.2 ("present iff has_activity = true").
fn encode_probe_body(has_activity: bool, earliest_seen: Option<u64>) -> Vec<u8> {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(2);
    // Map-key canonical ordering: bytewise-lex of CBOR-encoded keys.
    // "earliest_seen" < "has_activity" — `e` (0x65) < `h` (0x68).
    if let Some(ts) = earliest_seen.filter(|_| has_activity) {
        entries.push((
            Value::Text("earliest_seen".into()),
            Value::Integer(ts.into()),
        ));
    }
    entries.push((
        Value::Text("has_activity".into()),
        Value::Bool(has_activity),
    ));
    let body = Value::Map(entries);
    let mut buf = Vec::with_capacity(32);
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    buf
}

fn ok_cbor(body: Vec<u8>) -> Response {
    let mut r = (StatusCode::OK, body).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    r
}

// ---------------------------------------------------------------------------
// Time helper
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Challenge handler — §14.1 step 1
// ---------------------------------------------------------------------------

/// `POST /federation/v1/prior-home/challenge` (§14.1 step 1).
///
/// Stateless mint: a fresh 32-byte nonce + this instance's signature
/// over the canonical §5.6 bytes is the entire transaction. No
/// server-side challenge LRU; the response from §14.1 step 4
/// verifies the challenge signature against the receiver's own
/// pubkey, so an in-process restart or load-balanced replica is
/// transparent to the requester.
///
/// ## §14.3 rate-limit ordering
///
/// Three checks run before the Ed25519 signing step, in the cheapest-
/// first order called for by §14.3 ("Pre-verification cap" /
/// "Post-verification cap"):
///
/// 1. Body decode + curve validation. A garbage K is rejected without
///    burning any rate-limit budget.
/// 2. Per-source-IP cap (`PRIOR_HOME_CHALLENGE_RPM_PER_IP = 60`).
///    Belt-and-suspenders against a single network-layer origin
///    saturating the signing CPU regardless of which K it submits.
///    `Option<ConnectInfo>` because the in-process test transport
///    does not populate it; production binds via
///    `into_make_service_with_connect_info` so the extractor is
///    always present on real traffic.
///
///    **Caveat — reverse-proxy collapse.** `main.rs` binds the
///    server to `127.0.0.1` behind a Caddy / nginx reverse proxy
///    (see project README). The `SocketAddr` axum sees is therefore
///    the proxy's loopback peer, not the remote federation peer's
///    public IP, and the per-IP bucket effectively becomes a global
///    60 rpm cap across all peers under that deployment shape. The
///    per-K cap below is the meaningful per-peer bound; the per-IP
///    cap still adds useful coverage in topologies that terminate
///    federation traffic directly on this process (single-tenant
///    self-hosting, dev loops). Replacing the `ConnectInfo` source
///    with the `X-Forwarded-For` extraction used by
///    `rate_limit::ClientIpKeyExtractor::Smart` is tracked as a
///    follow-up and gated on `server.trust_proxy_headers`.
/// 3. Per-subject-key cap (`PRIOR_HOME_CHALLENGE_RPM_PER_KEY = 10`).
///    Charged only after curve validation so garbage K values
///    cannot deplete a real K's bucket.
///
/// Both 429s use `Retry-After: 60` per §14.3.
pub async fn handle_challenge(
    State(state): State<Arc<AppState>>,
    // `Option<Extension<ConnectInfo<…>>>` rather than
    // `Option<ConnectInfo<…>>` because in axum 0.8 only `Extension<T>`
    // implements `OptionalFromRequestParts`; `ConnectInfo` itself
    // hard-rejects when absent. The `into_make_service_with_connect_info`
    // path inserts `ConnectInfo<SocketAddr>` directly into request
    // extensions, so reading it back through `Extension<...>` works
    // identically in production and lets the test transport
    // (`router.oneshot`, no ConnectInfo) degrade to `None`.
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let req = match ChallengeReq::decode(&body) {
        Some(p) => p,
        None => return bad_request("malformed"),
    };

    // §14.1 step-1 errors: `invalid_key` for a 32-byte blob that's not
    // a valid Ed25519 pubkey. We don't check anything else about K
    // here — that's the redeem step's job. The check is curve-membership
    // only; we don't query our users table at challenge issuance because
    // the protocol explicitly supports probing peers that have *never*
    // seen K (the negative `has_activity: false` answer is by design).
    if VerifyingKey::from_bytes(&req.key).is_err() {
        return bad_request("invalid_key");
    }

    // §14.3 per-IP cap. Charged before signing as the cheap pre-
    // verification rejection. The in-process test transport does
    // not populate ConnectInfo (it dispatches via `router.oneshot`
    // rather than a TcpListener), so absence is treated as "skip"
    // rather than reject — the per-K cap still applies. Production
    // traffic always carries a real ConnectInfo because `main.rs`
    // serves via `into_make_service_with_connect_info::<SocketAddr>`.
    if let Some(Extension(ConnectInfo(addr))) = connect_info
        && !state
            .prior_home_challenge_rate_limiter
            .try_admit_ip(addr.ip())
    {
        return prior_home_challenge_too_many_requests();
    }

    // §14.3 per-K cap. Charged only after curve validation so a
    // misbehaving sender spamming garbage K bytes cannot deplete a
    // real K's per-minute budget.
    if !state
        .prior_home_challenge_rate_limiter
        .try_admit_key(req.key)
    {
        return prior_home_challenge_too_many_requests();
    }

    let mut nonce = [0u8; PRIOR_HOME_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);

    let now = now_ms();
    let challenge = PriorHomeChallenge {
        responder_instance_key: *state.instance_key.public_bytes(),
        subject_key: req.key,
        nonce,
        created_at: now,
        expires_at: now.saturating_add(PRIOR_HOME_CHALLENGE_TTL_MS),
    };
    let payload = SignedPayload::PriorHomeChallenge(challenge).encode();
    let signature = state.instance_key.sign(&payload);
    let wire = encode_signed_object(&payload, &signature);
    ok_cbor(encode_challenge_body(&wire))
}

// ---------------------------------------------------------------------------
// Probe handler — §14.1 steps 2–10 + §14.2 has_activity
// ---------------------------------------------------------------------------

/// `POST /federation/v1/prior-home/probe` (§14.2).
///
/// Verifies the §14.1 challenge/response pair, applies the §14.3
/// per-subject rate limit, then computes the §14.2 `has_activity`
/// answer from local credential state.
pub async fn handle_probe(
    State(state): State<Arc<AppState>>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let subject_key = match verify_prior_home_request(&state, &body).await {
        Ok(k) => k,
        Err(resp) => return resp,
    };

    // §14.1 step 10 / §14.2 serve. Look up a live local credential row
    // for K. The clauses encode "lives here, not a federated stub, not
    // soft-deleted":
    //
    // - `signup_method != 'federated'` excludes Phase-9.5 hydrated
    //   remote-author stubs (and Phase-9.9 §12.6-disposed local users
    //   that were flipped to 'federated' on move-out).
    // - `home_instance IS NULL` is the canonical "lives here" marker
    //   (set by `signup_complete` and by move-in).
    // - `deleted_at IS NULL` filters out soft-deleted rows. The
    //   soft-deleted case is intentionally treated as "no activity"
    //   here rather than 403 — the §14.1 step-8 subject_deactivated
    //   path runs earlier, scanning for a federation-grade
    //   `deactivate` signed_object. A soft-deleted row without a
    //   corresponding `deactivate` (e.g. a `DELETE /api/me` user that
    //   had no active signing key at delete time) shouldn't
    //   masquerade as a discoverable prior home, but it isn't a
    //   wire-deactivate either.
    let key_slice: &[u8] = subject_key.as_slice();
    let row = match sqlx::query!(
        "SELECT created_at AS \"created_at!: String\" \
         FROM users \
         WHERE public_key = ? \
           AND signup_method != 'federated' \
           AND home_instance IS NULL \
           AND deleted_at IS NULL",
        key_slice,
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "db error looking up local credential in prior-home probe");
            return internal_error();
        }
    };

    let (has_activity, earliest_seen) = match row {
        Some(r) => {
            let ms = iso_to_unix_ms(&r.created_at);
            (true, Some(ms))
        }
        None => (false, None),
    };

    ok_cbor(encode_probe_body(has_activity, earliest_seen))
}

// ---------------------------------------------------------------------------
// Shared §14.1 verifier (steps 2–9)
// ---------------------------------------------------------------------------

/// Apply §14.1 verification steps 2–9 (step 1 is the envelope
/// middleware; step 10 is the per-endpoint serve). Returns the
/// authenticated `subject_key` on success.
///
/// Shared by §14.2 probe and the §14.5 / §14.6 bulk-fetch endpoints
/// (Phase 10.2). The rate-limit step (9) lives here so the three
/// endpoints share a single counter per §14.3 ("Why a shared counter").
pub(crate) async fn verify_prior_home_request(
    state: &Arc<AppState>,
    body: &[u8],
) -> Result<[u8; 32], Response> {
    // Step 2: outer body shape.
    let req = match ProbeReq::decode(body) {
        Some(p) => p,
        None => return Err(bad_request("malformed")),
    };

    // Re-unwrap each WireFormat blob: the body carries each signed
    // object as raw `{ "p", "s" }` CBOR bytes, so peel the framing
    // back to (payload, signature) for verification.
    let (challenge_payload, challenge_sig) =
        match crate::federation::envelope::decode_signed_object(&req.challenge) {
            Some(pair) => pair,
            None => return Err(bad_request("malformed")),
        };
    let (response_payload, response_sig) =
        match crate::federation::envelope::decode_signed_object(&req.response) {
            Some(pair) => pair,
            None => return Err(bad_request("malformed")),
        };

    // Step 3: challenge signature verifies under *this* instance's
    // current pubkey. A challenge issued by a rotated-out key or by a
    // different peer collapses to `wrong_responder` per §14.4.
    let our_pubkey = *state.instance_key.public_bytes();
    let our_vk = match VerifyingKey::from_bytes(&our_pubkey) {
        Ok(k) => k,
        Err(_) => {
            tracing::error!("instance pubkey is not a valid Ed25519 point");
            return Err(internal_error());
        }
    };
    if signed::verify(&challenge_payload, &challenge_sig, &our_vk).is_err() {
        return Err(bad_request("wrong_responder"));
    }
    let challenge = match SignedPayload::parse(&challenge_payload) {
        Ok(SignedPayload::PriorHomeChallenge(c)) => c,
        _ => return Err(bad_request("invalid_challenge")),
    };
    // The signature verifies, but the responder field could still
    // disagree with our current key (e.g. the challenge was signed by
    // a stale-but-still-valid mint that named a different instance).
    // The signature check above forecloses that under normal rotation
    // semantics — a key that signed our_pubkey-shaped challenge IS
    // us — but we double-check the field for defense in depth.
    if challenge.responder_instance_key != our_pubkey {
        return Err(bad_request("wrong_responder"));
    }

    // Step 4: response signature verifies under `response.subject_key`.
    // We parse the response first to learn the claimed signer, then
    // verify. The verify step picks up tampering between the parse and
    // the on-wire bytes (the canonical re-encode check inside
    // [`signed::verify`]).
    let response = match SignedPayload::parse(&response_payload) {
        Ok(SignedPayload::PriorHomeResponse(r)) => r,
        _ => return Err(bad_request("invalid_response")),
    };
    let subject_vk = match VerifyingKey::from_bytes(&response.subject_key) {
        Ok(k) => k,
        Err(_) => return Err(bad_request("invalid_response")),
    };
    if signed::verify(&response_payload, &response_sig, &subject_vk).is_err() {
        return Err(bad_request("invalid_response"));
    }

    // Step 5: `challenge.subject_key == response.subject_key`. The
    // outer body has no separate `K` field — the authenticated K is
    // `response.subject_key`, and it must match the challenge's
    // binding.
    if challenge.subject_key != response.subject_key {
        return Err(bad_request("subject_mismatch"));
    }

    // The §5.7 response carries `challenge_hash = SHA256(challenge.payload)`
    // — pin that to the bytes we just verified, so an attacker cannot
    // pair a fresh response with someone else's challenge.
    let actual_hash: [u8; 32] = Sha256::digest(&challenge_payload).into();
    if response.challenge_hash != actual_hash {
        return Err(bad_request("subject_mismatch"));
    }

    let now = now_ms();

    // Step 6: challenge has not expired.
    if now > challenge.expires_at {
        return Err(bad_request("expired_challenge"));
    }

    // Step 7: response freshness within MAX_FEDERATION_CLOCK_SKEW.
    // Same constant as the §6.5 step-11 envelope clock-skew filter
    // — federation-wide assumption is callers are within 60s.
    if now.abs_diff(response.created_at) > MAX_CLOCK_SKEW_MS {
        return Err(bad_request("skew_exceeded"));
    }

    // Step 8: subject_deactivated. Scan stored `deactivate` signed
    // objects for one whose `user` field equals `subject_key`. The
    // set is bounded by the deactivate count (one per locally- or
    // remotely-observed terminal deactivation); no dedicated index
    // yet — `signed_objects` is keyed by canonical_hash, so we walk
    // the class-filtered subset. If this becomes hot we add a
    // `(user_key, canonical_hash)` projection table; for V1, scan.
    match is_subject_deactivated(state, &response.subject_key).await {
        Ok(true) => return Err(forbidden("subject_deactivated")),
        Ok(false) => {}
        Err(e) => {
            tracing::error!(error = %e, "db error scanning deactivates in prior-home probe");
            return Err(internal_error());
        }
    }

    // Step 9: §14.3 rate-limit admit, keyed on subject_key. Shared
    // counter across §14.2 / §14.5 / §14.6 per §14.3 prose ("Why a
    // shared counter").
    if !state
        .prior_home_rate_limiter
        .try_admit(response.subject_key)
    {
        return Err(prior_home_too_many_requests());
    }

    Ok(response.subject_key)
}

// ---------------------------------------------------------------------------
// Deactivate scan + ISO time helper
// ---------------------------------------------------------------------------

/// Scan `signed_objects` for a `t = 'deactivate'` whose `user` field
/// equals `subject_key`. V1 walks the class-filtered subset and parses
/// each payload; the set is small (one row per terminal deactivation
/// the receiver has observed). A dedicated index lands if the scan
/// becomes a hot path.
async fn is_subject_deactivated(
    state: &Arc<AppState>,
    subject_key: &[u8; 32],
) -> Result<bool, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT payload AS \"payload?: Vec<u8>\" \
         FROM signed_objects WHERE inner_class = ?",
        TAG_DEACTIVATION,
    )
    .fetch_all(&state.db)
    .await?;
    for r in rows {
        // `payload IS NULL` means the row was erased per §3.1; the
        // deactivate itself is the erasure authority for the user's
        // own content but the deactivate row never erases *itself*,
        // so a NULL here is unexpected. Skip defensively rather than
        // misclassify.
        let Some(payload) = r.payload else { continue };
        let Ok(parsed) = SignedPayload::parse(&payload) else {
            continue;
        };
        if let SignedPayload::Deactivation(d) = parsed
            && &d.user == subject_key
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Parse the ISO-8601 `%Y-%m-%dT%H:%M:%SZ` `users.created_at` format
/// to Unix milliseconds. Returns 0 on parse failure — the §14.2 wire
/// shape doesn't have an explicit "unknown" sentinel and a 0 timestamp
/// is unambiguous (no realistic prior home registered K at the Unix
/// epoch), so a corrupt column surfaces as 0 ms rather than a 500.
/// We log the failure so operators can investigate a column shape
/// drift rather than silently emitting an epoch timestamp on the wire.
fn iso_to_unix_ms(iso: &str) -> u64 {
    match chrono::NaiveDateTime::parse_from_str(iso, "%Y-%m-%dT%H:%M:%SZ") {
        Ok(dt) => u64::try_from(dt.and_utc().timestamp_millis()).unwrap_or_else(|_| {
            tracing::warn!(
                value = %iso,
                "users.created_at parsed but does not fit u64 ms; emitting 0 on the prior-home wire",
            );
            0
        }),
        Err(e) => {
            tracing::warn!(
                value = %iso,
                error = %e,
                "users.created_at failed ISO-8601 parse; emitting 0 on the prior-home wire",
            );
            0
        }
    }
}

// ---------------------------------------------------------------------------
// §14.5 / §14.6 bulk-fetch request decoder
// ---------------------------------------------------------------------------

/// `POST /federation/v1/prior-home/content-by-key` and
/// `POST /federation/v1/prior-home/inbound-edges-by-key` body shape
/// (`docs/federation-protocol.md` §14.5 / §14.6):
///
/// ```text
/// { "challenge": WireFormat,   // §5.6 echoed verbatim (may be reused
///                              //   across pages within
///                              //   PRIOR_HOME_CHALLENGE_TTL)
///   "response":  WireFormat,   // §5.7 freshly signed per page
///   "since":     bstr or absent,
///   "limit":     uint or absent }
/// ```
///
/// Same `challenge` + `response` pair as the §14.2 probe, plus optional
/// keyset-pagination fields. The verbatim WireFormat bytes get fed
/// through `verify_prior_home_request` after extracting `since`/`limit`
/// here, so the two handlers share §14.1 verification semantics.
pub(crate) struct BulkFetchReq {
    pub(crate) challenge: Vec<u8>,
    pub(crate) response: Vec<u8>,
    pub(crate) since: Option<Vec<u8>>,
    pub(crate) limit: Option<u32>,
}

impl BulkFetchReq {
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut challenge_field: Option<Vec<u8>> = None;
        let mut response_field: Option<Vec<u8>> = None;
        let mut since_field: Option<Vec<u8>> = None;
        let mut limit_field: Option<u32> = None;
        for (k, v) in entries {
            let key_name = match k {
                Value::Text(s) => s,
                _ => return None,
            };
            match key_name.as_str() {
                "challenge" => {
                    if challenge_field.is_some() {
                        return None;
                    }
                    match v {
                        Value::Bytes(b) => challenge_field = Some(b),
                        _ => return None,
                    }
                }
                "response" => {
                    if response_field.is_some() {
                        return None;
                    }
                    match v {
                        Value::Bytes(b) => response_field = Some(b),
                        _ => return None,
                    }
                }
                "since" => {
                    if since_field.is_some() {
                        return None;
                    }
                    match v {
                        Value::Bytes(b) => since_field = Some(b),
                        _ => return None,
                    }
                }
                "limit" => {
                    if limit_field.is_some() {
                        return None;
                    }
                    match v {
                        Value::Integer(i) => {
                            let n: i128 = i.into();
                            if !(1..=u32::MAX as i128).contains(&n) {
                                return None;
                            }
                            limit_field = Some(n as u32);
                        }
                        _ => return None,
                    }
                }
                _ => return None,
            }
        }
        Some(Self {
            challenge: challenge_field?,
            response: response_field?,
            since: since_field,
            limit: limit_field,
        })
    }
}

/// Common preamble for §14.5 / §14.6: decode the body, peel off
/// `since` / `limit`, run §14.1 verification, return the authenticated
/// subject_key plus the resolved cursor + page size.
///
/// `since` is the raw bytes from the request body (we treat the cursor
/// as opaque on the wire). The §10.5.2 / §9.3 cursor decoder accepts
/// base64url ASCII *or* raw bytes — but our §10.5.1 sibling routes
/// emit raw bytes inside the response (`next_cursor`: bstr) and the
/// §10.5.1 GET variants accept the base64url form on the URL. §14.5
/// transports cursors as bstr both ways (request body + response), so
/// we base64url-encode the raw bytes back to the string form
/// `decode_cursor` expects.
async fn verify_bulk_fetch_request(
    state: &Arc<AppState>,
    body: &[u8],
) -> Result<([u8; 32], Option<crate::federation::backfill::Cursor>, u32), Response> {
    let req = match BulkFetchReq::decode(body) {
        Some(r) => r,
        None => return Err(bad_request("malformed")),
    };

    let limit = match req.limit {
        None => MAX_BACKFILL_PAGE,
        Some(n) if (1..=MAX_BACKFILL_PAGE).contains(&n) => n,
        _ => return Err(bad_request("limit_out_of_range")),
    };

    let cursor = match &req.since {
        None => None,
        // An empty `since` bstr is rejected rather than silently treated
        // as "no cursor", matching `decode_cursor`'s strict
        // CURSOR_LEN-or-reject contract. A caller that wants the first
        // page should omit `since` entirely.
        Some(b) if b.is_empty() => return Err(bad_request("invalid_cursor")),
        Some(b) => {
            // Cursors are emitted raw (bstr) by `encode_pull_backfill_body`,
            // and §14.5 / §14.6 transport them as raw bstr both ways.
            // `decode_cursor` operates on the base64url ASCII form (it
            // is also used by the §10.5.1 GET routes whose `?since=` is
            // base64url-encoded on the URL), so we round-trip raw → b64
            // here to reuse one decoder.
            let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
            match decode_cursor(&s) {
                Some(c) => Some(c),
                None => return Err(bad_request("invalid_cursor")),
            }
        }
    };

    // Repack into a `ProbeReq`-shaped body for the §14.1 verifier. The
    // existing verifier consumes only `challenge` + `response`, so we
    // re-encode just those two fields — the `since`/`limit` fields are
    // page-control parameters and not part of the verifier's scope.
    let probe_body = Value::Map(vec![
        (Value::Text("challenge".into()), Value::Bytes(req.challenge)),
        (Value::Text("response".into()), Value::Bytes(req.response)),
    ]);
    let mut probe_buf = Vec::new();
    ciborium::ser::into_writer(&probe_body, &mut probe_buf).expect("ciborium ser is infallible");

    let subject_key = match verify_prior_home_request(state, &probe_buf).await {
        Ok(k) => k,
        Err(resp) => return Err(resp),
    };

    Ok((subject_key, cursor, limit))
}

// ---------------------------------------------------------------------------
// §14.5 — POST /federation/v1/prior-home/content-by-key
// ---------------------------------------------------------------------------

/// `POST /federation/v1/prior-home/content-by-key` (§14.5).
///
/// Returns signed objects authored by K — `post-rev`, `retract`,
/// `profile`, and outbound `trust-edge` records — paginated under the
/// §10.5.2 `{ objects, next_cursor?, complete }` envelope.
///
/// Object scope (per §14.5 prose):
/// - `post-rev` authored by K (joined via `post_revisions` →
///   `posts.author`).
/// - `retract` authored by K (joined via `posts.retraction_signature
///   = signed_objects.signature` and `posts.author`).
/// - `profile` authored by K (joined via `profile_revisions.user_id`).
/// - `trust-edge` with `source_user = K` (joined via
///   `trust_edges.source_user`). Inbound edges ride §14.6.
///
/// Move declarations and prior-home challenge/response artifacts are
/// excluded: moves propagate via §12 unconditional flood + §12.3 chain
/// backfill, and challenges/responses are ephemeral per §5.6 / §5.7.
///
/// **Erasure carve-out.** The Phase 10.2 implementation skips erased
/// rows (`payload IS NULL`) in the bulk page — same as the §10.5.1
/// `/backfill/by-author` cut. The spec's "all-page-erased → 410 Gone"
/// shape is not yet implemented; a sender that needs a specific
/// erasure follows up reactively via §10.5.1 `/backfill/by-hash`.
/// Documenting here so we land the 410 path with the other §10.5.2
/// 410 work rather than dropping it into this phase.
pub async fn handle_content_by_key(
    State(state): State<Arc<AppState>>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let (subject_key, cursor, limit) = match verify_bulk_fetch_request(&state, &body).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    // Resolve K to local users.id. §14.5 serves only what the
    // responding peer has authored locally — so a key with no local
    // `users` row produces `complete: true` with an empty page (same
    // carve-out as §10.5.1 `/backfill/by-author`).
    let key_slice: &[u8] = subject_key.as_slice();
    let user_id_opt =
        match sqlx::query_scalar!("SELECT id FROM users WHERE public_key = ?", key_slice,)
            .fetch_optional(&state.db)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "db error resolving subject key in content-by-key");
                return internal_error();
            }
        };
    let Some(user_id) = user_id_opt else {
        return ok_response(encode_pull_backfill_body(&[], None, true));
    };

    // Page-fetch: `limit + 1` rows for next-page detection. UNION ALL
    // across the four §14.5 classes; each branch joins to the
    // class-specific projection table. The outer keyset-pagination
    // predicate runs against the union and orders by
    // (so.received_at, so.canonical_hash) per §14.5 step 11.
    //
    // Note: SQLite cannot bind a parameter more than once across CTE
    // boundaries cleanly via sqlx's `query!`, so each `?` is its own
    // binding even when the value is identical. The repetition is
    // intentional and not a bug.
    let fetch_n = (limit as i64) + 1;
    let cursor_iso: Option<String> = cursor.as_ref().map(|c| c.created_at.clone());
    let cursor_hash: Option<Vec<u8>> = cursor.as_ref().map(|c| c.canonical_hash.to_vec());

    // Note on the retract branch's `posts.retraction_signature = so.signature`
    // join: `signature` is not UNIQUE in `signed_objects`, but Ed25519
    // signatures are deterministic per (privkey, message) and collisions
    // across distinct payloads are cryptographically infeasible, so in
    // practice this join is 1:1. The cleaner long-term shape would be a
    // `posts.retraction_canonical_hash` column joined against
    // `so.canonical_hash` (the actual PRIMARY KEY); deferred as a schema
    // migration.
    let rows = match sqlx::query!(
        "SELECT so.canonical_hash AS \"canonical_hash!: Vec<u8>\", \
                so.received_at AS \"received_at!: String\", \
                so.payload AS \"payload?: Vec<u8>\", \
                so.signature AS \"signature!: Vec<u8>\" \
         FROM ( \
                SELECT so.canonical_hash, so.received_at, so.payload, so.signature \
                FROM signed_objects so \
                JOIN post_revisions pr ON pr.canonical_hash = so.canonical_hash \
                JOIN posts p ON p.id = pr.post_id \
                WHERE p.author = ? AND so.payload IS NOT NULL \
                UNION ALL \
                SELECT so.canonical_hash, so.received_at, so.payload, so.signature \
                FROM signed_objects so \
                JOIN posts p ON p.retraction_signature = so.signature \
                WHERE so.inner_class = 'retract' \
                  AND p.author = ? \
                  AND so.payload IS NOT NULL \
                UNION ALL \
                SELECT so.canonical_hash, so.received_at, so.payload, so.signature \
                FROM signed_objects so \
                JOIN profile_revisions prv ON prv.canonical_hash = so.canonical_hash \
                WHERE prv.user_id = ? AND so.payload IS NOT NULL \
                UNION ALL \
                SELECT so.canonical_hash, so.received_at, so.payload, so.signature \
                FROM signed_objects so \
                JOIN trust_edges te ON te.canonical_hash = so.canonical_hash \
                WHERE te.source_user = ? AND so.payload IS NOT NULL \
         ) so \
         WHERE ( \
                ? IS NULL \
                OR so.received_at > ? \
                OR (so.received_at = ? AND so.canonical_hash > ?) \
         ) \
         ORDER BY so.received_at ASC, so.canonical_hash ASC \
         LIMIT ?",
        user_id,
        user_id,
        user_id,
        user_id,
        cursor_iso,
        cursor_iso,
        cursor_iso,
        cursor_hash,
        fetch_n,
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "db error walking content-by-key page");
            return internal_error();
        }
    };

    let has_more = (rows.len() as i64) > limit as i64;
    let mut page_rows: Vec<PullChainRow> = Vec::with_capacity(limit as usize);
    for row in rows.into_iter().take(limit as usize) {
        // Belt-and-suspenders against erased rows: the SQL `WHERE` clause
        // already filters `payload IS NOT NULL` in each UNION ALL branch,
        // but matching the `/backfill/by-author` posture means a `NULL`
        // payload here is treated as "elide the row" rather than the
        // unwrap blowing the request up.
        let Some(payload) = row.payload else {
            continue;
        };
        let canonical_hash: [u8; 32] = match row.canonical_hash.as_slice().try_into() {
            Ok(h) => h,
            Err(_) => {
                tracing::error!(
                    "content-by-key: signed_objects row has non-32-byte canonical_hash"
                );
                return internal_error();
            }
        };
        page_rows.push(PullChainRow {
            payload,
            signature: row.signature,
            received_at: row.received_at,
            canonical_hash,
        });
    }

    let next_cursor = if has_more && let Some(last) = page_rows.last() {
        encode_cursor(&last.received_at, &last.canonical_hash)
    } else {
        None
    };
    let complete = !has_more;
    if !complete && next_cursor.is_none() {
        tracing::error!(
            "content-by-key: tail row carries non-standard ISO timestamp; \
             cannot mint a next_cursor without violating §10.5.2 invariant"
        );
        return internal_error();
    }

    ok_response(encode_pull_backfill_body(&page_rows, next_cursor, complete))
}

// ---------------------------------------------------------------------------
// §14.6 — POST /federation/v1/prior-home/inbound-edges-by-key
// ---------------------------------------------------------------------------

/// `POST /federation/v1/prior-home/inbound-edges-by-key` (§14.6).
///
/// Returns signed `trust-edge` objects with `target_user = K` —
/// "who has trusted K" — paginated under the §10.5.2 envelope.
///
/// **No `direction` parameter.** Per §14.6 prose, §14.6 is fixed to
/// `target` only. Outbound edges (`source_user = K`) ride §14.5
/// alongside K-authored content. The split keeps the recovery flow
/// non-overlapping: §14.5 covers everything K signed, §14.6 covers
/// everything signed *about* K. The §10.5.1 peer-authed
/// `/backfill/edges-by-key?direction=...` route exposes both
/// directions for normal-traffic backfill — that is a separate
/// surface with different auth semantics.
///
/// Same erasure carve-out as §14.5: erased rows are elided from the
/// bulk page; the 410-Gone shape lands with the broader §10.5.2 410
/// work.
///
/// **Threat-model note.** The §14.1 challenge/response auth surface
/// gates this endpoint on possession of K's private key — the same
/// material that authorises signing as K. So anyone who can read this
/// endpoint already controls K's signing capability. The marginal
/// disclosure here is the full *inbound* trust set across federated
/// instances (including signed distrust/block edges normally hidden by
/// the aggregate trust-graph UI). This is intentional per §14.6: the
/// whole purpose of §14 is data-recovery on key compromise / migration,
/// which requires the migrating identity to enumerate trust pointing
/// *at* it. Operators should treat key compromise as also yielding
/// trust-graph enumeration, not just impersonation.
pub async fn handle_inbound_edges_by_key(
    State(state): State<Arc<AppState>>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let (subject_key, cursor, limit) = match verify_bulk_fetch_request(&state, &body).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    // Resolve K to local users.id. Phase 5 only persists `trust_edges`
    // rows for pairs whose target is a local user; a K with no local
    // row has no inbound edges in our store, so `complete: true` with
    // an empty page is the correct answer.
    let key_slice: &[u8] = subject_key.as_slice();
    let user_id_opt =
        match sqlx::query_scalar!("SELECT id FROM users WHERE public_key = ?", key_slice,)
            .fetch_optional(&state.db)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "db error resolving subject key in inbound-edges-by-key"
                );
                return internal_error();
            }
        };
    let Some(user_id) = user_id_opt else {
        return ok_response(encode_pull_backfill_body(&[], None, true));
    };

    let fetch_n = (limit as i64) + 1;
    let cursor_iso: Option<String> = cursor.as_ref().map(|c| c.created_at.clone());
    let cursor_hash: Option<Vec<u8>> = cursor.as_ref().map(|c| c.canonical_hash.to_vec());

    let rows = match sqlx::query!(
        "SELECT te.canonical_hash AS \"canonical_hash!: Vec<u8>\", \
                so.received_at AS \"received_at!: String\", \
                so.payload AS \"payload?: Vec<u8>\", \
                so.signature AS \"signature!: Vec<u8>\" \
         FROM trust_edges te \
         JOIN signed_objects so ON so.canonical_hash = te.canonical_hash \
         WHERE te.target_user = ? \
           AND so.payload IS NOT NULL \
           AND ( \
                ? IS NULL \
                OR so.received_at > ? \
                OR (so.received_at = ? AND te.canonical_hash > ?) \
         ) \
         ORDER BY so.received_at ASC, te.canonical_hash ASC \
         LIMIT ?",
        user_id,
        cursor_iso,
        cursor_iso,
        cursor_iso,
        cursor_hash,
        fetch_n,
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "db error walking inbound-edges-by-key page");
            return internal_error();
        }
    };

    let has_more = (rows.len() as i64) > limit as i64;
    let mut page_rows: Vec<PullChainRow> = Vec::with_capacity(limit as usize);
    for row in rows.into_iter().take(limit as usize) {
        let Some(payload) = row.payload else {
            continue;
        };
        let canonical_hash: [u8; 32] = match row.canonical_hash.as_slice().try_into() {
            Ok(h) => h,
            Err(_) => {
                tracing::error!(
                    "inbound-edges-by-key: trust_edges row has non-32-byte canonical_hash"
                );
                return internal_error();
            }
        };
        page_rows.push(PullChainRow {
            payload,
            signature: row.signature,
            received_at: row.received_at,
            canonical_hash,
        });
    }

    let next_cursor = if has_more && let Some(last) = page_rows.last() {
        encode_cursor(&last.received_at, &last.canonical_hash)
    } else {
        None
    };
    let complete = !has_more;
    if !complete && next_cursor.is_none() {
        tracing::error!(
            "inbound-edges-by-key: tail row carries non-standard ISO timestamp; \
             cannot mint a next_cursor without violating §10.5.2 invariant"
        );
        return internal_error();
    }

    ok_response(encode_pull_backfill_body(&page_rows, next_cursor, complete))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_ttl_constant_matches_spec() {
        // §14.3: PRIOR_HOME_CHALLENGE_TTL default 60 s.
        assert_eq!(PRIOR_HOME_CHALLENGE_TTL_MS, 60_000);
    }

    #[test]
    fn nonce_size_constant_matches_spec() {
        // §14.3: PRIOR_HOME_NONCE_BYTES default 32.
        assert_eq!(PRIOR_HOME_NONCE_BYTES, 32);
    }

    #[test]
    fn challenge_req_decode_round_trips() {
        let key = [0xabu8; 32];
        let body = Value::Map(vec![(
            Value::Text("key".into()),
            Value::Bytes(key.to_vec()),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let parsed = ChallengeReq::decode(&buf).expect("decode");
        assert_eq!(parsed.key, key);
    }

    #[test]
    fn challenge_req_rejects_wrong_length_key() {
        let body = Value::Map(vec![(
            Value::Text("key".into()),
            Value::Bytes(vec![0u8; 31]),
        )]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert!(ChallengeReq::decode(&buf).is_none());
    }

    #[test]
    fn challenge_req_rejects_extra_keys() {
        let body = Value::Map(vec![
            (Value::Text("key".into()), Value::Bytes(vec![0u8; 32])),
            (Value::Text("extra".into()), Value::Bool(true)),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert!(ChallengeReq::decode(&buf).is_none());
    }

    #[test]
    fn probe_req_decode_round_trips() {
        let body = Value::Map(vec![
            (
                Value::Text("challenge".into()),
                Value::Bytes(b"chal".to_vec()),
            ),
            (
                Value::Text("response".into()),
                Value::Bytes(b"resp".to_vec()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let parsed = ProbeReq::decode(&buf).expect("decode");
        assert_eq!(parsed.challenge, b"chal");
        assert_eq!(parsed.response, b"resp");
    }

    #[test]
    fn encode_probe_body_omits_earliest_seen_when_not_active() {
        let buf = encode_probe_body(false, None);
        let value: Value = ciborium::de::from_reader(buf.as_slice()).unwrap();
        let map = match value {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        // Only `has_activity` should appear.
        assert_eq!(map.len(), 1);
        let (k, v) = &map[0];
        assert_eq!(*k, Value::Text("has_activity".into()));
        assert_eq!(*v, Value::Bool(false));
    }

    #[test]
    fn encode_probe_body_includes_earliest_seen_when_active() {
        let buf = encode_probe_body(true, Some(1_700_000_000_000));
        let value: Value = ciborium::de::from_reader(buf.as_slice()).unwrap();
        let map = match value {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        assert_eq!(map.len(), 2);
        // Canonical key order: "earliest_seen" < "has_activity".
        assert_eq!(map[0].0, Value::Text("earliest_seen".into()));
        assert_eq!(map[1].0, Value::Text("has_activity".into()));
    }

    #[test]
    fn iso_to_unix_ms_parses_typical_value() {
        // 2026-01-01T00:00:00Z = 1767225600000 ms since epoch.
        let ms = iso_to_unix_ms("2026-01-01T00:00:00Z");
        assert_eq!(ms, 1_767_225_600_000);
    }

    #[test]
    fn iso_to_unix_ms_returns_zero_on_garbage() {
        assert_eq!(iso_to_unix_ms("not a date"), 0);
    }
}
