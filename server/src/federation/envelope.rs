//! Federation envelope (`X-Prismoire-Federation-Auth`) sign / verify.
//!
//! Implements the §6 procedure end-to-end for the two routes
//! Phase 2 actually mounts: the bootstrap-exception verification
//! that `POST /federation/v1/peer-request` needs (§6.5 step 5
//! "except when the route is ..."), and the standard known-peer
//! verification that `POST /federation/v1/peer-response` needs.
//!
//! Phase 3 will lift this into a proper Axum middleware that the
//! whole `/federation/v1/*` router sits behind; for now the
//! per-handler call-site is fine — the verifier itself is the
//! same code either way.
//!
//! Wire shape recap (`federation-protocol.md` §6.3):
//!
//! ```text
//! X-Prismoire-Federation-Auth: base64url( CBOR { "p": payload, "s": sig } )
//! ```
//!
//! where `payload` is the canonical CBOR of a `fed-envelope`
//! (`signed.rs::FedEnvelope`) and `sig` is the Ed25519 signature
//! by the sender's instance key over `payload`.

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use http::{HeaderValue, Method};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::federation::instance_key::InstanceKey;
use crate::signed::{self, FedEnvelope, SignedPayload};

/// HTTP header carrying the envelope. Per `federation-protocol.md`
/// §6.3.
pub const AUTH_HEADER: &str = "X-Prismoire-Federation-Auth";

/// Default clock-skew window for envelope `created_at` (`MAX_FED…`).
/// 60 seconds matches `federation-protocol.md` §6.5 step 11.
pub const MAX_CLOCK_SKEW_MS: u64 = 60_000;

/// Default per-instance nonce-LRU bound. Sized for Phase 2 test
/// loads; will be tuned against real peer counts in Phase 4 (see
/// the §6 open follow-up in `docs/federation-impl-plan.md` §6).
pub const DEFAULT_NONCE_LRU_SIZE: usize = 4096;

/// In-process per-instance replay defense for the §6.5 step-12
/// nonce check.
///
/// Keyed on the `(sender_pubkey, nonce)` pair as documented in §6.7.
/// The structure is a FIFO-eviction `HashSet` rather than a true
/// LRU: the §6.5 step-11 clock-skew filter (default 60s) bounds how
/// long an attacker-controlled nonce can stay relevant, so the eviction
/// policy doesn't need to be fancy — it just needs to cap memory.
/// Phase 4 will revisit sizing and may swap in a sliding-window
/// implementation; the public API here will absorb that change.
pub struct NonceLru {
    inner: Mutex<NonceLruInner>,
    max_size: usize,
}

struct NonceLruInner {
    seen: HashSet<([u8; 32], [u8; 16])>,
    order: VecDeque<([u8; 32], [u8; 16])>,
}

impl NonceLru {
    /// New LRU with capacity `max_size`. Choose `0` to disable
    /// replay protection (useful for Layer-0 tests that exercise
    /// the rest of the verifier without depending on shared state).
    pub fn new(max_size: usize) -> Self {
        Self {
            inner: Mutex::new(NonceLruInner {
                seen: HashSet::new(),
                order: VecDeque::new(),
            }),
            max_size,
        }
    }

    /// Returns `true` if `(sender, nonce)` was previously unseen and
    /// has now been recorded; `false` if the pair was already
    /// present (the caller must reject as replay per §6.5 step 12).
    ///
    /// Capacity `0` short-circuits to `true` so the verifier passes
    /// — see [`Self::new`].
    ///
    /// **Nonce-burn semantics.** Insertion happens *before* any
    /// post-nonce verification step rejects the envelope (e.g. body
    /// hash, scope/method/path mismatch), so a valid-but-rejected
    /// envelope still consumes its nonce. In practice this is
    /// benign: each envelope mints a fresh 16-byte random nonce, so
    /// no legitimate sender ever retries the same one. A
    /// network-level redrive of the exact same envelope bytes
    /// (e.g. retransmitted by a misbehaving proxy) would surface as
    /// a phantom `Replay` rather than the underlying failure — a
    /// confusing-but-safe diagnostic. If a future operator surface
    /// makes this distinction worth preserving, move the insert
    /// after all other checks.
    pub fn check_and_insert(&self, sender: [u8; 32], nonce: [u8; 16]) -> bool {
        if self.max_size == 0 {
            return true;
        }
        let mut g = self.inner.lock().expect("nonce LRU poisoned");
        let key = (sender, nonce);
        if !g.seen.insert(key) {
            return false;
        }
        g.order.push_back(key);
        while g.order.len() > self.max_size {
            if let Some(old) = g.order.pop_front() {
                g.seen.remove(&old);
            }
        }
        true
    }
}

impl Default for NonceLru {
    fn default() -> Self {
        Self::new(DEFAULT_NONCE_LRU_SIZE)
    }
}

/// Verifier mode flag, selecting between the §6.5-step-5 standard
/// path (look the sender up in the peers table) and the
/// peer-request bootstrap exception (self-consistency only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyMode {
    /// Standard mode: sender pubkey must match an active peer.
    KnownPeer,
    /// Bootstrap mode (peer-request only): no peer record exists
    /// yet. The verifier accepts whichever key signed the envelope;
    /// the caller is responsible for the additional
    /// `envelope.sender == body.initiator_instance_pubkey`
    /// self-consistency check documented in §5.4 / §6.5 step 5.
    Bootstrap,
}

/// Discriminated failure modes from [`verify_inbound`].
///
/// One-per-step granularity by design: the negative-fixture
/// regression tests in Phase 3 will pin each failure mode to a
/// distinct variant. Operators see a 401 with the body
/// `{"error":"unauthorized"}` (§6.5) — the distinction stays
/// server-side, surfacing via the per-peer anomaly counter (§20).
///
/// `PartialEq` is implemented by-hand below: every variant compares
/// by discriminant only, since `sqlx::Error` (held by [`Db`]) is
/// not itself `PartialEq`. That's exactly what tests want — they
/// only ever ask "is this the *kind* of failure I expected" — and
/// it avoids dragging structural equality through opaque error
/// internals.
#[derive(Debug)]
pub enum VerifyError {
    /// No `X-Prismoire-Federation-Auth` header on the request.
    MissingHeader,
    /// Header value present but not valid base64url.
    BadBase64,
    /// Base64url decoded fine but the bytes are not a valid
    /// `SignedObject` CBOR `{ "p", "s" }` map.
    BadWireFormat,
    /// Payload bytes did not parse as a `signed.rs::SignedPayload`.
    BadPayload,
    /// Payload parsed but the inner class tag was not
    /// `"fed-envelope"`.
    NotFedEnvelope,
    /// Envelope `sender` does not match any active peer
    /// (`VerifyMode::KnownPeer` only).
    UnknownSender,
    /// Ed25519 verification of the envelope signature failed
    /// against the asserted `sender` key.
    SignatureFailed,
    /// Envelope `receiver` did not match this instance's current
    /// public key (§6.5 step 7).
    WrongReceiver,
    /// Envelope `method` did not match the actual HTTP method
    /// (§6.5 step 8).
    MethodMismatch,
    /// Envelope `path` did not match the actual request path
    /// (§6.5 step 9).
    PathMismatch,
    /// Envelope `body_hash` (present or absent) did not match the
    /// actual request body (§6.5 step 10).
    BodyHashMismatch,
    /// `|now - created_at| > MAX_CLOCK_SKEW_MS` (§6.5 step 11).
    ClockSkew,
    /// `(sender, nonce)` already seen within the LRU window (§6.5
    /// step 12).
    Replay,
    /// Database failure during peer lookup.
    Db(sqlx::Error),
}

impl From<sqlx::Error> for VerifyError {
    fn from(value: sqlx::Error) -> Self {
        VerifyError::Db(value)
    }
}

impl PartialEq for VerifyError {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl Eq for VerifyError {}

/// Build the `X-Prismoire-Federation-Auth` header for an outbound
/// federation request. Caller attaches the returned `HeaderValue`
/// to the request and dispatches via the transport.
///
/// `request_body` is the *exact* bytes that will be transmitted,
/// including their CBOR encoding — the receiver hashes the wire
/// body, not a re-encoded copy.
pub fn sign_outbound(
    instance_key: &InstanceKey,
    receiver_pubkey: [u8; 32],
    method: &Method,
    path: &str,
    request_body: &[u8],
) -> HeaderValue {
    let body_hash = if request_body.is_empty() {
        None
    } else {
        Some(sha256(request_body))
    };

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let envelope = FedEnvelope {
        sender: *instance_key.public_bytes(),
        receiver: receiver_pubkey,
        method: method.as_str().to_ascii_uppercase(),
        path: path.to_string(),
        body_hash,
        created_at: now_unix_ms(),
        nonce,
    };

    let payload = SignedPayload::FedEnvelope(envelope).encode();
    let signature = instance_key.sign(&payload);

    let wire = encode_signed_object(&payload, &signature);
    let b64 = URL_SAFE_NO_PAD.encode(&wire);

    // base64url is ASCII so the header value can never reject; the
    // `expect` documents the invariant rather than hiding a real
    // failure mode.
    HeaderValue::from_str(&b64).expect("base64url is ASCII")
}

/// Decode + verify the auth header attached to an inbound request.
///
/// `our_pubkey` is this instance's currently-active signing pubkey
/// (compared against the envelope `receiver` field in step 7). `db`
/// is consulted to resolve `envelope.sender` when `mode =
/// VerifyMode::KnownPeer`; ignored in bootstrap mode. `nonce_lru`
/// is updated in step 12.
///
/// On success, returns the parsed [`FedEnvelope`] — callers needing
/// the request body for routing/dispatch already have it; the
/// envelope itself is returned mostly so caller-specific
/// cross-checks (e.g. peer-request's
/// `envelope.sender == body.initiator_instance_pubkey`) can run.
#[allow(clippy::too_many_arguments)]
pub async fn verify_inbound(
    db: &SqlitePool,
    our_pubkey: &[u8; 32],
    nonce_lru: &NonceLru,
    mode: VerifyMode,
    method: &Method,
    path: &str,
    body: &[u8],
    header: Option<&HeaderValue>,
) -> Result<FedEnvelope, VerifyError> {
    // §6.5 step 1: extract header.
    let header = header.ok_or(VerifyError::MissingHeader)?;
    let header_str = header.to_str().map_err(|_| VerifyError::BadBase64)?;

    // §6.5 step 2: base64url decode.
    let wire_bytes = URL_SAFE_NO_PAD
        .decode(header_str.as_bytes())
        .map_err(|_| VerifyError::BadBase64)?;

    // §6.5 step 3: parse the `{ p, s }` wire format.
    let (payload_bytes, signature_bytes) =
        decode_signed_object(&wire_bytes).ok_or(VerifyError::BadWireFormat)?;

    // §6.5 step 3 / 4: parse the inner payload + confirm class.
    let payload = SignedPayload::parse(&payload_bytes).map_err(|_| VerifyError::BadPayload)?;
    let envelope = match payload {
        SignedPayload::FedEnvelope(e) => e,
        _ => return Err(VerifyError::NotFedEnvelope),
    };

    // §6.5 step 5: sender lookup. Bootstrap path skips this; the
    // caller verifies envelope.sender == body's claimed pubkey.
    match mode {
        VerifyMode::KnownPeer => {
            let sender_slice: &[u8] = envelope.sender.as_slice();
            let row = sqlx::query!(
                "SELECT instance_pubkey FROM peers \
                 WHERE instance_pubkey = ? AND status = 'active' LIMIT 1",
                sender_slice
            )
            .fetch_optional(db)
            .await?;
            if row.is_none() {
                return Err(VerifyError::UnknownSender);
            }
        }
        VerifyMode::Bootstrap => {}
    }

    // §6.5 step 6: signature verify.
    let verifying_key =
        VerifyingKey::from_bytes(&envelope.sender).map_err(|_| VerifyError::SignatureFailed)?;
    signed::verify(&payload_bytes, &signature_bytes, &verifying_key)
        .map_err(|_| VerifyError::SignatureFailed)?;

    // §6.5 step 7: receiver matches us.
    if &envelope.receiver != our_pubkey {
        return Err(VerifyError::WrongReceiver);
    }

    // §6.5 step 8: method matches.
    if envelope.method != method.as_str().to_ascii_uppercase() {
        return Err(VerifyError::MethodMismatch);
    }

    // §6.5 step 9: path matches.
    if envelope.path != path {
        return Err(VerifyError::PathMismatch);
    }

    // §6.5 step 10: body_hash check.
    match (&envelope.body_hash, body.is_empty()) {
        (None, true) => {} // empty body; absent hash; OK
        (Some(_), true) => return Err(VerifyError::BodyHashMismatch),
        (None, false) => return Err(VerifyError::BodyHashMismatch),
        (Some(expected), false) => {
            if expected != &sha256(body) {
                return Err(VerifyError::BodyHashMismatch);
            }
        }
    }

    // §6.5 step 11: clock skew.
    let now = now_unix_ms();
    let diff = now.abs_diff(envelope.created_at);
    if diff > MAX_CLOCK_SKEW_MS {
        return Err(VerifyError::ClockSkew);
    }

    // §6.5 step 12: replay rejection.
    if !nonce_lru.check_and_insert(envelope.sender, envelope.nonce) {
        return Err(VerifyError::Replay);
    }

    Ok(envelope)
}

/// SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Current time as Unix milliseconds. Panics only if the system
/// clock is before the Unix epoch, which would indicate a config
/// disaster well outside this module's concern. `pub(crate)` so the
/// peering handlers can mint matching `created_at` values without
/// each module growing its own copy.
pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_millis() as u64
}

/// Encode the §6.3 `SignedObject` wire format: a canonical CBOR
/// map `{ "p": payload, "s": sig }`. Keys are sorted (`"p"` <
/// `"s"` by bytewise compare).
fn encode_signed_object(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let map = Value::Map(vec![
        (Value::Text("p".to_string()), Value::Bytes(payload.to_vec())),
        (
            Value::Text("s".to_string()),
            Value::Bytes(signature.to_vec()),
        ),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&map, &mut buf).expect("ciborium serialization is infallible");
    buf
}

/// Decode the §6.3 `SignedObject` wire format. Returns `None` on
/// any structural deviation (not a map, wrong keys, non-bytes
/// values, extra entries). Callers translate `None` to
/// [`VerifyError::BadWireFormat`].
fn decode_signed_object(bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let value: Value = ciborium::de::from_reader(bytes).ok()?;
    let entries = match value {
        Value::Map(m) => m,
        _ => return None,
    };
    if entries.len() != 2 {
        return None;
    }
    let mut payload: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;
    for (k, v) in entries {
        let key = match k {
            Value::Text(s) => s,
            _ => return None,
        };
        let bytes = match v {
            Value::Bytes(b) => b,
            _ => return None,
        };
        match key.as_str() {
            "p" => payload = Some(bytes),
            "s" => signature = Some(bytes),
            _ => return None,
        }
    }
    Some((payload?, signature?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_key() -> InstanceKey {
        InstanceKey::new(SigningKey::generate(&mut OsRng))
    }

    #[test]
    fn nonce_lru_rejects_exact_replay() {
        let lru = NonceLru::new(64);
        let sender = [1u8; 32];
        let nonce = [2u8; 16];
        assert!(lru.check_and_insert(sender, nonce));
        assert!(!lru.check_and_insert(sender, nonce));
    }

    #[test]
    fn nonce_lru_distinct_pairs_pass() {
        let lru = NonceLru::new(64);
        assert!(lru.check_and_insert([1; 32], [0; 16]));
        assert!(lru.check_and_insert([1; 32], [1; 16])); // same sender, different nonce
        assert!(lru.check_and_insert([2; 32], [0; 16])); // different sender, same nonce
    }

    #[test]
    fn nonce_lru_zero_capacity_passes_everything() {
        let lru = NonceLru::new(0);
        assert!(lru.check_and_insert([1; 32], [2; 16]));
        assert!(lru.check_and_insert([1; 32], [2; 16]));
    }

    #[test]
    fn signed_object_wire_round_trips() {
        let payload = b"hello world".to_vec();
        let signature = vec![0xab; 64];
        let wire = encode_signed_object(&payload, &signature);
        let (p, s) = decode_signed_object(&wire).expect("decode");
        assert_eq!(p, payload);
        assert_eq!(s, signature);
    }

    #[test]
    fn signed_object_rejects_extra_keys() {
        let mut entries = vec![
            (Value::Text("p".into()), Value::Bytes(b"x".to_vec())),
            (Value::Text("s".into()), Value::Bytes(b"y".to_vec())),
            (Value::Text("z".into()), Value::Bytes(b"junk".to_vec())),
        ];
        entries.sort_by(|a, b| match (&a.0, &b.0) {
            (Value::Text(ka), Value::Text(kb)) => ka.cmp(kb),
            _ => std::cmp::Ordering::Equal,
        });
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
        assert!(decode_signed_object(&buf).is_none());
    }

    #[tokio::test]
    async fn sign_then_verify_round_trip() {
        let pool = fresh_pool().await;
        let sender = test_key();
        // For verify_inbound's step-5 KnownPeer lookup we need a row
        // for the sender. Insert a minimal `active` peer row.
        insert_active_peer(&pool, sender.public_bytes()).await;

        let receiver_pubkey: [u8; 32] = *sender.public_bytes(); // self-loop
        let lru = NonceLru::new(64);

        let body = b"{\"hello\":\"world\"}";
        let header = sign_outbound(
            &sender,
            receiver_pubkey,
            &Method::POST,
            "/federation/v1/peer-request",
            body,
        );

        let envelope = verify_inbound(
            &pool,
            &receiver_pubkey,
            &lru,
            VerifyMode::KnownPeer,
            &Method::POST,
            "/federation/v1/peer-request",
            body,
            Some(&header),
        )
        .await
        .expect("round-trip verify");
        assert_eq!(&envelope.sender, sender.public_bytes());
        assert_eq!(envelope.path, "/federation/v1/peer-request");
        assert_eq!(envelope.method, "POST");
    }

    #[tokio::test]
    async fn replay_is_rejected_on_second_attempt() {
        let pool = fresh_pool().await;
        let sender = test_key();
        insert_active_peer(&pool, sender.public_bytes()).await;
        let receiver_pubkey = *sender.public_bytes();
        let lru = NonceLru::new(64);

        let body = b"x";
        let header = sign_outbound(
            &sender,
            receiver_pubkey,
            &Method::POST,
            "/federation/v1/peer-request",
            body,
        );

        // First call: OK
        verify_inbound(
            &pool,
            &receiver_pubkey,
            &lru,
            VerifyMode::KnownPeer,
            &Method::POST,
            "/federation/v1/peer-request",
            body,
            Some(&header),
        )
        .await
        .expect("first verify");

        // Second call with the same header: must reject as replay.
        let err = verify_inbound(
            &pool,
            &receiver_pubkey,
            &lru,
            VerifyMode::KnownPeer,
            &Method::POST,
            "/federation/v1/peer-request",
            body,
            Some(&header),
        )
        .await
        .expect_err("replay must fail");
        assert_eq!(err, VerifyError::Replay);
    }

    #[tokio::test]
    async fn body_tamper_rejected() {
        let pool = fresh_pool().await;
        let sender = test_key();
        insert_active_peer(&pool, sender.public_bytes()).await;
        let receiver_pubkey = *sender.public_bytes();
        let lru = NonceLru::new(64);

        let header = sign_outbound(
            &sender,
            receiver_pubkey,
            &Method::POST,
            "/federation/v1/peer-request",
            b"original",
        );

        let err = verify_inbound(
            &pool,
            &receiver_pubkey,
            &lru,
            VerifyMode::KnownPeer,
            &Method::POST,
            "/federation/v1/peer-request",
            b"tampered",
            Some(&header),
        )
        .await
        .expect_err("tampered body must fail");
        assert_eq!(err, VerifyError::BodyHashMismatch);
    }

    #[tokio::test]
    async fn bootstrap_mode_skips_peer_lookup() {
        let pool = fresh_pool().await;
        let sender = test_key();
        // Deliberately do *not* insert a peers row — bootstrap mode
        // must accept the envelope anyway (peer-request bootstrap).
        let receiver_pubkey = *sender.public_bytes();
        let lru = NonceLru::new(64);

        let header = sign_outbound(
            &sender,
            receiver_pubkey,
            &Method::POST,
            "/federation/v1/peer-request",
            b"hello",
        );

        verify_inbound(
            &pool,
            &receiver_pubkey,
            &lru,
            VerifyMode::Bootstrap,
            &Method::POST,
            "/federation/v1/peer-request",
            b"hello",
            Some(&header),
        )
        .await
        .expect("bootstrap mode accepts unknown sender");
    }

    async fn fresh_pool() -> SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    async fn insert_active_peer(pool: &SqlitePool, pubkey: &[u8; 32]) {
        let pubkey_slice: &[u8] = pubkey;
        let domain = format!("test-{}.example", &hex::encode(&pubkey[..4]));
        let request_id: &[u8] = &[0xaa; 16];
        sqlx::query!(
            "INSERT INTO peers \
             (instance_pubkey, instance_domain, status, direction, request_id) \
             VALUES (?, ?, 'active', 'outbound', ?)",
            pubkey_slice,
            domain,
            request_id,
        )
        .execute(pool)
        .await
        .unwrap();
    }

    // Tiny inline hex helper for the test-only fake domain above; the
    // real `hex` lives in `instance_key.rs` and isn't worth exposing
    // crate-wide just for this.
    mod hex {
        pub fn encode(bytes: &[u8]) -> String {
            let mut s = String::with_capacity(bytes.len() * 2);
            for b in bytes {
                s.push_str(&format!("{b:02x}"));
            }
            s
        }
    }
}
