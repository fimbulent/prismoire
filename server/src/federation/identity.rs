//! `GET /federation/v1/identity` — instance identity card.
//!
//! The only unauthenticated route on the federation surface per
//! `docs/federation-protocol.md` §5.2. Returns a CBOR map describing
//! this instance: its bare canonical domain, its current Ed25519
//! signing pubkey, the protocol versions it speaks, the capability
//! flags it implements, and a small set of *opt-in* operator
//! metadata fields (`announce`, `instance_age_days`,
//! `user_count_bucket`). Those last fields stay absent by default so
//! a freshly-installed instance discloses only the cryptographically-
//! necessary identity surface.
//!
//! Phase 2 implements the required core (domain, pubkey,
//! `protocol_versions`, `capabilities`); the opt-in metadata fields
//! are wired through as `None`s for now and will land alongside the
//! admin config surface that lets operators flip them on. The
//! `deprecated_capabilities` field is similarly absent until §19
//! deprecation tracking ships.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use ciborium::value::{Integer, Value};

use crate::federation::instance_key::InstanceKey;

/// Content-Type for every CBOR response on `/federation/v1/*`.
/// Matches the RFC 8949 IANA registration.
pub const CBOR_CONTENT_TYPE: &str = "application/cbor";

/// Protocol versions this build implements. V1 only for now; the
/// type matches the spec's `array of uint` shape.
pub const PROTOCOL_VERSIONS: &[u64] = &[1];

/// V1 capability vocabulary as documented in
/// `docs/federation-protocol.md` §5.3. The order chosen here matches
/// the spec table; on the wire we emit the array as-is (`array of
/// tstr`, no sorting required).
///
/// Phase 2 advertises the full required set even though none of the
/// associated routes (frontier sync, edge sync, content sync, …)
/// exist yet. This is intentional: the §5.4 handshake intersects
/// advertised sets to compute `agreed_capabilities`, and if a
/// freshly-built instance advertised an empty set the handshake
/// would always negotiate down to nothing usable. The mismatch
/// between "advertised" and "actually implemented" is what the
/// per-peer anomaly counter (§20) tracks; for harness tests in
/// Phase 2 there is no traffic past handshake so the divergence is
/// inert. Later phases will narrow this to the routes the build
/// actually services.
pub const CAPABILITIES: &[&str] = &[
    "frontier-sync",
    "edge-sync",
    "content-sync",
    "pull-backfill",
    "profile-sync",
    "user-status",
    "thread-status",
    "attachment-fetch",
    "reports",
];

/// Typed view of the identity card. Constructed from `AppState` at
/// request time, then handed to [`encode`] for the wire bytes.
///
/// Optional fields are `Option<...>` so callers (handler + tests)
/// can mint a card with whichever fields they have without a
/// builder. Absence on the wire is signalled by omitting the
/// corresponding key (CBOR-null is *not* used — protocol §5.2
/// explicitly says "absent").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCard {
    /// Bare canonical domain. Must match the host of the request
    /// (operator visually confirms; the protocol does not bind this
    /// to TLS material).
    pub instance_domain: String,
    /// Instance signing pubkey, raw 32 bytes (§6.2).
    pub instance_pubkey: [u8; 32],
    /// Supported `/federation/vN/*` versions.
    pub protocol_versions: Vec<u64>,
    /// Capability flags advertised by this instance.
    pub capabilities: Vec<String>,
    /// Operator-set introduction string. Default absent.
    pub announce: Option<String>,
    /// Opt-in coarse instance age. Default absent.
    pub instance_age_days: Option<u64>,
    /// Opt-in user-count bucket (`"1-10"`, `"10-100"`, …). Default
    /// absent.
    pub user_count_bucket: Option<String>,
}

impl IdentityCard {
    /// Build the standard card for this instance from the runtime
    /// inputs the handler has (domain + signing key). All opt-in
    /// metadata fields default to `None`; admin-config support to
    /// flip them on lands in a later phase.
    pub fn standard(instance_domain: String, key: &InstanceKey) -> Self {
        Self {
            instance_domain,
            instance_pubkey: *key.public_bytes(),
            protocol_versions: PROTOCOL_VERSIONS.to_vec(),
            capabilities: CAPABILITIES.iter().map(|s| (*s).to_string()).collect(),
            announce: None,
            instance_age_days: None,
            user_count_bucket: None,
        }
    }

    /// Encode to the §5.2 CBOR shape. Keys are emitted in spec
    /// table order; the identity card is not a signed payload so
    /// the canonical-CBOR rules of `signed.rs` don't apply — the
    /// receiver decodes by key lookup, not by byte compare.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries: Vec<(Value, Value)> = vec![
            (
                Value::Text("instance_domain".to_string()),
                Value::Text(self.instance_domain.clone()),
            ),
            (
                Value::Text("instance_pubkey".to_string()),
                Value::Bytes(self.instance_pubkey.to_vec()),
            ),
            (
                Value::Text("protocol_versions".to_string()),
                Value::Array(
                    self.protocol_versions
                        .iter()
                        .map(|v| Value::Integer(Integer::from(*v)))
                        .collect(),
                ),
            ),
            (
                Value::Text("capabilities".to_string()),
                Value::Array(
                    self.capabilities
                        .iter()
                        .map(|c| Value::Text(c.clone()))
                        .collect(),
                ),
            ),
        ];

        if let Some(s) = &self.announce {
            entries.push((Value::Text("announce".to_string()), Value::Text(s.clone())));
        }
        if let Some(d) = self.instance_age_days {
            entries.push((
                Value::Text("instance_age_days".to_string()),
                Value::Integer(Integer::from(d)),
            ));
        }
        if let Some(b) = &self.user_count_bucket {
            entries.push((
                Value::Text("user_count_bucket".to_string()),
                Value::Text(b.clone()),
            ));
        }

        let mut buf = Vec::with_capacity(128);
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf)
            .expect("ciborium serialization is infallible into Vec");
        buf
    }

    /// Decode a wire identity card.
    ///
    /// **Strictness policy.** Tolerant on *unknown* keys (any
    /// non-text key, or a text key we don't recognize, is skipped
    /// per the protocol's forward-compatibility expectations).
    /// Strict on the *value shape* of every key we do recognize —
    /// required OR optional — because a wrong-typed `announce` is
    /// just as much a producer bug as a wrong-typed `instance_pubkey`
    /// and silently dropping it would mask the bug. Returns `None`
    /// on any such structural deviation.
    ///
    /// Used by the initiator side of §5.4 to read the responder's
    /// identity card before signing the peer-request envelope (which
    /// needs the responder's `instance_pubkey`).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };

        let mut domain: Option<String> = None;
        let mut pubkey: Option<[u8; 32]> = None;
        let mut versions: Option<Vec<u64>> = None;
        let mut caps: Option<Vec<String>> = None;
        let mut announce: Option<String> = None;
        let mut age_days: Option<u64> = None;
        let mut bucket: Option<String> = None;

        for (k, v) in entries {
            let key = match k {
                Value::Text(s) => s,
                // Spec only defines text-string keys; an integer-key
                // entry is non-conforming. Skip rather than reject
                // so unknown extensions don't break decode entirely.
                _ => continue,
            };
            match key.as_str() {
                "instance_domain" => {
                    if let Value::Text(s) = v {
                        domain = Some(s);
                    } else {
                        return None;
                    }
                }
                "instance_pubkey" => {
                    if let Value::Bytes(b) = v
                        && let Ok(arr) = <[u8; 32]>::try_from(b.as_slice())
                    {
                        pubkey = Some(arr);
                    } else {
                        return None;
                    }
                }
                "protocol_versions" => {
                    if let Value::Array(items) = v {
                        let mut out = Vec::with_capacity(items.len());
                        for it in items {
                            let n: u64 = match it {
                                Value::Integer(i) => i.try_into().ok()?,
                                _ => return None,
                            };
                            out.push(n);
                        }
                        versions = Some(out);
                    } else {
                        return None;
                    }
                }
                "capabilities" => {
                    if let Value::Array(items) = v {
                        let mut out = Vec::with_capacity(items.len());
                        for it in items {
                            match it {
                                Value::Text(s) => out.push(s),
                                _ => return None,
                            }
                        }
                        caps = Some(out);
                    } else {
                        return None;
                    }
                }
                "announce" => {
                    if let Value::Text(s) = v {
                        announce = Some(s);
                    } else {
                        return None;
                    }
                }
                "instance_age_days" => {
                    if let Value::Integer(i) = v {
                        age_days = Some(i.try_into().ok()?);
                    } else {
                        return None;
                    }
                }
                "user_count_bucket" => {
                    if let Value::Text(s) = v {
                        bucket = Some(s);
                    } else {
                        return None;
                    }
                }
                // Unknown keys (e.g. `deprecated_capabilities` from a
                // future build, or operator-extension fields) are
                // ignored — forward-compatibility per §5.3.
                _ => {}
            }
        }

        Some(IdentityCard {
            instance_domain: domain?,
            instance_pubkey: pubkey?,
            protocol_versions: versions?,
            capabilities: caps?,
            announce,
            instance_age_days: age_days,
            user_count_bucket: bucket,
        })
    }
}

/// `GET /federation/v1/identity` handler.
///
/// Reads the instance domain and signing pubkey straight off the
/// shared `AppState`. The route is wired into the federation
/// subrouter by [`crate::federation::router::federation_router`].
///
/// The §5.2 spec calls for tight per-source-IP rate limiting
/// (`IDENTITY_RPM=60`). Phase 2 leaves that to the outer
/// `ip_limiter` already applied at `build_app`; a dedicated tighter
/// bucket lands once the rate-limit module grows a federation
/// scope.
pub async fn get_identity(State(state): State<Arc<crate::AppState>>) -> impl IntoResponse {
    let card = IdentityCard::standard(state.instance_domain.clone(), &state.instance_key);
    let body = card.encode();
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn sample_card() -> IdentityCard {
        IdentityCard {
            instance_domain: "alpha.example".to_string(),
            instance_pubkey: [7u8; 32],
            protocol_versions: vec![1],
            capabilities: vec!["frontier-sync".to_string(), "edge-sync".to_string()],
            announce: None,
            instance_age_days: None,
            user_count_bucket: None,
        }
    }

    #[test]
    fn encode_then_decode_round_trips_required_fields() {
        let card = sample_card();
        let bytes = card.encode();
        let decoded = IdentityCard::decode(&bytes).expect("decode required-only card");
        assert_eq!(decoded, card);
    }

    #[test]
    fn encode_then_decode_round_trips_optional_fields() {
        let mut card = sample_card();
        card.announce = Some("Hello from Alpha!".to_string());
        card.instance_age_days = Some(42);
        card.user_count_bucket = Some("10-100".to_string());
        let bytes = card.encode();
        let decoded = IdentityCard::decode(&bytes).expect("decode full card");
        assert_eq!(decoded, card);
    }

    #[test]
    fn decode_ignores_unknown_keys() {
        // Build a wire map with an extra `future_extension` key the
        // V1 decoder doesn't know about — must not break decode.
        let mut entries: Vec<(Value, Value)> = vec![
            (
                Value::Text("instance_domain".into()),
                Value::Text("x.example".into()),
            ),
            (
                Value::Text("instance_pubkey".into()),
                Value::Bytes(vec![0xab; 32]),
            ),
            (
                Value::Text("protocol_versions".into()),
                Value::Array(vec![Value::Integer(Integer::from(1u64))]),
            ),
            (
                Value::Text("capabilities".into()),
                Value::Array(vec![Value::Text("edge-sync".into())]),
            ),
            (
                Value::Text("future_extension".into()),
                Value::Text("ignore me".into()),
            ),
        ];
        entries.sort_by_key(|(k, _)| match k {
            Value::Text(s) => s.clone(),
            _ => String::new(),
        });
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
        let card = IdentityCard::decode(&buf).expect("decode with unknown key");
        assert_eq!(card.instance_domain, "x.example");
        assert_eq!(card.capabilities, vec!["edge-sync".to_string()]);
    }

    #[test]
    fn decode_rejects_short_pubkey() {
        let entries: Vec<(Value, Value)> = vec![
            (
                Value::Text("instance_domain".into()),
                Value::Text("x.example".into()),
            ),
            (
                Value::Text("instance_pubkey".into()),
                Value::Bytes(vec![0xab; 16]),
            ),
            (
                Value::Text("protocol_versions".into()),
                Value::Array(vec![Value::Integer(Integer::from(1u64))]),
            ),
            (Value::Text("capabilities".into()), Value::Array(vec![])),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
        assert!(IdentityCard::decode(&buf).is_none());
    }

    #[test]
    fn standard_pulls_pubkey_from_instance_key() {
        let key = InstanceKey::new(SigningKey::generate(&mut OsRng));
        let card = IdentityCard::standard("alpha.example".to_string(), &key);
        assert_eq!(&card.instance_pubkey, key.public_bytes());
        assert_eq!(card.protocol_versions, PROTOCOL_VERSIONS.to_vec());
        assert_eq!(
            card.capabilities.len(),
            CAPABILITIES.len(),
            "standard card advertises full V1 capability set"
        );
    }
}
