//! Per-peer frontier-sync wire surface
//! (`docs/federation-protocol.md` §7.4, §8 + implementation plan
//! Phase 4).
//!
//! Three routes mount under `/federation/v1`:
//!
//! ```text
//! POST /federation/v1/frontier/announce     (§8.3 full snapshot)
//! POST /federation/v1/frontier/delta        (§8.4 additions-only update)
//! GET  /federation/v1/frontier              (§8.5 pull pattern)
//! ```
//!
//! All three are mounted behind `verify_known_peer`: the sender must
//! be an `active` peer per §6 envelope auth. This module owns the
//! wire types (`FilterSpec`, `FrontierAnnounce`, `FrontierDelta`,
//! `FrontierSnapshot`), CBOR encode/decode, the in-memory
//! [`LocalFrontier`] snapshot that the GET route serves and that
//! `peers_interested_in` consumes, and the three HTTP handlers.
//!
//! The bloom-filter primitive itself lives in [`super::bloom`] — this
//! module composes those filters into wire structures and persists
//! peer-supplied frontiers into the `peer_frontiers` table.
//!
//! **Routing fanout (`POST /announce` outbound).** The operator-side
//! [`operator_announce_frontier`] helper builds the local snapshot
//! over the trust graph (3-hop content closure → `visible_filter`,
//! 2-hop edge-origin closure → `expansion_filter`), signs the body
//! per §6, and dispatches to the supplied peer via the federation
//! transport. Background re-announce / per-peer fanout is the Phase 5+
//! concern that consumes this helper; Phase 4 ships the helper itself
//! plus the receiving end.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Extension, Query, State};
use axum::http::{Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::{Integer, Value};
use http::HeaderValue;
use sqlx::SqlitePool;

use crate::AppState;
use crate::federation::bloom::{self, BloomFilter};
use crate::federation::envelope::{self, AUTH_HEADER};
use crate::federation::errors::{bad_request, conflict, internal_error, not_found, unauthorized};
use crate::federation::frontier_store::{self, FrontierReader};
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::instance_key::InstanceKey;
use crate::federation::middleware::VerifiedBody;
use crate::federation::routing::{self, Mode};
use crate::federation::transport::{FederationTransport, PeerId, TransportError};
use crate::signed::FedEnvelope;
use crate::trust::TrustGraph;

/// Default target false-positive rate for locally-produced frontier
/// filters (§8.2 "Sizing target"). 1% is the spec's reference design.
const DEFAULT_FPR_TARGET: f32 = 0.01;

/// Default `k` (hash count) when sizing produces a per-key bit budget
/// near the spec's reference 10 bits/key. Used as a fallback only —
/// `bloom::recommend_k` overrides this whenever a sensible
/// closure-based sizing is available.
const DEFAULT_K: u32 = 7;

/// `active_horizon_days = 0` per §8.3 means "no active-set trimming."
/// V1 of this implementation does not yet trim by recency (the
/// trust-graph BFS over `current_trust_edges` is itself the closure);
/// the field is advertised honestly as 0 until a future phase wires
/// in the trim lever.
const NO_TRIMMING: u32 = 0;

// ---------------------------------------------------------------------------
// AgeCeilings: §8.10 per-root celebrity cleave (sparse, non-Bloom)
// ---------------------------------------------------------------------------

/// §8.3/§8.4 `AgeCeilings`: a sparse map `root_pubkey -> genesis_at
/// cutoff (unix ms)`. Only cleaved roots appear; an absent root means
/// "no ceiling, admit all". An empty map encodes to no wire field at
/// all (absent == no celebrity cleave). Held as a `BTreeMap` so the
/// CBOR encoding is deterministic (key-sorted) — the existing frontier
/// codec does not chase canonical CBOR, but a stable order keeps
/// round-trip tests and golden bytes reproducible.
pub type AgeCeilings = BTreeMap<[u8; 32], u64>;

/// Encode an [`AgeCeilings`] map as a CBOR `Value::Map` of
/// `bstr(32) -> u64`. Caller decides whether to emit it (skip when
/// empty so the wire field stays absent).
fn age_ceilings_to_cbor_value(ceilings: &AgeCeilings) -> Value {
    Value::Map(
        ceilings
            .iter()
            .map(|(root, cutoff)| {
                (
                    Value::Bytes(root.to_vec()),
                    Value::Integer(Integer::from(*cutoff)),
                )
            })
            .collect(),
    )
}

/// Decode a CBOR `Value::Map` of `bstr(32) -> u64` into an
/// [`AgeCeilings`]. Returns `None` (failing the whole decode) on a
/// non-map value, a root key that is not exactly 32 bytes, or a cutoff
/// that is not a non-negative integer in `u64` range.
fn age_ceilings_from_cbor_value(value: Value) -> Option<AgeCeilings> {
    let entries = match value {
        Value::Map(m) => m,
        _ => return None,
    };
    let mut out = AgeCeilings::new();
    for (k, v) in entries {
        let root: [u8; 32] = match k {
            Value::Bytes(b) => b.try_into().ok()?,
            _ => return None,
        };
        let cutoff: u64 = match v {
            Value::Integer(i) => i.try_into().ok()?,
            _ => return None,
        };
        out.insert(root, cutoff);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Wire types: FilterSpec / FrontierAnnounce / FrontierDelta / FrontierSnapshot
// ---------------------------------------------------------------------------

/// §8.2 `FilterSpec`: one of the two filters carried in an announce
/// or snapshot (visible_filter or expansion_filter).
///
/// The wire layout is the same shape used in [`FrontierSnapshot`]
/// (the GET response) — we keep one CBOR encode/decode pair here to
/// avoid drift between the two uses.
#[derive(Debug, Clone, PartialEq)]
pub struct FilterSpec {
    /// Family discriminator, per §8.2. V1 accepts only
    /// `prismoire-bloom-v1`; future families dispatch off this string.
    pub family: String,
    /// Hash count.
    pub k: u32,
    /// Bit count; multiple of 64, in `[64, 2^32)`.
    pub m: u32,
    /// Sender-estimated key cardinality. Informational.
    pub n_est: u64,
    /// Sender-designed FPR target. Informational.
    pub fpr_target: f32,
    /// Filter bytes; exactly `m / 8` bytes.
    pub bytes: Vec<u8>,
}

impl FilterSpec {
    /// Build a `FilterSpec` from a populated [`BloomFilter`]. The wire
    /// representation copies the filter's bytes; this is a producer-
    /// side helper used by the local-frontier compute path.
    pub fn from_bloom(filter: &BloomFilter) -> Self {
        Self {
            family: bloom::FAMILY.to_string(),
            k: filter.k,
            m: filter.m,
            n_est: filter.n_est,
            fpr_target: filter.fpr_target,
            bytes: filter.bits.clone(),
        }
    }

    /// Validate the spec against the §8.2 parameter ranges and
    /// reconstruct a [`BloomFilter`]. The receiver side calls this
    /// after CBOR decode to lift the wire spec into the in-memory
    /// type the routing layer consumes. Returns the spec-table error
    /// code per §8.3 on rejection so the handler can surface it
    /// verbatim.
    pub fn into_bloom(self) -> Result<BloomFilter, &'static str> {
        if self.family != bloom::FAMILY {
            return Err("unsupported_family");
        }
        if !(bloom::MIN_K..=bloom::MAX_K).contains(&self.k) {
            return Err("filter_param_out_of_range");
        }
        if self.m < bloom::MIN_M_BITS
            || (self.m as u64) >= bloom::MAX_M_BITS
            || !self.m.is_multiple_of(64)
        {
            return Err("filter_param_out_of_range");
        }
        if self.bytes.len() != (self.m / 8) as usize {
            return Err("bytes_length_mismatch");
        }
        BloomFilter::from_parts(self.k, self.m, self.n_est, self.fpr_target, self.bytes)
            .map_err(|_| "filter_param_out_of_range")
    }

    fn to_cbor_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::Text("family".into()),
                Value::Text(self.family.clone()),
            ),
            (
                Value::Text("k".into()),
                Value::Integer(Integer::from(self.k)),
            ),
            (
                Value::Text("m".into()),
                Value::Integer(Integer::from(self.m)),
            ),
            (
                Value::Text("n_est".into()),
                Value::Integer(Integer::from(self.n_est)),
            ),
            (
                Value::Text("fpr_target".into()),
                Value::Float(self.fpr_target as f64),
            ),
            (
                Value::Text("bytes".into()),
                Value::Bytes(self.bytes.clone()),
            ),
        ])
    }

    fn from_cbor_value(v: Value) -> Option<Self> {
        let entries = match v {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut family: Option<String> = None;
        let mut k: Option<u32> = None;
        let mut m: Option<u32> = None;
        let mut n_est: Option<u64> = None;
        let mut fpr_target: Option<f32> = None;
        let mut bytes: Option<Vec<u8>> = None;
        for (key, val) in entries {
            let key = match key {
                Value::Text(s) => s,
                _ => continue,
            };
            match key.as_str() {
                "family" => {
                    if let Value::Text(s) = val {
                        family = Some(s);
                    } else {
                        return None;
                    }
                }
                "k" => {
                    if let Value::Integer(i) = val {
                        let n: u64 = i.try_into().ok()?;
                        k = Some(u32::try_from(n).ok()?);
                    } else {
                        return None;
                    }
                }
                "m" => {
                    if let Value::Integer(i) = val {
                        let n: u64 = i.try_into().ok()?;
                        m = Some(u32::try_from(n).ok()?);
                    } else {
                        return None;
                    }
                }
                "n_est" => {
                    if let Value::Integer(i) = val {
                        n_est = Some(i.try_into().ok()?);
                    } else {
                        return None;
                    }
                }
                "fpr_target" => match val {
                    Value::Float(f) => fpr_target = Some(f as f32),
                    // `fpr_target` is a probability in (0, 1); accepting
                    // CBOR integers would silently coerce values like
                    // `5` into `5.0`, which `from_parts` would then
                    // reject as out-of-spec — but only after the rest
                    // of the message has been parsed. Reject at the
                    // type-tag level instead so the wire shape is
                    // enforced exactly.
                    _ => return None,
                },
                "bytes" => {
                    if let Value::Bytes(b) = val {
                        bytes = Some(b);
                    } else {
                        return None;
                    }
                }
                _ => {}
            }
        }
        Some(FilterSpec {
            family: family?,
            k: k?,
            m: m?,
            n_est: n_est?,
            fpr_target: fpr_target?,
            bytes: bytes?,
        })
    }
}

/// §8.3 `POST /frontier/announce` request body.
#[derive(Debug, Clone, PartialEq)]
pub struct FrontierAnnounce {
    /// Monotonic per (sender, receiver) pair.
    pub version: u64,
    /// Unix ms; when this filter pair became active locally.
    pub epoch_start: u64,
    /// 0 == no trimming; informational.
    pub active_horizon_days: u32,
    /// 3-hop content closure.
    pub visible_filter: FilterSpec,
    /// 2-hop edge-origin closure.
    pub expansion_filter: FilterSpec,
    /// §7.2 routing mode the sender currently uses for the
    /// `sender → receiver` direction (Phase 6.5 fold-in: piggybacked
    /// on the frontier announce instead of the full §7.2 POST /mode
    /// flow). The receiver stores this as `inbound_mode` for the
    /// sender peer. Absent on the wire is decoded as
    /// [`Mode::Filtered`] — the conservative §7.2 default for any
    /// peer whose build predates this field.
    pub mode: Mode,
    /// §8.10 per-root celebrity cleave. Sparse map of `root_pubkey ->
    /// genesis_at cutoff (unix ms)`; only cleaved roots appear. Empty
    /// means "no celebrity cleave" and is omitted from the wire
    /// entirely (absent == no ceiling). `/announce` carries the full
    /// snapshot: the receiver replaces its stored ceiling set with this
    /// map verbatim.
    pub age_ceilings: AgeCeilings,
}

impl FrontierAnnounce {
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            (
                Value::Text("version".into()),
                Value::Integer(Integer::from(self.version)),
            ),
            (
                Value::Text("epoch_start".into()),
                Value::Integer(Integer::from(self.epoch_start)),
            ),
            (
                Value::Text("active_horizon_days".into()),
                Value::Integer(Integer::from(self.active_horizon_days)),
            ),
            (
                Value::Text("visible_filter".into()),
                self.visible_filter.to_cbor_value(),
            ),
            (
                Value::Text("expansion_filter".into()),
                self.expansion_filter.to_cbor_value(),
            ),
            (
                Value::Text("mode".into()),
                Value::Text(self.mode.as_db_str().into()),
            ),
        ];
        // §8.3: `age_ceilings` is optional — emit it only when at least
        // one root is cleaved, so an uncleaved frontier stays
        // byte-for-byte identical to a pre-Slice-C announce.
        if !self.age_ceilings.is_empty() {
            entries.push((
                Value::Text("age_ceilings".into()),
                age_ceilings_to_cbor_value(&self.age_ceilings),
            ));
        }
        let value = Value::Map(entries);
        let mut buf = Vec::with_capacity(256);
        ciborium::ser::into_writer(&value, &mut buf).expect("ciborium ser infallible");
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut version: Option<u64> = None;
        let mut epoch_start: Option<u64> = None;
        let mut active_horizon_days: Option<u32> = None;
        let mut visible_filter: Option<FilterSpec> = None;
        let mut expansion_filter: Option<FilterSpec> = None;
        // §7.2 default — a sender whose build predates Phase 6.5
        // omits the field; per the conservative-default rule we read
        // that as `filtered`.
        let mut mode: Mode = Mode::Filtered;
        // §8.3 default — absent `age_ceilings` means no celebrity
        // cleave (admit all roots), which the empty map represents.
        let mut age_ceilings = AgeCeilings::new();
        for (k, v) in entries {
            let key = match k {
                Value::Text(s) => s,
                _ => continue,
            };
            match key.as_str() {
                "version" => {
                    if let Value::Integer(i) = v {
                        version = Some(i.try_into().ok()?);
                    } else {
                        return None;
                    }
                }
                "epoch_start" => {
                    if let Value::Integer(i) = v {
                        epoch_start = Some(i.try_into().ok()?);
                    } else {
                        return None;
                    }
                }
                "active_horizon_days" => {
                    if let Value::Integer(i) = v {
                        let n: u64 = i.try_into().ok()?;
                        active_horizon_days = Some(u32::try_from(n).ok()?);
                    } else {
                        return None;
                    }
                }
                "visible_filter" => {
                    visible_filter = Some(FilterSpec::from_cbor_value(v)?);
                }
                "expansion_filter" => {
                    expansion_filter = Some(FilterSpec::from_cbor_value(v)?);
                }
                "mode" => {
                    if let Value::Text(s) = v {
                        mode = Mode::from_db_str(&s);
                    } else {
                        return None;
                    }
                }
                "age_ceilings" => {
                    age_ceilings = age_ceilings_from_cbor_value(v)?;
                }
                _ => {}
            }
        }
        Some(FrontierAnnounce {
            version: version?,
            epoch_start: epoch_start?,
            active_horizon_days: active_horizon_days?,
            visible_filter: visible_filter?,
            expansion_filter: expansion_filter?,
            mode,
            age_ceilings,
        })
    }
}

/// §8.4 `POST /frontier/delta` request body.
#[derive(Debug, Clone, PartialEq)]
pub struct FrontierDelta {
    /// Sender's view of receiver's currently-applied version.
    pub prev_version: u64,
    /// New version; MUST be > prev_version.
    pub new_version: u64,
    /// Optional content-filter OR-mask; `m_c / 8` bytes when present.
    pub visible_mask: Option<Vec<u8>>,
    /// Optional edge-origin OR-mask; `m_e / 8` bytes when present.
    pub expansion_mask: Option<Vec<u8>>,
    /// §7.2 routing mode the sender currently uses for the
    /// `sender → receiver` direction. Same Phase 6.5 fold-in
    /// semantics as [`FrontierAnnounce::mode`]: receiver stores this
    /// as `inbound_mode` for the sender peer and independently
    /// recomputes the local `outbound_mode` from coverage. Absent on
    /// the wire decodes to [`Mode::Filtered`].
    pub mode: Mode,
    /// §8.4 per-root celebrity-cleave update. Sparse map of
    /// `root_pubkey -> genesis_at cutoff (unix ms)` for **moved** roots
    /// only; merged over the receiver's stored ceiling map
    /// (last-writer-wins, cutoff MAY decrease to tighten within a
    /// generation). Empty means "no ceiling change" and is omitted from
    /// the wire. At least one of `masks` / `age_ceilings` must carry an
    /// entry, else the delta is `empty_delta`.
    pub age_ceilings: AgeCeilings,
}

impl FrontierDelta {
    pub fn encode(&self) -> Vec<u8> {
        let mut mask_entries: Vec<(Value, Value)> = Vec::with_capacity(2);
        if let Some(m) = &self.visible_mask {
            mask_entries.push((
                Value::Text("visible_filter".into()),
                Value::Bytes(m.clone()),
            ));
        }
        if let Some(m) = &self.expansion_mask {
            mask_entries.push((
                Value::Text("expansion_filter".into()),
                Value::Bytes(m.clone()),
            ));
        }
        let mut entries = vec![
            (
                Value::Text("prev_version".into()),
                Value::Integer(Integer::from(self.prev_version)),
            ),
            (
                Value::Text("new_version".into()),
                Value::Integer(Integer::from(self.new_version)),
            ),
            (Value::Text("masks".into()), Value::Map(mask_entries)),
            (
                Value::Text("mode".into()),
                Value::Text(self.mode.as_db_str().into()),
            ),
        ];
        // §8.4: `age_ceilings` is optional — emit only on a ceiling
        // change so a filter-only delta stays compatible with the
        // pre-Slice-C wire shape.
        if !self.age_ceilings.is_empty() {
            entries.push((
                Value::Text("age_ceilings".into()),
                age_ceilings_to_cbor_value(&self.age_ceilings),
            ));
        }
        let value = Value::Map(entries);
        let mut buf = Vec::with_capacity(128);
        ciborium::ser::into_writer(&value, &mut buf).expect("ciborium ser infallible");
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut prev_version: Option<u64> = None;
        let mut new_version: Option<u64> = None;
        let mut visible_mask: Option<Vec<u8>> = None;
        let mut expansion_mask: Option<Vec<u8>> = None;
        let mut mode: Mode = Mode::Filtered;
        let mut age_ceilings = AgeCeilings::new();
        for (k, v) in entries {
            let key = match k {
                Value::Text(s) => s,
                _ => continue,
            };
            match key.as_str() {
                "prev_version" => {
                    if let Value::Integer(i) = v {
                        prev_version = Some(i.try_into().ok()?);
                    } else {
                        return None;
                    }
                }
                "new_version" => {
                    if let Value::Integer(i) = v {
                        new_version = Some(i.try_into().ok()?);
                    } else {
                        return None;
                    }
                }
                "masks" => {
                    let mask_entries = match v {
                        Value::Map(m) => m,
                        _ => return None,
                    };
                    for (mk, mv) in mask_entries {
                        let mk_str = match mk {
                            Value::Text(s) => s,
                            _ => continue,
                        };
                        let mb = match mv {
                            Value::Bytes(b) => b,
                            _ => return None,
                        };
                        match mk_str.as_str() {
                            "visible_filter" => visible_mask = Some(mb),
                            "expansion_filter" => expansion_mask = Some(mb),
                            _ => {}
                        }
                    }
                }
                "mode" => {
                    if let Value::Text(s) = v {
                        mode = Mode::from_db_str(&s);
                    } else {
                        return None;
                    }
                }
                "age_ceilings" => {
                    age_ceilings = age_ceilings_from_cbor_value(v)?;
                }
                _ => {}
            }
        }
        Some(FrontierDelta {
            prev_version: prev_version?,
            new_version: new_version?,
            visible_mask,
            expansion_mask,
            mode,
            age_ceilings,
        })
    }
}

/// §8.5 `GET /frontier?since=...` response body (the 200 case).
#[derive(Debug, Clone, PartialEq)]
pub struct FrontierSnapshot {
    pub version: u64,
    pub epoch_start: u64,
    pub active_horizon_days: u32,
    pub visible_filter: FilterSpec,
    pub expansion_filter: FilterSpec,
    /// Opaque cursor, ≤ 64 bytes per §8.5.
    pub cursor: Vec<u8>,
    /// §8.10 per-root celebrity cleave, mirrored from the §8.3 announce
    /// snapshot so a §8.5 pull conveys the same ceiling set a push
    /// would. Empty means "no celebrity cleave" and is omitted from the
    /// wire.
    pub age_ceilings: AgeCeilings,
}

impl FrontierSnapshot {
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            (
                Value::Text("version".into()),
                Value::Integer(Integer::from(self.version)),
            ),
            (
                Value::Text("epoch_start".into()),
                Value::Integer(Integer::from(self.epoch_start)),
            ),
            (
                Value::Text("active_horizon_days".into()),
                Value::Integer(Integer::from(self.active_horizon_days)),
            ),
            (
                Value::Text("visible_filter".into()),
                self.visible_filter.to_cbor_value(),
            ),
            (
                Value::Text("expansion_filter".into()),
                self.expansion_filter.to_cbor_value(),
            ),
            (
                Value::Text("cursor".into()),
                Value::Bytes(self.cursor.clone()),
            ),
        ];
        if !self.age_ceilings.is_empty() {
            entries.push((
                Value::Text("age_ceilings".into()),
                age_ceilings_to_cbor_value(&self.age_ceilings),
            ));
        }
        let value = Value::Map(entries);
        let mut buf = Vec::with_capacity(256);
        ciborium::ser::into_writer(&value, &mut buf).expect("ciborium ser infallible");
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value: Value = ciborium::de::from_reader(bytes).ok()?;
        let entries = match value {
            Value::Map(m) => m,
            _ => return None,
        };
        let mut version: Option<u64> = None;
        let mut epoch_start: Option<u64> = None;
        let mut active_horizon_days: Option<u32> = None;
        let mut visible_filter: Option<FilterSpec> = None;
        let mut expansion_filter: Option<FilterSpec> = None;
        let mut cursor: Option<Vec<u8>> = None;
        let mut age_ceilings = AgeCeilings::new();
        for (k, v) in entries {
            let key = match k {
                Value::Text(s) => s,
                _ => continue,
            };
            match key.as_str() {
                "version" => {
                    if let Value::Integer(i) = v {
                        version = Some(i.try_into().ok()?);
                    } else {
                        return None;
                    }
                }
                "epoch_start" => {
                    if let Value::Integer(i) = v {
                        epoch_start = Some(i.try_into().ok()?);
                    } else {
                        return None;
                    }
                }
                "active_horizon_days" => {
                    if let Value::Integer(i) = v {
                        let n: u64 = i.try_into().ok()?;
                        active_horizon_days = Some(u32::try_from(n).ok()?);
                    } else {
                        return None;
                    }
                }
                "visible_filter" => {
                    visible_filter = Some(FilterSpec::from_cbor_value(v)?);
                }
                "expansion_filter" => {
                    expansion_filter = Some(FilterSpec::from_cbor_value(v)?);
                }
                "cursor" => {
                    if let Value::Bytes(b) = v {
                        cursor = Some(b);
                    } else {
                        return None;
                    }
                }
                "age_ceilings" => {
                    age_ceilings = age_ceilings_from_cbor_value(v)?;
                }
                _ => {}
            }
        }
        Some(FrontierSnapshot {
            version: version?,
            epoch_start: epoch_start?,
            active_horizon_days: active_horizon_days?,
            visible_filter: visible_filter?,
            expansion_filter: expansion_filter?,
            cursor: cursor?,
            age_ceilings,
        })
    }
}

// ---------------------------------------------------------------------------
// LocalFrontier: this instance's own snapshot
// ---------------------------------------------------------------------------

/// This instance's currently-published frontier snapshot.
///
/// Held behind `AppState.local_frontier` so handlers (the §8.5 GET
/// route, the §7 routing path when it needs sender-side coverage data)
/// can read it without recomputing. The producer side
/// (`refresh_local_frontier`) recomputes from the trust graph and the
/// `users` table whenever a peer-bound announce or delta needs to go
/// out; the routing layer reads it without locking the trust graph.
#[derive(Debug, Clone)]
pub struct LocalFrontier {
    /// Monotonic per-instance announce version. Bumped only when the
    /// filter bytes change — re-publishing the same closure to a new
    /// peer reuses the previous version.
    pub version: u64,
    /// `epoch_start` field for the §8.3 announce body. Unix ms when
    /// the current filter pair was first computed.
    pub epoch_start: u64,
    /// 3-hop forward closure over local users.
    pub visible_filter: BloomFilter,
    /// 2-hop forward closure over local users.
    pub expansion_filter: BloomFilter,
    /// Opaque cursor we hand back from §8.5 GET callers. Server-
    /// chosen format: `version_be(8) || epoch_start_be(8)`. Total 16
    /// bytes, comfortably under the spec's 64-byte ceiling.
    pub cursor: Vec<u8>,
    /// Raw 32-byte pubkeys of every author in the 3-hop content
    /// closure — the *plaintext* set the `visible_filter` bloom was
    /// built from. Retained (not just the bloom) so the §7.6 / §10.5
    /// proactive pull-backfill path can diff `new − old` across a
    /// refresh and learn exactly which authors newly entered the
    /// frontier, without false positives from bloom membership tests.
    /// Never serialized — purely a local-side diff aid.
    pub visible_keys: HashSet<[u8; 32]>,
    /// §8.10 per-root celebrity cleave we publish to peers, loaded from
    /// the `local_frontier_age_ceilings` table on every refresh. Empty
    /// until the §8.9/§8.10 enforcement layer (Slice E) starts writing
    /// rows; carried here so the §8.3 announce producer and the §8.5
    /// GET route can advertise it without a second query. Empty means
    /// "no cleave" and is omitted from the wire.
    pub age_ceilings: AgeCeilings,
}

impl LocalFrontier {
    /// First-boot placeholder: empty filters with `m = MIN_M_BITS`,
    /// matching nothing. Distinct from the §8.8 all-ones sentinel
    /// (which matches everything); this placeholder is what every
    /// instance publishes before the first refresh runs, and the
    /// `peers_interested_in` routing path treats it as "no local
    /// users known yet, no fanout."
    pub fn empty() -> Self {
        let visible_filter =
            BloomFilter::new_empty(DEFAULT_K, bloom::MIN_M_BITS, 0, DEFAULT_FPR_TARGET)
                .expect("MIN_M_BITS and DEFAULT_K are in range");
        let expansion_filter = visible_filter.clone();
        let now = envelope::now_unix_ms();
        let cursor = encode_cursor(0, now);
        Self {
            version: 0,
            epoch_start: now,
            visible_filter,
            expansion_filter,
            cursor,
            visible_keys: HashSet::new(),
            age_ceilings: AgeCeilings::new(),
        }
    }
}

/// Encode an opaque §8.5 cursor as `version_be(8) || epoch_start_be(8)`.
/// Format is server-private — callers treat it as opaque bytes — but
/// keeping the layout deterministic lets the GET-route 304 short
/// circuit compare against the supplied bytes without reparsing.
fn encode_cursor(version: u64, epoch_start: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&epoch_start.to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// Frontier compute / refresh path (local side)
// ---------------------------------------------------------------------------

/// Result of [`compute_local_frontier`].
#[derive(Debug)]
pub enum ComputeError {
    /// Local-user query failed.
    Db(sqlx::Error),
}

impl From<sqlx::Error> for ComputeError {
    fn from(e: sqlx::Error) -> Self {
        ComputeError::Db(e)
    }
}

/// Build a fresh [`LocalFrontier`] from the current trust graph and
/// the `users` table.
///
/// Seeds the BFS from `SELECT id FROM users WHERE home_instance IS
/// NULL AND status = 'active'` — local active users only, in line
/// with §7.4 ("authors whose posts are potentially visible to local
/// users"). The 3-hop forward closure populates the `visible_filter`;
/// the 2-hop closure populates the `expansion_filter` (§7.4: hop-3
/// users contribute as edge *targets* but never as edge *sources*).
///
/// Each reachable UUID is resolved to its `users.public_key` (raw 32
/// bytes) before being inserted into the filter — the wire key for
/// federation is the user's signing pubkey, not their local UUID. A
/// user with no `public_key` (legacy local-only account that never
/// minted a passkey) is silently skipped: it has nothing for a peer
/// to route content against.
///
/// `version` is left as 0; the caller (`refresh_local_frontier`)
/// decides whether to bump it based on whether the filter bytes
/// actually changed.
pub async fn compute_local_frontier(
    db: &SqlitePool,
    trust_graph: &TrustGraph,
) -> Result<LocalFrontier, ComputeError> {
    // 1. Seed set: all local active users.
    let local_user_rows =
        sqlx::query!("SELECT id FROM users WHERE home_instance IS NULL AND status = 'active'",)
            .fetch_all(db)
            .await?;
    let local_users: Vec<uuid::Uuid> = local_user_rows
        .into_iter()
        .filter_map(|r| uuid::Uuid::parse_str(&r.id).ok())
        .collect();

    // 2. Forward closures via the trust graph. `forward_visible_closure`
    //    shares the scoring kernel with `forward_scores` (decay, distrust
    //    handling) and prunes paths whose combined score falls below
    //    `MINIMUM_TRUST_THRESHOLD` — the same visibility cutoff the rest
    //    of the app uses. Without this pruning the bloom would carry
    //    users that are structurally invisible to every local reader,
    //    wasting frontier bytes and inflating peers' fetch traffic.
    //    Sources are included unconditionally (a local user is trivially
    //    visible to themselves and must be advertised for author-keyed
    //    routing).
    let three_hop = trust_graph.forward_visible_closure(&local_users, 3);
    let two_hop = trust_graph.forward_visible_closure(&local_users, 2);

    // 3. Resolve UUIDs → public keys. Users without a public_key (no
    //    passkey ever bound) cannot be routed against by peers; skip
    //    them entirely rather than inserting null-equivalent bytes.
    let visible_keys = resolve_public_keys(db, &three_hop).await?;
    let edge_keys = resolve_public_keys(db, &two_hop).await?;

    let visible_filter = build_bloom_from_keys(&visible_keys);
    let expansion_filter = build_bloom_from_keys(&edge_keys);

    // §8.10 cleave set we currently publish. Written by the Slice-E
    // enforcement layer; empty until then.
    let age_ceilings = load_local_age_ceilings(db).await?;

    let now = envelope::now_unix_ms();
    Ok(LocalFrontier {
        version: 0,
        epoch_start: now,
        visible_filter,
        expansion_filter,
        cursor: encode_cursor(0, now),
        visible_keys: visible_keys.into_iter().collect(),
        age_ceilings,
    })
}

/// Materialise one [`FrontierReader`] per local active user for the
/// §8.9/§8.12 reverse-frontier rebuild ([`rebuild_reverse_frontier`]).
///
/// Each reader carries its Ed25519 public key (a reverse-BFS root) and
/// its forward trust scores (author UUID → score), read from the
/// in-memory [`TrustGraph`]. Forward trust is local-only and never
/// crosses the wire, so the caller materialises it here and hands it in
/// (`forward_scores`'s own `MINIMUM_TRUST_THRESHOLD` prune applies). A
/// user without a 32-byte `public_key` is skipped: peers cannot route
/// against them, so they cannot be a reverse root.
async fn build_frontier_readers(
    db: &SqlitePool,
    trust_graph: &TrustGraph,
) -> Result<Vec<FrontierReader>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT id, public_key FROM users \
         WHERE home_instance IS NULL AND status = 'active' \
           AND public_key IS NOT NULL AND length(public_key) = 32",
    )
    .fetch_all(db)
    .await?;

    let mut readers = Vec::with_capacity(rows.len());
    for row in rows {
        let Ok(uuid) = uuid::Uuid::parse_str(&row.id) else {
            continue;
        };
        let Ok(key) = <[u8; 32]>::try_from(row.public_key.as_slice()) else {
            continue;
        };
        let forward_scores = trust_graph
            .forward_scores(uuid)
            .into_iter()
            .map(|s| (s.target_user, s.score))
            .collect();
        readers.push(FrontierReader {
            key,
            forward_scores,
        });
    }
    Ok(readers)
}

/// Load this instance's published §8.10 celebrity-cleave set from
/// `local_frontier_age_ceilings`. Skips rows whose `root_key` is not
/// exactly 32 bytes (a corrupt row should not poison the whole
/// frontier refresh). Cutoffs are stored as `i64`; negatives (which a
/// genesis_at can never legitimately be) are dropped.
async fn load_local_age_ceilings(db: &SqlitePool) -> Result<AgeCeilings, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT root_key AS \"root_key!: Vec<u8>\", cutoff FROM local_frontier_age_ceilings",
    )
    .fetch_all(db)
    .await?;
    let mut out = AgeCeilings::new();
    for row in rows {
        let Ok(root) = <[u8; 32]>::try_from(row.root_key) else {
            continue;
        };
        let Ok(cutoff) = u64::try_from(row.cutoff) else {
            continue;
        };
        out.insert(root, cutoff);
    }
    Ok(out)
}

/// §8.3 full-snapshot apply for a peer's celebrity cleave: replace
/// every `peer_frontier_age_ceilings` row for `peer` with the supplied
/// map. An `/announce` carries the complete ceiling set, so a root
/// absent from `ceilings` must be cleared (the peer un-cleaved it).
/// Runs the delete + inserts in one transaction so the row set never
/// transiently empties under a concurrent read.
async fn replace_peer_age_ceilings(
    db: &SqlitePool,
    peer: &[u8],
    ceilings: &AgeCeilings,
) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    sqlx::query!(
        "DELETE FROM peer_frontier_age_ceilings WHERE peer_pubkey = ?",
        peer,
    )
    .execute(&mut *tx)
    .await?;
    for (root, cutoff) in ceilings {
        let root_slice: &[u8] = root;
        let cutoff_i = *cutoff as i64;
        sqlx::query!(
            "INSERT INTO peer_frontier_age_ceilings (peer_pubkey, root_key, cutoff) \
             VALUES (?, ?, ?)",
            peer,
            root_slice,
            cutoff_i,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// §8.4 additions-only apply for a peer's celebrity cleave: merge the
/// supplied roots over `peer`'s stored ceiling map, last-writer-wins
/// (the delta's cutoff overwrites unconditionally — §8.4 permits a
/// *tighter* cutoff within a generation, and loosening only happens via
/// full re-announce). Roots not mentioned in the delta are left
/// untouched. A no-op when `ceilings` is empty (a filter-only delta).
async fn merge_peer_age_ceilings(
    db: &SqlitePool,
    peer: &[u8],
    ceilings: &AgeCeilings,
) -> Result<(), sqlx::Error> {
    if ceilings.is_empty() {
        return Ok(());
    }
    let mut tx = db.begin().await?;
    for (root, cutoff) in ceilings {
        let root_slice: &[u8] = root;
        let cutoff_i = *cutoff as i64;
        sqlx::query!(
            "INSERT INTO peer_frontier_age_ceilings (peer_pubkey, root_key, cutoff) \
             VALUES (?, ?, ?) \
             ON CONFLICT(peer_pubkey, root_key) DO UPDATE SET cutoff = excluded.cutoff",
            peer,
            root_slice,
            cutoff_i,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Fetch the raw 32-byte `public_key` of every local active user.
/// Used by the §7.2 mode-classification path on
/// `handle_frontier_announce` / `handle_frontier_delta` to compute
/// `coverage(sender.visible_filter, our local users)` without
/// running the full trust-graph closure. Skips rows whose
/// `public_key` is NULL or not exactly 32 bytes — those keys cannot
/// participate in routing.
async fn fetch_local_user_pubkeys(db: &SqlitePool) -> Result<Vec<[u8; 32]>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT public_key AS \"public_key!: Vec<u8>\" \
         FROM users \
         WHERE home_instance IS NULL \
           AND status = 'active' \
           AND public_key IS NOT NULL \
           AND length(public_key) = 32",
    )
    .fetch_all(db)
    .await?;
    let mut keys = Vec::with_capacity(rows.len());
    for row in rows {
        if let Ok(arr) = <[u8; 32]>::try_from(row.public_key.as_slice()) {
            keys.push(arr);
        }
    }
    Ok(keys)
}

/// Keep only the keys belonging to *remote* users (`home_instance IS
/// NOT NULL`). Proactive by-author backfill (§7.6) pulls an author's
/// existing content *from a peer* — that only makes sense for authors
/// whose home is another instance. Local authors' content already
/// lives here, so backfilling them would fan out a burst of futile
/// `/backfill/by-author` GETs to peers that have nothing to return.
async fn filter_remote_authors(
    db: &SqlitePool,
    keys: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>, sqlx::Error> {
    let mut remote = Vec::new();
    for key in keys {
        let key_slice = key.as_slice();
        let is_remote = sqlx::query_scalar!(
            "SELECT 1 AS \"found!: i64\" FROM users \
             WHERE public_key = ? AND home_instance IS NOT NULL",
            key_slice,
        )
        .fetch_optional(db)
        .await?
        .is_some();
        if is_remote {
            remote.push(*key);
        }
    }
    Ok(remote)
}

/// Resolve a set of user UUIDs to their `public_key` BLOBs. Skips
/// rows where `public_key` is NULL or not exactly 32 bytes — those
/// can't be used as routing keys regardless.
async fn resolve_public_keys(
    db: &SqlitePool,
    uuids: &HashSet<uuid::Uuid>,
) -> Result<Vec<[u8; 32]>, sqlx::Error> {
    if uuids.is_empty() {
        return Ok(Vec::new());
    }
    // SQLite has no array-binding; issue a single query that pulls
    // every user's public_key and filter in-memory. The local users
    // table is small relative to the closure size — the join cost
    // here is dominated by the closure size, not the user count.
    let rows = sqlx::query!(
        "SELECT id, public_key FROM users WHERE public_key IS NOT NULL AND length(public_key) = 32",
    )
    .fetch_all(db)
    .await?;
    let mut out = Vec::with_capacity(uuids.len());
    for row in rows {
        let Ok(id) = uuid::Uuid::parse_str(&row.id) else {
            continue;
        };
        if !uuids.contains(&id) {
            continue;
        }
        if let Ok(arr) = <[u8; 32]>::try_from(row.public_key.as_slice()) {
            out.push(arr);
        }
    }
    Ok(out)
}

/// Build a sized bloom filter populated with `keys`. Sizes `m` per
/// `bloom::recommend_m(n, 1%)` and `k` per `bloom::recommend_k`.
///
/// An empty input produces the minimum-sized empty filter; the
/// receiver's coverage scan over zero local users is vacuously 1.0
/// per [`BloomFilter::coverage`] (so a fresh peering's first announce
/// does not stall the mode-detection path).
fn build_bloom_from_keys(keys: &[[u8; 32]]) -> BloomFilter {
    let n = keys.len() as u64;
    let m = bloom::recommend_m(n, DEFAULT_FPR_TARGET);
    let k = bloom::recommend_k(m, n);
    let mut filter = BloomFilter::new_empty(k, m, n, DEFAULT_FPR_TARGET)
        .expect("recommend_m / recommend_k stay in spec range");
    for key in keys {
        filter.insert(key);
    }
    filter
}

/// Outcome of a [`refresh_local_frontier_detailed`] call: the (new or
/// unchanged) snapshot plus the change signal the fanout worker needs.
#[derive(Debug)]
pub struct FrontierRefresh {
    /// The current snapshot after the refresh — a freshly-minted Arc
    /// when `changed`, otherwise the previous (unchanged) Arc.
    pub frontier: Arc<LocalFrontier>,
    /// True when the filter bytes changed and the version was bumped.
    pub changed: bool,
    /// Authors that newly entered the 3-hop content closure this
    /// refresh (`new − old`), as raw pubkeys. Empty when unchanged.
    /// Drives the §7.6 / §10.5 proactive by-author pull-backfill.
    pub added_visible_keys: Vec<[u8; 32]>,
}

/// Recompute the local frontier and, if its contents changed, swap
/// the cached snapshot under `state.local_frontier` and bump the
/// version + cursor.
///
/// Compares the *filter bytes* (and the `k` / `m` parameters) rather
/// than recomputing the closure — a re-run that yields identical
/// filter bytes is treated as a no-op and the existing version is
/// preserved. Callers that want a fresh announce regardless (e.g. a
/// rotation or an operator-forced re-announce) can mint a new
/// version externally; this helper exists for the steady-state path
/// where re-running on every peer-bound announce would needlessly
/// inflate the version counter.
pub async fn refresh_local_frontier(state: &AppState) -> Result<Arc<LocalFrontier>, ComputeError> {
    Ok(refresh_local_frontier_detailed(state).await?.frontier)
}

/// Like [`refresh_local_frontier`] but also reports whether the
/// snapshot changed and which authors newly entered the content
/// closure. The added-author diff is computed under the same write
/// lock as the swap, so it can't race a concurrent refresh: the set
/// returned is exactly `new − old` for the version this call produced.
pub async fn refresh_local_frontier_detailed(
    state: &AppState,
) -> Result<FrontierRefresh, ComputeError> {
    let trust_graph = state
        .trust_graph
        .read()
        .map(|g| Arc::clone(&g))
        .unwrap_or_else(|poisoned| Arc::clone(&poisoned.into_inner()));
    let mut next = compute_local_frontier(&state.db, &trust_graph).await?;

    let mut guard = state
        .local_frontier
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let prev = guard.clone();
    let changed = filter_bytes_differ(&prev.visible_filter, &next.visible_filter)
        || filter_bytes_differ(&prev.expansion_filter, &next.expansion_filter);

    if changed {
        let added_visible_keys: Vec<[u8; 32]> = next
            .visible_keys
            .difference(&prev.visible_keys)
            .copied()
            .collect();
        // Pure monotonic counter — `prev.version + 1` is strictly
        // greater than `prev` regardless of refresh cadence. Wall-clock
        // belongs in `epoch_start` / `cursor`, not in the version
        // field; conflating them inflates version to ~1.7e12 on the
        // first change and makes operator-driven announces use values
        // that look nothing like the spec's small monotonic counter.
        next.version = prev.version.saturating_add(1);
        next.cursor = encode_cursor(next.version, next.epoch_start);
        let new_arc = Arc::new(next);
        *guard = Arc::clone(&new_arc);
        Ok(FrontierRefresh {
            frontier: new_arc,
            changed: true,
            added_visible_keys,
        })
    } else {
        Ok(FrontierRefresh {
            frontier: prev,
            changed: false,
            added_visible_keys: Vec::new(),
        })
    }
}

/// True if the two filters differ in shape *or* in any bit. We can't
/// compare the `BloomFilter`s directly because `f32` is not `Eq`; we
/// also explicitly *don't* care about `n_est` or `fpr_target` drift
/// (informational only).
fn filter_bytes_differ(a: &BloomFilter, b: &BloomFilter) -> bool {
    a.k != b.k || a.m != b.m || a.bits != b.bits
}

// ---------------------------------------------------------------------------
// Handlers: announce, delta, get
// ---------------------------------------------------------------------------

/// `POST /federation/v1/frontier/announce` handler (§8.3).
pub async fn handle_frontier_announce(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let parsed = match FrontierAnnounce::decode(&body) {
        Some(p) => p,
        None => return bad_request("malformed"),
    };

    // §8.3 monotonicity. Reject `version <= last_applied`. The "<="
    // check excludes equal-version re-announces from triggering a
    // state change; the spec calls for them to be idempotent rather
    // than rejected, so we look up the existing row and short-circuit
    // a same-version replay as an OK with the current cursor.
    //
    // This read-then-write check is not atomic, so two announces from
    // the same sender in flight at once (e.g. a §8.6 first-contact and
    // a §8.7 change-fanout — both routine after Phase 11.9.4) could
    // pass the check and then race the upsert, letting a stale lower
    // version clobber a newer one. The `ON CONFLICT … WHERE
    // excluded.applied_version > peer_frontiers.applied_version` guard
    // on the upsert below closes that window atomically; this read
    // check stays for the 400 / idempotent-200 response shaping.
    //
    // The `outbound_mode` column is read for §7.2 hysteresis on the
    // mode classification we re-run below: a pair already in `All`
    // demotes only when coverage drops below LOW_THRESHOLD, while a
    // pair in `Filtered` promotes only at HIGH_THRESHOLD.
    let sender_slice: &[u8] = &envelope.sender;
    let existing = match sqlx::query!(
        "SELECT applied_version, cursor, outbound_mode \
         FROM peer_frontiers WHERE peer_pubkey = ?",
        sender_slice,
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "db error reading peer_frontiers for announce");
            return internal_error();
        }
    };

    let prior_outbound_mode = existing
        .as_ref()
        .map(|row| Mode::from_db_str(&row.outbound_mode))
        .unwrap_or(Mode::Filtered);

    if let Some(ref row) = existing {
        let applied: u64 = row.applied_version as u64;
        if parsed.version < applied {
            return bad_request("version_not_monotonic");
        }
        if parsed.version == applied {
            // Idempotent re-apply: return the existing cursor without
            // touching the stored filter bytes.
            return announce_response(applied, &row.cursor);
        }
    }

    // Validate both filters before any persistence — §8.3 says no
    // partial-apply.
    let visible = match parsed.visible_filter.clone().into_bloom() {
        Ok(f) => f,
        Err(code) => return bad_request(code),
    };
    let expansion = match parsed.expansion_filter.clone().into_bloom() {
        Ok(f) => f,
        Err(code) => return bad_request(code),
    };

    // §7.2 outbound-mode classification: coverage of the sender's
    // visible_filter against *our* local-user pubkeys decides what
    // mode we use to send to them. Hysteresis uses the prior mode
    // pulled above so a pair already in `All` doesn't oscillate just
    // because coverage briefly dipped into [LOW, HIGH).
    let local_keys = match fetch_local_user_pubkeys(&state.db).await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "db error reading local users for mode classification");
            return internal_error();
        }
    };
    let new_outbound_mode = routing::classify_mode(prior_outbound_mode, &visible, &local_keys);
    let inbound_mode_str = parsed.mode.as_db_str();
    let outbound_mode_str = new_outbound_mode.as_db_str();

    // Mint a server-side cursor for this apply. Same shape as
    // LocalFrontier — opaque to the peer.
    let cursor = encode_cursor(parsed.version, parsed.epoch_start);

    let version_i = parsed.version as i64;
    let epoch_i = parsed.epoch_start as i64;
    let horizon_i = parsed.active_horizon_days as i64;
    let visible_family = parsed.visible_filter.family;
    let visible_k = visible.k as i64;
    let visible_m = visible.m as i64;
    let visible_n = parsed.visible_filter.n_est as i64;
    let visible_fpr = parsed.visible_filter.fpr_target as f64;
    let expansion_family = parsed.expansion_filter.family;
    let expansion_k = expansion.k as i64;
    let expansion_m = expansion.m as i64;
    let expansion_n = parsed.expansion_filter.n_est as i64;
    let expansion_fpr = parsed.expansion_filter.fpr_target as f64;
    let visible_bytes_slice: &[u8] = &visible.bits;
    let expansion_bytes_slice: &[u8] = &expansion.bits;
    let cursor_slice: &[u8] = &cursor;

    let result = sqlx::query!(
        "INSERT INTO peer_frontiers ( \
             peer_pubkey, applied_version, epoch_start, active_horizon_days, \
             visible_family, visible_k, visible_m, visible_n_est, visible_fpr_target, visible_bytes, \
             expansion_family, expansion_k, expansion_m, expansion_n_est, expansion_fpr_target, expansion_bytes, \
             cursor, inbound_mode, outbound_mode, updated_at \
         ) VALUES ( \
             ?, ?, ?, ?, \
             ?, ?, ?, ?, ?, ?, \
             ?, ?, ?, ?, ?, ?, \
             ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         ) \
         ON CONFLICT(peer_pubkey) DO UPDATE SET \
             applied_version = excluded.applied_version, \
             epoch_start = excluded.epoch_start, \
             active_horizon_days = excluded.active_horizon_days, \
             visible_family = excluded.visible_family, \
             visible_k = excluded.visible_k, \
             visible_m = excluded.visible_m, \
             visible_n_est = excluded.visible_n_est, \
             visible_fpr_target = excluded.visible_fpr_target, \
             visible_bytes = excluded.visible_bytes, \
             expansion_family = excluded.expansion_family, \
             expansion_k = excluded.expansion_k, \
             expansion_m = excluded.expansion_m, \
             expansion_n_est = excluded.expansion_n_est, \
             expansion_fpr_target = excluded.expansion_fpr_target, \
             expansion_bytes = excluded.expansion_bytes, \
             cursor = excluded.cursor, \
             inbound_mode = excluded.inbound_mode, \
             outbound_mode = excluded.outbound_mode, \
             updated_at = excluded.updated_at \
         WHERE excluded.applied_version > peer_frontiers.applied_version",
        sender_slice,
        version_i,
        epoch_i,
        horizon_i,
        visible_family,
        visible_k,
        visible_m,
        visible_n,
        visible_fpr,
        visible_bytes_slice,
        expansion_family,
        expansion_k,
        expansion_m,
        expansion_n,
        expansion_fpr,
        expansion_bytes_slice,
        cursor_slice,
        inbound_mode_str,
        outbound_mode_str,
    )
    .execute(&state.db)
    .await;
    let result = match result {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "failed to persist peer_frontiers row");
            return internal_error();
        }
    };

    // §8.3 full-snapshot apply of the celebrity cleave — but only when
    // our write actually won the monotonic guard. If the guard blocked
    // us (`rows_affected == 0`), a newer announce already owns the row,
    // and replacing its ceilings with our stale snapshot would clobber
    // a fresher cleave set.
    if result.rows_affected() != 0
        && let Err(e) =
            replace_peer_age_ceilings(&state.db, sender_slice, &parsed.age_ceilings).await
    {
        tracing::error!(error = %e, "failed to replace peer_frontier_age_ceilings on announce");
        return internal_error();
    }

    // If the monotonic guard (`WHERE excluded.applied_version >
    // peer_frontiers.applied_version`) blocked the write, the row we
    // hold is *newer* than this announce. Don't claim we applied
    // `parsed.version` — re-read the persisted row so the 200 reports
    // the version/cursor the peer should actually sync against.
    if result.rows_affected() == 0 {
        match sqlx::query!(
            "SELECT applied_version, cursor AS \"cursor!: Vec<u8>\" \
             FROM peer_frontiers WHERE peer_pubkey = ?",
            sender_slice,
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(Some(row)) => {
                return announce_response(row.applied_version as u64, &row.cursor);
            }
            Ok(None) => {
                // No conflicting row existed, yet nothing was inserted —
                // shouldn't happen, but fall through to the optimistic
                // response rather than fabricate a state.
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to re-read peer_frontiers after guarded upsert");
                return internal_error();
            }
        }
    }

    announce_response(parsed.version, &cursor)
}

fn announce_response(applied_version: u64, cursor: &[u8]) -> Response {
    let body = Value::Map(vec![
        (
            Value::Text("applied_version".into()),
            Value::Integer(Integer::from(applied_version)),
        ),
        (Value::Text("cursor".into()), Value::Bytes(cursor.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(64);
    ciborium::ser::into_writer(&body, &mut buf).expect("ser infallible");
    let mut response = (StatusCode::OK, buf).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    response
}

/// `POST /federation/v1/frontier/delta` handler (§8.4).
pub async fn handle_frontier_delta(
    State(state): State<Arc<AppState>>,
    Extension(envelope): Extension<FedEnvelope>,
    Extension(VerifiedBody(body)): Extension<VerifiedBody>,
) -> Response {
    let parsed = match FrontierDelta::decode(&body) {
        Some(p) => p,
        None => return bad_request("malformed"),
    };

    if parsed.new_version <= parsed.prev_version {
        return bad_request("version_not_monotonic");
    }
    // §8.4: at least one of `masks` / `age_ceilings` must carry an
    // entry — a delta that touches neither has nothing to apply.
    if parsed.visible_mask.is_none()
        && parsed.expansion_mask.is_none()
        && parsed.age_ceilings.is_empty()
    {
        return bad_request("empty_delta");
    }

    let sender_slice: &[u8] = &envelope.sender;
    let row = match sqlx::query!(
        "SELECT applied_version, epoch_start, active_horizon_days, \
                visible_family, visible_k, visible_m, visible_n_est, visible_fpr_target, visible_bytes, \
                expansion_family, expansion_k, expansion_m, expansion_n_est, expansion_fpr_target, expansion_bytes, \
                outbound_mode \
         FROM peer_frontiers WHERE peer_pubkey = ?",
        sender_slice,
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            // §8.4 doesn't define a dedicated code for "no prior
            // announce ever applied"; the 409 path with
            // `current_version = 0` is the closest match — the sender
            // MUST re-announce per the spec, and 0 truthfully tells
            // them what we have applied.
            return delta_version_conflict(0);
        }
        Err(e) => {
            tracing::error!(error = %e, "db error reading peer_frontiers for delta");
            return internal_error();
        }
    };

    let stored_version = row.applied_version as u64;
    if parsed.prev_version != stored_version {
        return delta_version_conflict(stored_version);
    }

    let prior_outbound_mode = Mode::from_db_str(&row.outbound_mode);
    // Preserve the existing content-filter sizing for the §7.2
    // coverage reclassification below. `k` / `m` are invariant under
    // OR-mask apply (delta only updates bytes, not sizing) so we
    // round-trip them through the bloom builder unchanged.
    let visible_k_existing = row.visible_k;
    let visible_m_existing = row.visible_m;
    let visible_n_existing = row.visible_n_est;
    let visible_fpr_existing = row.visible_fpr_target;

    // Apply each supplied mask. Either filter may be absent on the
    // wire; absence means "leave this filter alone." The table's
    // CHECK on `length(visible_bytes) = m/8` already enforced shape at
    // insert.
    let mut visible_bytes = row.visible_bytes;
    if let Some(mask) = &parsed.visible_mask {
        if mask.len() != visible_bytes.len() {
            return bad_request("or_mask_length_mismatch");
        }
        for (b, m) in visible_bytes.iter_mut().zip(mask.iter()) {
            *b |= *m;
        }
    }
    let mut expansion_bytes = row.expansion_bytes;
    if let Some(mask) = &parsed.expansion_mask {
        if mask.len() != expansion_bytes.len() {
            return bad_request("or_mask_length_mismatch");
        }
        for (b, m) in expansion_bytes.iter_mut().zip(mask.iter()) {
            *b |= *m;
        }
    }

    // §7.2 reclassification on delta apply. OR-mask additions can
    // only raise coverage of the content filter against our local
    // users, so a delta can promote `Filtered → All` but never
    // demote on its own; hysteresis against the persisted
    // `outbound_mode` keeps an already-`All` pair stable.
    let visible_k_u = match u32::try_from(visible_k_existing) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!("stored visible_k out of range; cannot reclassify mode");
            return internal_error();
        }
    };
    let visible_m_u = match u32::try_from(visible_m_existing) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!("stored visible_m out of range; cannot reclassify mode");
            return internal_error();
        }
    };
    let visible_n_u = match u64::try_from(visible_n_existing) {
        Ok(v) => v,
        Err(_) => {
            tracing::error!("stored visible_n_est out of range; cannot reclassify mode");
            return internal_error();
        }
    };
    let new_outbound_mode = match BloomFilter::from_parts(
        visible_k_u,
        visible_m_u,
        visible_n_u,
        visible_fpr_existing as f32,
        visible_bytes.clone(),
    ) {
        Ok(visible) => {
            let local_keys = match fetch_local_user_pubkeys(&state.db).await {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!(error = %e, "db error reading local users for mode classification");
                    return internal_error();
                }
            };
            routing::classify_mode(prior_outbound_mode, &visible, &local_keys)
        }
        Err(e) => {
            // The bytes we just merged failed bloom validation. This
            // shouldn't happen — sizing didn't change and the CHECK
            // constraint enforces byte-length — so an `error!` here is
            // a serious-internal-invariant signal worth paging on, not
            // a `warn!`. We still keep the prior mode (rather than
            // refusing the delta apply): the merged bytes themselves
            // are valid OR-mask additions to an already-validated
            // filter; only the mode reclassification side-channel
            // failed, and falling back to `prior_outbound_mode` is the
            // most conservative choice.
            tracing::error!(
                error = ?e,
                "post-delta bloom reconstruction failed; keeping prior outbound_mode"
            );
            prior_outbound_mode
        }
    };
    let inbound_mode_str = parsed.mode.as_db_str();
    let outbound_mode_str = new_outbound_mode.as_db_str();

    let new_version_i = parsed.new_version as i64;
    let cursor = encode_cursor(parsed.new_version, row.epoch_start as u64);
    let cursor_slice: &[u8] = &cursor;
    let visible_slice: &[u8] = &visible_bytes;
    let expansion_slice: &[u8] = &expansion_bytes;
    let update = sqlx::query!(
        "UPDATE peer_frontiers \
         SET applied_version = ?, visible_bytes = ?, expansion_bytes = ?, cursor = ?, \
             inbound_mode = ?, outbound_mode = ?, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE peer_pubkey = ?",
        new_version_i,
        visible_slice,
        expansion_slice,
        cursor_slice,
        inbound_mode_str,
        outbound_mode_str,
        sender_slice,
    )
    .execute(&state.db)
    .await;
    if let Err(e) = update {
        tracing::error!(error = %e, "failed to apply frontier delta");
        return internal_error();
    }

    // §8.4 additions-only merge of the celebrity cleave. No-op for a
    // filter-only delta; tightens (or last-writer-wins overwrites) the
    // stored ceiling for any root the delta carries.
    if let Err(e) = merge_peer_age_ceilings(&state.db, sender_slice, &parsed.age_ceilings).await {
        tracing::error!(error = %e, "failed to merge peer_frontier_age_ceilings on delta");
        return internal_error();
    }

    announce_response(parsed.new_version, &cursor)
}

/// §8.4 409 body shape: `{ "error": "version_mismatch", "current_version": <u64> }`.
fn delta_version_conflict(current: u64) -> Response {
    let body = Value::Map(vec![
        (
            Value::Text("error".into()),
            Value::Text("version_mismatch".into()),
        ),
        (
            Value::Text("current_version".into()),
            Value::Integer(Integer::from(current)),
        ),
    ]);
    let mut buf = Vec::with_capacity(48);
    ciborium::ser::into_writer(&body, &mut buf).expect("ser infallible");
    let mut response = (StatusCode::CONFLICT, buf).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    response
}

/// Query string for `GET /federation/v1/frontier`. `since` is the
/// opaque cursor the peer last received; absent means "from scratch."
#[derive(serde::Deserialize)]
pub struct FrontierGetParams {
    pub since: Option<String>,
}

/// `GET /federation/v1/frontier` handler (§8.5).
///
/// Returns this instance's *own* current frontier (the
/// [`LocalFrontier`] snapshot on `AppState`), not the requesting
/// peer's. The route is symmetric to `/frontier/announce` in
/// direction: announces push *our* frontier outbound; this GET lets
/// a peer pull *our* frontier inbound after a reconnect.
pub async fn handle_frontier_get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<FrontierGetParams>,
) -> Response {
    let frontier = match state.local_frontier.read() {
        Ok(g) => Arc::clone(&g),
        Err(poisoned) => Arc::clone(&poisoned.into_inner()),
    };

    if let Some(since_b64) = params.since.as_deref()
        && !since_b64.is_empty()
        && let Ok(bytes) = URL_SAFE_NO_PAD.decode(since_b64.as_bytes())
        && bytes == frontier.cursor
    {
        // §8.5: cursor matches current version → 304 Not Modified with
        // an empty body.
        return StatusCode::NOT_MODIFIED.into_response();
    }

    let snapshot = FrontierSnapshot {
        version: frontier.version,
        epoch_start: frontier.epoch_start,
        active_horizon_days: NO_TRIMMING,
        visible_filter: FilterSpec::from_bloom(&frontier.visible_filter),
        expansion_filter: FilterSpec::from_bloom(&frontier.expansion_filter),
        cursor: frontier.cursor.clone(),
        age_ceilings: frontier.age_ceilings.clone(),
    };
    let body = snapshot.encode();
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    response
}

// ---------------------------------------------------------------------------
// Operator-side: announce our frontier to a peer
// ---------------------------------------------------------------------------

/// Outcome of [`operator_announce_frontier`].
#[derive(Debug)]
pub enum AnnounceError {
    Transport(TransportError),
    UnexpectedStatus(StatusCode),
    Compute(ComputeError),
}

impl From<ComputeError> for AnnounceError {
    fn from(e: ComputeError) -> Self {
        AnnounceError::Compute(e)
    }
}

/// Build the §8.3 announce body from our current `LocalFrontier`,
/// sign it under the §6 envelope, dispatch it to `peer` via the
/// shared transport. Refreshes the local snapshot first so the wire
/// announce reflects any trust-graph changes since the last fanout.
///
/// Returns the applied version the peer ACKed in its 200 response
/// (or surfaces the failure). Called from the §8.7 background
/// fanout worker ([`frontier_fanout_loop`]) on a frontier change,
/// from [`spawn_first_contact_announce`] on §8.6 peer activation, and
/// directly by the operator-forced re-announce path / test harness.
pub async fn operator_announce_frontier(
    state: &AppState,
    instance_key: &InstanceKey,
    transport: &Arc<dyn FederationTransport>,
    peer_pubkey: [u8; 32],
) -> Result<u64, AnnounceError> {
    let frontier = refresh_local_frontier(state).await?;

    // §7.2 mode signal: stamp our currently-confirmed `outbound_mode`
    // for this peer into the announce body. Read from
    // `peer_frontiers` if we have a row for them; otherwise default
    // to `Filtered` ("fresh peering never starts in all-mode"). The
    // mode-change wire signal piggybacks on the announce instead of
    // the dedicated §7.2 POST /mode flow — see Phase 6.5 deviation
    // note in `docs/federation-impl-plan.md`.
    let peer_slice: &[u8] = &peer_pubkey;
    let our_outbound_mode = match sqlx::query!(
        "SELECT outbound_mode FROM peer_frontiers WHERE peer_pubkey = ?",
        peer_slice,
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(r)) => Mode::from_db_str(&r.outbound_mode),
        Ok(None) => Mode::Filtered,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "db error reading outbound_mode; defaulting to Filtered on announce"
            );
            Mode::Filtered
        }
    };

    let announce = FrontierAnnounce {
        version: frontier.version,
        epoch_start: frontier.epoch_start,
        active_horizon_days: NO_TRIMMING,
        visible_filter: FilterSpec::from_bloom(&frontier.visible_filter),
        expansion_filter: FilterSpec::from_bloom(&frontier.expansion_filter),
        mode: our_outbound_mode,
        age_ceilings: frontier.age_ceilings.clone(),
    };
    let body_bytes = announce.encode();

    let path = "/federation/v1/frontier/announce";
    let header_value =
        envelope::sign_outbound(instance_key, peer_pubkey, &Method::POST, path, &body_bytes);
    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .header(AUTH_HEADER, header_value)
        .body(Bytes::from(body_bytes))
        .expect("request builder");

    let response = transport
        .request(&PeerId::from_bytes(peer_pubkey), request)
        .await
        .map_err(AnnounceError::Transport)?;
    if response.status() != StatusCode::OK {
        return Err(AnnounceError::UnexpectedStatus(response.status()));
    }
    Ok(frontier.version)
}

// ---------------------------------------------------------------------------
// §8.7 change-fanout worker (Trigger 2 + Trigger 3)
// ---------------------------------------------------------------------------

/// Background worker that turns trust-graph rebuilds into frontier
/// fanout. Driven by `frontier_dirty`, which `trust::rebuild_loop`
/// fires once per successful graph swap — a natural epoch bucket,
/// since the rebuild loop already debounces and coalesces edge bursts.
///
/// On each tick it recomputes the local frontier
/// ([`refresh_local_frontier_detailed`]). When the snapshot actually
/// changed (filter bytes differ → version bump) it:
///
/// 1. **§8.7 re-announce** — fans out a fresh `/frontier/announce` to
///    every active peer. MVP ships full re-announce, not minimal
///    deltas: §8.7 permits a full announce in place of a delta, and a
///    redundant announce is a cheap no-op on the receiver thanks to its
///    `last_applied_announce_version` guard. (Delta encoding is the
///    Phase 11.9.6 optimization.)
/// 2. **§7.6 / §10.5 proactive pull-backfill** — for every author that
///    *newly* entered the content closure this refresh, schedules a
///    by-author backfill so the author's existing content arrives
///    (push only carries content authored after the announce).
///
/// All federation I/O is `tokio::spawn`ed so neither a slow peer nor a
/// large backfill can stall the next rebuild's fanout.
pub async fn frontier_fanout_loop(state: Arc<AppState>, frontier_dirty: Arc<tokio::sync::Notify>) {
    loop {
        frontier_dirty.notified().await;

        // §8.9/§8.12 reverse-frontier rebuild. This loop is woken only by
        // `frontier_dirty`, fired once per coalesced trust-graph swap, so
        // the reverse rebuild inherits the forward rebuild's debounce — it
        // can run no more often than the (already minutes-scale on large
        // instances) graph rebuild, and `Notify`'s single permit collapses
        // any wakes that land mid-rebuild. That is the §8.12 "same cadence
        // as re-announce" SHOULD, for free. Runs *before* the forward
        // refresh so any age ceilings it publishes to
        // `local_frontier_age_ceilings` are picked up by `compute_local_frontier`
        // below and ride out on this cycle's announce. Continue-on-error: a
        // reverse failure must not block the forward re-announce — stale
        // ceilings are absorbed by the K-generation grace window and the
        // §8.10 opportunistic source-side backstop.
        {
            let trust_graph = state
                .trust_graph
                .read()
                .map(|g| Arc::clone(&g))
                .unwrap_or_else(|poisoned| Arc::clone(&poisoned.into_inner()));
            match build_frontier_readers(&state.db, &trust_graph).await {
                Ok(readers) => {
                    match frontier_store::rebuild_reverse_frontier(
                        &state.db,
                        &readers,
                        frontier_store::DEFAULT_FRONTIER_CAP,
                        frontier_store::FRONTIER_MAX_DEPTH,
                        frontier_store::FRONTIER_GC_K,
                    )
                    .await
                    {
                        Ok(outcome) => tracing::debug!(
                            generation = outcome.generation,
                            edges_swept = outcome.sweep.edges_swept,
                            stubs_swept = outcome.sweep.stubs_swept,
                            ceilings_published = outcome.ceilings.published,
                            ceilings_cleared = outcome.ceilings.cleared,
                            "frontier fanout: reverse frontier rebuilt",
                        ),
                        Err(e) => tracing::warn!(
                            error = %e,
                            "frontier fanout: reverse frontier rebuild failed",
                        ),
                    }
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "frontier fanout: building reverse-frontier readers failed",
                ),
            }
        }

        let refresh = match refresh_local_frontier_detailed(&state).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = ?e, "frontier fanout: refresh failed");
                continue;
            }
        };
        if !refresh.changed {
            continue;
        }

        // Trigger 2 — re-announce the new frontier to every active peer.
        match crate::federation::prior_home_recovery::list_active_peers(&state).await {
            Ok(peers) => {
                for (peer_key, peer_domain) in peers {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        match operator_announce_frontier(
                            &state,
                            &state.instance_key,
                            &state.federation_transport,
                            peer_key,
                        )
                        .await
                        {
                            Ok(version) => tracing::debug!(
                                peer = %peer_domain,
                                version,
                                "frontier fanout: re-announced",
                            ),
                            Err(e) => tracing::debug!(
                                peer = %peer_domain,
                                error = ?e,
                                "frontier fanout: re-announce failed",
                            ),
                        }
                    });
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "frontier fanout: db error listing active peers");
            }
        }

        // Trigger 3 — proactive by-author backfill for newly-frontier'd
        // authors so their existing content arrives, not just future
        // pushes. Only *remote* authors are worth backfilling: a peer
        // has nothing to serve for a local author, so spawning a pull
        // for one would just burn a futile round-trip. `added_visible_keys`
        // is dominated by local authors (every local user expansion), so
        // this filter is the difference between one targeted pull and a
        // burst of dead requests.
        let remote_authors = match filter_remote_authors(&state.db, &refresh.added_visible_keys)
            .await
        {
            Ok(keys) => keys,
            Err(e) => {
                tracing::warn!(error = %e, "frontier fanout: db error filtering remote authors");
                continue;
            }
        };
        for author_key in remote_authors {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                crate::federation::prior_home_recovery::proactive_author_backfill(
                    &state, author_key,
                )
                .await;
            });
        }
    }
}

/// §8.6 first-contact announce. Spawn-and-forget our current frontier
/// to a peer that has just transitioned to `active`, so the peer's
/// `peers_interested_in` routing leaves empty-filter mode and content
/// starts flowing. Per §8.6 each side announces on activation; this is
/// our half. Deliberately fire-and-forget: a slow or unreachable peer
/// must not stall the handshake response, and a failed first announce
/// is self-healing — the next §8.7 change-fanout or a §8.5 reconnect
/// pull re-establishes the peer's view of our frontier.
pub fn spawn_first_contact_announce(state: Arc<AppState>, peer_pubkey: [u8; 32]) {
    tokio::spawn(async move {
        match operator_announce_frontier(
            &state,
            &state.instance_key,
            &state.federation_transport,
            peer_pubkey,
        )
        .await
        {
            Ok(version) => tracing::debug!(
                peer = %crate::users::hex_lower(&peer_pubkey),
                version,
                "§8.6 first-contact announce sent",
            ),
            Err(e) => tracing::debug!(
                peer = %crate::users::hex_lower(&peer_pubkey),
                error = ?e,
                "§8.6 first-contact announce failed (repaired by next fanout/pull)",
            ),
        }
    });
}

// Quiet unused-import warnings on builds that don't exercise certain
// error helpers yet (e.g. `conflict` / `not_found` / `unauthorized`
// are reserved for the §8.5 / §6 edge cases the routing path will
// add in Phase 5). Keeping them imported keeps the error-helper API
// surface visible to anyone scanning this file.
#[allow(dead_code)]
fn _unused_error_helpers() -> [Response; 3] {
    [
        conflict("placeholder"),
        not_found("placeholder"),
        unauthorized(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_filter() -> FilterSpec {
        let mut f = BloomFilter::new_empty(7, 1024, 10, 0.01).unwrap();
        f.insert(b"alice");
        FilterSpec::from_bloom(&f)
    }

    #[test]
    fn announce_round_trips() {
        let a = FrontierAnnounce {
            version: 42,
            epoch_start: 1_700_000_000_000,
            active_horizon_days: 0,
            visible_filter: sample_filter(),
            expansion_filter: sample_filter(),
            mode: Mode::All,
            age_ceilings: AgeCeilings::new(),
        };
        let bytes = a.encode();
        let decoded = FrontierAnnounce::decode(&bytes).expect("decode");
        assert_eq!(decoded, a);
    }

    #[test]
    fn announce_round_trips_with_age_ceilings() {
        let mut ceilings = AgeCeilings::new();
        ceilings.insert([0x11; 32], 1_600_000_000_000);
        ceilings.insert([0x22; 32], 1_650_000_000_000);
        let a = FrontierAnnounce {
            version: 42,
            epoch_start: 1_700_000_000_000,
            active_horizon_days: 0,
            visible_filter: sample_filter(),
            expansion_filter: sample_filter(),
            mode: Mode::All,
            age_ceilings: ceilings,
        };
        let bytes = a.encode();
        let decoded = FrontierAnnounce::decode(&bytes).expect("decode");
        assert_eq!(decoded, a);
    }

    #[test]
    fn announce_empty_age_ceilings_omits_wire_field() {
        // An empty cleave set must not emit an `age_ceilings` key —
        // keeps the wire byte-identical to a pre-Slice-C announce.
        let a = FrontierAnnounce {
            version: 1,
            epoch_start: 1,
            active_horizon_days: 0,
            visible_filter: sample_filter(),
            expansion_filter: sample_filter(),
            mode: Mode::Filtered,
            age_ceilings: AgeCeilings::new(),
        };
        let value: Value = ciborium::de::from_reader(a.encode().as_slice()).expect("decode value");
        let keys: Vec<&str> = match &value {
            Value::Map(m) => m
                .iter()
                .filter_map(|(k, _)| match k {
                    Value::Text(s) => Some(s.as_str()),
                    _ => None,
                })
                .collect(),
            _ => panic!("expected map"),
        };
        assert!(!keys.contains(&"age_ceilings"));
    }

    #[test]
    fn announce_missing_mode_decodes_as_filtered() {
        // Forward-compat: a peer whose build predates Phase 6.5
        // omits the `mode` field; the §7.2 conservative default is
        // `filtered`.
        let value = Value::Map(vec![
            (Value::Text("version".into()), Value::Integer(7.into())),
            (
                Value::Text("epoch_start".into()),
                Value::Integer(1_700_000_000_000u64.into()),
            ),
            (
                Value::Text("active_horizon_days".into()),
                Value::Integer(0.into()),
            ),
            (
                Value::Text("visible_filter".into()),
                sample_filter().to_cbor_value(),
            ),
            (
                Value::Text("expansion_filter".into()),
                sample_filter().to_cbor_value(),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf).expect("ser");
        let decoded = FrontierAnnounce::decode(&buf).expect("decode");
        assert_eq!(decoded.mode, Mode::Filtered);
    }

    #[test]
    fn delta_round_trips_both_masks() {
        let d = FrontierDelta {
            prev_version: 41,
            new_version: 42,
            visible_mask: Some(vec![0u8; 128]),
            expansion_mask: Some(vec![0xFFu8; 128]),
            mode: Mode::All,
            age_ceilings: AgeCeilings::new(),
        };
        let bytes = d.encode();
        let decoded = FrontierDelta::decode(&bytes).expect("decode");
        assert_eq!(decoded, d);
    }

    #[test]
    fn delta_round_trips_content_only() {
        let d = FrontierDelta {
            prev_version: 41,
            new_version: 42,
            visible_mask: Some(vec![0xAAu8; 128]),
            expansion_mask: None,
            mode: Mode::Filtered,
            age_ceilings: AgeCeilings::new(),
        };
        let bytes = d.encode();
        let decoded = FrontierDelta::decode(&bytes).expect("decode");
        assert_eq!(decoded, d);
    }

    #[test]
    fn delta_round_trips_age_ceilings_only() {
        // §8.4 permits a ceiling-only delta (no masks).
        let mut ceilings = AgeCeilings::new();
        ceilings.insert([0x33; 32], 1_500_000_000_000);
        let d = FrontierDelta {
            prev_version: 41,
            new_version: 42,
            visible_mask: None,
            expansion_mask: None,
            mode: Mode::Filtered,
            age_ceilings: ceilings,
        };
        let bytes = d.encode();
        let decoded = FrontierDelta::decode(&bytes).expect("decode");
        assert_eq!(decoded, d);
    }

    #[test]
    fn snapshot_round_trips() {
        let s = FrontierSnapshot {
            version: 5,
            epoch_start: 1_700_000_000_000,
            active_horizon_days: 30,
            visible_filter: sample_filter(),
            expansion_filter: sample_filter(),
            cursor: vec![1, 2, 3, 4],
            age_ceilings: AgeCeilings::new(),
        };
        let bytes = s.encode();
        let decoded = FrontierSnapshot::decode(&bytes).expect("decode");
        assert_eq!(decoded, s);
    }

    #[test]
    fn snapshot_round_trips_with_age_ceilings() {
        let mut ceilings = AgeCeilings::new();
        ceilings.insert([0x44; 32], 1_550_000_000_000);
        let s = FrontierSnapshot {
            version: 5,
            epoch_start: 1_700_000_000_000,
            active_horizon_days: 30,
            visible_filter: sample_filter(),
            expansion_filter: sample_filter(),
            cursor: vec![1, 2, 3, 4],
            age_ceilings: ceilings,
        };
        let bytes = s.encode();
        let decoded = FrontierSnapshot::decode(&bytes).expect("decode");
        assert_eq!(decoded, s);
    }

    #[test]
    fn filter_spec_into_bloom_rejects_wrong_family() {
        let mut spec = sample_filter();
        spec.family = "future-family-v0".to_string();
        assert_eq!(spec.into_bloom().unwrap_err(), "unsupported_family");
    }

    #[test]
    fn filter_spec_into_bloom_rejects_bad_bytes_length() {
        let mut spec = sample_filter();
        spec.bytes.pop(); // 128 - 1 = 127 bytes; m/8 = 128
        assert_eq!(spec.into_bloom().unwrap_err(), "bytes_length_mismatch");
    }

    #[test]
    fn filter_spec_into_bloom_rejects_param_out_of_range() {
        let mut spec = sample_filter();
        spec.k = 0;
        assert_eq!(spec.into_bloom().unwrap_err(), "filter_param_out_of_range");
        let mut spec = sample_filter();
        spec.m = 100; // not a multiple of 64
        assert_eq!(spec.into_bloom().unwrap_err(), "filter_param_out_of_range");
    }

    #[test]
    fn empty_local_frontier_matches_nothing() {
        let lf = LocalFrontier::empty();
        assert_eq!(lf.version, 0);
        assert_eq!(lf.visible_filter.m, bloom::MIN_M_BITS);
        assert!(!lf.visible_filter.contains(b"any key"));
    }

    #[test]
    fn cursor_encoding_round_trips_version_and_epoch() {
        let c = encode_cursor(0x0102030405060708, 0x1112131415161718);
        assert_eq!(c.len(), 16);
        let mut v_bytes = [0u8; 8];
        v_bytes.copy_from_slice(&c[..8]);
        let mut e_bytes = [0u8; 8];
        e_bytes.copy_from_slice(&c[8..]);
        assert_eq!(u64::from_be_bytes(v_bytes), 0x0102030405060708);
        assert_eq!(u64::from_be_bytes(e_bytes), 0x1112131415161718);
    }
}
