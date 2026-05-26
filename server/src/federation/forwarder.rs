//! §7.5 interest-routed gossip forwarder.
//!
//! Sits behind the [`crate::federation::edges`] push handler (and the
//! local trust-edge originate paths in [`crate::users`]) to fan a
//! newly-applied or freshly-originated signed object out to interested
//! peers via the §7.4 routing-class dispatch, capped at the §7.5
//! `REDUNDANCY_K` distinct downstream peers.
//!
//! ## Shape of the dedup-LRU
//!
//! `docs/federation-protocol.md` §7.5 keys the dedup-LRU on the
//! object's **canonical_hash** (32 bytes) and stores
//! `{ forwarded_to: bitset[N_peers], created_at }` as the value. The
//! forwarding check is `popcount(forwarded_to) < REDUNDANCY_K`; each
//! enqueue sets one bit. "Forward to at most K *distinct* peers" rather
//! than "forward K times total" — re-arrivals along independent paths
//! don't burn budget against peers we already forwarded to.
//!
//! V1 uses a dense `Vec<u64>` bitset and a process-local peer-pubkey →
//! bit-index registry. TODO: switch to a sparse map when peer counts
//! go far beyond the 50-peer V1 sizing budget (§7.5 "for peer counts
//! much beyond 50, switch to a sparse map; the bitset is fine for V1
//! expected scales").
//!
//! Storage is `quick_cache::sync::Cache<[u8; 32], Arc<ForwardingEntry>>`:
//! sharded-concurrent under the hood, so the forwarder hot path doesn't
//! serialise on a single outer mutex the way a `Mutex<LruCache<…>>`
//! would. The `Arc<ForwardingEntry>` value gives us interior mutability
//! (a plain `std::sync::Mutex` around the bitset) so clones returned
//! from `get` mutate the same underlying state.
//!
//! ## Hybrid time + size eviction (§7.5)
//!
//! - **Size bound** — [`DEDUP_LRU_MAX_ENTRIES`] (default 1M). The
//!   underlying `Cache` evicts LRU-oldest on size pressure.
//! - **Time bound** — [`T_PROPAGATE_MAX`] (default 1h). Stored on the
//!   entry as `created_at`; lookups that find an expired entry treat
//!   it as a miss and create a fresh entry. The size bound and time
//!   bound work whichever fires first, per the spec.
//!
//! ## Fire-and-forget dispatch
//!
//! [`forward_signed_object`] spawns a Tokio task and returns
//! immediately: §7.5 mandates "The local write path NEVER blocks on
//! outbound queue pressure". Dispatches happen on the spawned task;
//! per-peer transport failures are logged but not retried inline —
//! the §10.5 pull-backfill is the correctness backstop for dropped
//! sends.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use ciborium::value::Value;
use http::{Method, Request};
use quick_cache::sync::Cache;

use crate::AppState;
use crate::federation::envelope::{AUTH_HEADER, sign_outbound};
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::routing::{ForwardingClass, REDUNDANCY_K, peers_interested_in};
use crate::federation::transport::PeerId;

/// §7.5 dedup-LRU time bound (`T_propagate_max`, default 1h).
/// An entry older than this is treated as a miss and re-initialised
/// on next lookup; the matching `MAX_QUEUE_OBJECT_AGE` outbound-queue
/// staleness cap guarantees no object is ever delivered past this
/// horizon, so a late re-arrival is a fresh forwarding decision.
pub const T_PROPAGATE_MAX: Duration = Duration::from_secs(3600);

/// §7.5 dedup-LRU size bound (`DEDUP_LRU_MAX_ENTRIES`, default 1M).
/// Memory budget ≈ 40 MB at 50 peers per the spec sizing model
/// (~32-byte key + ~7-byte bitset + LRU overhead per entry).
pub const DEDUP_LRU_MAX_ENTRIES: usize = 1_000_000;

/// Path the forwarder pushes wire bytes to on each downstream peer
/// for the §9.1 edges class.
const EDGES_PATH: &str = "/federation/v1/edges";

/// Path the forwarder pushes wire bytes to on each downstream peer
/// for the §10.1 content classes (post-rev, retract, admin-rm,
/// profile, thread-create, deactivate).
const CONTENT_PATH: &str = "/federation/v1/content";

/// Per-class dispatch: which downstream route + which body-wrapper
/// CBOR key to use. Trust-edges go to `/edges` and wrap each
/// WireFormat blob as `{ "edges": [bstr] }`; every Authored class
/// goes to `/content` and wraps as `{ "objects": [bstr] }`.
fn route_and_body_key(class: ForwardingClass) -> (&'static str, &'static str) {
    match class {
        ForwardingClass::TrustEdge => (EDGES_PATH, "edges"),
        ForwardingClass::Authored => (CONTENT_PATH, "objects"),
    }
}

// ---------------------------------------------------------------------------
// Bitset
// ---------------------------------------------------------------------------

/// Dense bitset of peer indices we've already forwarded a given
/// canonical_hash to. Grows monotonically as new peer indices are
/// assigned.
///
/// TODO: §7.5 calls for switching to a sparse map (e.g. `HashSet<u32>`)
/// once peer counts go far beyond the 50-peer V1 sizing budget. The
/// dense `Vec<u64>` is cheaper at small N (~7 bytes for 50 peers)
/// but its overhead is linear in `peer_index.next` regardless of
/// actual peers-with-bits-set.
#[derive(Default)]
struct BitSet {
    chunks: Vec<u64>,
}

impl BitSet {
    fn contains(&self, bit: usize) -> bool {
        let (i, m) = (bit / 64, bit % 64);
        self.chunks.get(i).is_some_and(|c| (c >> m) & 1 == 1)
    }

    fn set(&mut self, bit: usize) {
        let (i, m) = (bit / 64, bit % 64);
        if i >= self.chunks.len() {
            self.chunks.resize(i + 1, 0);
        }
        self.chunks[i] |= 1u64 << m;
    }

    fn popcount(&self) -> u32 {
        self.chunks.iter().map(|c| c.count_ones()).sum()
    }
}

// ---------------------------------------------------------------------------
// Forwarding entry — one row of the dedup-LRU
// ---------------------------------------------------------------------------

/// One LRU row. `forwarded_to` is the §7.5 per-hash bitset of peer
/// indices we've enqueued this object to; `created_at` underwrites
/// the [`T_PROPAGATE_MAX`] time-based eviction.
///
/// The `Mutex<BitSet>` around the bitset is the only writer-side lock
/// in the hot path. The outer cache returns `Arc<Self>` by clone, so
/// every concurrent forwarder caller for the same hash sees the same
/// underlying mutex and bitset state.
struct ForwardingEntry {
    forwarded_to: Mutex<BitSet>,
    created_at: Instant,
}

// ---------------------------------------------------------------------------
// Peer index — process-local pubkey → bit assignment
// ---------------------------------------------------------------------------

/// Lazy registry assigning a dense bit index to each peer pubkey
/// the forwarder has ever seen this process. Indices are never
/// reused — a peer going inactive just stops appearing in routing
/// results; their old bit lingers in any cached entry but no future
/// fanout sets it. Restart resets the registry (and the LRU), which
/// is fine: the LRU is best-effort and a fresh process re-learns
/// peers as objects flow.
#[derive(Default)]
struct PeerIndex {
    by_pubkey: HashMap<[u8; 32], usize>,
    next: usize,
}

impl PeerIndex {
    fn index_for(&mut self, pk: [u8; 32]) -> usize {
        if let Some(&i) = self.by_pubkey.get(&pk) {
            return i;
        }
        let i = self.next;
        self.next += 1;
        self.by_pubkey.insert(pk, i);
        i
    }
}

// ---------------------------------------------------------------------------
// ForwardingLru — the §7.5 dedup-LRU + peer index, shared on AppState
// ---------------------------------------------------------------------------

/// Process-wide §7.5 forwarding state: the canonical-hash → bitset
/// LRU, plus the peer-pubkey → bit-index registry that the bitset is
/// indexed by. One instance lives on [`AppState`] and is consulted by
/// the originator path (`crate::users::set_trust_edge` /
/// `crate::users::delete_trust_edge`) and the relay path
/// (`crate::federation::edges::handle_edges_push`).
pub struct ForwardingLru {
    cache: Cache<[u8; 32], Arc<ForwardingEntry>>,
    peer_index: Mutex<PeerIndex>,
}

impl ForwardingLru {
    /// Build a default-sized §7.5 dedup-LRU.
    pub fn new() -> Self {
        Self {
            cache: Cache::new(DEDUP_LRU_MAX_ENTRIES),
            peer_index: Mutex::new(PeerIndex::default()),
        }
    }

    /// Look up the entry for `hash`, or create a fresh one. Treats an
    /// entry whose `created_at` is older than [`T_PROPAGATE_MAX`] as
    /// expired and overwrites it.
    ///
    /// Has a benign TOCTOU race: two concurrent fanouts of the same
    /// fresh hash may both insert a new entry, and the second insert
    /// clobbers any bits the first one set. The consequence is a
    /// rare re-forward to one peer that already received the object;
    /// the peer dedups on `canonical_hash` and returns `duplicate`,
    /// so the net effect is a bandwidth blip, not a correctness bug.
    /// V1 accepts this; revisit with `get_value_or_guard_async` if
    /// soak metrics ever show meaningful duplicate-from-self churn.
    fn get_or_init_entry(&self, hash: &[u8; 32]) -> Arc<ForwardingEntry> {
        if let Some(entry) = self.cache.get(hash)
            && entry.created_at.elapsed() < T_PROPAGATE_MAX
        {
            return entry;
        }
        let fresh = Arc::new(ForwardingEntry {
            forwarded_to: Mutex::new(BitSet::default()),
            created_at: Instant::now(),
        });
        self.cache.insert(*hash, fresh.clone());
        fresh
    }

    /// Resolve a peer pubkey to its dense bit index, allocating one
    /// if this pubkey has not been seen before.
    fn peer_index_for(&self, pk: [u8; 32]) -> usize {
        self.peer_index
            .lock()
            .expect("peer_index poisoned")
            .index_for(pk)
    }
}

impl Default for ForwardingLru {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// §7.5 forward a freshly-applied or freshly-originated signed object
/// to up to `REDUNDANCY_K` interested peers. Fire-and-forget: returns
/// immediately and dispatches happen on a spawned task.
///
/// `arrived_from` is `Some(sender_pubkey)` for relayed objects (skip
/// pushing back to the source) and `None` for originator pushes.
///
/// Per §7.5 the originator runs the same `popcount < REDUNDANCY_K`
/// check as a forwarder, so an originator with more than K
/// interest-matching peers direct-pushes K and lets gossip carry the
/// rest. Originator vs forwarder is indistinguishable on the wire —
/// it's purely a matter of which entry-point inserted the LRU row.
pub fn forward_signed_object(
    state: Arc<AppState>,
    canonical_hash: [u8; 32],
    class: ForwardingClass,
    routing_key: Vec<u8>,
    wire_bytes: Vec<u8>,
    arrived_from: Option<[u8; 32]>,
) {
    tokio::spawn(async move {
        if let Err(e) = forward_inner(
            &state,
            canonical_hash,
            class,
            &routing_key,
            wire_bytes,
            arrived_from,
        )
        .await
        {
            tracing::warn!(error = %e, "forwarder fanout failed");
        }
    });
}

/// Core fanout: gather candidates, pick the next K (after exclusions),
/// dispatch to each on its own task. Returns `Err` only for DB faults
/// in the candidate lookup; per-peer transport failures are logged
/// and swallowed inside the dispatch tasks.
async fn forward_inner(
    state: &Arc<AppState>,
    canonical_hash: [u8; 32],
    class: ForwardingClass,
    routing_key: &[u8],
    wire_bytes: Vec<u8>,
    arrived_from: Option<[u8; 32]>,
) -> Result<(), sqlx::Error> {
    let candidates = peers_interested_in(state, class, routing_key).await?;
    if candidates.is_empty() {
        return Ok(());
    }

    let entry = state.forwarding_lru.get_or_init_entry(&canonical_hash);

    // Decide which peers to send to under the REDUNDANCY_K cap. Holds
    // the bitset mutex for the whole pick to keep the popcount /
    // contains / set sequence atomic against concurrent fanouts.
    let to_send: Vec<[u8; 32]> = {
        let mut bs = entry.forwarded_to.lock().expect("forwarded_to poisoned");
        let mut picks = Vec::new();
        for peer in &candidates {
            if Some(peer.instance_pubkey) == arrived_from {
                continue;
            }
            let idx = state.forwarding_lru.peer_index_for(peer.instance_pubkey);
            if bs.contains(idx) {
                continue;
            }
            if (bs.popcount() as usize) >= REDUNDANCY_K {
                break;
            }
            bs.set(idx);
            picks.push(peer.instance_pubkey);
        }
        picks
    };

    if to_send.is_empty() {
        return Ok(());
    }

    let (path, body_key) = route_and_body_key(class);
    let body = encode_singleton_body(body_key, &wire_bytes);
    for peer_pk in to_send {
        let state_for_task = state.clone();
        let body = body.clone();
        tokio::spawn(async move {
            dispatch_one(&state_for_task, peer_pk, path, body).await;
        });
    }

    Ok(())
}

/// Build a §9.1 / §10.1 push body wrapping a single WireFormat blob
/// under the given top-level key (`"edges"` or `"objects"`). The
/// fanout always sends one object per push — the per-peer push paths
/// are independent and there's nothing to batch on the relay side.
fn encode_singleton_body(key: &str, wire: &[u8]) -> Vec<u8> {
    let body = Value::Map(vec![(
        Value::Text(key.into()),
        Value::Array(vec![Value::Bytes(wire.to_vec())]),
    )]);
    let mut buf = Vec::with_capacity(wire.len() + 32);
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    buf
}

/// Build and dispatch one §9.1 push to one downstream peer. Failure
/// is logged at `warn` and dropped: the §10.5 pull-backfill is the
/// correctness backstop for any sends the forwarder can't get
/// through.
async fn dispatch_one(state: &Arc<AppState>, peer_pk: [u8; 32], path: &'static str, body: Vec<u8>) {
    let header = sign_outbound(&state.instance_key, peer_pk, &Method::POST, path, &body);
    let req = match Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(http::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .header(AUTH_HEADER, header)
        .body(Bytes::from(body))
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "forwarder failed to build outbound request");
            return;
        }
    };
    let peer_id = PeerId::from_bytes(peer_pk);
    match state.federation_transport.request(&peer_id, req).await {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            tracing::warn!(
                peer = %peer_id,
                status = %resp.status(),
                "forwarder peer returned non-2xx",
            );
        }
        Err(e) => {
            tracing::warn!(peer = %peer_id, error = %e, "forwarder dispatch failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests (Layer 0): bitset + peer index + LRU semantics
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitset_grows_and_counts() {
        let mut b = BitSet::default();
        assert_eq!(b.popcount(), 0);
        b.set(0);
        b.set(63);
        b.set(64);
        b.set(200);
        assert!(b.contains(0));
        assert!(b.contains(63));
        assert!(b.contains(64));
        assert!(b.contains(200));
        assert!(!b.contains(1));
        assert!(!b.contains(199));
        assert_eq!(b.popcount(), 4);
    }

    #[test]
    fn peer_index_assigns_stably() {
        let mut p = PeerIndex::default();
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        let i_a = p.index_for(a);
        let i_b = p.index_for(b);
        assert_ne!(i_a, i_b);
        // Same pubkey → same index.
        assert_eq!(p.index_for(a), i_a);
        assert_eq!(p.index_for(b), i_b);
    }

    #[test]
    fn lru_returns_same_entry_within_ttl() {
        let lru = ForwardingLru::new();
        let h = [1u8; 32];
        let e1 = lru.get_or_init_entry(&h);
        e1.forwarded_to
            .lock()
            .unwrap()
            .set(lru.peer_index_for([0x11; 32]));
        let e2 = lru.get_or_init_entry(&h);
        // Same Arc → same bitset state visible.
        assert_eq!(e2.forwarded_to.lock().unwrap().popcount(), 1);
        assert!(Arc::ptr_eq(&e1, &e2));
    }

    #[test]
    fn encode_singleton_body_round_trips_to_cbor_map() {
        let wire = b"hello".to_vec();
        let body = encode_singleton_body("edges", &wire);
        let v: Value = ciborium::de::from_reader(body.as_slice()).expect("cbor");
        let Value::Map(m) = v else {
            panic!("not a map");
        };
        let edges = m
            .into_iter()
            .find_map(|(k, v)| match k {
                Value::Text(t) if t == "edges" => Some(v),
                _ => None,
            })
            .expect("edges key");
        let Value::Array(arr) = edges else {
            panic!("edges not array");
        };
        assert_eq!(arr.len(), 1);
        let Value::Bytes(b) = &arr[0] else {
            panic!("not bytes");
        };
        assert_eq!(b, &wire);
    }

    #[test]
    fn route_and_body_key_picks_per_class() {
        let (path, key) = route_and_body_key(ForwardingClass::TrustEdge);
        assert_eq!(path, "/federation/v1/edges");
        assert_eq!(key, "edges");
        let (path, key) = route_and_body_key(ForwardingClass::Authored);
        assert_eq!(path, "/federation/v1/content");
        assert_eq!(key, "objects");
    }
}
