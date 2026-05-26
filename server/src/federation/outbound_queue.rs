//! §7.3 outbound queue + drain workers.
//!
//! Replaces the Phase 6.3 fire-and-forget `tokio::spawn(dispatch_one)`
//! pattern in [`super::forwarder`] with a per-peer FIFO queue drained
//! by a long-lived worker task, with exponential backoff on transient
//! failures, plus the §7.5 queue-sizing caps (per-peer object/byte
//! cap, process-wide byte cap, staleness cap).
//!
//! ## Architecture
//!
//! - One [`OutboundQueues`] per process; lives on [`AppState`].
//! - Internally a `HashMap<peer_pk, PeerQueue>` guarded by a single
//!   `std::sync::Mutex`. The lock is held only for the duration of
//!   enqueue / take-batch / requeue / set-flag operations — never
//!   across an `.await`. Per the spec sizing model (50 peers V1) this
//!   single-lock approach is fine; we can shard later if benches show
//!   contention.
//! - Each peer queue carries a `tokio::sync::Notify` (`wake`) the
//!   drain worker waits on. Enqueue triggers `wake.notify_one()`.
//! - On the first enqueue for a peer, the queue spawns a drain
//!   worker. The worker runs forever (Phase 6.4 explicitly defers
//!   peer-removal stop conditions to a later phase).
//! - One in-flight HTTP request per peer at a time
//!   (`PeerQueue::in_flight`). Concurrency across peers is unbounded.
//!
//! ## Caps (§7.5)
//!
//! Enqueue path:
//!
//! 1. **Per-peer caps fire first.** If `bytes_per_peer` or
//!    `objects_per_peer` would be exceeded, drop oldest entries from
//!    *this* peer's queue head until the new object fits.
//! 2. **Global byte cap fires second.** If `total_bytes` would be
//!    exceeded, drop oldest entries from the *largest* peer queue
//!    (by bytes), repeating until the new object fits. The peer being
//!    enqueued to is itself eligible — its own newly-added bytes
//!    count toward "largest".
//!
//! Drain path: `object_max_age_secs` is checked when a batch is
//! taken; items older than the cap are dropped before the egress
//! write per §7.5 "objects older than this are dropped at the moment
//! they would otherwise be transmitted".
//!
//! ## Batching
//!
//! Up to `MAX_CONTENT_BATCH_OUTBOUND = 64` queued items destined for
//! the same peer with the same `(path, body_key)` pair are coalesced
//! into a single push. The receiver's `MAX_CONTENT_BATCH` (`§10.6`,
//! also 64) is the matching cap. Items with mismatched `path` or
//! `body_key` end the batch (the next batch picks up where this one
//! stopped) — trust-edges and authored content never mix in one HTTP
//! call.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use ciborium::value::Value;
use http::{Method, Request, StatusCode};
use tokio::sync::Notify;

use crate::federation::envelope::{AUTH_HEADER, sign_outbound};
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::instance_key::InstanceKey;
use crate::federation::transport::{FederationTransport, PeerId};

/// §10.6-mirroring outbound batch cap. Coalesce up to this many
/// queue-head items into a single push.
///
/// Kept as a wire-canonical `const` rather than a TOML knob because
/// the receiver's matching `MAX_CONTENT_BATCH = 64` (§10.6) is a
/// protocol invariant — a batch larger than 64 would be rejected by
/// every conforming peer.
pub const MAX_CONTENT_BATCH_OUTBOUND: usize = 64;

// ---------------------------------------------------------------------------
// Config types
// ---------------------------------------------------------------------------

/// Runtime shape of the operator-tunable outbound-queue knobs.
///
/// The TOML-deserialised form lives in `prismoire-config` as
/// [`prismoire_config::OutboundQueueConfig`]; this module's struct is
/// what the runtime actually consumes (`Duration` instead of raw
/// seconds/ms). Convert via the `From<&prismoire_config::OutboundQueueConfig>`
/// impl below — `main.rs` does this once at startup before passing
/// into [`OutboundQueues::new`].
#[derive(Clone, Debug)]
pub struct OutboundQueueConfig {
    /// Process-wide byte budget. See `prismoire_config::OutboundQueueConfig::total_bytes`.
    pub total_bytes: usize,
    /// Per-peer byte cap.
    pub bytes_per_peer: usize,
    /// Per-peer object-count cap.
    pub objects_per_peer: usize,
    /// Staleness cap.
    pub object_max_age: Duration,
    /// Max items coalesced into one HTTP push (wire-canonical, see
    /// [`MAX_CONTENT_BATCH_OUTBOUND`]).
    pub max_batch: usize,
    /// Backoff schedule applied on transient failures.
    pub backoff: BackoffPolicy,
}

impl From<&prismoire_config::OutboundQueueConfig> for OutboundQueueConfig {
    fn from(cfg: &prismoire_config::OutboundQueueConfig) -> Self {
        Self {
            total_bytes: cfg.total_bytes,
            bytes_per_peer: cfg.bytes_per_peer,
            objects_per_peer: cfg.objects_per_peer,
            object_max_age: Duration::from_secs(cfg.object_max_age_secs),
            max_batch: MAX_CONTENT_BATCH_OUTBOUND,
            backoff: BackoffPolicy::from(&cfg.backoff),
        }
    }
}

#[cfg(any(test, feature = "test-auth"))]
impl OutboundQueueConfig {
    /// Test-shaped defaults: caps stay generous (tests don't exercise
    /// the overflow paths unless they shrink the relevant cap
    /// explicitly), but the backoff is shortened so the rare retry
    /// path doesn't burn whole-second sleeps in the pre-commit run.
    ///
    /// Feature-gated to `test-auth` so prod code paths cannot
    /// accidentally reference the test preset.
    pub fn test_fast() -> Self {
        let mut out = OutboundQueueConfig::from(&prismoire_config::OutboundQueueConfig::default());
        out.backoff = BackoffPolicy::test_fast();
        out
    }
}

/// Exponential-backoff schedule applied on transient drain failures
/// (5xx, 429, transport error). Full-jitter: actual sleep is
/// `rand::random::<f64>() * current_delay`.
#[derive(Clone, Debug)]
pub struct BackoffPolicy {
    /// First retry delay after a transient failure.
    pub initial: Duration,
    /// Cap on the exponentiated delay.
    pub max: Duration,
    /// Multiplier applied per failed attempt (typically 2.0).
    pub multiplier: f64,
}

impl From<&prismoire_config::BackoffConfig> for BackoffPolicy {
    fn from(cfg: &prismoire_config::BackoffConfig) -> Self {
        Self {
            initial: Duration::from_millis(cfg.initial_ms),
            max: Duration::from_millis(cfg.max_ms),
            multiplier: cfg.multiplier,
        }
    }
}

#[cfg(any(test, feature = "test-auth"))]
impl BackoffPolicy {
    /// Tight schedule for tests so retries don't dominate wall time.
    /// Feature-gated to `test-auth` so prod code paths cannot reference it.
    pub fn test_fast() -> Self {
        Self {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(100),
            multiplier: 2.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// One queued object awaiting delivery to a single peer.
#[derive(Clone)]
struct QueuedObject {
    /// `/federation/v1/content` or `/federation/v1/edges`.
    path: &'static str,
    /// `"objects"` or `"edges"` — top-level key wrapping the batch
    /// array in the CBOR push body.
    body_key: &'static str,
    /// The singleton WireFormat blob the originator/forwarder produced.
    /// The queue batches N of these into one CBOR push body when
    /// draining.
    wire_bytes: Vec<u8>,
    /// Insertion time. Compared against `object_max_age` on drain to
    /// drop stale items before the egress write.
    enqueued_at: Instant,
}

/// Per-peer state: the FIFO of pending objects, current byte total,
/// wake/idle flags, and a flag preventing duplicate worker spawns.
struct PeerQueue {
    items: VecDeque<QueuedObject>,
    bytes: usize,
    /// Drain worker waits on this; enqueue calls `notify_one()`.
    wake: Arc<Notify>,
    /// Set on first enqueue for this peer to ensure exactly one
    /// drain worker exists.
    worker_spawned: bool,
    /// `true` between "drain worker took a batch" and "drain worker
    /// finished the HTTP round-trip and updated state". The combined
    /// "queue empty AND `in_flight == false` for every peer" check is
    /// what [`OutboundQueues::wait_idle`] tests.
    in_flight: bool,
    /// Set by [`OutboundQueues::drop_peer`] to tell the drain worker
    /// to exit on its next wake (admin de-peering, peer-key rotation).
    /// The worker observes this under the inner mutex and returns
    /// after marking itself not in-flight, so `wait_idle()` doesn't
    /// hang on a dropped peer's queue.
    stopped: bool,
}

impl PeerQueue {
    fn new() -> Self {
        Self {
            items: VecDeque::new(),
            bytes: 0,
            wake: Arc::new(Notify::new()),
            worker_spawned: false,
            in_flight: false,
            stopped: false,
        }
    }
}

/// Shared inner state — `Mutex`-guarded so the enqueue path, the
/// take-batch step inside the drain worker, and the `wait_idle`
/// observer all see a consistent snapshot. The mutex is never held
/// across an `.await`.
struct OutboundQueuesState {
    peers: HashMap<[u8; 32], PeerQueue>,
    total_bytes: usize,
}

// ---------------------------------------------------------------------------
// Public type
// ---------------------------------------------------------------------------

/// §7.3 outbound queue + drain workers.
///
/// See the module-level docstring for the full design. Held on
/// [`AppState`] as an `Arc<OutboundQueues>` so the forwarder can call
/// `state.outbound_queues.enqueue(...)` without taking out a lifetime
/// over the AppState.
pub struct OutboundQueues {
    inner: Arc<Mutex<OutboundQueuesState>>,
    config: OutboundQueueConfig,
    transport: Arc<dyn FederationTransport>,
    instance_key: Arc<InstanceKey>,
    /// Notified each time a per-peer queue transitions to fully-idle
    /// (empty AND `in_flight == false`). [`Self::wait_idle`] uses this
    /// to wake without polling.
    idle_notify: Arc<Notify>,
}

impl OutboundQueues {
    /// Construct a new queue collection. No workers spawn at
    /// construction time — they're lazy on first enqueue per-peer.
    pub fn new(
        config: OutboundQueueConfig,
        transport: Arc<dyn FederationTransport>,
        instance_key: Arc<InstanceKey>,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(Mutex::new(OutboundQueuesState {
                peers: HashMap::new(),
                total_bytes: 0,
            })),
            config,
            transport,
            instance_key,
            idle_notify: Arc::new(Notify::new()),
        })
    }

    /// Enqueue one object for delivery to `peer_pk`. Enforces per-peer
    /// caps first (drop oldest from this peer), then global cap (drop
    /// oldest from the largest peer). Spawns the per-peer drain worker
    /// on first enqueue. Never blocks the caller on egress.
    pub fn enqueue(
        self: &Arc<Self>,
        peer_pk: [u8; 32],
        path: &'static str,
        body_key: &'static str,
        wire_bytes: Vec<u8>,
    ) {
        let object_bytes = wire_bytes.len();
        let object = QueuedObject {
            path,
            body_key,
            wire_bytes,
            enqueued_at: Instant::now(),
        };

        let (spawn_needed, wake) = {
            let mut state = self.inner.lock().expect("outbound_queue poisoned");

            // Ensure the peer entry exists.
            let entry_exists = state.peers.contains_key(&peer_pk);
            if !entry_exists {
                state.peers.insert(peer_pk, PeerQueue::new());
            }

            // --- Step 1: per-peer caps ---
            // Drop oldest from THIS peer's queue until adding
            // `object_bytes` would fit both caps. Tally bytes-freed
            // locally and update `state.total_bytes` after the inner
            // borrow ends to keep the borrow checker happy.
            let mut peer_dropped = 0u64;
            let mut peer_bytes_freed = 0usize;
            {
                let q = state
                    .peers
                    .get_mut(&peer_pk)
                    .expect("just inserted if missing");
                while !q.items.is_empty()
                    && (q.items.len() + 1 > self.config.objects_per_peer
                        || q.bytes + object_bytes > self.config.bytes_per_peer)
                {
                    let dropped = q.items.pop_front().expect("non-empty");
                    let n = dropped.wire_bytes.len();
                    // Saturating: a desync between the accounting and
                    // the actual queue contents (which would be a bug
                    // elsewhere) shouldn't take down the process via a
                    // debug-mode underflow panic.
                    q.bytes = q.bytes.saturating_sub(n);
                    peer_bytes_freed += n;
                    peer_dropped += 1;
                }
            }
            state.total_bytes = state.total_bytes.saturating_sub(peer_bytes_freed);
            if peer_dropped > 0 {
                tracing::warn!(
                    peer = %PeerId::from_bytes(peer_pk),
                    dropped_objects = peer_dropped,
                    "outbound queue overflow (per-peer cap), dropping oldest",
                );
            }

            // If after dropping the whole peer queue the new object
            // still doesn't fit the per-peer caps (object is itself
            // bigger than `bytes_per_peer`), drop the new object
            // instead. Single object > 32 MiB shouldn't happen given
            // our wire formats, but we'd rather log and skip than
            // panic.
            {
                let q = state.peers.get(&peer_pk).expect("entry exists");
                if q.items.is_empty() && object_bytes > self.config.bytes_per_peer {
                    tracing::warn!(
                        peer = %PeerId::from_bytes(peer_pk),
                        object_bytes,
                        cap = self.config.bytes_per_peer,
                        "outbound queue: single object exceeds per-peer byte cap, dropping",
                    );
                    return;
                }
            }

            // --- Step 2: global byte cap ---
            // If adding the object would push the process-wide total
            // over `total_bytes`, evict oldest from the LARGEST peer
            // queue (by bytes), repeating until the new object fits.
            // Eviction includes the peer we're enqueueing to.
            while state.total_bytes + object_bytes > self.config.total_bytes {
                // Find the largest-by-bytes peer with at least one
                // queued item.
                let largest_pk = state
                    .peers
                    .iter()
                    .filter(|(_, q)| !q.items.is_empty())
                    .max_by_key(|(_, q)| q.bytes)
                    .map(|(pk, _)| *pk);
                let Some(largest_pk) = largest_pk else {
                    // No peer has anything to evict — the new object
                    // alone exceeds the global cap. Drop it.
                    tracing::warn!(
                        peer = %PeerId::from_bytes(peer_pk),
                        object_bytes,
                        total_cap = self.config.total_bytes,
                        "outbound queue: object exceeds global cap with all queues empty, dropping",
                    );
                    return;
                };
                let q = state
                    .peers
                    .get_mut(&largest_pk)
                    .expect("non-empty in iteration");
                let dropped = q.items.pop_front().expect("filtered non-empty");
                let n = dropped.wire_bytes.len();
                q.bytes = q.bytes.saturating_sub(n);
                state.total_bytes = state.total_bytes.saturating_sub(n);
                tracing::warn!(
                    peer = %PeerId::from_bytes(largest_pk),
                    dropped_objects = 1u64,
                    "outbound queue overflow (global byte cap), evicting oldest from largest peer",
                );
            }

            // --- Step 3: enqueue ---
            // Worker-spawn check happens under the lock so two
            // concurrent first-enqueues don't both spawn.
            let (spawn_needed, wake) = {
                let q = state.peers.get_mut(&peer_pk).expect("peer entry exists");
                q.items.push_back(object);
                q.bytes += object_bytes;
                // Step-1 eviction should have made room for exactly one
                // more object; if this fires the eviction loop bound is
                // wrong somewhere.
                debug_assert!(
                    q.items.len() <= self.config.objects_per_peer,
                    "per-peer object cap violated after enqueue: {} > {}",
                    q.items.len(),
                    self.config.objects_per_peer,
                );
                let spawn_needed = !q.worker_spawned;
                if spawn_needed {
                    q.worker_spawned = true;
                }
                (spawn_needed, q.wake.clone())
            };
            state.total_bytes += object_bytes;
            (spawn_needed, wake)
        };

        if spawn_needed {
            spawn_drain_worker(self.clone(), peer_pk, wake.clone());
        }
        wake.notify_one();
    }

    /// Wait until every per-peer queue is empty AND no in-flight HTTP.
    /// Returns `true` if idle within `timeout`, `false` if the deadline
    /// passes first. Tests use this instead of polling
    /// `signed_objects` row counts.
    pub async fn wait_idle(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.is_idle_now() {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self.is_idle_now();
            }
            // `idle_notify.notified()` returns a future; awaiting it
            // races against the timeout. Note: we may miss a notify
            // that fires before we register, hence the re-check at the
            // top of the loop and the bounded `notified` wait — we
            // never wait longer than 50ms without re-checking, even
            // though the workers always notify on transition.
            let bounded_wait = remaining.min(Duration::from_millis(50));
            tokio::select! {
                _ = self.idle_notify.notified() => {}
                _ = tokio::time::sleep(bounded_wait) => {}
            }
        }
    }

    fn is_idle_now(&self) -> bool {
        let state = self.inner.lock().expect("outbound_queue poisoned");
        state
            .peers
            .values()
            .all(|q| q.items.is_empty() && !q.in_flight)
    }

    /// Snapshot of current depth for a single peer: `(object_count, byte_count)`.
    /// Returns `(0, 0)` if the peer is unknown.
    pub fn depth_for(&self, peer_pk: &[u8; 32]) -> (usize, usize) {
        let state = self.inner.lock().expect("outbound_queue poisoned");
        match state.peers.get(peer_pk) {
            Some(q) => (q.items.len(), q.bytes),
            None => (0, 0),
        }
    }

    /// Snapshot of the process-wide byte total across every per-peer
    /// queue. Useful as a sanity tripwire ("did we stay under the
    /// global cap?").
    pub fn total_bytes(&self) -> usize {
        let state = self.inner.lock().expect("outbound_queue poisoned");
        state.total_bytes
    }

    /// Tell the per-peer drain worker for `peer_pk` to exit at its next
    /// wake, then signal it so it does so promptly. Anything currently
    /// queued for that peer is discarded (admin de-peering deliberately
    /// drops pending sends — the §10.5 pull-backfill on re-peering is
    /// what restores convergence if the peer rejoins).
    ///
    /// No-op if the peer has no queue (no worker was ever spawned for
    /// it). Safe to call multiple times.
    pub fn drop_peer(&self, peer_pk: &[u8; 32]) {
        let wake = {
            let mut state = self.inner.lock().expect("outbound_queue poisoned");
            let Some(q) = state.peers.get_mut(peer_pk) else {
                return;
            };
            q.stopped = true;
            q.wake.clone()
        };
        wake.notify_one();
    }
}

// ---------------------------------------------------------------------------
// Drain worker
// ---------------------------------------------------------------------------

/// Spawn the long-lived per-peer drain worker. One per peer; runs
/// until [`OutboundQueues::drop_peer`] flips the per-queue `stopped`
/// flag (admin de-peering, peer-key rotation), at which point the
/// worker drops the queue entry and exits.
fn spawn_drain_worker(queues: Arc<OutboundQueues>, peer_pk: [u8; 32], wake: Arc<Notify>) {
    tokio::spawn(async move {
        let mut backoff_current = queues.config.backoff.initial;
        loop {
            // Outer wait: park until enqueue, backoff sleep, or
            // drop_peer wakes us.
            wake.notified().await;

            if check_and_remove_if_stopped(&queues, peer_pk) {
                return;
            }

            // Inner loop: keep draining batches as long as the HTTP
            // calls succeed; back out on transient failure or
            // drop_peer.
            loop {
                if check_and_remove_if_stopped(&queues, peer_pk) {
                    return;
                }
                let batch = take_batch(&queues, peer_pk);
                if batch.is_empty() {
                    // Queue is empty or only contained stale items;
                    // mark idle and break to outer wait.
                    mark_idle(&queues, peer_pk);
                    break;
                }

                // Sanity: all batch items share the same (path,
                // body_key). `take_batch` enforces this.
                let path = batch[0].path;
                let body_key = batch[0].body_key;
                let wires: Vec<&[u8]> = batch.iter().map(|i| i.wire_bytes.as_slice()).collect();
                let body = encode_batch_body(body_key, &wires);

                let outcome =
                    dispatch_one(&queues.transport, &queues.instance_key, peer_pk, path, body)
                        .await;

                match outcome {
                    DispatchOutcome::Success => {
                        // Pop the batch we drained (it was lifted out
                        // of the queue by `take_batch` already; nothing
                        // to do here). Reset backoff.
                        backoff_current = queues.config.backoff.initial;
                        // Continue inner loop — try to drain more.
                    }
                    DispatchOutcome::Terminal4xx(status) => {
                        // 4xx is terminal per §7.5: signature/class
                        // errors are not retryable. The batch is gone
                        // (we already removed it in take_batch); just
                        // log and try the next batch.
                        tracing::warn!(
                            peer = %PeerId::from_bytes(peer_pk),
                            status = %status,
                            dropped_objects = batch.len(),
                            "outbound peer returned 4xx, dropping batch",
                        );
                        backoff_current = queues.config.backoff.initial;
                    }
                    DispatchOutcome::Transient => {
                        // Put items back at the FRONT of the queue, in
                        // original order, and back off. The inner loop
                        // breaks; the outer wait re-arms us when either
                        // a new enqueue notifies us or the backoff
                        // sleep completes and notifies us.
                        requeue_front(&queues, peer_pk, batch);
                        mark_in_flight_false(&queues, peer_pk);

                        let jittered = jitter_full(backoff_current);
                        tracing::debug!(
                            peer = %PeerId::from_bytes(peer_pk),
                            backoff_ms = jittered.as_millis() as u64,
                            "outbound transient failure, backing off",
                        );

                        let wake_after = wake.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(jittered).await;
                            wake_after.notify_one();
                        });

                        backoff_current = std::cmp::min(
                            backoff_current.mul_f64(queues.config.backoff.multiplier),
                            queues.config.backoff.max,
                        );
                        break;
                    }
                }
            }
        }
    });
}

/// Drop the front of `peer_pk`'s queue into a batch of up to
/// `max_batch` items that share `(path, body_key)`. Also drops stale
/// items whose `enqueued_at` is older than `object_max_age` BEFORE
/// adding them to the batch (§7.5 staleness cap).
///
/// Marks `in_flight = true` if the returned batch is non-empty.
/// Returns an empty `Vec` if the queue is exhausted (or only contains
/// stale items) — caller is expected to call `mark_idle` and break.
fn take_batch(queues: &Arc<OutboundQueues>, peer_pk: [u8; 32]) -> Vec<QueuedObject> {
    let mut state = queues.inner.lock().expect("outbound_queue poisoned");
    let Some(q) = state.peers.get_mut(&peer_pk) else {
        return Vec::new();
    };

    let mut batch: Vec<QueuedObject> = Vec::new();
    let mut first_route: Option<(&'static str, &'static str)> = None;
    let mut stale_dropped = 0u64;
    let mut stale_bytes_total = 0usize;

    while batch.len() < queues.config.max_batch {
        let Some(front) = q.items.front() else { break };

        // Staleness check first: drop without ever adding to batch.
        if front.enqueued_at.elapsed() > queues.config.object_max_age {
            let stale = q.items.pop_front().expect("just peeked");
            let n = stale.wire_bytes.len();
            q.bytes = q.bytes.saturating_sub(n);
            stale_bytes_total += n;
            stale_dropped += 1;
            continue;
        }

        // Route check: end the batch if the next item targets a
        // different route. The caller starts a fresh batch on the
        // next iteration of the worker's inner loop.
        let this_route = (front.path, front.body_key);
        if let Some(route) = first_route {
            if route != this_route {
                break;
            }
        } else {
            first_route = Some(this_route);
        }

        let item = q.items.pop_front().expect("just peeked");
        q.bytes = q.bytes.saturating_sub(item.wire_bytes.len());
        batch.push(item);
    }

    if stale_dropped > 0 {
        state.total_bytes = state.total_bytes.saturating_sub(stale_bytes_total);
        tracing::debug!(
            peer = %PeerId::from_bytes(peer_pk),
            dropped_stale = stale_dropped,
            "dropped stale items past outbound_queue.object_max_age_secs",
        );
    }

    if batch.is_empty() {
        return batch;
    }

    // We're about to issue an HTTP call; subtract the batch bytes
    // from total_bytes only after the HTTP completes? No — they're
    // gone from the queue NOW. If the dispatch fails transiently and
    // we requeue, we re-add to both `q.bytes` and `state.total_bytes`.
    let batch_bytes: usize = batch.iter().map(|i| i.wire_bytes.len()).sum();
    state.total_bytes = state.total_bytes.saturating_sub(batch_bytes);

    // Re-borrow `q` after the `state.total_bytes` mutation.
    let q = state.peers.get_mut(&peer_pk).expect("entry exists");
    q.in_flight = true;
    batch
}

/// Restore a transient-failure batch to the front of the peer's queue
/// in its original order, and refund the bytes counters.
fn requeue_front(queues: &Arc<OutboundQueues>, peer_pk: [u8; 32], batch: Vec<QueuedObject>) {
    let mut state = queues.inner.lock().expect("outbound_queue poisoned");
    let Some(q) = state.peers.get_mut(&peer_pk) else {
        // Peer disappeared mid-flight (not possible in Phase 6.4 since
        // we never remove peer entries, but be defensive).
        return;
    };
    // Push back in REVERSE order using `push_front` so the original
    // order is preserved at the head.
    let mut refund: usize = 0;
    for item in batch.into_iter().rev() {
        refund += item.wire_bytes.len();
        q.items.push_front(item);
    }
    q.bytes += refund;
    state.total_bytes += refund;
}

/// Mark this peer's worker as no longer holding an in-flight request.
fn mark_in_flight_false(queues: &Arc<OutboundQueues>, peer_pk: [u8; 32]) {
    let mut state = queues.inner.lock().expect("outbound_queue poisoned");
    if let Some(q) = state.peers.get_mut(&peer_pk) {
        q.in_flight = false;
    }
}

/// Mark idle (empty + in_flight=false) and signal the global
/// idle_notify so `wait_idle` can pick it up.
fn mark_idle(queues: &Arc<OutboundQueues>, peer_pk: [u8; 32]) {
    let mut state = queues.inner.lock().expect("outbound_queue poisoned");
    if let Some(q) = state.peers.get_mut(&peer_pk) {
        q.in_flight = false;
    }
    drop(state);
    queues.idle_notify.notify_waiters();
}

/// If `peer_pk`'s queue has been marked `stopped` (by
/// [`OutboundQueues::drop_peer`]), refund its byte total to the
/// global counter, remove the entry, signal the global idle notify,
/// and return `true` so the caller knows to exit. Otherwise return
/// `false` and let the worker continue.
fn check_and_remove_if_stopped(queues: &Arc<OutboundQueues>, peer_pk: [u8; 32]) -> bool {
    let mut state = queues.inner.lock().expect("outbound_queue poisoned");
    let Some(q) = state.peers.get(&peer_pk) else {
        return true; // already removed
    };
    if !q.stopped {
        return false;
    }
    let bytes = q.bytes;
    state.peers.remove(&peer_pk);
    state.total_bytes = state.total_bytes.saturating_sub(bytes);
    drop(state);
    queues.idle_notify.notify_waiters();
    true
}

/// Full-jitter backoff: actual delay is `rand * current`, floored at
/// `max(current / 10, 1ms)`. See AWS "Exponential Backoff And Jitter"
/// (2015). With a `max` cap of e.g. 5 minutes this still tops out at
/// 5 minutes worst-case.
///
/// The floor matters because uniform `rand` can return very small
/// values: at `initial = 1s` a `rand = 1e-6` yields a 1µs sleep,
/// which is effectively a tight retry loop against a peer that just
/// returned a transient error. A 10%-of-current floor scales with the
/// backoff so even at the `test_fast` `initial = 10ms` setting tests
/// still see jittered values (range `[1ms, 10ms)`), and at the
/// production `initial = 1s` the floor lands at 100ms — small enough
/// to be invisible to humans but large enough to bound the worst-case
/// retry rate.
fn jitter_full(current: Duration) -> Duration {
    let r: f64 = rand::random::<f64>(); // uniform [0, 1)
    let scaled = current.as_secs_f64() * r;
    let dur = Duration::from_secs_f64(scaled.max(0.0));
    let floor = (current / 10).max(Duration::from_millis(1));
    dur.max(floor)
}

// ---------------------------------------------------------------------------
// HTTP dispatch
// ---------------------------------------------------------------------------

/// Outcome categories a single HTTP push can produce. Mirrors the
/// §7.5 "transient vs terminal" split.
enum DispatchOutcome {
    Success,
    /// 4xx response. Per §7.5 terminal — signature / class / format
    /// errors are not retryable.
    Terminal4xx(StatusCode),
    /// 5xx, 429, transport error, or `UnknownPeer` (which we treat as
    /// transient per the Phase 6.4 plan: the pull-backfill will heal
    /// anything truly lost, and a peer being temporarily missing from
    /// the registry should not poison the queue).
    Transient,
}

/// Build, sign, and dispatch one batched push to one downstream peer.
/// Returns the categorised outcome for the worker's match arm.
async fn dispatch_one(
    transport: &Arc<dyn FederationTransport>,
    instance_key: &Arc<InstanceKey>,
    peer_pk: [u8; 32],
    path: &'static str,
    body: Vec<u8>,
) -> DispatchOutcome {
    let header = sign_outbound(instance_key, peer_pk, &Method::POST, path, &body);
    let req = match Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(http::header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .header(AUTH_HEADER, header)
        .body(Bytes::from(body))
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "outbound queue: failed to build request");
            // Build errors are terminal at this layer — retrying the
            // exact same construction will fail the same way.
            return DispatchOutcome::Terminal4xx(StatusCode::BAD_REQUEST);
        }
    };

    let peer_id = PeerId::from_bytes(peer_pk);
    match transport.request(&peer_id, req).await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                DispatchOutcome::Success
            } else if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                tracing::warn!(
                    peer = %peer_id,
                    status = %status,
                    "outbound transient (5xx/429); will retry",
                );
                DispatchOutcome::Transient
            } else if status.is_client_error() {
                DispatchOutcome::Terminal4xx(status)
            } else {
                // 1xx / 3xx: redirects are blocked at the transport
                // layer; informational responses shouldn't reach this
                // branch in practice. Treat as transient so we don't
                // silently drop on protocol oddities.
                tracing::warn!(
                    peer = %peer_id,
                    status = %status,
                    "outbound unexpected status; treating as transient",
                );
                DispatchOutcome::Transient
            }
        }
        Err(e) => {
            tracing::warn!(peer = %peer_id, error = %e, "outbound transport error; will retry");
            DispatchOutcome::Transient
        }
    }
}

/// Encode a §9.1 / §10.1 push body wrapping N WireFormat blobs under
/// the given top-level key (`"edges"` or `"objects"`). N=1 reproduces
/// the previous `encode_singleton_body` shape byte-exactly.
fn encode_batch_body(key: &str, wires: &[&[u8]]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.to_vec())).collect();
    let body = Value::Map(vec![(Value::Text(key.into()), Value::Array(arr))]);
    let approx_cap: usize = 32 + wires.iter().map(|w| w.len() + 8).sum::<usize>();
    let mut buf = Vec::with_capacity(approx_cap);
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    buf
}

// ---------------------------------------------------------------------------
// Layer-0 tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::instance_key::InstanceKey;
    use std::collections::VecDeque;

    /// Stub transport that returns canned statuses. If `responses` is
    /// empty, defaults to 200 OK. Records each call's `(PeerId, body)`
    /// for assertions.
    #[allow(clippy::type_complexity)]
    struct StubTransport {
        responses: Arc<Mutex<VecDeque<StatusCode>>>,
        calls: Arc<Mutex<Vec<(PeerId, Vec<u8>)>>>,
    }

    impl StubTransport {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                responses: Arc::new(Mutex::new(VecDeque::new())),
                calls: Arc::new(Mutex::new(Vec::new())),
            })
        }

        fn push_response(&self, status: StatusCode) {
            self.responses.lock().unwrap().push_back(status);
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl FederationTransport for StubTransport {
        fn request<'a>(
            &'a self,
            target: &'a PeerId,
            request: Request<Bytes>,
        ) -> crate::federation::transport::TransportFuture<'a> {
            let target = *target;
            let calls = self.calls.clone();
            let responses = self.responses.clone();
            Box::pin(async move {
                let body = request.into_body().to_vec();
                calls.lock().unwrap().push((target, body));
                let status = responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(StatusCode::OK);
                let resp = http::Response::builder()
                    .status(status)
                    .body(Bytes::new())
                    .unwrap();
                Ok(resp)
            })
        }
    }

    fn test_instance_key() -> Arc<InstanceKey> {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut OsRng);
        Arc::new(InstanceKey::new(signing))
    }

    /// Build queues with the given config + a stub transport.
    fn build(config: OutboundQueueConfig) -> (Arc<OutboundQueues>, Arc<StubTransport>) {
        let transport = StubTransport::new();
        let key = test_instance_key();
        let q = OutboundQueues::new(config, transport.clone(), key);
        (q, transport)
    }

    #[tokio::test]
    async fn enqueue_within_caps_increases_depth() {
        let (q, transport) = build(OutboundQueueConfig {
            // Disable the worker draining by making transport always
            // fail-transient so the items stay queued? Simpler: drain
            // happens but the depth check fires before any wake gets
            // through. Use a peer whose worker we DO want to drain,
            // then wait_idle and confirm transport saw 3 calls.
            ..OutboundQueueConfig::test_fast()
        });
        let peer = [0x11u8; 32];
        q.enqueue(peer, "/federation/v1/content", "objects", vec![0xAA; 16]);
        q.enqueue(peer, "/federation/v1/content", "objects", vec![0xBB; 16]);
        q.enqueue(peer, "/federation/v1/content", "objects", vec![0xCC; 16]);

        // wait_idle: with default 200 stub responses, all three get
        // drained (potentially in one batch).
        assert!(q.wait_idle(Duration::from_secs(2)).await);
        assert_eq!(q.depth_for(&peer), (0, 0));
        assert_eq!(q.total_bytes(), 0);
        assert!(transport.call_count() >= 1);
    }

    #[tokio::test]
    async fn per_peer_byte_cap_drops_oldest() {
        // 100-byte per-peer cap; each item is 40 bytes. Three fit
        // (120 > 100, so only two fit). We push 5 → expect last two
        // to remain after caps fire on each enqueue.
        //
        // Wire it so the worker never actually drains: use a tiny
        // backoff but immediately stop the transport from succeeding
        // by feeding it 503s in front of the queue. Simpler:
        // we don't care if the worker drains them — we observe the
        // CALLS recorded by the transport in their original order.
        //
        // Approach: use a peer that is unknown to the transport.
        // StubTransport accepts any peer ID, so we instead inspect
        // depth BEFORE any drain by using a transport that holds on
        // a never-resolving await. Too complex — use a transport that
        // returns 503 forever so items stay queued.
        let (q, transport) = build(OutboundQueueConfig {
            bytes_per_peer: 100,
            ..OutboundQueueConfig::test_fast()
        });
        // Feed many 503s so nothing actually leaves.
        for _ in 0..50 {
            transport.push_response(StatusCode::SERVICE_UNAVAILABLE);
        }
        let peer = [0x22u8; 32];
        for i in 0..5u8 {
            q.enqueue(peer, "/federation/v1/content", "objects", vec![i; 40]);
        }
        // Give the worker a moment to attempt and re-queue.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (n, b) = q.depth_for(&peer);
        assert!(n <= 5, "depth must be bounded under cap (n={n})");
        // The per-peer byte cap is 100; should not exceed by more than
        // one object's worth (the new enqueue is allowed first then
        // older drops). We assert the cap holds within one object.
        assert!(b <= 100, "per-peer bytes must be <= cap: got {b}",);
    }

    #[tokio::test]
    async fn per_peer_object_cap_drops_oldest() {
        let (q, transport) = build(OutboundQueueConfig {
            objects_per_peer: 3,
            ..OutboundQueueConfig::test_fast()
        });
        for _ in 0..50 {
            transport.push_response(StatusCode::SERVICE_UNAVAILABLE);
        }
        let peer = [0x33u8; 32];
        for i in 0..5u8 {
            q.enqueue(peer, "/federation/v1/content", "objects", vec![i; 8]);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (n, _) = q.depth_for(&peer);
        assert!(n <= 3, "object cap must hold: got {n}");
    }

    #[tokio::test]
    async fn global_byte_cap_evicts_from_largest_peer() {
        // total=1024, per_peer=900. Enqueue 800B to peer A (under
        // both caps). Then enqueue 400B to peer B → total would be
        // 1200 > 1024, so evict from largest peer (A).
        let (q, transport) = build(OutboundQueueConfig {
            total_bytes: 1024,
            bytes_per_peer: 900,
            objects_per_peer: 100,
            ..OutboundQueueConfig::test_fast()
        });
        for _ in 0..50 {
            transport.push_response(StatusCode::SERVICE_UNAVAILABLE);
        }
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        q.enqueue(a, "/federation/v1/content", "objects", vec![0; 800]);
        // Give the worker a chance to take and re-queue the A item.
        tokio::time::sleep(Duration::from_millis(5)).await;
        q.enqueue(b, "/federation/v1/content", "objects", vec![0; 400]);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (a_n, a_b) = q.depth_for(&a);
        let (b_n, b_b) = q.depth_for(&b);
        assert!(
            q.total_bytes() <= 1024,
            "global cap must hold: got {} (a={a_b}, b={b_b})",
            q.total_bytes(),
        );
        // B's new object survived (it was just enqueued and is at
        // most 400B, fits trivially).
        assert!(b_n >= 1, "peer B should retain its newest object");
        // A's queue shrank (it was the largest at the moment of
        // global-cap pressure).
        assert!(
            a_b < 800 || a_n == 0,
            "peer A's queue should have shrunk under global pressure: a_n={a_n}, a_b={a_b}",
        );
    }

    #[tokio::test]
    async fn stale_items_dropped_on_drain() {
        // Force the dispatcher into transient-failure mode so the
        // worker enters its backoff path. While the worker is asleep
        // the items pass `object_max_age`; on the next wake
        // `take_batch` drops them as stale before any further egress.
        let (q, transport) = build(OutboundQueueConfig {
            object_max_age: Duration::from_millis(30),
            backoff: BackoffPolicy {
                initial: Duration::from_millis(80),
                max: Duration::from_millis(80),
                multiplier: 1.0,
            },
            ..OutboundQueueConfig::test_fast()
        });
        // First attempt: 503 → worker re-queues + backs off ~80ms.
        transport.push_response(StatusCode::SERVICE_UNAVAILABLE);
        // If the worker wakes again before items go stale, the next
        // call is also 503; either way, eventually staleness fires.
        for _ in 0..10 {
            transport.push_response(StatusCode::SERVICE_UNAVAILABLE);
        }

        let peer = [0x44u8; 32];
        q.enqueue(peer, "/federation/v1/content", "objects", vec![0; 16]);
        q.enqueue(peer, "/federation/v1/content", "objects", vec![0; 16]);

        assert!(q.wait_idle(Duration::from_secs(2)).await);
        assert_eq!(q.depth_for(&peer), (0, 0));
        // Pure-stale guarantee is hard with the current architecture
        // (the worker may have made one failed attempt before the
        // items aged out). The load-bearing assertion is that the
        // queue ends up empty even though no successful response was
        // ever provided — staleness MUST have fired. We bound the
        // call count to "no more than a handful" as the tripwire that
        // staleness short-circuits the retry loop.
        assert!(
            transport.call_count() <= 3,
            "stale items must short-circuit retries: got {} calls",
            transport.call_count(),
        );
    }

    #[tokio::test]
    async fn backoff_grows_until_success() {
        let (q, transport) = build(OutboundQueueConfig {
            backoff: BackoffPolicy {
                initial: Duration::from_millis(1),
                max: Duration::from_millis(20),
                multiplier: 2.0,
            },
            ..OutboundQueueConfig::test_fast()
        });
        // 3 failures then success.
        transport.push_response(StatusCode::SERVICE_UNAVAILABLE);
        transport.push_response(StatusCode::SERVICE_UNAVAILABLE);
        transport.push_response(StatusCode::SERVICE_UNAVAILABLE);
        transport.push_response(StatusCode::OK);
        let peer = [0x55u8; 32];
        q.enqueue(peer, "/federation/v1/content", "objects", vec![0xEE; 8]);
        assert!(q.wait_idle(Duration::from_secs(2)).await);
        assert!(
            transport.call_count() >= 4,
            "should retry at least 3 times before succeeding: got {}",
            transport.call_count(),
        );
        assert_eq!(q.depth_for(&peer), (0, 0));
    }

    #[tokio::test]
    async fn four_xx_is_terminal() {
        let (q, transport) = build(OutboundQueueConfig::test_fast());
        transport.push_response(StatusCode::BAD_REQUEST);
        // Subsequent calls (if any) would return 200 — we assert
        // there are no subsequent calls.
        let peer = [0x66u8; 32];
        q.enqueue(peer, "/federation/v1/content", "objects", vec![0xFF; 8]);
        assert!(q.wait_idle(Duration::from_secs(2)).await);
        assert_eq!(q.depth_for(&peer), (0, 0));
        assert_eq!(
            transport.call_count(),
            1,
            "4xx should drop the batch after exactly one attempt",
        );
    }

    #[test]
    fn encode_batch_body_round_trips() {
        let wires: Vec<&[u8]> = vec![b"alpha", b"beta", b"gamma"];
        let body = encode_batch_body("objects", &wires);
        let v: Value = ciborium::de::from_reader(body.as_slice()).expect("cbor");
        let Value::Map(m) = v else {
            panic!("not a map");
        };
        let arr = m
            .into_iter()
            .find_map(|(k, v)| match k {
                Value::Text(t) if t == "objects" => Some(v),
                _ => None,
            })
            .expect("objects key");
        let Value::Array(a) = arr else {
            panic!("not array");
        };
        assert_eq!(a.len(), 3);
    }
}
