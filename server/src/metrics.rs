//! In-process metrics collection for the admin dashboard.
//!
//! A small `Metrics` struct is hung off `AppState` and consumed by
//! `admin_overview` / `admin_routes`. Counters are atomics where
//! unwindowed (BFS hit/miss) and bucketed under a mutex where
//! windowed (per-route 24h rolling stats). Histograms are fixed-size
//! ring buffers of timestamped samples; quantiles are computed on
//! read.
//!
//! See `docs/metrics.md` for the design rationale — why this lives in
//! process rather than via Prometheus or the `metrics` crate facade.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, Utc};

/// Max samples retained per histogram. 1024 is plenty for p50/p95/p99
/// at the sample rates we see (graph builds ≤ every 30s; per-route
/// latency samples cap at 1024 most-recent regardless of rate).
const HISTOGRAM_CAPACITY: usize = 1024;

/// Length of the per-route rolling window, in hours.
const ROLLING_WINDOW_HOURS: u64 = 24;

const MS_PER_HOUR: u64 = 60 * 60 * 1000;

/// Wall-clock "now" in milliseconds since Unix epoch. Isolated here
/// so tests can bypass it via the `_at` methods.
fn now_ms() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}

/// Shared metrics handle. Held as `Arc<Metrics>` on `AppState` so
/// handlers and background tasks can record without locking anything
/// they don't strictly need to.
pub struct Metrics {
    /// BFS forward-cache (distance_map) hit counter.
    pub bfs_forward_hits: AtomicU64,
    /// BFS forward-cache (distance_map) miss counter.
    pub bfs_forward_misses: AtomicU64,
    /// BFS reverse-cache (reverse_score_map) hit counter.
    pub bfs_reverse_hits: AtomicU64,
    /// BFS reverse-cache (reverse_score_map) miss counter.
    pub bfs_reverse_misses: AtomicU64,

    /// Recent graph-build durations, in milliseconds.
    graph_load_ms: Mutex<RingHistogram>,

    /// Timestamp of the last successful trust graph swap, or `None`
    /// if a rebuild has not yet succeeded.
    last_rebuild_at: RwLock<Option<DateTime<Utc>>>,

    /// Per-route request stats keyed by `(method, matched_path)`.
    /// Populated by the route-metrics middleware; cardinality is
    /// bounded by the number of routes registered at startup, so
    /// there's no unbounded growth risk from user-supplied URLs.
    routes: RwLock<HashMap<RouteKey, Arc<RouteStats>>>,

    /// Rolling 24h count of failed WebAuthn authentication ceremonies
    /// (credential verification failed or the challenge ID was
    /// invalid). Recorded from the auth handlers and surfaced on the
    /// admin overview.
    failed_auth: HourlyCounter,
}

/// Key identifying a route for metrics aggregation. We key on the
/// *matched* path template (`/api/threads/{id}`, not
/// `/api/threads/3e5a…`) so per-route stats don't explode with URL
/// parameters.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct RouteKey {
    /// HTTP method (`"GET"`, `"POST"`, …).
    pub method: String,
    /// Matched path template, e.g. `/api/threads/{id}`.
    pub path: String,
}

/// One hour's worth of per-route counters. A bucket is "fresh" if its
/// `hour` tag is within `ROLLING_WINDOW_HOURS` of the current clock
/// hour; stale buckets are logically empty and get reset on next use.
#[derive(Clone, Copy, Default)]
struct HourBucket {
    /// Hour-of-epoch this bucket belongs to, or `None` if the slot
    /// has never been written.
    hour: Option<u64>,
    total: u64,
    success: u64,
    client_error: u64,
    server_error: u64,
}

#[derive(Default, Clone, Copy)]
struct Counters {
    total: u64,
    success: u64,
    client_error: u64,
    server_error: u64,
}

/// Response class for a single request's status code.
enum StatusClass {
    Success,
    ClientError,
    ServerError,
}

fn classify(status: u16) -> StatusClass {
    match status {
        200..=399 => StatusClass::Success,
        400..=499 => StatusClass::ClientError,
        _ => StatusClass::ServerError,
    }
}

/// Per-route stats. All mutation goes through a single mutex — at the
/// traffic rates we realistically see on a self-hosted instance the
/// critical section is a few atomic adds and a VecDeque push, so
/// contention cost is in the noise.
struct RouteStats {
    inner: Mutex<RouteStatsInner>,
}

struct RouteStatsInner {
    /// 24 hourly buckets indexed by `hour_of_epoch % 24`. A write
    /// rotates the slot if its tag is stale.
    buckets: [HourBucket; ROLLING_WINDOW_HOURS as usize],
    /// All-time counters — never reset.
    cumulative: Counters,
    /// Timestamped latency samples; `quantile_since` filters to the
    /// 24h window on read.
    latency_ms: RingHistogram,
}

impl RouteStats {
    fn new() -> Self {
        Self {
            inner: Mutex::new(RouteStatsInner {
                buckets: [HourBucket::default(); ROLLING_WINDOW_HOURS as usize],
                cumulative: Counters::default(),
                latency_ms: RingHistogram::new(HISTOGRAM_CAPACITY),
            }),
        }
    }

    fn record_at(&self, status: u16, latency_ms: f64, now_ms: u64) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let now_hour = now_ms / MS_PER_HOUR;
        let slot = (now_hour % ROLLING_WINDOW_HOURS) as usize;

        // Rotate the slot if it's carrying stats from a previous day.
        if inner.buckets[slot].hour != Some(now_hour) {
            inner.buckets[slot] = HourBucket {
                hour: Some(now_hour),
                ..HourBucket::default()
            };
        }

        let cls = classify(status);
        inner.buckets[slot].total += 1;
        inner.cumulative.total += 1;
        match cls {
            StatusClass::Success => {
                inner.buckets[slot].success += 1;
                inner.cumulative.success += 1;
            }
            StatusClass::ClientError => {
                inner.buckets[slot].client_error += 1;
                inner.cumulative.client_error += 1;
            }
            StatusClass::ServerError => {
                inner.buckets[slot].server_error += 1;
                inner.cumulative.server_error += 1;
            }
        }

        inner.latency_ms.push(now_ms, latency_ms);
    }

    fn snapshot_at(&self, key: &RouteKey, now_ms: u64) -> RouteSnapshot {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => {
                return RouteSnapshot::empty(key);
            }
        };
        let now_hour = now_ms / MS_PER_HOUR;
        // Sum only the buckets whose hour tag is within the window.
        let mut window = Counters::default();
        for b in &inner.buckets {
            if let Some(h) = b.hour
                && now_hour.saturating_sub(h) < ROLLING_WINDOW_HOURS
            {
                window.total += b.total;
                window.success += b.success;
                window.client_error += b.client_error;
                window.server_error += b.server_error;
            }
        }

        let cutoff_ms = now_ms.saturating_sub(ROLLING_WINDOW_HOURS * MS_PER_HOUR);
        let p50 = inner.latency_ms.quantile_since(0.50, cutoff_ms);
        let p95 = inner.latency_ms.quantile_since(0.95, cutoff_ms);
        let p99 = inner.latency_ms.quantile_since(0.99, cutoff_ms);

        RouteSnapshot {
            method: key.method.clone(),
            path: key.path.clone(),
            total_24h: window.total,
            success_24h: window.success,
            client_error_24h: window.client_error,
            server_error_24h: window.server_error,
            latency_ms_p50_24h: p50,
            latency_ms_p95_24h: p95,
            latency_ms_p99_24h: p99,
            total_all: inner.cumulative.total,
            success_all: inner.cumulative.success,
            client_error_all: inner.cumulative.client_error,
            server_error_all: inner.cumulative.server_error,
        }
    }
}

impl Metrics {
    /// Construct a fresh `Metrics` with all counters zeroed and no
    /// route buckets allocated yet. Route buckets are added lazily on
    /// first request through each route.
    pub fn new() -> Self {
        Self {
            bfs_forward_hits: AtomicU64::new(0),
            bfs_forward_misses: AtomicU64::new(0),
            bfs_reverse_hits: AtomicU64::new(0),
            bfs_reverse_misses: AtomicU64::new(0),
            graph_load_ms: Mutex::new(RingHistogram::new(HISTOGRAM_CAPACITY)),
            last_rebuild_at: RwLock::new(None),
            routes: RwLock::new(HashMap::new()),
            failed_auth: HourlyCounter::new(),
        }
    }

    /// Increment the BFS forward-cache hit counter.
    pub fn record_bfs_forward_hit(&self) {
        self.bfs_forward_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the BFS forward-cache miss counter.
    pub fn record_bfs_forward_miss(&self) {
        self.bfs_forward_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the BFS reverse-cache hit counter.
    pub fn record_bfs_reverse_hit(&self) {
        self.bfs_reverse_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the BFS reverse-cache miss counter.
    pub fn record_bfs_reverse_miss(&self) {
        self.bfs_reverse_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a graph-build duration.
    pub fn record_graph_load_ms(&self, ms: f64) {
        if let Ok(mut h) = self.graph_load_ms.lock() {
            h.push(now_ms(), ms);
        }
    }

    /// Reset BFS hit/miss counters. Called on graph rebuild: the BFS
    /// caches are tied to a specific `TrustGraph` instance, so old
    /// counts don't apply to the new graph. The `last_rebuild_at`
    /// timestamp gives the window the current counts cover.
    pub fn reset_bfs_counters(&self) {
        self.bfs_forward_hits.store(0, Ordering::Relaxed);
        self.bfs_forward_misses.store(0, Ordering::Relaxed);
        self.bfs_reverse_hits.store(0, Ordering::Relaxed);
        self.bfs_reverse_misses.store(0, Ordering::Relaxed);
    }

    /// Record the timestamp of the most recent successful trust graph
    /// swap. Surfaced on the admin overview as `last_rebuild_at`.
    pub fn set_last_rebuild(&self, at: DateTime<Utc>) {
        if let Ok(mut slot) = self.last_rebuild_at.write() {
            *slot = Some(at);
        }
    }

    /// Record one failed WebAuthn authentication ceremony (credential
    /// verification failed, or the challenge ID was invalid).
    pub fn record_failed_auth(&self) {
        self.failed_auth.record_at(now_ms());
    }

    /// Count of failed WebAuthn authentication ceremonies in the last
    /// [`ROLLING_WINDOW_HOURS`] hours.
    pub fn failed_auth_count_24h(&self) -> u64 {
        self.failed_auth.count_24h_at(now_ms())
    }

    /// Record one request's outcome against its route template.
    ///
    /// `path` should be the matched path pattern
    /// (e.g. `/api/threads/{id}`), not the raw URL. If the request
    /// didn't match any route, pass a stable sentinel like
    /// `"<unmatched>"` so the stat bucket stays bounded.
    pub fn record_request(&self, method: &str, path: &str, status: u16, latency_ms: f64) {
        self.record_request_at(method, path, status, latency_ms, now_ms());
    }

    /// Same as `record_request` but with an explicit clock — used by
    /// tests to drive the windowing logic deterministically.
    fn record_request_at(
        &self,
        method: &str,
        path: &str,
        status: u16,
        latency_ms: f64,
        now_ms: u64,
    ) {
        let key = RouteKey {
            method: method.to_string(),
            path: path.to_string(),
        };
        // Fast path: try to reuse the existing entry under a read lock.
        if let Ok(map) = self.routes.read()
            && let Some(stats) = map.get(&key)
        {
            stats.record_at(status, latency_ms, now_ms);
            return;
        }
        // Slow path: first request for this route — insert, then record.
        let stats = if let Ok(mut map) = self.routes.write() {
            map.entry(key)
                .or_insert_with(|| Arc::new(RouteStats::new()))
                .clone()
        } else {
            return;
        };
        stats.record_at(status, latency_ms, now_ms);
    }

    /// Snapshot of per-route stats, sorted by 24h request count desc.
    pub fn route_snapshot(&self) -> Vec<RouteSnapshot> {
        self.route_snapshot_at(now_ms())
    }

    fn route_snapshot_at(&self, now_ms: u64) -> Vec<RouteSnapshot> {
        let Ok(map) = self.routes.read() else {
            return Vec::new();
        };
        let mut out: Vec<RouteSnapshot> = map
            .iter()
            .map(|(key, stats)| stats.snapshot_at(key, now_ms))
            .collect();
        out.sort_by(|a, b| b.total_24h.cmp(&a.total_24h));
        out
    }

    /// Snapshot: capture an immutable view for the admin overview.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let fwd_hits = self.bfs_forward_hits.load(Ordering::Relaxed);
        let fwd_misses = self.bfs_forward_misses.load(Ordering::Relaxed);
        let rev_hits = self.bfs_reverse_hits.load(Ordering::Relaxed);
        let rev_misses = self.bfs_reverse_misses.load(Ordering::Relaxed);

        let total_hits = fwd_hits + rev_hits;
        let total = total_hits + fwd_misses + rev_misses;
        let hit_rate = if total == 0 {
            None
        } else {
            Some(total_hits as f64 / total as f64)
        };

        let (p50, p95, p99) = self
            .graph_load_ms
            .lock()
            .ok()
            .map(|h| (h.quantile(0.50), h.quantile(0.95), h.quantile(0.99)))
            .unwrap_or((None, None, None));

        let last_rebuild_at = self.last_rebuild_at.read().ok().and_then(|g| *g);

        MetricsSnapshot {
            bfs_hit_rate: hit_rate,
            bfs_total_lookups: total,
            graph_load_ms_p50: p50,
            graph_load_ms_p95: p95,
            graph_load_ms_p99: p99,
            last_rebuild_at,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot captured from a `Metrics` instance. All fields are
/// already-computed values safe to serialize to the admin API.
pub struct MetricsSnapshot {
    /// BFS cache hit rate across both forward and reverse lookups, in
    /// `[0, 1]`, or `None` if no lookups have happened yet.
    pub bfs_hit_rate: Option<f64>,
    /// Total lookups (hits + misses) in the current rebuild window.
    pub bfs_total_lookups: u64,
    pub graph_load_ms_p50: Option<f64>,
    pub graph_load_ms_p95: Option<f64>,
    pub graph_load_ms_p99: Option<f64>,
    pub last_rebuild_at: Option<DateTime<Utc>>,
}

/// Per-route stats captured in a snapshot. Two scopes of counter:
/// `_24h` is the rolling last-24h window (primary admin view); `_all`
/// is cumulative since process start (secondary — "has this route
/// ever been hit?").
///
/// Latency quantiles are only reported for the 24h window — the
/// underlying ring buffer has bounded capacity so "all-time" latency
/// doesn't have a meaningful definition here.
pub struct RouteSnapshot {
    pub method: String,
    pub path: String,

    pub total_24h: u64,
    pub success_24h: u64,
    pub client_error_24h: u64,
    pub server_error_24h: u64,
    pub latency_ms_p50_24h: Option<f64>,
    pub latency_ms_p95_24h: Option<f64>,
    pub latency_ms_p99_24h: Option<f64>,

    pub total_all: u64,
    pub success_all: u64,
    pub client_error_all: u64,
    pub server_error_all: u64,
}

impl RouteSnapshot {
    fn empty(key: &RouteKey) -> Self {
        Self {
            method: key.method.clone(),
            path: key.path.clone(),
            total_24h: 0,
            success_24h: 0,
            client_error_24h: 0,
            server_error_24h: 0,
            latency_ms_p50_24h: None,
            latency_ms_p95_24h: None,
            latency_ms_p99_24h: None,
            total_all: 0,
            success_all: 0,
            client_error_all: 0,
            server_error_all: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Rolling 24h counter
// ---------------------------------------------------------------------------

/// One hour's worth of a plain event count.
#[derive(Clone, Copy, Default)]
struct HourlyBucket {
    /// Hour-of-epoch this bucket belongs to, or `None` if unused.
    hour: Option<u64>,
    count: u64,
}

/// Rolling 24h event counter. Unlike `RouteStats` this keeps no
/// latency or status breakdown — just a count per hour — and is used
/// for lightweight signals like failed auth ceremonies.
struct HourlyCounter {
    buckets: Mutex<[HourlyBucket; ROLLING_WINDOW_HOURS as usize]>,
}

impl HourlyCounter {
    fn new() -> Self {
        Self {
            buckets: Mutex::new([HourlyBucket::default(); ROLLING_WINDOW_HOURS as usize]),
        }
    }

    fn record_at(&self, now_ms: u64) {
        let Ok(mut buckets) = self.buckets.lock() else {
            return;
        };
        let now_hour = now_ms / MS_PER_HOUR;
        let slot = (now_hour % ROLLING_WINDOW_HOURS) as usize;
        if buckets[slot].hour != Some(now_hour) {
            buckets[slot] = HourlyBucket {
                hour: Some(now_hour),
                count: 0,
            };
        }
        buckets[slot].count += 1;
    }

    fn count_24h_at(&self, now_ms: u64) -> u64 {
        let Ok(buckets) = self.buckets.lock() else {
            return 0;
        };
        let now_hour = now_ms / MS_PER_HOUR;
        let mut total = 0u64;
        for b in buckets.iter() {
            if let Some(h) = b.hour
                && now_hour.saturating_sub(h) < ROLLING_WINDOW_HOURS
            {
                total += b.count;
            }
        }
        total
    }
}

// ---------------------------------------------------------------------------
// Ring-buffer histogram
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct TimedSample {
    at_ms: u64,
    value: f64,
}

/// Fixed-capacity ring buffer of timestamped samples. Once full, the
/// oldest sample is dropped on each push. Quantiles are computed by
/// sorting a copy; cheap at the sizes we use.
///
/// Timestamps are stored so callers can filter by time on read
/// (`quantile_since`) without losing the all-samples case (`quantile`).
struct RingHistogram {
    samples: VecDeque<TimedSample>,
    capacity: usize,
}

impl RingHistogram {
    fn new(capacity: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, at_ms: u64, value: f64) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(TimedSample { at_ms, value });
    }

    /// Approximate quantile via nearest-rank on a sorted copy.
    ///
    /// `q` is clamped to `[0, 1]`. Returns `None` if no samples exist.
    fn quantile(&self, q: f64) -> Option<f64> {
        quantile_of(self.samples.iter().map(|s| s.value), q)
    }

    /// Approximate quantile restricted to samples with `at_ms >= since_ms`.
    fn quantile_since(&self, q: f64, since_ms: u64) -> Option<f64> {
        quantile_of(
            self.samples
                .iter()
                .filter(|s| s.at_ms >= since_ms)
                .map(|s| s.value),
            q,
        )
    }
}

fn quantile_of(values: impl Iterator<Item = f64>, q: f64) -> Option<f64> {
    let mut sorted: Vec<f64> = values.collect();
    if sorted.is_empty() {
        return None;
    }
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let q = q.clamp(0.0, 1.0);
    let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    Some(sorted[idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_histogram_quantiles_on_small_sample() {
        let mut h = RingHistogram::new(10);
        for v in [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0] {
            h.push(0, v);
        }
        // Nearest-rank p50 on 10 samples: idx = round(9 * 0.5) = 5 → 60.0
        assert_eq!(h.quantile(0.50), Some(60.0));
        assert_eq!(h.quantile(0.95), Some(100.0));
        assert_eq!(h.quantile(0.0), Some(10.0));
        assert_eq!(h.quantile(1.0), Some(100.0));
    }

    #[test]
    fn ring_histogram_drops_oldest_when_full() {
        let mut h = RingHistogram::new(3);
        h.push(0, 1.0);
        h.push(0, 2.0);
        h.push(0, 3.0);
        h.push(0, 4.0);
        assert_eq!(h.samples.len(), 3);
        // 1.0 was dropped, so min is 2.0
        assert_eq!(h.quantile(0.0), Some(2.0));
        assert_eq!(h.quantile(1.0), Some(4.0));
    }

    #[test]
    fn ring_histogram_quantile_since_filters_old_samples() {
        let mut h = RingHistogram::new(100);
        h.push(100, 1.0);
        h.push(200, 2.0);
        h.push(300, 3.0);
        // Samples at or after t=200 → {2, 3}. p50 of 2 samples: idx=round(1*0.5)=1 → 3.0
        assert_eq!(h.quantile_since(0.5, 200), Some(3.0));
        // Cut-off after all samples → None
        assert_eq!(h.quantile_since(0.5, 400), None);
        // Cut-off before all → same as quantile()
        assert_eq!(h.quantile_since(0.5, 0), h.quantile(0.5));
    }

    #[test]
    fn empty_histogram_returns_none() {
        let h = RingHistogram::new(10);
        assert_eq!(h.quantile(0.5), None);
    }

    #[test]
    fn metrics_hit_rate_none_when_no_lookups() {
        let m = Metrics::new();
        assert_eq!(m.snapshot().bfs_hit_rate, None);
    }

    #[test]
    fn metrics_hit_rate_combines_forward_and_reverse() {
        let m = Metrics::new();
        m.record_bfs_forward_hit();
        m.record_bfs_forward_hit();
        m.record_bfs_forward_miss();
        m.record_bfs_reverse_hit();
        m.record_bfs_reverse_miss();
        // 3 hits / 5 total
        let snap = m.snapshot();
        assert_eq!(snap.bfs_hit_rate, Some(0.6));
        assert_eq!(snap.bfs_total_lookups, 5);
    }

    // ---- Route windowing ----

    /// Pick a base time in the current epoch so the test reads like a
    /// real-world timeline. With `HourBucket.hour` now `Option<u64>`,
    /// there's no sentinel collision to avoid — any fixed timestamp
    /// would do.
    const T0: u64 = 1_700_000_000_000; // 2023-11-14, any modern time

    #[test]
    fn record_request_counts_both_window_and_cumulative() {
        let m = Metrics::new();
        m.record_request_at("GET", "/a", 200, 5.0, T0);
        m.record_request_at("GET", "/a", 500, 25.0, T0);
        m.record_request_at("POST", "/b", 404, 10.0, T0);

        let snap = m.route_snapshot_at(T0);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].path, "/a");
        assert_eq!(snap[0].total_24h, 2);
        assert_eq!(snap[0].success_24h, 1);
        assert_eq!(snap[0].server_error_24h, 1);
        assert_eq!(snap[0].total_all, 2);
        assert_eq!(snap[1].path, "/b");
        assert_eq!(snap[1].client_error_24h, 1);
        assert_eq!(snap[1].client_error_all, 1);
    }

    #[test]
    fn window_drops_samples_older_than_24h() {
        let m = Metrics::new();
        // Old hit at T0, new hit ~25h later.
        m.record_request_at("GET", "/a", 200, 5.0, T0);
        let later = T0 + 25 * MS_PER_HOUR;
        m.record_request_at("GET", "/a", 200, 7.0, later);

        let snap = m.route_snapshot_at(later);
        assert_eq!(snap.len(), 1);
        // Only the recent hit counts toward the 24h window...
        assert_eq!(snap[0].total_24h, 1);
        // ...but the cumulative view has both.
        assert_eq!(snap[0].total_all, 2);
        // Latency p50 for the window is the recent sample.
        assert_eq!(snap[0].latency_ms_p50_24h, Some(7.0));
    }

    #[test]
    fn window_retains_samples_within_24h_even_across_hour_rollover() {
        let m = Metrics::new();
        // Sample at T0, another 23h later — both within the window
        // from the perspective of "now = T0 + 23h".
        m.record_request_at("GET", "/a", 200, 5.0, T0);
        let later = T0 + 23 * MS_PER_HOUR;
        m.record_request_at("GET", "/a", 200, 7.0, later);

        let snap = m.route_snapshot_at(later);
        assert_eq!(snap[0].total_24h, 2);
    }

    #[test]
    fn same_slot_reused_after_24h_does_not_leak_old_counts() {
        // A request at hour H and another at hour H+24 both map to
        // bucket index H % 24; the later write must rotate, not
        // accumulate on top of the stale value.
        let m = Metrics::new();
        m.record_request_at("GET", "/a", 200, 5.0, T0);
        let later = T0 + 24 * MS_PER_HOUR;
        m.record_request_at("GET", "/a", 500, 7.0, later);

        let snap = m.route_snapshot_at(later);
        // The old success is gone from the window; only the new 500 counts.
        assert_eq!(snap[0].total_24h, 1);
        assert_eq!(snap[0].success_24h, 0);
        assert_eq!(snap[0].server_error_24h, 1);
        // Cumulative still has both.
        assert_eq!(snap[0].total_all, 2);
    }

    #[test]
    fn failed_auth_counter_windows_24h() {
        let c = HourlyCounter::new();
        // Three events at T0, one 23h later → all within the window.
        c.record_at(T0);
        c.record_at(T0);
        c.record_at(T0);
        let later = T0 + 23 * MS_PER_HOUR;
        c.record_at(later);
        assert_eq!(c.count_24h_at(later), 4);

        // Jump 25h past the original T0 — the three old events fall out
        // of the window, only the later event remains.
        let much_later = T0 + 25 * MS_PER_HOUR;
        assert_eq!(c.count_24h_at(much_later), 1);
    }

    #[test]
    fn reset_bfs_counters_clears_only_counters() {
        let m = Metrics::new();
        m.record_bfs_forward_hit();
        m.record_graph_load_ms(42.0);
        m.reset_bfs_counters();
        let snap = m.snapshot();
        assert_eq!(snap.bfs_hit_rate, None);
        // Graph load histogram was not cleared
        assert_eq!(snap.graph_load_ms_p50, Some(42.0));
    }
}
