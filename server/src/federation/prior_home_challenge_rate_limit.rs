//! §14.3 receiver-side rate limits for
//! `POST /federation/v1/prior-home/challenge`.
//!
//! Two parallel per-minute counters gate the challenge-issuance step:
//!
//! - `PRIOR_HOME_CHALLENGE_RPM_PER_IP = 60` — per source IP. The
//!   cheap pre-verification belt-and-suspenders called out in
//!   `docs/federation-protocol.md` §14.3 ("limited by source IP as a
//!   pre-verification belt-and-suspenders"). Caps Ed25519 *signing*
//!   load from any single network-layer origin, including a
//!   misbehaving but envelope-authenticated peer.
//! - `PRIOR_HOME_CHALLENGE_RPM_PER_KEY = 10` — per subject key K
//!   (the body's `key` field, after curve validation). Spec-table
//!   "Post-verification cap on issued-and-redeemed challenges per K."
//!   Burns budget *only* on a K that passed `is_valid_pubkey`, so an
//!   attacker spamming garbage K values can't deplete this counter.
//!
//! ## Pairing with the §14.3 daily limiter
//!
//! Distinct from the §14.3 `PRIOR_HOME_PROBES_PER_DAY_PER_KEY` budget
//! ([`crate::federation::prior_home_rate_limit::PriorHomeRateLimiter`]):
//!
//! - This module's two counters fire at the *challenge-issuance*
//!   endpoint, before the receiver has spent any Ed25519 signing
//!   effort. Budget window: 60 seconds.
//! - The daily limiter fires at *redeem* time (probe + the §14.5 /
//!   §14.6 bulk-fetch endpoints), after the §14.1 verification has
//!   established a real, captured-key-backed `subject_key`. Budget
//!   window: 24 hours, shared across the three serve endpoints.
//!
//! A handshake that successfully issues a challenge but then fails to
//! redeem still pays the per-minute issuance cost; it does not consume
//! the daily probe budget.
//!
//! ## Semantics
//!
//! Fixed-window per key — same shape as the sibling §10.6 / §10.5.5 /
//! §14.3 limiters. Each (IP|subject_key) carries a `(window_start,
//! count)`; the count rolls when the window expires. Overflow returns
//! `429 Too Many Requests` with `Retry-After: 60` per §14.3, via
//! [`prior_home_challenge_too_many_requests`].
//!
//! Fixed-window (not sliding) for the same reason the other federation
//! limiters use it: one `(ts, u32)` per key is cheaper than a
//! per-request timestamp ring, and the worst-case "burst at rollover"
//! is bounded by `2 * cap` across two adjacent windows — well under
//! enumeration-shape volumes for a 60 / 10 RPM cap.
//!
//! ## State lifetime
//!
//! In-memory only; reset on restart is acceptable for a per-minute
//! enumeration-defense limiter (a misbehaving peer's burst budget
//! cannot be sustained across many restarts of the targeted instance).
//! Both maps are swept periodically by [`cleanup_loop`] so the
//! `HashMap`s cannot grow without bound as one-shot IPs and keys
//! churn through.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// §14.3 `PRIOR_HOME_CHALLENGE_RPM_PER_IP`. Per-source-IP cap on
/// challenge-issuance requests per minute. Spec default; revisit on
/// soak data.
pub const PRIOR_HOME_CHALLENGE_RPM_PER_IP: u32 = 60;

/// §14.3 `PRIOR_HOME_CHALLENGE_RPM_PER_KEY`. Per-subject-key cap on
/// challenge-issuance requests per minute, charged only on a K that
/// passed curve validation. Spec default; revisit on soak data.
pub const PRIOR_HOME_CHALLENGE_RPM_PER_KEY: u32 = 10;

/// Per-IP + per-subject-key rolling-60s request counter for
/// `/federation/v1/prior-home/challenge`.
///
/// One process-wide instance lives on [`crate::AppState`]; the
/// challenge handler calls [`Self::try_admit_ip`] and
/// [`Self::try_admit_key`] in that order, before performing the
/// Ed25519 signing of the §5.6 challenge payload.
pub struct PriorHomeChallengeRateLimiter {
    /// Per-IP map. Bounded by the count of distinct source IPs seen
    /// in the last window (the [`Self::cleanup_stale_at`] sweep drops
    /// any entry whose window has fully expired). Worst-case live
    /// retention is `WINDOW_SECS + sweep_period`.
    ips: Mutex<HashMap<IpAddr, WindowState>>,
    /// Per-K map. Bounded by the count of distinct *curve-valid*
    /// subject keys; garbage K values are rejected before they reach
    /// the per-key counter.
    keys: Mutex<HashMap<[u8; 32], WindowState>>,
    /// Per-IP cap as an `AtomicU32` so integration tests sharing the
    /// `Arc<Self>` on `AppState` can tighten or loosen the bound at
    /// runtime without rebuilding the harness. Production wires the
    /// spec constant once at startup and never mutates it.
    max_per_ip_per_window: AtomicU32,
    /// Per-subject-key cap as an `AtomicU32`. Same rationale as
    /// `max_per_ip_per_window`.
    max_per_key_per_window: AtomicU32,
}

#[derive(Clone, Copy)]
struct WindowState {
    window_start_secs: u64,
    count: u32,
}

impl PriorHomeChallengeRateLimiter {
    /// Window length in seconds. Pinned to the "minute" the §14.3
    /// table uses for `PRIOR_HOME_CHALLENGE_RPM_*`.
    pub const WINDOW_SECS: u64 = 60;

    /// New limiter with custom per-IP / per-K caps. Production uses
    /// [`Default`]; tests parameterise for tractable arithmetic.
    pub fn new(max_per_ip_per_window: u32, max_per_key_per_window: u32) -> Self {
        Self {
            ips: Mutex::new(HashMap::new()),
            keys: Mutex::new(HashMap::new()),
            max_per_ip_per_window: AtomicU32::new(max_per_ip_per_window),
            max_per_key_per_window: AtomicU32::new(max_per_key_per_window),
        }
    }

    /// Adjust both caps at runtime. Used by integration tests that
    /// share an `Arc<Self>` with the wired-up handler — they tighten
    /// the bound from `u32::MAX` (test-harness default) to the value
    /// the test wants to assert on. Production never calls this.
    pub fn set_caps(&self, max_per_ip_per_window: u32, max_per_key_per_window: u32) {
        self.max_per_ip_per_window
            .store(max_per_ip_per_window, Ordering::Relaxed);
        self.max_per_key_per_window
            .store(max_per_key_per_window, Ordering::Relaxed);
    }

    /// Admit one challenge-issuance attempt against the per-IP
    /// counter. Returns `true` on admit (counter incremented),
    /// `false` on overflow (counter *not* incremented — a rejected
    /// admit does not burn budget further).
    pub fn try_admit_ip(&self, ip: IpAddr) -> bool {
        self.try_admit_ip_at(ip, now_secs())
    }

    /// Test-visible variant taking an explicit `now_secs`.
    pub fn try_admit_ip_at(&self, ip: IpAddr, now_secs: u64) -> bool {
        let cap = self.max_per_ip_per_window.load(Ordering::Relaxed);
        let mut g = self
            .ips
            .lock()
            .expect("prior-home challenge limiter poisoned");
        admit(&mut g, ip, now_secs, cap)
    }

    /// Admit one challenge-issuance attempt against the per-subject-
    /// key counter. Same semantics as [`Self::try_admit_ip`]. The
    /// caller MUST verify K is a valid Ed25519 curve point before
    /// charging this counter — see the module docstring.
    pub fn try_admit_key(&self, key: [u8; 32]) -> bool {
        self.try_admit_key_at(key, now_secs())
    }

    /// Test-visible variant taking an explicit `now_secs`.
    pub fn try_admit_key_at(&self, key: [u8; 32], now_secs: u64) -> bool {
        let cap = self.max_per_key_per_window.load(Ordering::Relaxed);
        let mut g = self
            .keys
            .lock()
            .expect("prior-home challenge limiter poisoned");
        admit(&mut g, key, now_secs, cap)
    }

    /// Drop per-IP and per-key entries whose window has fully expired
    /// as of `now_secs`. The retention predicate is `now - window_start
    /// < WINDOW_SECS`, so any entry whose 60s window has passed is
    /// removed at the next sweep; live retention is at most
    /// `WINDOW_SECS + sweep_period`.
    pub fn cleanup_stale_at(&self, now_secs: u64) {
        let mut ips = self
            .ips
            .lock()
            .expect("prior-home challenge limiter poisoned");
        ips.retain(|_k, v| now_secs.saturating_sub(v.window_start_secs) < Self::WINDOW_SECS);
        drop(ips);
        let mut keys = self
            .keys
            .lock()
            .expect("prior-home challenge limiter poisoned");
        keys.retain(|_k, v| now_secs.saturating_sub(v.window_start_secs) < Self::WINDOW_SECS);
    }
}

impl Default for PriorHomeChallengeRateLimiter {
    fn default() -> Self {
        Self::new(
            PRIOR_HOME_CHALLENGE_RPM_PER_IP,
            PRIOR_HOME_CHALLENGE_RPM_PER_KEY,
        )
    }
}

/// Shared fixed-window admit step used by both `try_admit_ip` and
/// `try_admit_key`. Generic over the key type so the two maps stay
/// separately locked (no false sharing of the same mutex).
fn admit<K: std::hash::Hash + Eq>(
    map: &mut HashMap<K, WindowState>,
    key: K,
    now_secs: u64,
    max_per_window: u32,
) -> bool {
    let entry = map.entry(key).or_insert(WindowState {
        window_start_secs: now_secs,
        count: 0,
    });
    if now_secs.saturating_sub(entry.window_start_secs)
        >= PriorHomeChallengeRateLimiter::WINDOW_SECS
    {
        entry.window_start_secs = now_secs;
        entry.count = 0;
    }
    if entry.count >= max_per_window {
        return false;
    }
    entry.count = entry.count.saturating_add(1);
    true
}

/// Build a `429 Too Many Requests` response with `Retry-After: 60`
/// per §14.3. Body is empty per the spec convention used by the other
/// federation rate-limiter 429 helpers; `Retry-After` is the only
/// sender signal.
pub fn prior_home_challenge_too_many_requests() -> Response {
    let mut r = (StatusCode::TOO_MANY_REQUESTS, "").into_response();
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    r
}

/// Background sweep that calls
/// [`PriorHomeChallengeRateLimiter::cleanup_stale_at`] once per
/// window. Combined with the sweep cadence, live retention is at
/// most `WINDOW_SECS + sweep_period` (≈ 2 minutes worst case).
pub async fn cleanup_loop(
    limiter: std::sync::Arc<PriorHomeChallengeRateLimiter>,
    label: &'static str,
) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
        PriorHomeChallengeRateLimiter::WINDOW_SECS,
    ));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        limiter.cleanup_stale_at(now_secs());
        tracing::debug!(target: "federation::rate_limit", limiter = label, "rate limiter swept");
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip(b: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, b))
    }
    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn ip_admits_within_per_minute_budget() {
        let l = PriorHomeChallengeRateLimiter::new(3, 10);
        assert!(l.try_admit_ip_at(ip(1), 1000));
        assert!(l.try_admit_ip_at(ip(1), 1000));
        assert!(l.try_admit_ip_at(ip(1), 1000));
        // 4th request inside the same window exceeds the per-IP cap.
        assert!(!l.try_admit_ip_at(ip(1), 1000));
    }

    #[test]
    fn key_admits_within_per_minute_budget() {
        let l = PriorHomeChallengeRateLimiter::new(60, 2);
        assert!(l.try_admit_key_at(key(1), 1000));
        assert!(l.try_admit_key_at(key(1), 1000));
        // 3rd request inside the same window exceeds the per-key cap.
        assert!(!l.try_admit_key_at(key(1), 1000));
    }

    #[test]
    fn separate_ips_have_separate_budgets() {
        let l = PriorHomeChallengeRateLimiter::new(1, 10);
        assert!(l.try_admit_ip_at(ip(1), 1000));
        assert!(!l.try_admit_ip_at(ip(1), 1000));
        // Different IP gets its own bucket.
        assert!(l.try_admit_ip_at(ip(2), 1000));
    }

    #[test]
    fn separate_keys_have_separate_budgets() {
        let l = PriorHomeChallengeRateLimiter::new(60, 1);
        assert!(l.try_admit_key_at(key(1), 1000));
        assert!(!l.try_admit_key_at(key(1), 1000));
        assert!(l.try_admit_key_at(key(2), 1000));
    }

    #[test]
    fn ip_and_key_counters_are_independent() {
        // A request that admits via per-IP doesn't burn per-key budget,
        // and vice versa. Tests that the two HashMaps are not aliased.
        let l = PriorHomeChallengeRateLimiter::new(2, 1);
        // Saturate per-key for K=1.
        assert!(l.try_admit_key_at(key(1), 1000));
        assert!(!l.try_admit_key_at(key(1), 1000));
        // Per-IP is unaffected by the per-key exhaustion.
        assert!(l.try_admit_ip_at(ip(1), 1000));
        assert!(l.try_admit_ip_at(ip(1), 1000));
        assert!(!l.try_admit_ip_at(ip(1), 1000));
    }

    #[test]
    fn window_rolls_after_a_minute() {
        let l = PriorHomeChallengeRateLimiter::new(2, 10);
        assert!(l.try_admit_ip_at(ip(1), 1000));
        assert!(l.try_admit_ip_at(ip(1), 1000));
        assert!(!l.try_admit_ip_at(ip(1), 1030));
        // 60 s later, fresh window — count zeroed.
        assert!(l.try_admit_ip_at(ip(1), 1060));
    }

    #[test]
    fn rejected_admit_does_not_burn_budget() {
        let l = PriorHomeChallengeRateLimiter::new(60, 2);
        assert!(l.try_admit_key_at(key(1), 1000));
        assert!(l.try_admit_key_at(key(1), 1000));
        assert!(!l.try_admit_key_at(key(1), 1000));
        // A misbehaving sender looping on 429s should not see the
        // window-end behavior diverge from one that stops.
        assert!(!l.try_admit_key_at(key(1), 1000));
        let g = l.keys.lock().unwrap();
        assert_eq!(g[&key(1)].count, 2);
    }

    #[test]
    fn cleanup_drops_expired_entries_from_both_maps() {
        let l = PriorHomeChallengeRateLimiter::new(60, 10);
        l.try_admit_ip_at(ip(1), 1000);
        l.try_admit_key_at(key(1), 1000);
        l.try_admit_ip_at(ip(2), 1080);
        l.try_admit_key_at(key(2), 1080);
        // IP=1, K=1 windows started at 1000; 1080 - 1000 = 80 > 60 → dropped.
        l.cleanup_stale_at(1080);
        let ips = l.ips.lock().unwrap();
        assert!(!ips.contains_key(&ip(1)));
        assert!(ips.contains_key(&ip(2)));
        let keys = l.keys.lock().unwrap();
        assert!(!keys.contains_key(&key(1)));
        assert!(keys.contains_key(&key(2)));
    }

    #[test]
    fn too_many_requests_response_carries_retry_after_minute() {
        let r = prior_home_challenge_too_many_requests();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            r.headers()
                .get(header::RETRY_AFTER)
                .unwrap()
                .to_str()
                .unwrap(),
            "60",
        );
    }
}
