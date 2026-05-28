//! §14.3 receiver-side rate limit for `/federation/v1/prior-home/*`.
//!
//! Per-subject-key per-day fixed-window counter that caps the number
//! of successful §14 calls a single user K can make against this
//! instance in any rolling 24-hour window. The counter is **shared**
//! across all three §14 endpoints (probe, content-by-key,
//! inbound-edges-by-key) — see `docs/federation-protocol.md` §14.3
//! ("Why a shared counter"): the threat model is identical
//! (captured-key enumeration), so splitting the budget would
//! near-double the per-key request count an attacker can sustain by
//! alternating endpoints.
//!
//! ## Semantics
//!
//! Fixed-window-per-subject-key — same shape as
//! [`ContentRateLimiter`](crate::federation::content_rate_limit::ContentRateLimiter)
//! and [`BackfillRateLimiter`](crate::federation::backfill_rate_limit::BackfillRateLimiter),
//! sized to a 24-hour window instead of an hour or a minute. Each
//! `subject_key` carries `(window_start_unix_secs, count_in_window)`.
//! The handler calls [`Self::try_admit`] *after* full §14.1
//! verification — a request that fails any earlier check (signature,
//! TTL, deactivation) does not burn budget. Overflow returns
//! `429 Too Many Requests` with `Retry-After: 86400` per §14.3.
//!
//! Fixed-window (not sliding) for the same reason the §10.5.5 / §10.6
//! limiters use it: one `(ts, u32)` per key is cheaper than a
//! per-request timestamp ring, and the worst-case "burst at
//! rollover" is bounded by `2 * PRIOR_HOME_PROBES_PER_DAY_PER_KEY`
//! over two adjacent windows — still well under enumeration-shape
//! volumes.
//!
//! ## State lifetime
//!
//! In-memory only — reset on restart is acceptable for an
//! enumeration-defense limiter (a key that has captured can't sustain
//! its budget across many restarts of the targeted instance, and the
//! map is bounded by the count of distinct K values that have
//! probed). The map is swept periodically by [`cleanup_loop`] so the
//! `HashMap` cannot grow without bound as one-shot subject keys churn
//! through.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// §14.3 `PRIOR_HOME_PROBES_PER_DAY_PER_KEY`. Daily ceiling on
/// successful §14.2 / §14.5 / §14.6 calls per subject key. Spec
/// default; revisit on soak data.
///
/// "Successful" means "passed §14.1 verification steps 1–9 and
/// reached the per-endpoint serve step." Verification failures
/// (signature, expired challenge, deactivation) do not burn budget.
///
/// **Sizing rationale.** The cap is generous (200/day) because §14.3
/// is *not* the relevant defense surface against a captured-K
/// attacker — see the matching §14.3 prose for the full argument.
/// Briefly: K's private key trivially exfiltrates K's data via
/// `/api/me/export` (no rate limit), via WebAuthn auth against the
/// regular API, or by fanning out across N peers. The surface this
/// limiter *does* meaningfully bound is a misbehaving destination D
/// looping bulk-fetch against one peer, which is already covered by
/// per-sender `BACKFILL_RPM_PER_PEER`. The ceiling is sized for the
/// legitimate worst case (one full paginated migration: §14.2 probe
/// plus §14.5 ~64 pages plus §14.6 ~64 pages plus retry headroom) rather than
/// a residual security argument the larger architecture already
/// makes redundantly. Smaller values silently degrade recovery to
/// the §14.7 peer-network fallback for any non-trivial account.
pub const PRIOR_HOME_PROBES_PER_DAY_PER_KEY: u32 = 200;

/// Per-subject-key rolling-24h request counter for §14 endpoints.
///
/// One process-wide instance lives on [`crate::AppState`]; every §14
/// handler calls [`Self::try_admit`] after full verification (steps
/// 1–9 of §14.1) and before serving the response.
pub struct PriorHomeRateLimiter {
    inner: Mutex<HashMap<[u8; 32], WindowState>>,
    max_per_window: u32,
}

#[derive(Clone, Copy)]
struct WindowState {
    window_start_secs: u64,
    count: u32,
}

impl PriorHomeRateLimiter {
    /// Window length in seconds. Pinned to the "day" the §14.3 table
    /// uses for `PRIOR_HOME_PROBES_PER_DAY_PER_KEY`.
    pub const WINDOW_SECS: u64 = 86_400;

    /// New limiter with a custom per-window cap. Production uses
    /// [`Default`]; tests parameterise for tractable assertion
    /// arithmetic.
    pub fn new(max_per_window: u32) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_per_window,
        }
    }

    /// Attempt to admit one more §14 call from `subject_key` into the
    /// current rolling-24h window.
    ///
    /// Returns `true` on admit (counter incremented). Returns `false`
    /// on overflow (counter *not* incremented — a rejected admit does
    /// not burn budget further). The current time is taken from
    /// `SystemTime::now()`; the `now_secs` override is for tests.
    pub fn try_admit(&self, subject_key: [u8; 32]) -> bool {
        self.try_admit_at(subject_key, now_secs())
    }

    /// Test-visible variant taking an explicit `now_secs`.
    pub fn try_admit_at(&self, subject_key: [u8; 32], now_secs: u64) -> bool {
        let mut g = self.inner.lock().expect("prior-home rate limiter poisoned");
        let entry = g.entry(subject_key).or_insert(WindowState {
            window_start_secs: now_secs,
            count: 0,
        });
        // Roll the window if the prior one has expired.
        if now_secs.saturating_sub(entry.window_start_secs) >= Self::WINDOW_SECS {
            entry.window_start_secs = now_secs;
            entry.count = 0;
        }
        if entry.count >= self.max_per_window {
            return false;
        }
        entry.count = entry.count.saturating_add(1);
        true
    }

    /// Drop per-subject entries whose window has fully expired as of
    /// `now_secs`. Mirrors the other federation rate limiters.
    pub fn cleanup_stale_at(&self, now_secs: u64) {
        let mut g = self.inner.lock().expect("prior-home rate limiter poisoned");
        g.retain(|_k, v| now_secs.saturating_sub(v.window_start_secs) < Self::WINDOW_SECS);
    }
}

impl Default for PriorHomeRateLimiter {
    fn default() -> Self {
        Self::new(PRIOR_HOME_PROBES_PER_DAY_PER_KEY)
    }
}

/// Build a `429 Too Many Requests` response with `Retry-After: 86400`
/// per §14.3. Body is empty per the spec convention used by the other
/// rate-limiter 429 helpers; `Retry-After` is the only sender signal.
pub fn prior_home_too_many_requests() -> Response {
    let mut r = (StatusCode::TOO_MANY_REQUESTS, "").into_response();
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("86400"));
    r
}

/// Background sweep that calls
/// [`PriorHomeRateLimiter::cleanup_stale_at`] on a daily cadence.
/// Mirrors the other federation-rate-limiter sweeps — same rationale,
/// stale-entry retention bounded by `2 * WINDOW_SECS`.
pub async fn cleanup_loop(limiter: std::sync::Arc<PriorHomeRateLimiter>, label: &'static str) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
        PriorHomeRateLimiter::WINDOW_SECS,
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
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn admits_within_daily_budget() {
        let l = PriorHomeRateLimiter::new(3);
        assert!(l.try_admit_at(key(1), 1000));
        assert!(l.try_admit_at(key(1), 1000));
        assert!(l.try_admit_at(key(1), 1000));
        // 4th call inside the same window exceeds the cap.
        assert!(!l.try_admit_at(key(1), 1000));
    }

    #[test]
    fn separate_keys_have_separate_budgets() {
        let l = PriorHomeRateLimiter::new(1);
        assert!(l.try_admit_at(key(1), 1000));
        assert!(!l.try_admit_at(key(1), 1000)); // K=1 saturated
        // K=2 unaffected.
        assert!(l.try_admit_at(key(2), 1000));
    }

    #[test]
    fn window_rolls_after_a_day() {
        let l = PriorHomeRateLimiter::new(2);
        assert!(l.try_admit_at(key(1), 1000));
        assert!(l.try_admit_at(key(1), 1000));
        assert!(!l.try_admit_at(key(1), 1030)); // saturated mid-window
        // 24h later, fresh window — count zeroed.
        assert!(l.try_admit_at(key(1), 1000 + 86_400));
    }

    #[test]
    fn rejected_admit_does_not_burn_budget() {
        let l = PriorHomeRateLimiter::new(2);
        assert!(l.try_admit_at(key(1), 1000));
        assert!(l.try_admit_at(key(1), 1000));
        assert!(!l.try_admit_at(key(1), 1000)); // 3rd rejected
        // Subsequent rejected attempts don't inflate the counter —
        // a misbehaving sender that loops on 429s shouldn't see the
        // window-end behavior diverge from one that stops.
        assert!(!l.try_admit_at(key(1), 1000));
        let g = l.inner.lock().unwrap();
        assert_eq!(g[&key(1)].count, 2);
    }

    #[test]
    fn cleanup_drops_expired_entries() {
        let l = PriorHomeRateLimiter::new(20);
        l.try_admit_at(key(1), 1000);
        l.try_admit_at(key(2), 1000 + 86_500);
        // K=1's window started at 1000; 87_500 - 1000 = 86_500 > 86_400 → dropped.
        l.cleanup_stale_at(1000 + 86_500);
        let g = l.inner.lock().unwrap();
        assert!(!g.contains_key(&key(1)));
        assert!(g.contains_key(&key(2)));
    }

    #[test]
    fn too_many_requests_response_carries_retry_after_day() {
        let r = prior_home_too_many_requests();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            r.headers()
                .get(header::RETRY_AFTER)
                .unwrap()
                .to_str()
                .unwrap(),
            "86400",
        );
    }
}
