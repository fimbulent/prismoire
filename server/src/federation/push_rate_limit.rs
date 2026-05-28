//! Per-peer per-minute request-rate limits for the Phase-11 secondary
//! status/governance push routes:
//!
//! - `POST /federation/v1/user-status`   (§16.5 `USER_STATUS_RPM_PER_PEER`)
//! - `POST /federation/v1/thread-status` (§17.5 `THREAD_STATUS_RPM_PER_PEER`)
//! - `POST /federation/v1/reports`       (§18.5 `REPORTS_RPM_PER_PEER`)
//!
//! ## Semantics
//!
//! Per `docs/federation-protocol.md` §16.5/§17.5/§18.5 each requesting
//! peer is gated on a single budget — at most N *requests* per rolling
//! 60-second window. Unlike the pull-backfill limiter
//! ([`BackfillRateLimiter`](crate::federation::backfill_rate_limit::BackfillRateLimiter))
//! these are *push* routes with no response body to meter, so there is
//! no byte budget — only the request count matters. The §10.6
//! per-source-instance object counter
//! ([`ContentRateLimiter`](crate::federation::content_rate_limit::ContentRateLimiter))
//! is the per-hour *object* ceiling; this is the per-minute *request*
//! ceiling, and the two are complementary DoS guards.
//!
//! Overflow returns `429 Too Many Requests` with `Retry-After: 60` and
//! an empty body. See [`push_too_many_requests`].
//!
//! Fixed-window (not sliding) for the same reason as the sibling
//! limiters: one `(window_start, request_count)` per peer is cheaper
//! than a per-request timestamp ring, and the worst-case "burst at
//! rollover" overrun is bounded by a single extra RPM.
//!
//! The `reports` ceiling (30/min) is deliberately tighter than the two
//! status ceilings (60/min): a report push lets the sender vary
//! `post_id` freely to flood the local moderation queue, whereas status
//! pushes are keyed to a bounded set of subjects/threads the sender is
//! authoritative for.
//!
//! ## Defaults are starting points
//!
//! All three constants are flagged in the spec as server-tunable
//! defaults (the §16.5/§17.5/§18.5 tables mark them "Required: No").
//! The numbers here mirror the spec's stated defaults verbatim.
//! Operator override is out of scope for Phase 11; revisit once we have
//! measured load to inform sizing.
//!
//! ## State lifetime
//!
//! In-memory only, same shape as the sibling limiters. A periodic sweep
//! ([`cleanup_loop`]) prunes per-peer entries whose window has fully
//! expired so the `HashMap` can't grow unbounded as short-lived peers
//! churn through.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// §16.5 `USER_STATUS_RPM_PER_PEER`. Per-peer request cap inside a
/// rolling 60-second window for `POST /federation/v1/user-status`.
/// Spec default; revisit on soak data.
pub const USER_STATUS_RPM_PER_PEER: u32 = 60;

/// §17.5 `THREAD_STATUS_RPM_PER_PEER`. Per-peer request cap inside a
/// rolling 60-second window for `POST /federation/v1/thread-status`.
/// Spec default; revisit on soak data.
pub const THREAD_STATUS_RPM_PER_PEER: u32 = 60;

/// §18.5 `REPORTS_RPM_PER_PEER`. Per-peer request cap inside a rolling
/// 60-second window for `POST /federation/v1/reports`. Tighter than the
/// status ceilings because the sender can vary `post_id` to flood the
/// moderation queue. Spec default; revisit on soak data.
pub const REPORTS_RPM_PER_PEER: u32 = 30;

/// Per-source request-rate counter for an inbound Phase-11 push route.
///
/// Three process-wide instances live on [`crate::AppState`] — one per
/// route, each constructed with its own RPM ceiling. Each handler calls
/// [`Self::try_admit`] at entry and rejects with
/// [`push_too_many_requests`] on `false`.
pub struct PushRateLimiter {
    inner: Mutex<HashMap<[u8; 32], WindowState>>,
    max_requests_per_window: u32,
}

#[derive(Clone, Copy)]
struct WindowState {
    window_start_secs: u64,
    request_count: u32,
}

impl PushRateLimiter {
    /// Window length. Pinned to the per-minute denominator the spec
    /// uses for all three budgets.
    pub const WINDOW_SECS: u64 = 60;

    /// New limiter with a custom request budget. Production uses the
    /// route-specific constructors below; tests parameterise for
    /// tractable assertion arithmetic.
    pub fn new(max_requests_per_window: u32) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_requests_per_window,
        }
    }

    /// `POST /federation/v1/user-status` limiter at the §16.5 default.
    pub fn for_user_status() -> Self {
        Self::new(USER_STATUS_RPM_PER_PEER)
    }

    /// `POST /federation/v1/thread-status` limiter at the §17.5 default.
    pub fn for_thread_status() -> Self {
        Self::new(THREAD_STATUS_RPM_PER_PEER)
    }

    /// `POST /federation/v1/reports` limiter at the §18.5 default.
    pub fn for_reports() -> Self {
        Self::new(REPORTS_RPM_PER_PEER)
    }

    /// Attempt to admit one more request from `sender`.
    ///
    /// Returns `true` on admit — the request counter is bumped by one.
    /// Returns `false` if the budget is already exhausted; in that case
    /// the counter is left untouched (a rejected admit does not burn
    /// budget further, so a sender looping on 429s does not diverge from
    /// one that backs off).
    pub fn try_admit(&self, sender: [u8; 32]) -> bool {
        self.try_admit_at(sender, now_secs())
    }

    /// Test-visible variant taking an explicit `now_secs`.
    pub fn try_admit_at(&self, sender: [u8; 32], now_secs: u64) -> bool {
        let mut g = self.inner.lock().expect("push rate limiter poisoned");
        let entry = g.entry(sender).or_insert(WindowState {
            window_start_secs: now_secs,
            request_count: 0,
        });
        // Roll the window if the prior one has expired. Overwriting
        // (rather than adding) is what makes this fixed-window.
        if now_secs.saturating_sub(entry.window_start_secs) >= Self::WINDOW_SECS {
            entry.window_start_secs = now_secs;
            entry.request_count = 0;
        }
        if entry.request_count >= self.max_requests_per_window {
            return false;
        }
        entry.request_count = entry.request_count.saturating_add(1);
        true
    }

    /// Drop per-peer entries whose window has fully expired as of
    /// `now_secs`. Mirrors
    /// [`BackfillRateLimiter::cleanup_stale_at`](crate::federation::backfill_rate_limit::BackfillRateLimiter::cleanup_stale_at).
    pub fn cleanup_stale_at(&self, now_secs: u64) {
        let mut g = self.inner.lock().expect("push rate limiter poisoned");
        g.retain(|_k, v| now_secs.saturating_sub(v.window_start_secs) < Self::WINDOW_SECS);
    }
}

/// Build a `429 Too Many Requests` response with `Retry-After: 60`, the
/// §16.5/§17.5/§18.5 mandated shape. Body is empty per the spec: the
/// `Retry-After` header is the only signal the sender consumes.
pub fn push_too_many_requests() -> Response {
    let mut r = (StatusCode::TOO_MANY_REQUESTS, "").into_response();
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    r
}

/// Background sweep that calls [`PushRateLimiter::cleanup_stale_at`] on
/// a fixed cadence. Mirrors the sibling-limiter sweeps — same rationale,
/// same bound on stale-entry retention (≤ `2 * WINDOW_SECS`).
pub async fn cleanup_loop(limiter: std::sync::Arc<PushRateLimiter>, label: &'static str) {
    let mut ticker =
        tokio::time::interval(std::time::Duration::from_secs(PushRateLimiter::WINDOW_SECS));
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

    fn peer(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn admits_within_request_budget() {
        let l = PushRateLimiter::new(3);
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(l.try_admit_at(peer(1), 1000));
        // 4th request inside the same window exceeds the RPM cap.
        assert!(!l.try_admit_at(peer(1), 1000));
    }

    #[test]
    fn budget_is_per_peer() {
        let l = PushRateLimiter::new(1);
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(!l.try_admit_at(peer(1), 1000));
        // peer(2) has its own independent budget.
        assert!(l.try_admit_at(peer(2), 1000));
    }

    #[test]
    fn window_rolls_after_a_minute() {
        let l = PushRateLimiter::new(2);
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(!l.try_admit_at(peer(1), 1030)); // saturated mid-window
        // 60s after the window start, fresh window — count zeroed.
        assert!(l.try_admit_at(peer(1), 1000 + 60));
    }

    #[test]
    fn rejected_admit_does_not_burn_budget() {
        let l = PushRateLimiter::new(2);
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(!l.try_admit_at(peer(1), 1000)); // 3rd rejected
        assert!(!l.try_admit_at(peer(1), 1000)); // still rejected, no inflation
        let g = l.inner.lock().unwrap();
        assert_eq!(g[&peer(1)].request_count, 2);
    }

    #[test]
    fn cleanup_drops_expired_entries() {
        let l = PushRateLimiter::new(100);
        l.try_admit_at(peer(1), 1000);
        l.try_admit_at(peer(2), 1090);
        // peer(1)'s window started at 1000; 1090 - 1000 = 90 > 60 → dropped.
        l.cleanup_stale_at(1090);
        let g = l.inner.lock().unwrap();
        assert!(!g.contains_key(&peer(1)));
        assert!(g.contains_key(&peer(2)));
    }

    #[test]
    fn route_constructors_carry_spec_defaults() {
        // Exhaust each route-specific ceiling exactly, then assert the
        // next request is the one that 429s.
        let us = PushRateLimiter::for_user_status();
        for _ in 0..USER_STATUS_RPM_PER_PEER {
            assert!(us.try_admit_at(peer(1), 1000));
        }
        assert!(!us.try_admit_at(peer(1), 1000));

        let ts = PushRateLimiter::for_thread_status();
        for _ in 0..THREAD_STATUS_RPM_PER_PEER {
            assert!(ts.try_admit_at(peer(1), 1000));
        }
        assert!(!ts.try_admit_at(peer(1), 1000));

        let rp = PushRateLimiter::for_reports();
        for _ in 0..REPORTS_RPM_PER_PEER {
            assert!(rp.try_admit_at(peer(1), 1000));
        }
        assert!(!rp.try_admit_at(peer(1), 1000));
    }

    #[test]
    fn too_many_requests_response_carries_retry_after_60() {
        let r = push_too_many_requests();
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
