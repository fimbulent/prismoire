//! §10.5.5 receiver-side rate limits for `/federation/v1/backfill/*`.
//!
//! Per-peer per-minute token-bucket-shaped fixed-window counter that
//! gates the three Phase-8 pull-backfill routes:
//!
//! - `POST /federation/v1/backfill/by-hash`
//! - `GET  /federation/v1/backfill/by-author`
//! - `GET  /federation/v1/backfill/edges-by-key`
//!
//! ## Semantics
//!
//! Per `docs/federation-protocol.md` §10.5.5 each requesting peer is
//! gated on two parallel budgets within a rolling 60-second window:
//!
//! - `BACKFILL_RPM_PER_PEER` — at most 100 *requests* per minute.
//! - `BACKFILL_BYTES_PER_MIN_PER_PEER` — at most 10 MiB of *response
//!   bytes* per minute. The byte budget is checked on entry but charged
//!   *after* the response is built — an in-flight request whose
//!   response would push the peer over the limit still completes, and
//!   only *subsequent* requests are rejected. This matches the spec's
//!   "Token-bucket; on exhaustion, in-flight responses still complete
//!   but new requests 429" wording.
//!
//! Overflow returns `429 Too Many Requests` with `Retry-After: 60`.
//! See [`backfill_too_many_requests`].
//!
//! Fixed-window (not sliding) for the same reason as
//! [`ContentRateLimiter`](crate::federation::content_rate_limit::ContentRateLimiter):
//! one `(window_start, request_count, bytes_count)` per peer is
//! cheaper than a per-request timestamp ring, and the worst-case
//! "burst at rollover" overrun is bounded by a single request's
//! response size + 1 RPM.
//!
//! ## Defaults are starting points
//!
//! Both constants are flagged in `docs/federation-protocol.md` §22
//! "Tunables to be resolved" as starting points pending soak-test
//! measurements. The numbers here mirror the spec's stated defaults
//! verbatim. Operator override is out of scope for Phase 8; revisit
//! once we have measured load to inform sizing.
//!
//! ## State lifetime
//!
//! In-memory only, same shape as [`ContentRateLimiter`]. A periodic
//! sweep ([`cleanup_loop`]) prunes per-peer entries whose window has
//! fully expired so the `HashMap` can't grow unbounded as
//! short-lived peers churn through.
//!
//! [`ContentRateLimiter`]: crate::federation::content_rate_limit::ContentRateLimiter

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// §10.5.5 `BACKFILL_RPM_PER_PEER`. Per-peer request count cap inside
/// a rolling 60-second window. Spec default; revisit on soak data.
pub const BACKFILL_RPM_PER_PEER: u32 = 100;

/// §10.5.5 `BACKFILL_BYTES_PER_MIN_PER_PEER`. Per-peer response-byte
/// budget inside the same 60-second window. 10 MiB, spec default.
pub const BACKFILL_BYTES_PER_MIN_PER_PEER: u64 = 10 * 1024 * 1024;

/// Per-source request-rate + byte-budget counter for inbound
/// `/federation/v1/backfill/*` calls.
///
/// One process-wide instance lives on [`crate::AppState`]; each
/// backfill handler calls [`Self::try_admit`] at entry and (on
/// success) [`Self::charge_bytes`] once the response body is built.
pub struct BackfillRateLimiter {
    inner: Mutex<HashMap<[u8; 32], WindowState>>,
    max_requests_per_window: u32,
    max_bytes_per_window: u64,
}

#[derive(Clone, Copy)]
struct WindowState {
    window_start_secs: u64,
    request_count: u32,
    bytes_count: u64,
}

impl BackfillRateLimiter {
    /// Window length. Pinned to the per-minute denominator the spec
    /// uses for both budgets.
    pub const WINDOW_SECS: u64 = 60;

    /// New limiter with custom budgets. Production uses [`Default`];
    /// tests parameterise for tractable assertion arithmetic.
    pub fn new(max_requests_per_window: u32, max_bytes_per_window: u64) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_requests_per_window,
            max_bytes_per_window,
        }
    }

    /// Attempt to admit one more backfill request from `sender`.
    ///
    /// Returns `true` on admit — the request counter is incremented
    /// by 1, the byte counter is left alone (the caller charges it
    /// via [`Self::charge_bytes`] once the response body is known).
    /// Returns `false` if either budget is already exhausted; in
    /// that case neither counter is touched (a rejected admit does
    /// not burn budget further).
    pub fn try_admit(&self, sender: [u8; 32]) -> bool {
        self.try_admit_at(sender, now_secs())
    }

    /// Test-visible variant taking an explicit `now_secs`.
    pub fn try_admit_at(&self, sender: [u8; 32], now_secs: u64) -> bool {
        let mut g = self.inner.lock().expect("backfill rate limiter poisoned");
        let entry = g.entry(sender).or_insert(WindowState {
            window_start_secs: now_secs,
            request_count: 0,
            bytes_count: 0,
        });
        // Roll the window if the prior one has expired. Overwriting
        // (rather than adding) is what makes this fixed-window.
        if now_secs.saturating_sub(entry.window_start_secs) >= Self::WINDOW_SECS {
            entry.window_start_secs = now_secs;
            entry.request_count = 0;
            entry.bytes_count = 0;
        }
        // Check both budgets. Byte budget gate is "already over" — an
        // in-flight response that pushes us over still completes (spec
        // §10.5.5); only subsequent admits see the 429.
        if entry.request_count >= self.max_requests_per_window {
            return false;
        }
        if entry.bytes_count >= self.max_bytes_per_window {
            return false;
        }
        entry.request_count = entry.request_count.saturating_add(1);
        true
    }

    /// Charge `bytes` to `sender`'s current-window byte counter. Called
    /// by each handler once the response body is built. If the window
    /// has rolled since [`Self::try_admit`] (unlikely but possible
    /// across a slow request), we start a fresh window stamped with the
    /// current time and credit it.
    pub fn charge_bytes(&self, sender: [u8; 32], bytes: u64) {
        self.charge_bytes_at(sender, bytes, now_secs());
    }

    /// Test-visible variant taking an explicit `now_secs`.
    pub fn charge_bytes_at(&self, sender: [u8; 32], bytes: u64, now_secs: u64) {
        let mut g = self.inner.lock().expect("backfill rate limiter poisoned");
        let entry = g.entry(sender).or_insert(WindowState {
            window_start_secs: now_secs,
            request_count: 0,
            bytes_count: 0,
        });
        if now_secs.saturating_sub(entry.window_start_secs) >= Self::WINDOW_SECS {
            entry.window_start_secs = now_secs;
            entry.request_count = 0;
            entry.bytes_count = 0;
        }
        entry.bytes_count = entry.bytes_count.saturating_add(bytes);
    }

    /// Drop per-peer entries whose window has fully expired as of
    /// `now_secs`. Mirrors [`ContentRateLimiter::cleanup_stale_at`].
    ///
    /// [`ContentRateLimiter::cleanup_stale_at`]: crate::federation::content_rate_limit::ContentRateLimiter::cleanup_stale_at
    pub fn cleanup_stale_at(&self, now_secs: u64) {
        let mut g = self.inner.lock().expect("backfill rate limiter poisoned");
        g.retain(|_k, v| now_secs.saturating_sub(v.window_start_secs) < Self::WINDOW_SECS);
    }
}

impl Default for BackfillRateLimiter {
    /// Default-budget instance used by [`AppState`] init.
    ///
    /// [`AppState`]: crate::AppState
    fn default() -> Self {
        Self::new(BACKFILL_RPM_PER_PEER, BACKFILL_BYTES_PER_MIN_PER_PEER)
    }
}

/// Build a `429 Too Many Requests` response with `Retry-After: 60`,
/// the §10.5.5 mandated shape. Body is empty per the spec: the
/// `Retry-After` header is the only signal the sender consumes.
pub fn backfill_too_many_requests() -> Response {
    let mut r = (StatusCode::TOO_MANY_REQUESTS, "").into_response();
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    r
}

/// Background sweep that calls [`BackfillRateLimiter::cleanup_stale_at`]
/// on a fixed cadence. Mirrors the content-limiter sweep — same
/// rationale, same bound on stale-entry retention
/// (≤ `2 * WINDOW_SECS`).
pub async fn cleanup_loop(limiter: std::sync::Arc<BackfillRateLimiter>, label: &'static str) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
        BackfillRateLimiter::WINDOW_SECS,
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

    fn peer(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn admits_within_request_budget() {
        let l = BackfillRateLimiter::new(3, 1_000_000);
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(l.try_admit_at(peer(1), 1000));
        // 4th request inside the same window exceeds RPM cap.
        assert!(!l.try_admit_at(peer(1), 1000));
    }

    #[test]
    fn rejects_when_byte_budget_already_over() {
        let l = BackfillRateLimiter::new(100, 1000);
        // 1st request admits, then a hefty response burns the byte budget.
        assert!(l.try_admit_at(peer(1), 5000));
        l.charge_bytes_at(peer(1), 1001, 5000);
        // 2nd request sees the byte budget already over → 429. The spec
        // explicitly contracts that the *first* request that pushes us
        // over still completes (its admit happened before the charge)
        // and only *subsequent* requests are rejected.
        assert!(!l.try_admit_at(peer(1), 5000));
    }

    #[test]
    fn byte_budget_does_not_affect_other_peers() {
        let l = BackfillRateLimiter::new(100, 1000);
        assert!(l.try_admit_at(peer(1), 1000));
        l.charge_bytes_at(peer(1), 5000, 1000);
        // peer(2) is unaffected.
        assert!(l.try_admit_at(peer(2), 1000));
    }

    #[test]
    fn window_rolls_after_a_minute() {
        let l = BackfillRateLimiter::new(2, 1000);
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(!l.try_admit_at(peer(1), 1030)); // saturated mid-window
        // 60s later, fresh window — request count zeroed.
        assert!(l.try_admit_at(peer(1), 1000 + 60));
    }

    #[test]
    fn window_rolls_zero_the_byte_count_too() {
        let l = BackfillRateLimiter::new(100, 1000);
        assert!(l.try_admit_at(peer(1), 1000));
        l.charge_bytes_at(peer(1), 999, 1000);
        // Still under, can admit again same window.
        assert!(l.try_admit_at(peer(1), 1000));
        l.charge_bytes_at(peer(1), 2, 1000); // pushes to 1001, over budget
        assert!(!l.try_admit_at(peer(1), 1030)); // 429 for new requests
        // Next minute resets both counters.
        assert!(l.try_admit_at(peer(1), 1000 + 60));
    }

    #[test]
    fn rejected_admit_does_not_burn_budget() {
        let l = BackfillRateLimiter::new(2, 1_000_000);
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(l.try_admit_at(peer(1), 1000));
        assert!(!l.try_admit_at(peer(1), 1000)); // 3rd rejected
        // Subsequent rejected attempts don't inflate request_count
        // further — a misbehaving sender that loops on 429s shouldn't
        // see the window-end behavior diverge from one that stops.
        assert!(!l.try_admit_at(peer(1), 1000));
        let g = l.inner.lock().unwrap();
        assert_eq!(g[&peer(1)].request_count, 2);
    }

    #[test]
    fn cleanup_drops_expired_entries() {
        let l = BackfillRateLimiter::new(100, 1_000_000);
        l.try_admit_at(peer(1), 1000);
        l.try_admit_at(peer(2), 1090);
        // peer(1)'s window started at 1000; 1090 - 1000 = 90 > 60 → dropped
        l.cleanup_stale_at(1090);
        let g = l.inner.lock().unwrap();
        assert!(!g.contains_key(&peer(1)));
        assert!(g.contains_key(&peer(2)));
    }

    #[test]
    fn too_many_requests_response_carries_retry_after_60() {
        let r = backfill_too_many_requests();
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
