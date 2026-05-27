//! Per-source-instance rate limit for `POST /federation/v1/content`
//! (Phase 7 §10.6 fold-in).
//!
//! Closes the abuse window flagged in `docs/federation-impl-plan.md`
//! Phase 6 ("No per-source rate limit on `/content`"): a peer could
//! sustain `MAX_CONTENT_BATCH = 64` objects per request indefinitely,
//! amplified by the trust-on-first-claim authoritative admin-rm
//! window. With move resolution now wired into `admin_rm` (Phase 7),
//! the matching content-side defense is this rolling-hour cap.
//!
//! ## Semantics
//!
//! Fixed-window-per-source. Each peer pubkey carries
//! `(window_start_unix_secs, applied_objects_in_window)`. On every
//! `/content` push the handler calls
//! [`ContentRateLimiter::check_and_count`] with the batch size; if
//! the post-increment count would exceed
//! [`MAX_CONTENT_OBJECTS_PER_HOUR`], the entire batch is rejected
//! with `400 rate_limited` *before* per-object processing — the
//! whole-batch reject is the simplest backpressure signal that lets
//! the sender drop into backoff without re-trying object-by-object.
//!
//! Fixed-window (rather than sliding) is intentional: a peer near
//! the cap may burst slightly over at window-rollover, but the
//! implementation is a single `(ts, u32)` per peer instead of a
//! per-object timestamp ring. The benign-burst surplus is bounded
//! by `MAX_CONTENT_BATCH` per push, well under abuse-shape volumes.
//!
//! ## State lifetime
//!
//! In-memory only. Reset on restart is fine — the cap is
//! defense-in-depth against sustained abuse, not a per-peer SLA.
//! The map grows bounded-by-peer-count: entries whose window has
//! expired are overwritten (not merely zeroed) on the next check
//! for that peer, so a long-departed peer never reaches GC. A
//! `cleanup_stale` API is exposed for an operator/test caller that
//! wants to scrub explicitly.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default per-source per-hour object cap. Chosen to admit
/// substantial steady-state traffic (≈156 max-batches per hour, or
/// one push every ~23 seconds at the per-request cap) while rejecting
/// sustained abuse-shape volumes. Not currently operator-tunable;
/// Phase 7 ships this as a single constant and revisits if any
/// operator runs into legitimate ceilings.
pub const MAX_CONTENT_OBJECTS_PER_HOUR: u32 = 10_000;

/// Per-source rolling-hour counter for inbound `/content` objects.
///
/// One process-wide instance lives on [`crate::AppState`]; the
/// `/content` handler calls [`ContentRateLimiter::check_and_count`]
/// at entry, before any per-object work.
pub struct ContentRateLimiter {
    inner: Mutex<HashMap<[u8; 32], WindowState>>,
    max_per_hour: u32,
}

#[derive(Clone, Copy)]
struct WindowState {
    window_start_secs: u64,
    count: u32,
}

impl ContentRateLimiter {
    /// Window length in seconds. Pinned to the "hour" the spec uses
    /// for §10.6's other per-source budgets so operator mental
    /// models stay consistent across routes.
    pub const WINDOW_SECS: u64 = 3600;

    /// New limiter with the supplied per-window cap. Production code
    /// uses [`MAX_CONTENT_OBJECTS_PER_HOUR`]; tests parameterise to
    /// keep the assertion arithmetic simple.
    pub fn new(max_per_hour: u32) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_per_hour,
        }
    }

    /// Attempt to admit `batch_size` more objects from `sender` into
    /// the current rolling-hour window.
    ///
    /// Returns `true` on admit (counter was incremented). Returns
    /// `false` on overflow (counter was *not* incremented — a
    /// rejected batch does not burn budget further). The current
    /// time is taken from `SystemTime::now()`; the `now_secs`
    /// override is for the unit tests that pin a synthetic clock.
    pub fn check_and_count(&self, sender: [u8; 32], batch_size: u32) -> bool {
        self.check_and_count_at(sender, batch_size, now_secs())
    }

    /// Test-visible variant taking an explicit `now_secs`. Same
    /// semantics as [`Self::check_and_count`].
    pub fn check_and_count_at(&self, sender: [u8; 32], batch_size: u32, now_secs: u64) -> bool {
        // batch_size = 0 is a no-op admit. The handler still calls
        // `empty_batch` reject upstream, but cheap to short-circuit.
        if batch_size == 0 {
            return true;
        }
        let mut g = self.inner.lock().expect("content rate limiter poisoned");
        let entry = g.entry(sender).or_insert(WindowState {
            window_start_secs: now_secs,
            count: 0,
        });
        // Roll the window if the prior one has expired. Overwriting
        // (rather than adding to) the count is what makes this fixed
        // rather than sliding.
        if now_secs.saturating_sub(entry.window_start_secs) >= Self::WINDOW_SECS {
            entry.window_start_secs = now_secs;
            entry.count = 0;
        }
        let new_count = entry.count.saturating_add(batch_size);
        if new_count > self.max_per_hour {
            return false;
        }
        entry.count = new_count;
        true
    }

    /// Drop per-peer entries whose window has fully expired as of
    /// `now_secs`. Optional housekeeping; the per-peer entries are
    /// already small enough that running prod without ever calling
    /// this only leaks O(N_peers) memory, but the dedicated sweep
    /// task ([`cleanup_loop`]) calls this hourly so unbounded growth
    /// for short-lived peers can't accumulate.
    pub fn cleanup_stale_at(&self, now_secs: u64) {
        let mut g = self.inner.lock().expect("content rate limiter poisoned");
        g.retain(|_k, v| now_secs.saturating_sub(v.window_start_secs) < Self::WINDOW_SECS);
    }
}

/// Background sweep that calls [`ContentRateLimiter::cleanup_stale_at`]
/// on a fixed cadence. Spawned once per limiter at startup so the
/// in-memory `HashMap<peer, WindowState>` can't grow without bound as
/// short-lived or departed peers churn through.
///
/// The sweep cadence is one window length: that's long enough that
/// the per-tick wakeup is negligible, short enough that no expired
/// entry sits around more than `2 * WINDOW_SECS` after its window
/// rolls.
pub async fn cleanup_loop(limiter: std::sync::Arc<ContentRateLimiter>, label: &'static str) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
        ContentRateLimiter::WINDOW_SECS,
    ));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        limiter.cleanup_stale_at(now_secs());
        tracing::debug!(target: "federation::rate_limit", limiter = label, "rate limiter swept");
    }
}

impl Default for ContentRateLimiter {
    /// Default-budget instance used by [`AppState`] init.
    ///
    /// [`AppState`]: crate::AppState
    fn default() -> Self {
        Self::new(MAX_CONTENT_OBJECTS_PER_HOUR)
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
    fn admits_within_budget() {
        let l = ContentRateLimiter::new(100);
        assert!(l.check_and_count_at(peer(1), 40, 1000));
        assert!(l.check_and_count_at(peer(1), 40, 1000));
    }

    #[test]
    fn rejects_when_increment_would_exceed() {
        let l = ContentRateLimiter::new(100);
        assert!(l.check_and_count_at(peer(1), 60, 1000));
        // 60 + 50 = 110 > 100 — must reject without incrementing
        assert!(!l.check_and_count_at(peer(1), 50, 1100));
        // The rejection didn't consume budget, so 40 more is fine
        assert!(l.check_and_count_at(peer(1), 40, 1200));
    }

    #[test]
    fn budget_is_per_sender() {
        let l = ContentRateLimiter::new(100);
        assert!(l.check_and_count_at(peer(1), 100, 1000));
        // peer 1 is saturated; peer 2 has its own window
        assert!(!l.check_and_count_at(peer(1), 1, 1100));
        assert!(l.check_and_count_at(peer(2), 100, 1200));
    }

    #[test]
    fn window_rolls_after_an_hour() {
        let l = ContentRateLimiter::new(100);
        assert!(l.check_and_count_at(peer(1), 100, 1000));
        assert!(!l.check_and_count_at(peer(1), 1, 1500)); // still in window
        // 3600s later, fresh window
        assert!(l.check_and_count_at(peer(1), 100, 1000 + 3600));
    }

    #[test]
    fn zero_batch_is_admitted_without_burning_budget() {
        let l = ContentRateLimiter::new(10);
        assert!(l.check_and_count_at(peer(1), 0, 1000));
        // budget is still 10 available
        assert!(l.check_and_count_at(peer(1), 10, 1000));
        assert!(!l.check_and_count_at(peer(1), 1, 1000));
    }

    #[test]
    fn cleanup_drops_expired_entries() {
        let l = ContentRateLimiter::new(100);
        l.check_and_count_at(peer(1), 1, 1000);
        l.check_and_count_at(peer(2), 1, 5000);
        l.cleanup_stale_at(5500);
        // peer(1)'s window started at 1000; 5500 - 1000 = 4500 > 3600 → dropped
        // peer(2)'s window started at 5000; still fresh
        let g = l.inner.lock().unwrap();
        assert!(!g.contains_key(&peer(1)));
        assert!(g.contains_key(&peer(2)));
    }
}
