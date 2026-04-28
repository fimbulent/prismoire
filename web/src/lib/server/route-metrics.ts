// In-process route metrics for the SvelteKit Node server.
//
// Mirrors the design of the Axum-side `server/src/metrics.rs`: per-route
// counters and latency quantiles in a 24h rolling window, computed on
// read. The shape diverges from the Rust side in two deliberate ways:
//
//   1. No cumulative `_all` counters. The admin UI only renders the 24h
//      window, so we don't pay the bookkeeping for an all-time view.
//   2. Three latency series per route, not one — total, upstream
//      (wall-clock time waiting on Axum from `event.fetch`), and
//      residual (total − upstream, the Node-side work not explained by
//      upstream calls). The residual is the column that justifies
//      running these metrics in addition to Axum's: a clean Axum panel
//      and a fat residual localizes "page is slow" to SSR / event-loop
//      blocking / sequential-await regressions, none of which the API
//      panel can see.
//
// Concurrency: the Node process is single-threaded JS, so plain
// property mutation is safe — no locks needed. Module-level state is
// shared across requests, which is exactly what we want for aggregate
// counters (contrast with per-user state; see `web/CLAUDE.md` "SSR
// safety under adapter-node").
//
// Naming convention: local variables and parameters use camelCase per
// project style. Fields on `RouteSnapshot` (and the `HourBucket`
// internals that feed them) intentionally stay snake_case to mirror
// the Axum-side `RouteStatsResponse` interface in `$lib/api/admin.ts`
// — the two stacked admin tables consume parallel shapes.

/// Max samples retained per latency histogram. Mirrors `HISTOGRAM_CAPACITY`
/// in `server/src/metrics.rs` so quantile precision matches the Axum side.
const HISTOGRAM_CAPACITY = 1024;

/// Length of the per-route rolling window, in hours.
const ROLLING_WINDOW_HOURS = 24;

const MS_PER_HOUR = 60 * 60 * 1000;

type StatusClass = 'success' | 'client_error' | 'server_error';

function classify(status: number): StatusClass {
	if (status >= 200 && status < 400) return 'success';
	if (status >= 400 && status < 500) return 'client_error';
	return 'server_error';
}

/// One hour's worth of per-route counters. A bucket is "fresh" when its
/// `hour` tag is within `ROLLING_WINDOW_HOURS` of the current clock
/// hour; stale buckets are rotated on next write. Field names line up
/// with the snake_case suffixes of `RouteSnapshot` so aggregation is a
/// direct copy.
interface HourBucket {
	hour: number | null;
	total: number;
	success: number;
	client_error: number;
	server_error: number;
}

function emptyBucket(): HourBucket {
	return { hour: null, total: 0, success: 0, client_error: 0, server_error: 0 };
}

interface TimedSample {
	atMs: number;
	value: number;
}

/// Fixed-capacity ring buffer of timestamped samples. Once full, the
/// oldest sample is overwritten on each push. Quantiles are computed
/// by sorting a copy on read; cheap at this size.
class RingHistogram {
	private samples: TimedSample[] = [];
	private head = 0;

	constructor(private readonly capacity: number) {}

	push(atMs: number, value: number): void {
		if (this.samples.length < this.capacity) {
			this.samples.push({ atMs, value });
			return;
		}
		this.samples[this.head] = { atMs, value };
		this.head = (this.head + 1) % this.capacity;
	}

	/// Approximate quantile via nearest-rank, restricted to samples with
	/// `atMs >= sinceMs`. Uses the same index formula as the Axum
	/// side: `idx = round((n - 1) * q)`.
	quantileSince(q: number, sinceMs: number): number | null {
		const filtered: number[] = [];
		for (const s of this.samples) {
			if (s.atMs >= sinceMs) filtered.push(s.value);
		}
		if (filtered.length === 0) return null;
		filtered.sort((a, b) => a - b);
		const clamped = Math.max(0, Math.min(1, q));
		const idx = Math.round((filtered.length - 1) * clamped);
		return filtered[idx];
	}
}

interface RouteStatsInner {
	buckets: HourBucket[];
	latencyTotalMs: RingHistogram;
	latencyUpstreamMs: RingHistogram;
	latencyResidualMs: RingHistogram;
}

function newRouteStats(): RouteStatsInner {
	const buckets: HourBucket[] = [];
	for (let i = 0; i < ROLLING_WINDOW_HOURS; i++) buckets.push(emptyBucket());
	return {
		buckets,
		latencyTotalMs: new RingHistogram(HISTOGRAM_CAPACITY),
		latencyUpstreamMs: new RingHistogram(HISTOGRAM_CAPACITY),
		latencyResidualMs: new RingHistogram(HISTOGRAM_CAPACITY)
	};
}

/// Per-route stats captured in a snapshot. All fields are 24h rolling
/// — there is no cumulative view (see file header for why).
///
/// Field names are snake_case to mirror `RouteStatsResponse` from
/// `$lib/api/admin.ts`; both tables in the admin UI consume parallel
/// shapes, and divergence here would force a translation layer for no
/// benefit.
export interface RouteSnapshot {
	method: string;
	path: string;

	total_24h: number;
	success_24h: number;
	client_error_24h: number;
	server_error_24h: number;

	/// Total request latency: wall-clock time the SvelteKit `handle`
	/// hook spent serving the request, including SSR rendering and any
	/// upstream `event.fetch` calls.
	latency_total_ms_p50_24h: number | null;
	latency_total_ms_p95_24h: number | null;
	latency_total_ms_p99_24h: number | null;

	/// Wall-clock time the request spent with at least one upstream
	/// fetch in flight. Overlapping fetches are counted once (not
	/// summed), so this represents real "blocked on Axum" time.
	latency_upstream_ms_p50_24h: number | null;
	latency_upstream_ms_p95_24h: number | null;
	latency_upstream_ms_p99_24h: number | null;

	/// `total − upstream` — the time spent on Node-side work that was
	/// NOT waiting on an upstream fetch. This is the column that
	/// justifies these metrics existing alongside Axum's: it isolates
	/// SSR cost, event-loop wait, and sequential-await orchestration
	/// overhead. Floored at 0 to avoid presenting confusing negative
	/// values from minor timer overlap.
	latency_residual_ms_p50_24h: number | null;
	latency_residual_ms_p95_24h: number | null;
	latency_residual_ms_p99_24h: number | null;
}

class RouteMetrics {
	/// Keyed by `"METHOD path-template"`, e.g. `"GET /admin/routes"`.
	/// Cardinality is bounded by the number of registered SvelteKit
	/// routes, since `event.route.id` is the matched template, not the
	/// raw URL. Unmatched routes (`event.route.id === null`) are
	/// skipped entirely by the caller — see `hooks.server.ts`.
	private routes = new Map<
		string,
		{ method: string; path: string; stats: RouteStatsInner }
	>();

	/// Record one request's outcome against its route template.
	record(
		method: string,
		path: string,
		status: number,
		totalMs: number,
		upstreamMs: number,
		nowMs: number = Date.now()
	): void {
		const key = `${method} ${path}`;
		let entry = this.routes.get(key);
		if (!entry) {
			entry = { method, path, stats: newRouteStats() };
			this.routes.set(key, entry);
		}
		const inner = entry.stats;

		const nowHour = Math.floor(nowMs / MS_PER_HOUR);
		const slot = nowHour % ROLLING_WINDOW_HOURS;
		// Rotate the slot if its tag is stale.
		if (inner.buckets[slot].hour !== nowHour) {
			inner.buckets[slot] = { ...emptyBucket(), hour: nowHour };
		}
		inner.buckets[slot].total += 1;
		inner.buckets[slot][classify(status)] += 1;

		inner.latencyTotalMs.push(nowMs, totalMs);
		inner.latencyUpstreamMs.push(nowMs, upstreamMs);
		// Floor at 0: the upstream timer can drift slightly past the
		// resolve() return in pathological cases, and showing negative
		// residuals would confuse readers of the dashboard.
		inner.latencyResidualMs.push(nowMs, Math.max(0, totalMs - upstreamMs));
	}

	/// Snapshot of per-route stats. Sorted by 24h request count desc
	/// — same default ordering as the Axum side; the UI overrides this
	/// with its own sort controls.
	snapshot(nowMs: number = Date.now()): RouteSnapshot[] {
		const out: RouteSnapshot[] = [];
		const nowHour = Math.floor(nowMs / MS_PER_HOUR);
		const cutoffMs = nowMs - ROLLING_WINDOW_HOURS * MS_PER_HOUR;

		for (const { method, path, stats } of this.routes.values()) {
			let total = 0;
			let success = 0;
			let clientError = 0;
			let serverError = 0;
			for (const b of stats.buckets) {
				if (b.hour === null) continue;
				const age = nowHour - b.hour;
				if (age < 0 || age >= ROLLING_WINDOW_HOURS) continue;
				total += b.total;
				success += b.success;
				clientError += b.client_error;
				serverError += b.server_error;
			}

			out.push({
				method,
				path,
				total_24h: total,
				success_24h: success,
				client_error_24h: clientError,
				server_error_24h: serverError,
				latency_total_ms_p50_24h: stats.latencyTotalMs.quantileSince(0.5, cutoffMs),
				latency_total_ms_p95_24h: stats.latencyTotalMs.quantileSince(0.95, cutoffMs),
				latency_total_ms_p99_24h: stats.latencyTotalMs.quantileSince(0.99, cutoffMs),
				latency_upstream_ms_p50_24h: stats.latencyUpstreamMs.quantileSince(0.5, cutoffMs),
				latency_upstream_ms_p95_24h: stats.latencyUpstreamMs.quantileSince(0.95, cutoffMs),
				latency_upstream_ms_p99_24h: stats.latencyUpstreamMs.quantileSince(0.99, cutoffMs),
				latency_residual_ms_p50_24h: stats.latencyResidualMs.quantileSince(0.5, cutoffMs),
				latency_residual_ms_p95_24h: stats.latencyResidualMs.quantileSince(0.95, cutoffMs),
				latency_residual_ms_p99_24h: stats.latencyResidualMs.quantileSince(0.99, cutoffMs)
			});
		}

		out.sort((a, b) => b.total_24h - a.total_24h);
		return out;
	}
}

/// Process-wide singleton recorder. Module-level state is shared across
/// requests, which is what we want for aggregate metrics. Per-user
/// state must never live here — see `web/CLAUDE.md` "SSR safety".
export const routeMetrics = new RouteMetrics();
