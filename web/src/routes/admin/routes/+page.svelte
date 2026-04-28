<script lang="ts">
	import type { RouteStatsResponse } from '$lib/api/admin';
	import type { RouteSnapshot as WebRouteSnapshot } from '$lib/server/route-metrics';

	let { data } = $props();

	// ----- Shared helpers -----

	/// Generic sort: nulls always sink to the bottom regardless of
	/// direction, so a route with no 24h samples never outranks one
	/// with data.
	function sortRows<T, K>(
		rows: readonly T[],
		key: K,
		dir: 'asc' | 'desc',
		valueFor: (r: T, k: K) => number | string | null
	): T[] {
		const out = [...rows];
		const sign = dir === 'asc' ? 1 : -1;
		out.sort((a, b) => {
			const av = valueFor(a, key);
			const bv = valueFor(b, key);
			if (av === null && bv === null) return 0;
			if (av === null) return 1;
			if (bv === null) return -1;
			if (typeof av === 'string' && typeof bv === 'string') {
				return av.localeCompare(bv) * sign;
			}
			return ((av as number) - (bv as number)) * sign;
		});
		return out;
	}

	function fmtMs(v: number | null): string {
		if (v === null) return '—';
		if (v < 10) return v.toFixed(1);
		return Math.round(v).toString();
	}

	function fmtPct(v: number | null): string {
		if (v === null) return '—';
		return `${(v * 100).toFixed(1)}%`;
	}

	function fmtCount(v: number): string {
		return v.toLocaleString();
	}

	// ----- API table -----

	type ApiSortKey =
		| 'path'
		| 'total_24h'
		| 'success_rate'
		| 'errors'
		| 'p50'
		| 'p95'
		| 'p99';

	let apiSortKey = $state<ApiSortKey>('total_24h');
	let apiSortDir = $state<'asc' | 'desc'>('desc');

	// Pull the successRate derivation out so the table row + sort agree.
	const apiSuccessRate = (r: RouteStatsResponse): number | null =>
		r.total_24h === 0 ? null : r.success_24h / r.total_24h;

	const apiErrors24h = (r: RouteStatsResponse): number =>
		r.client_error_24h + r.server_error_24h;

	function apiValueFor(r: RouteStatsResponse, key: ApiSortKey): number | string | null {
		switch (key) {
			case 'path':
				return `${r.method} ${r.path}`;
			case 'total_24h':
				return r.total_24h;
			case 'success_rate':
				return apiSuccessRate(r);
			case 'errors':
				return apiErrors24h(r);
			case 'p50':
				return r.latency_ms_p50_24h;
			case 'p95':
				return r.latency_ms_p95_24h;
			case 'p99':
				return r.latency_ms_p99_24h;
		}
	}

	const sortedApiRoutes = $derived.by(() => sortRows(data.routes, apiSortKey, apiSortDir, apiValueFor));

	function setApiSort(key: ApiSortKey) {
		if (apiSortKey === key) {
			apiSortDir = apiSortDir === 'asc' ? 'desc' : 'asc';
		} else {
			apiSortKey = key;
			// Path defaults to ascending (alphabetical); numeric columns to
			// descending ("show the biggest first").
			apiSortDir = key === 'path' ? 'asc' : 'desc';
		}
	}

	const apiArrow = (key: ApiSortKey) =>
		apiSortKey === key ? (apiSortDir === 'asc' ? ' ↑' : ' ↓') : '';

	// ----- Web table -----
	//
	// Columns mirror the API table for the total-latency series (p50/p95/p99)
	// so the two tables read alike, plus two diagnostic columns:
	// "Up p95" (wall-clock blocking time on Axum) and "Res p95" (Node-side
	// work not explained by upstream calls). Default sort is residual p95
	// descending — that is the column that justifies this table existing
	// alongside the API one. See `src/lib/server/route-metrics.ts`.

	type WebSortKey =
		| 'path'
		| 'total_24h'
		| 'success_rate'
		| 'errors'
		| 'p50'
		| 'p95'
		| 'p99'
		| 'up_p95'
		| 'res_p95';

	let webSortKey = $state<WebSortKey>('res_p95');
	let webSortDir = $state<'asc' | 'desc'>('desc');

	const webSuccessRate = (r: WebRouteSnapshot): number | null =>
		r.total_24h === 0 ? null : r.success_24h / r.total_24h;

	const webErrors24h = (r: WebRouteSnapshot): number =>
		r.client_error_24h + r.server_error_24h;

	function webValueFor(r: WebRouteSnapshot, key: WebSortKey): number | string | null {
		switch (key) {
			case 'path':
				return `${r.method} ${r.path}`;
			case 'total_24h':
				return r.total_24h;
			case 'success_rate':
				return webSuccessRate(r);
			case 'errors':
				return webErrors24h(r);
			case 'p50':
				return r.latency_total_ms_p50_24h;
			case 'p95':
				return r.latency_total_ms_p95_24h;
			case 'p99':
				return r.latency_total_ms_p99_24h;
			case 'up_p95':
				return r.latency_upstream_ms_p95_24h;
			case 'res_p95':
				return r.latency_residual_ms_p95_24h;
		}
	}

	const sortedWebRoutes = $derived.by(() => sortRows(data.webRoutes, webSortKey, webSortDir, webValueFor));

	function setWebSort(key: WebSortKey) {
		if (webSortKey === key) {
			webSortDir = webSortDir === 'asc' ? 'desc' : 'asc';
		} else {
			webSortKey = key;
			webSortDir = key === 'path' ? 'asc' : 'desc';
		}
	}

	const webArrow = (key: WebSortKey) =>
		webSortKey === key ? (webSortDir === 'asc' ? ' ↑' : ' ↓') : '';

	// ----- Per-table totals -----

	const apiTotalRequests24h = $derived(
		data.routes.reduce((acc, r) => acc + r.total_24h, 0)
	);
	const apiTotalErrors24h = $derived(
		data.routes.reduce((acc, r) => acc + apiErrors24h(r), 0)
	);
	const webTotalRequests24h = $derived(
		data.webRoutes.reduce((acc, r) => acc + r.total_24h, 0)
	);
	const webTotalErrors24h = $derived(
		data.webRoutes.reduce((acc, r) => acc + webErrors24h(r), 0)
	);
</script>

<div class="max-w-4xl mx-auto px-6 py-6 space-y-8">
	<section>
		<h2 class="text-base font-medium text-text-secondary mb-2">API routes</h2>
		<p class="text-sm text-text-muted mb-4">
			Per-route request stats from the Axum process, last 24 hours. Counts reset on server restart.
		</p>

		<div class="text-xs text-text-muted mb-4 flex flex-wrap items-center gap-x-4 gap-y-1">
			<span><span class="text-text-secondary">{fmtCount(apiTotalRequests24h)}</span> requests (24h)</span>
			<span><span class="text-text-secondary">{fmtCount(apiTotalErrors24h)}</span> errors (24h)</span>
			<span><span class="text-text-secondary">{data.routes.length}</span> routes observed</span>
		</div>

		{#if data.routes.length === 0}
			<div class="border border-border-subtle rounded p-8 text-center text-text-muted text-sm">
				No traffic recorded yet.
			</div>
		{:else}
			<div class="border border-border-subtle rounded overflow-x-auto">
				<table class="w-full text-sm">
					<thead class="bg-bg-elevated text-text-muted text-xs uppercase tracking-wide">
						<tr>
							<th class="text-left font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setApiSort('path')}>
									Route{apiArrow('path')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setApiSort('total_24h')}>
									Requests{apiArrow('total_24h')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setApiSort('success_rate')}>
									Success{apiArrow('success_rate')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setApiSort('errors')}>
									Errors{apiArrow('errors')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setApiSort('p50')}>
									p50 ms{apiArrow('p50')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setApiSort('p95')}>
									p95 ms{apiArrow('p95')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setApiSort('p99')}>
									p99 ms{apiArrow('p99')}
								</button>
							</th>
						</tr>
					</thead>
					<tbody>
						{#each sortedApiRoutes as r (r.method + ' ' + r.path)}
							{@const total = r.total_24h}
							{@const rate = apiSuccessRate(r)}
							{@const errs = apiErrors24h(r)}
							{@const hasServerErr = r.server_error_24h > 0}
							<tr class="border-t border-border-subtle">
								<td class="px-3 py-2 font-mono text-xs">
									<span class="text-text-muted">{r.method}</span>
									<span class="text-text-secondary">{r.path}</span>
								</td>
								<td class="px-3 py-2 text-right tabular-nums">{fmtCount(total)}</td>
								<td class="px-3 py-2 text-right tabular-nums">
									{#if rate === null}
										<span class="text-text-muted">—</span>
									{:else if rate >= 0.95}
										<span class="text-text-secondary">{fmtPct(rate)}</span>
									{:else}
										<span class="text-danger">{fmtPct(rate)}</span>
									{/if}
								</td>
								<td class="px-3 py-2 text-right tabular-nums">
									{#if errs === 0}
										<span class="text-text-muted">0</span>
									{:else if hasServerErr}
										<span class="text-danger" title="{r.server_error_24h} 5xx, {r.client_error_24h} 4xx">
											{fmtCount(errs)}
										</span>
									{:else}
										<span class="text-text-secondary" title="{r.client_error_24h} 4xx">
											{fmtCount(errs)}
										</span>
									{/if}
								</td>
								<td class="px-3 py-2 text-right tabular-nums text-text-secondary">
									{fmtMs(r.latency_ms_p50_24h)}
								</td>
								<td class="px-3 py-2 text-right tabular-nums text-text-secondary">
									{fmtMs(r.latency_ms_p95_24h)}
								</td>
								<td class="px-3 py-2 text-right tabular-nums text-text-secondary">
									{fmtMs(r.latency_ms_p99_24h)}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>

	<section>
		<h2 class="text-base font-medium text-text-secondary mb-2">Web routes</h2>
		<p class="text-sm text-text-muted mb-4">
			Per-route stats from the SvelteKit Node process, last 24 hours. <span class="text-text-secondary">Up p95</span>
			is wall-clock time waiting on Axum (overlapping fetches counted once);
			<span class="text-text-secondary">Res p95</span> is total minus upstream — Node-side work not explained
			by API calls (SSR, event-loop, sequential awaits). Sorted by Res p95 by default.
		</p>

		<div class="text-xs text-text-muted mb-4 flex flex-wrap items-center gap-x-4 gap-y-1">
			<span><span class="text-text-secondary">{fmtCount(webTotalRequests24h)}</span> requests (24h)</span>
			<span><span class="text-text-secondary">{fmtCount(webTotalErrors24h)}</span> errors (24h)</span>
			<span><span class="text-text-secondary">{data.webRoutes.length}</span> routes observed</span>
		</div>

		{#if data.webRoutes.length === 0}
			<div class="border border-border-subtle rounded p-8 text-center text-text-muted text-sm">
				No traffic recorded yet.
			</div>
		{:else}
			<div class="border border-border-subtle rounded overflow-x-auto">
				<table class="w-full text-sm">
					<thead class="bg-bg-elevated text-text-muted text-xs uppercase tracking-wide">
						<tr>
							<th class="text-left font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setWebSort('path')}>
									Route{webArrow('path')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setWebSort('total_24h')}>
									Requests{webArrow('total_24h')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setWebSort('success_rate')}>
									Success{webArrow('success_rate')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setWebSort('errors')}>
									Errors{webArrow('errors')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setWebSort('p50')}>
									p50 ms{webArrow('p50')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setWebSort('p95')}>
									p95 ms{webArrow('p95')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button type="button" class="hover:text-text-secondary" onclick={() => setWebSort('p99')}>
									p99 ms{webArrow('p99')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button
									type="button"
									class="hover:text-text-secondary"
									title="Wall-clock time spent waiting on upstream Axum fetches (parallel fetches counted once)."
									onclick={() => setWebSort('up_p95')}
								>
									Up p95{webArrow('up_p95')}
								</button>
							</th>
							<th class="text-right font-medium px-3 py-2">
								<button
									type="button"
									class="hover:text-text-secondary"
									title="Total p95 minus upstream p95 — Node-side work not explained by API calls."
									onclick={() => setWebSort('res_p95')}
								>
									Res p95{webArrow('res_p95')}
								</button>
							</th>
						</tr>
					</thead>
					<tbody>
						{#each sortedWebRoutes as r (r.method + ' ' + r.path)}
							{@const total = r.total_24h}
							{@const rate = webSuccessRate(r)}
							{@const errs = webErrors24h(r)}
							{@const hasServerErr = r.server_error_24h > 0}
							<tr class="border-t border-border-subtle">
								<td class="px-3 py-2 font-mono text-xs">
									<span class="text-text-muted">{r.method}</span>
									<span class="text-text-secondary">{r.path}</span>
								</td>
								<td class="px-3 py-2 text-right tabular-nums">{fmtCount(total)}</td>
								<td class="px-3 py-2 text-right tabular-nums">
									{#if rate === null}
										<span class="text-text-muted">—</span>
									{:else if rate >= 0.95}
										<span class="text-text-secondary">{fmtPct(rate)}</span>
									{:else}
										<span class="text-danger">{fmtPct(rate)}</span>
									{/if}
								</td>
								<td class="px-3 py-2 text-right tabular-nums">
									{#if errs === 0}
										<span class="text-text-muted">0</span>
									{:else if hasServerErr}
										<span class="text-danger" title="{r.server_error_24h} 5xx, {r.client_error_24h} 4xx">
											{fmtCount(errs)}
										</span>
									{:else}
										<span class="text-text-secondary" title="{r.client_error_24h} 4xx">
											{fmtCount(errs)}
										</span>
									{/if}
								</td>
								<td class="px-3 py-2 text-right tabular-nums text-text-secondary">
									{fmtMs(r.latency_total_ms_p50_24h)}
								</td>
								<td class="px-3 py-2 text-right tabular-nums text-text-secondary">
									{fmtMs(r.latency_total_ms_p95_24h)}
								</td>
								<td class="px-3 py-2 text-right tabular-nums text-text-secondary">
									{fmtMs(r.latency_total_ms_p99_24h)}
								</td>
								<td class="px-3 py-2 text-right tabular-nums text-text-muted">
									{fmtMs(r.latency_upstream_ms_p95_24h)}
								</td>
								<td class="px-3 py-2 text-right tabular-nums text-text-secondary">
									{fmtMs(r.latency_residual_ms_p95_24h)}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>
</div>
