<script lang="ts">
	import type { RouteStatsResponse } from '$lib/api/admin';

	let { data } = $props();

	type SortKey =
		| 'path'
		| 'total_24h'
		| 'success_rate'
		| 'errors'
		| 'p50'
		| 'p95'
		| 'p99';

	let sortKey = $state<SortKey>('total_24h');
	let sortDir = $state<'asc' | 'desc'>('desc');

	// Pull the successRate derivation out so the table row + sort agree.
	const successRate = (r: RouteStatsResponse): number | null =>
		r.total_24h === 0 ? null : r.success_24h / r.total_24h;

	const errors24h = (r: RouteStatsResponse): number =>
		r.client_error_24h + r.server_error_24h;

	function valueFor(r: RouteStatsResponse, key: SortKey): number | string | null {
		switch (key) {
			case 'path':
				return `${r.method} ${r.path}`;
			case 'total_24h':
				return r.total_24h;
			case 'success_rate':
				return successRate(r);
			case 'errors':
				return errors24h(r);
			case 'p50':
				return r.latency_ms_p50_24h;
			case 'p95':
				return r.latency_ms_p95_24h;
			case 'p99':
				return r.latency_ms_p99_24h;
		}
	}

	// Sort with nulls always pushed to the bottom regardless of direction —
	// a route with no 24h latency samples should never outrank one with data.
	const sortedRoutes = $derived.by(() => {
		const rows = [...data.routes];
		const dir = sortDir === 'asc' ? 1 : -1;
		rows.sort((a, b) => {
			const av = valueFor(a, sortKey);
			const bv = valueFor(b, sortKey);
			if (av === null && bv === null) return 0;
			if (av === null) return 1;
			if (bv === null) return -1;
			if (typeof av === 'string' && typeof bv === 'string') {
				return av.localeCompare(bv) * dir;
			}
			return ((av as number) - (bv as number)) * dir;
		});
		return rows;
	});

	function setSort(key: SortKey) {
		if (sortKey === key) {
			sortDir = sortDir === 'asc' ? 'desc' : 'asc';
		} else {
			sortKey = key;
			// Path defaults to ascending (alphabetical); numeric columns to
			// descending ("show the biggest first").
			sortDir = key === 'path' ? 'asc' : 'desc';
		}
	}

	const arrow = (key: SortKey) =>
		sortKey === key ? (sortDir === 'asc' ? ' ↑' : ' ↓') : '';

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

	const totalRequests24h = $derived(
		data.routes.reduce((acc, r) => acc + r.total_24h, 0)
	);
	const totalErrors24h = $derived(
		data.routes.reduce((acc, r) => acc + errors24h(r), 0)
	);
</script>

<div class="max-w-4xl mx-auto px-6 py-6">
	<p class="text-sm text-text-muted mb-4">
		Per-route request stats from the last 24 hours. Counts reset on server restart.
	</p>

	<div class="text-xs text-text-muted mb-4 flex flex-wrap items-center gap-x-4 gap-y-1">
		<span><span class="text-text-secondary">{fmtCount(totalRequests24h)}</span> requests (24h)</span>
		<span><span class="text-text-secondary">{fmtCount(totalErrors24h)}</span> errors (24h)</span>
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
							<button
								type="button"
								class="hover:text-text-secondary"
								onclick={() => setSort('path')}
							>
								Route{arrow('path')}
							</button>
						</th>
						<th class="text-right font-medium px-3 py-2">
							<button
								type="button"
								class="hover:text-text-secondary"
								onclick={() => setSort('total_24h')}
							>
								Requests{arrow('total_24h')}
							</button>
						</th>
						<th class="text-right font-medium px-3 py-2">
							<button
								type="button"
								class="hover:text-text-secondary"
								onclick={() => setSort('success_rate')}
							>
								Success{arrow('success_rate')}
							</button>
						</th>
						<th class="text-right font-medium px-3 py-2">
							<button
								type="button"
								class="hover:text-text-secondary"
								onclick={() => setSort('errors')}
							>
								Errors{arrow('errors')}
							</button>
						</th>
						<th class="text-right font-medium px-3 py-2">
							<button
								type="button"
								class="hover:text-text-secondary"
								onclick={() => setSort('p50')}
							>
								p50 ms{arrow('p50')}
							</button>
						</th>
						<th class="text-right font-medium px-3 py-2">
							<button
								type="button"
								class="hover:text-text-secondary"
								onclick={() => setSort('p95')}
							>
								p95 ms{arrow('p95')}
							</button>
						</th>
						<th class="text-right font-medium px-3 py-2">
							<button
								type="button"
								class="hover:text-text-secondary"
								onclick={() => setSort('p99')}
							>
								p99 ms{arrow('p99')}
							</button>
						</th>
					</tr>
				</thead>
				<tbody>
					{#each sortedRoutes as r (r.method + ' ' + r.path)}
						{@const total = r.total_24h}
						{@const rate = successRate(r)}
						{@const errs = errors24h(r)}
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
								{:else if rate >= 0.99}
									<span class="text-text-secondary">{fmtPct(rate)}</span>
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
</div>
