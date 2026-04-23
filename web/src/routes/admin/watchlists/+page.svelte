<script lang="ts">
	import type { UserChip } from '$lib/api/admin';
	import { relativeTime } from '$lib/format';

	let { data } = $props();

	const w = $derived(data.watchlists);
	const t = $derived(w.thresholds);

	// Renders ∞ for divide-by-zero ratios (trusts == 0 while distrusts
	// exist). The backend sends `null` for those rows.
	function fmtRatio(ratio: number | null): string {
		if (ratio === null) return '∞';
		if (ratio >= 10) return ratio.toFixed(0);
		return ratio.toFixed(1);
	}

	function fmtPct(v: number | null): string {
		if (v === null) return '—';
		return `${Math.round(v * 100)}%`;
	}

	// Color the ratio cell by severity.
	function ratioClass(ratio: number | null): string {
		if (ratio === null) return 'text-danger';
		if (ratio >= 3) return 'text-danger';
		if (ratio >= 1) return 'text-warning';
		return 'text-text-secondary';
	}

	function hitRateClass(rate: number | null): string {
		if (rate === null) return 'text-text-muted';
		if (rate >= 0.5) return 'text-danger';
		if (rate >= 0.25) return 'text-warning';
		return 'text-text-secondary';
	}
</script>

{#snippet userChip(user: UserChip)}
	<a
		href="/@{encodeURIComponent(user.display_name)}"
		class="text-text-primary no-underline hover:underline font-medium"
	>
		{user.display_name}
	</a>
	{#if user.status === 'suspended'}
		<span
			class="inline-block text-xs px-1.5 py-0.5 rounded font-semibold bg-danger/15 text-danger align-middle ml-1"
		>
			suspended
		</span>
	{/if}
{/snippet}

<div class="max-w-4xl mx-auto px-6 py-6 space-y-5">
	<!-- Most Distrusted Users -->
	<section class="bg-bg-surface border border-border rounded-md p-5">
		<div
			class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2"
		>
			Most Distrusted Users
		</div>
		<div class="text-xs text-text-muted mb-3">
			Users ranked by number of inbound distrusts. Showing users distrusted by
			at least {t.min_inbound_distrusts} other users. Excludes banned users.
		</div>
		{#if w.most_distrusted.length === 0}
			<div class="text-xs text-text-muted italic">No users cross the threshold.</div>
		{:else}
			<table class="w-full text-sm">
				<thead>
					<tr
						class="border-b border-border-subtle text-xs text-text-muted uppercase tracking-wider"
					>
						<th class="text-left py-2 pr-3 font-semibold w-8">#</th>
						<th class="text-left py-2 pr-3 font-semibold">User</th>
						<th class="text-right py-2 pr-3 font-semibold">Distrusts</th>
						<th class="text-right py-2 pr-3 font-semibold">Trusts</th>
						<th class="text-right py-2 font-semibold">Ratio</th>
					</tr>
				</thead>
				<tbody>
					{#each w.most_distrusted as row, i (row.user.id)}
						<tr class="border-b border-border-subtle last:border-0 hover:bg-bg-hover">
							<td class="py-2 pr-3 text-text-muted">{i + 1}</td>
							<td class="py-2 pr-3">{@render userChip(row.user)}</td>
							<td class="py-2 pr-3 text-right font-mono text-danger tabular-nums">
								{row.inbound_distrusts}
							</td>
							<td class="py-2 pr-3 text-right font-mono text-text-muted tabular-nums">
								{row.inbound_trusts}
							</td>
							<td
								class={`py-2 text-right font-mono tabular-nums ${ratioClass(row.ratio)}`}
							>
								{fmtRatio(row.ratio)}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</section>

	<!-- Highest Distrust:Trust Ratio -->
	<section class="bg-bg-surface border border-border rounded-md p-5">
		<div
			class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2"
		>
			Highest Distrust:Trust Ratio
		</div>
		<div class="text-xs text-text-muted mb-3">
			Users where inbound distrusts significantly outweigh inbound trusts. May
			indicate problematic behavior. Showing users with at least
			{t.min_inbound_edges_for_ratio} total inbound edges. Excludes banned users.
		</div>
		{#if w.distrust_trust_ratio.length === 0}
			<div class="text-xs text-text-muted italic">No users cross the threshold.</div>
		{:else}
			<table class="w-full text-sm">
				<thead>
					<tr
						class="border-b border-border-subtle text-xs text-text-muted uppercase tracking-wider"
					>
						<th class="text-left py-2 pr-3 font-semibold w-8">#</th>
						<th class="text-left py-2 pr-3 font-semibold">User</th>
						<th class="text-right py-2 pr-3 font-semibold">D:T Ratio</th>
						<th class="text-right py-2 pr-3 font-semibold">Posts</th>
						<th class="text-right py-2 font-semibold">Joined</th>
					</tr>
				</thead>
				<tbody>
					{#each w.distrust_trust_ratio as row, i (row.user.id)}
						<tr class="border-b border-border-subtle last:border-0 hover:bg-bg-hover">
							<td class="py-2 pr-3 text-text-muted">{i + 1}</td>
							<td class="py-2 pr-3">{@render userChip(row.user)}</td>
							<td
								class={`py-2 pr-3 text-right font-mono tabular-nums ${ratioClass(row.ratio)}`}
							>
								{fmtRatio(row.ratio)}
							</td>
							<td class="py-2 pr-3 text-right font-mono text-text-muted tabular-nums">
								{row.post_count}
							</td>
							<td class="py-2 text-right text-text-muted">
								{relativeTime(row.joined_at)}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</section>

	<!-- Ban-Adjacent Trusters -->
	<section class="bg-bg-surface border border-border rounded-md p-5">
		<div
			class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2"
		>
			Ban-Adjacent Trusters
		</div>
		<div class="text-xs text-text-muted mb-3">
			Users ranked by what fraction of their current outbound trust edges
			targeted users who were later banned or suspended. High ratios may
			indicate sybil collusion. Based on ban trust snapshots; showing users with
			at least {t.min_trusts_issued_for_ban_adjacent} current outbound trusts.
			Excludes banned users.
		</div>
		{#if w.ban_adjacent_trusters.length === 0}
			<div class="text-xs text-text-muted italic">No users cross the threshold.</div>
		{:else}
			<table class="w-full text-sm">
				<thead>
					<tr
						class="border-b border-border-subtle text-xs text-text-muted uppercase tracking-wider"
					>
						<th class="text-left py-2 pr-3 font-semibold w-8">#</th>
						<th class="text-left py-2 pr-3 font-semibold">User</th>
						<th class="text-right py-2 pr-3 font-semibold">Banned Trusts</th>
						<th class="text-right py-2 pr-3 font-semibold">Total Trusts</th>
						<th class="text-right py-2 font-semibold">Hit Rate</th>
					</tr>
				</thead>
				<tbody>
					{#each w.ban_adjacent_trusters as row, i (row.user.id)}
						<tr class="border-b border-border-subtle last:border-0 hover:bg-bg-hover">
							<td class="py-2 pr-3 text-text-muted">{i + 1}</td>
							<td class="py-2 pr-3">{@render userChip(row.user)}</td>
							<td class="py-2 pr-3 text-right font-mono text-danger tabular-nums">
								{row.banned_trusts}
							</td>
							<td class="py-2 pr-3 text-right font-mono text-text-muted tabular-nums">
								{row.total_trusts}
							</td>
							<td
								class={`py-2 text-right font-mono font-semibold tabular-nums ${hitRateClass(row.hit_rate)}`}
							>
								{fmtPct(row.hit_rate)}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</section>
</div>
