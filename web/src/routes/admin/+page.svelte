<script lang="ts">
	import BarChart from '$lib/components/charts/BarChart.svelte';
	import { relativeTime } from '$lib/format';

	let { data } = $props();
	const overview = $derived(data.overview);

	// Posts per day: label with the day-of-month of each ISO date.
	const postsPerDayChart = $derived(
		overview.posts_per_day.map((d) => ({
			label: String(new Date(d.date + 'T00:00:00Z').getUTCDate()),
			value: d.count
		}))
	);

	// New users per week: label as W1..W7 with the final bar labeled "Now".
	const newUsersPerWeekChart = $derived(
		overview.new_users_per_week.map((w, i, arr) => ({
			label: i === arr.length - 1 ? 'Now' : `W${i + 1}`,
			value: w.count
		}))
	);

	const totalPostsInWindow = $derived(
		overview.posts_per_day.reduce((sum, d) => sum + d.count, 0)
	);
	const newUsersThisWeek = $derived(
		overview.new_users_per_week.at(-1)?.count ?? 0
	);

	const activeDelta = $derived(overview.active_users_7d - overview.active_users_prev_7d);
</script>

<div class="max-w-4xl mx-auto px-6 py-6">
	<!-- Stat cards -->
	<div class="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-6">
		<div class="bg-bg-surface border border-border rounded-md px-5 py-4">
			<div class="text-[0.7rem] uppercase tracking-wider text-text-muted">Total Users</div>
			<div class="text-2xl font-bold text-text-primary">{overview.total_users}</div>
			{#if overview.new_users_7d > 0}
				<div class="text-xs font-semibold text-success mt-0.5">
					+{overview.new_users_7d} this week
				</div>
			{:else}
				<div class="text-xs text-text-muted mt-0.5">no new users this week</div>
			{/if}
		</div>

		<div class="bg-bg-surface border border-border rounded-md px-5 py-4">
			<div class="text-[0.7rem] uppercase tracking-wider text-text-muted">Active Users (7d)</div>
			<div class="text-2xl font-bold text-text-primary">{overview.active_users_7d}</div>
			{#if activeDelta > 0}
				<div class="text-xs font-semibold text-success mt-0.5">+{activeDelta} vs last week</div>
			{:else if activeDelta < 0}
				<div class="text-xs font-semibold text-danger mt-0.5">{activeDelta} vs last week</div>
			{:else}
				<div class="text-xs text-text-muted mt-0.5">no change vs last week</div>
			{/if}
		</div>

		<div class="bg-bg-surface border border-border rounded-md px-5 py-4">
			<div class="text-[0.7rem] uppercase tracking-wider text-text-muted">Posts Today</div>
			<div class="text-2xl font-bold text-text-primary">{overview.posts_today}</div>
			<div class="text-xs text-text-muted mt-0.5">
				avg {(overview.posts_7d / 7).toFixed(1)}/day (7d)
			</div>
		</div>

		<div class="bg-bg-surface border border-border rounded-md px-5 py-4">
			<div class="text-[0.7rem] uppercase tracking-wider text-text-muted">Threads Today</div>
			<div class="text-2xl font-bold text-text-primary">{overview.threads_today}</div>
			<div class="text-xs text-text-muted mt-0.5">
				avg {(overview.threads_7d / 7).toFixed(1)}/day (7d)
			</div>
		</div>

		<div class="bg-bg-surface border border-border rounded-md px-5 py-4">
			<div class="text-[0.7rem] uppercase tracking-wider text-text-muted">Rooms</div>
			<div class="text-2xl font-bold text-text-primary">{overview.total_rooms}</div>
			<div class="text-xs text-text-muted mt-0.5">
				{overview.empty_rooms}
				{overview.empty_rooms === 1 ? 'empty' : 'empty'}
			</div>
		</div>

		<div class="bg-bg-surface border border-border rounded-md px-5 py-4">
			<div class="text-[0.7rem] uppercase tracking-wider text-text-muted">Pending Reports</div>
			<div
				class="text-2xl font-bold {overview.pending_reports > 0
					? 'text-danger'
					: 'text-text-primary'}"
			>
				{overview.pending_reports}
			</div>
			{#if overview.pending_reports > 0 && overview.oldest_pending_report_at}
				<div class="text-xs text-text-muted mt-0.5">
					oldest: {relativeTime(overview.oldest_pending_report_at)}
				</div>
			{:else}
				<div class="text-xs text-text-muted mt-0.5">all resolved</div>
			{/if}
		</div>
	</div>

	<!-- Charts -->
	<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
		<div class="bg-bg-surface border border-border rounded-md p-4">
			<div class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
				Posts per day (14d)
			</div>
			<BarChart data={postsPerDayChart} caption={`Total: ${totalPostsInWindow} posts`} />
		</div>

		<div class="bg-bg-surface border border-border rounded-md p-4">
			<div class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
				New users per week (8w)
			</div>
			<BarChart
				data={newUsersPerWeekChart}
				caption={`This week: ${newUsersThisWeek} new ${newUsersThisWeek === 1 ? 'user' : 'users'}`}
			/>
		</div>
	</div>

	<!-- Trust graph health -->
	<div class="bg-bg-surface border border-border rounded-md p-5 mb-6">
		<div class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
			Trust Graph Health
		</div>
		<div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
			<div>
				<div class="text-lg font-bold text-text-primary">
					{overview.trust.trust_edges.toLocaleString()}
				</div>
				<div class="text-xs text-text-muted">Trust edges</div>
			</div>
			<div>
				<div class="text-lg font-bold text-text-primary">
					{overview.trust.distrust_edges.toLocaleString()}
				</div>
				<div class="text-xs text-text-muted">Distrust edges</div>
			</div>
			<div>
				<div class="text-lg font-bold text-text-primary">
					{overview.trust.avg_trusts_per_user.toFixed(1)}
				</div>
				<div class="text-xs text-text-muted">Avg trusts/user</div>
			</div>
			<div>
				<div class="text-lg font-bold text-text-primary">
					{overview.trust.avg_distrusts_per_user.toFixed(1)}
				</div>
				<div class="text-xs text-text-muted">Avg distrusts/user</div>
			</div>
		</div>
		<div
			class="mt-4 pt-3 border-t border-border-subtle flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted"
		>
			<span>
				Last trust recomputation:
				<span class="text-text-secondary">
					{overview.trust.last_rebuild_at
						? relativeTime(overview.trust.last_rebuild_at)
						: '—'}
				</span>
			</span>
			<span>
				BFS cache hit rate:
				<span class="text-text-secondary">
					{overview.trust.bfs_cache_hit_rate !== null
						? `${(overview.trust.bfs_cache_hit_rate * 100).toFixed(1)}%`
						: '—'}
				</span>
			</span>
			<span>
				Graph load time:
				<span class="text-text-secondary">
					{overview.trust.graph_load_ms_p50 !== null
						? `${overview.trust.graph_load_ms_p50.toFixed(1)}ms`
						: '—'}
				</span>
			</span>
		</div>
	</div>

	<!-- Sessions & auth -->
	<div class="bg-bg-surface border border-border rounded-md p-5">
		<div class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
			Sessions &amp; Auth
		</div>
		<div class="grid grid-cols-3 gap-4">
			<div>
				<div class="text-lg font-bold text-text-primary">
					{overview.sessions.active_sessions}
				</div>
				<div class="text-xs text-text-muted">Active sessions</div>
			</div>
			<div>
				<div class="text-lg font-bold text-text-primary">{overview.sessions.logins_today}</div>
				<div class="text-xs text-text-muted">Logins today</div>
			</div>
			<div>
				<div class="text-lg font-bold text-text-primary">{overview.sessions.failed_auth_24h}</div>
				<div class="text-xs text-text-muted">Failed auth (24h)</div>
			</div>
		</div>
	</div>
</div>
