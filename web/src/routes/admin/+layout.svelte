<script lang="ts">
	import { page } from '$app/state';

	let { data, children } = $props();

	// Pick the active tab from the route path. `/admin` → overview,
	// `/admin/reports` → reports, `/admin/watchlists` → watchlists.
	const tab = $derived.by(() => {
		const seg = page.url.pathname.split('/')[2] ?? '';
		if (seg === 'reports') return 'reports';
		if (seg === 'watchlists') return 'watchlists';
		if (seg === 'actions') return 'actions';
		if (seg === 'routes') return 'routes';
		return 'overview';
	});

	const tabClass = (active: boolean) =>
		`font-sans text-sm px-4 py-2 border-b-2 transition-colors whitespace-nowrap no-underline ${
			active
				? 'text-accent border-b-accent font-semibold'
				: 'text-text-muted border-b-transparent hover:text-text-secondary'
		}`;
</script>

<svelte:head>
	<title>Admin Dashboard — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-0">
	<h1 class="text-xl font-bold mb-4">Admin Dashboard</h1>
	<div class="flex border-b border-border gap-1 overflow-x-auto">
		<a href="/admin" class={tabClass(tab === 'overview')}>Overview</a>
		<a href="/admin/reports" class={tabClass(tab === 'reports')}>
			Reports
			{#if data.pendingReports > 0}
				<span
					class="inline-flex items-center justify-center text-xs font-bold rounded-full px-1.5 py-0.5 ml-1 bg-danger/20 text-danger min-w-5"
				>
					{data.pendingReports}
				</span>
			{/if}
		</a>
		<a href="/admin/watchlists" class={tabClass(tab === 'watchlists')}>Watchlists</a>
		<a href="/admin/actions" class={tabClass(tab === 'actions')}>Actions</a>
		<a href="/admin/routes" class={tabClass(tab === 'routes')}>Routes</a>
	</div>
</div>

{@render children()}
