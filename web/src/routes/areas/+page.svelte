<script lang="ts">
	import { listAreas, type Area } from '$lib/api/areas';
	import { session } from '$lib/stores/session.svelte';
	import { relativeTime } from '$lib/format';
	import { goto } from '$app/navigation';

	let areas = $state<Area[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let searchQuery = $state('');

	$effect(() => {
		loadAreas();
	});

	async function loadAreas() {
		loading = true;
		error = null;
		try {
			areas = await listAreas();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load areas';
		} finally {
			loading = false;
		}
	}

	let filteredAreas = $derived(
		searchQuery.trim()
			? areas.filter(
					(a) =>
						a.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
						a.description.toLowerCase().includes(searchQuery.toLowerCase())
				)
			: areas
	);
</script>

<svelte:head>
	<title>All Areas — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-4 flex items-center justify-between">
	<h1 class="text-xl font-bold">All Areas</h1>
	{#if session.isLoggedIn}
		<button
			onclick={() => goto('/area/new')}
			class="text-sm px-3 py-1.5 rounded-md cursor-pointer border border-accent bg-accent text-bg font-medium hover:opacity-90"
		>
			New Area
		</button>
	{/if}
</div>

<div class="max-w-4xl mx-auto px-6 pb-5">
	<input
		type="text"
		placeholder="Search areas..."
		bind:value={searchQuery}
		class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted"
	/>
</div>

<div class="max-w-4xl mx-auto px-6 pb-16">
	{#if loading}
		<div class="text-center text-text-muted py-12">Loading areas…</div>
	{:else if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else if filteredAreas.length === 0}
		<div class="text-center text-text-muted py-12">
			{#if searchQuery.trim()}
				No areas match your search.
			{:else}
				No areas yet. Be the first to create one!
			{/if}
		</div>
	{:else}
		<div class="space-y-3">
			{#each filteredAreas as area (area.id)}
				<a
					href="/area/{encodeURIComponent(area.slug)}"
					class="block border border-border rounded-md p-5 bg-bg-surface no-underline transition-[background,border-color] duration-150 hover:bg-bg-hover hover:border-accent-muted"
				>
					<div class="mb-1.5">
						<h3 class="text-base font-bold text-text-primary">{area.name}</h3>
					</div>
					{#if area.description}
						<p class="text-sm text-text-secondary mb-3">{area.description}</p>
					{/if}
					<div class="flex items-center gap-4 text-xs text-text-muted">
						<span
							>{area.thread_count}
							{area.thread_count === 1 ? 'thread' : 'threads'}</span
						>
						<span>{area.post_count} {area.post_count === 1 ? 'post' : 'posts'}</span>
						{#if area.last_activity}
							<span
								>Last active <span class="text-text-secondary"
									>{relativeTime(area.last_activity)}</span
								></span
							>
						{/if}
					</div>
				</a>
			{/each}
		</div>
	{/if}
</div>
