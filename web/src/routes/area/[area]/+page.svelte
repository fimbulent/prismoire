<script lang="ts">
	import { getArea, type Area } from '$lib/api/areas';
	import { relativeTime } from '$lib/format';
	import { page } from '$app/state';

	let area = $state<Area | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	$effect(() => {
		const name = page.params.area;
		if (name) loadArea(name);
	});

	async function loadArea(name: string) {
		loading = true;
		error = null;
		try {
			area = await getArea(name);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load area';
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>{area ? `${area.name} — Prismoire` : 'Area — Prismoire'}</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-4 pb-2 text-sm text-text-muted">
	<a href="/" class="hover:text-text-secondary">All Areas</a>
	{#if area}
		<span class="mx-1">/</span>
		<span class="text-text-secondary">{area.name}</span>
	{/if}
</div>

<div class="max-w-4xl mx-auto px-6 pb-16">
	{#if loading}
		<div class="text-center text-text-muted py-12">Loading area…</div>
	{:else if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else if area}
		<div class="pt-2 pb-6">
			<h1 class="text-xl font-bold mb-1">{area.name}</h1>
			{#if area.description}
				<p class="text-sm text-text-secondary">{area.description}</p>
			{/if}
			<div class="flex items-center gap-4 text-xs text-text-muted mt-3">
				<span>Created by <span class="text-text-secondary">{area.created_by_name}</span></span>
				<span>{area.thread_count} {area.thread_count === 1 ? 'thread' : 'threads'}</span>
				<span>{area.post_count} {area.post_count === 1 ? 'post' : 'posts'}</span>
				{#if area.last_activity}
					<span
						>Last active <span class="text-text-secondary"
							>{relativeTime(area.last_activity)}</span
						></span
					>
				{/if}
			</div>
		</div>

		<div class="text-center text-text-muted py-12 border border-border-subtle rounded-md bg-bg-surface">
			No threads yet. Threads are coming soon.
		</div>
	{/if}
</div>
