<script lang="ts">
	import { topAreas, type AreaSummary } from '$lib/api/areas';
	import { page } from '$app/state';

	let { children } = $props();

	let areas = $state<AreaSummary[]>([]);

	$effect(() => {
		topAreas().then((a) => (areas = a));
	});

	let currentSlug = $derived(page.params.area);
</script>

<div class="bg-bg-surface-dim border-b border-border-subtle">
	<div class="max-w-4xl mx-auto px-6 flex items-center gap-0 overflow-x-auto">
		<a
			href="/area/all"
			class="text-sm px-4 py-2.5 border-b-2 whitespace-nowrap transition-colors duration-150
				{currentSlug === 'all'
				? 'text-accent border-accent font-semibold'
				: 'text-text-secondary border-transparent hover:text-text-primary'}"
		>
			All
		</a>
		{#each areas as area (area.slug)}
			<a
				href="/area/{encodeURIComponent(area.slug)}"
				class="text-sm px-4 py-2.5 border-b-2 whitespace-nowrap transition-colors duration-150
					{currentSlug === area.slug
					? 'text-accent border-accent font-semibold'
					: 'text-text-secondary border-transparent hover:text-text-primary'}"
			>
				{area.name}
			</a>
		{/each}
		<a
			href="/areas"
			class="ml-auto text-text-muted text-xs no-underline hover:text-text-secondary hover:underline whitespace-nowrap py-3 pl-4"
		>
			All Areas
		</a>
	</div>
</div>

{@render children()}
