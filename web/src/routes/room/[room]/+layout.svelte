<script lang="ts">
	import { topRooms, type RoomSummary } from '$lib/api/rooms';
	import { page } from '$app/state';
	import { session } from '$lib/stores/session.svelte';

	let { children } = $props();

	let rooms = $state<RoomSummary[]>([]);

	$effect(() => {
		topRooms().then((r) => (rooms = r));
	});

	let currentSlug = $derived(page.params.room);
</script>

{#if session.isLoggedIn}
<div class="bg-bg-surface-dim border-b border-border-subtle">
	<div class="max-w-4xl mx-auto px-6 flex items-center gap-0 overflow-x-auto">
		<a
			href="/room/all"
			class="text-sm px-4 py-2.5 border-b-2 whitespace-nowrap transition-colors duration-150
				{currentSlug === 'all'
				? 'text-accent border-accent font-semibold'
				: 'text-text-secondary border-transparent hover:text-text-primary'}"
		>
			All
		</a>
		{#each rooms as room (room.slug)}
			<a
				href="/room/{encodeURIComponent(room.slug)}"
				class="text-sm px-4 py-2.5 border-b-2 whitespace-nowrap transition-colors duration-150
					{currentSlug === room.slug
					? 'text-accent border-accent font-semibold'
					: 'text-text-secondary border-transparent hover:text-text-primary'}"
			>
				{room.name}
			</a>
		{/each}
		<a
			href="/rooms"
			class="ml-auto text-text-muted text-xs no-underline hover:text-text-secondary hover:underline whitespace-nowrap py-3 pl-4"
		>
			All Rooms
		</a>
	</div>
</div>
{/if}

{@render children()}
