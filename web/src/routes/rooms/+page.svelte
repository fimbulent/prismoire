<script lang="ts">
	import { session } from '$lib/stores/session.svelte';
	import { relativeTime } from '$lib/format';
	import { goto } from '$app/navigation';
	import Badge from '$lib/components/ui/Badge.svelte';

	let { data } = $props();
	let rooms = $derived(data.rooms);
	let searchQuery = $state('');

	let filteredRooms = $derived(
		searchQuery.trim()
			? rooms.filter((r) => r.slug.includes(searchQuery.trim().toLowerCase()))
			: rooms
	);
</script>

<svelte:head>
	<title>All Rooms — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-4 flex items-center justify-between">
	<h1 class="text-xl font-bold">All Rooms</h1>
	{#if session.isLoggedIn}
		<button
			onclick={() => goto('/thread/new')}
			class="text-sm px-3 py-1.5 rounded-md cursor-pointer border border-accent bg-accent text-bg font-medium hover:opacity-90"
		>
			New Thread
		</button>
	{/if}
</div>

<div class="max-w-4xl mx-auto px-6 pb-5">
	<input
		type="text"
		placeholder="Search rooms..."
		bind:value={searchQuery}
		class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted"
	/>
</div>

<div class="max-w-4xl mx-auto px-6 pb-16">
	{#if filteredRooms.length === 0}
		<div class="text-center text-text-muted py-12">
			{#if searchQuery.trim()}
				No rooms match your search.
			{:else}
				No rooms yet.
			{/if}
		</div>
	{:else}
		<div class="space-y-3">
			{#each filteredRooms as room (room.id)}
				<a
					href="/room/{encodeURIComponent(room.slug)}"
					class="block border border-border rounded-md p-5 bg-bg-surface no-underline transition-[background,border-color] duration-150 hover:bg-bg-hover hover:border-accent-muted"
				>
					<div class="mb-1.5 flex items-center gap-2">
						<h3 class="text-base font-bold text-text-primary">{room.slug}</h3>
						{#if room.is_announcement}
							<Badge>Announcements</Badge>
						{/if}
					</div>
					<div class="flex items-center gap-4 text-xs text-text-muted">
						<span
							>{room.thread_count}
							{room.thread_count === 1 ? 'thread' : 'threads'}</span
						>
						<span>{room.post_count} {room.post_count === 1 ? 'post' : 'posts'}</span>
						{#if room.last_activity}
							<span
								>Last active <span class="text-text-secondary"
									>{relativeTime(room.last_activity)}</span
								></span
							>
						{/if}
					</div>
				</a>
			{/each}
		</div>
	{/if}
</div>
