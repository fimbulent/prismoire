<script lang="ts">
	import { listTopics, type Topic } from '$lib/api/topics';
	import { session } from '$lib/stores/session.svelte';
	import { relativeTime } from '$lib/format';
	import { goto } from '$app/navigation';

	let topics = $state<Topic[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let searchQuery = $state('');

	$effect(() => {
		loadTopics();
	});

	async function loadTopics() {
		loading = true;
		error = null;
		try {
			topics = await listTopics();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load topics';
		} finally {
			loading = false;
		}
	}

	let filteredTopics = $derived(
		searchQuery.trim()
			? topics.filter(
					(t) =>
						t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
						t.description.toLowerCase().includes(searchQuery.toLowerCase())
				)
			: topics
	);
</script>

<svelte:head>
	<title>All Topics — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-4 flex items-center justify-between">
	<h1 class="text-xl font-bold">All Topics</h1>
	{#if session.isLoggedIn}
		<button
			onclick={() => goto('/t/new')}
			class="text-sm px-3 py-1.5 rounded-md cursor-pointer border border-accent bg-accent text-bg font-medium hover:opacity-90"
		>
			New Topic
		</button>
	{/if}
</div>

<div class="max-w-4xl mx-auto px-6 pb-5">
	<input
		type="text"
		placeholder="Search topics..."
		bind:value={searchQuery}
		class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted"
	/>
</div>

<div class="max-w-4xl mx-auto px-6 pb-16">
	{#if loading}
		<div class="text-center text-text-muted py-12">Loading topics…</div>
	{:else if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else if filteredTopics.length === 0}
		<div class="text-center text-text-muted py-12">
			{#if searchQuery.trim()}
				No topics match your search.
			{:else}
				No topics yet. Be the first to create one!
			{/if}
		</div>
	{:else}
		<div class="space-y-3">
			{#each filteredTopics as topic (topic.id)}
				<a
					href="/t/{encodeURIComponent(topic.slug)}"
					class="block border border-border rounded-md p-5 bg-bg-surface no-underline transition-[background,border-color] duration-150 hover:bg-bg-hover hover:border-accent-muted"
				>
					<div class="mb-1.5">
						<h3 class="text-base font-bold text-text-primary">{topic.name}</h3>
					</div>
					{#if topic.description}
						<p class="text-sm text-text-secondary mb-3">{topic.description}</p>
					{/if}
					<div class="flex items-center gap-4 text-xs text-text-muted">
						<span
							>{topic.thread_count}
							{topic.thread_count === 1 ? 'thread' : 'threads'}</span
						>
						<span>{topic.post_count} {topic.post_count === 1 ? 'post' : 'posts'}</span>
						{#if topic.last_activity}
							<span
								>Last active <span class="text-text-secondary"
									>{relativeTime(topic.last_activity)}</span
								></span
							>
						{/if}
					</div>
				</a>
			{/each}
		</div>
	{/if}
</div>
