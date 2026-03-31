<script lang="ts">
	import { getTopic, type Topic } from '$lib/api/topics';
	import { relativeTime } from '$lib/format';
	import { page } from '$app/state';

	let topic = $state<Topic | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	$effect(() => {
		const name = page.params.topic;
		if (name) loadTopic(name);
	});

	async function loadTopic(name: string) {
		loading = true;
		error = null;
		try {
			topic = await getTopic(name);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load topic';
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>{topic ? `${topic.name} — Prismoire` : 'Topic — Prismoire'}</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-4 pb-2 text-sm text-text-muted">
	<a href="/" class="hover:text-text-secondary">All Topics</a>
	{#if topic}
		<span class="mx-1">/</span>
		<span class="text-text-secondary">{topic.name}</span>
	{/if}
</div>

<div class="max-w-4xl mx-auto px-6 pb-16">
	{#if loading}
		<div class="text-center text-text-muted py-12">Loading topic…</div>
	{:else if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else if topic}
		<div class="pt-2 pb-6">
			<h1 class="text-xl font-bold mb-1">{topic.name}</h1>
			{#if topic.description}
				<p class="text-sm text-text-secondary">{topic.description}</p>
			{/if}
			<div class="flex items-center gap-4 text-xs text-text-muted mt-3">
				<span>Created by <span class="text-text-secondary">{topic.created_by_name}</span></span>
				<span>{topic.thread_count} {topic.thread_count === 1 ? 'thread' : 'threads'}</span>
				<span>{topic.post_count} {topic.post_count === 1 ? 'post' : 'posts'}</span>
				{#if topic.last_activity}
					<span
						>Last active <span class="text-text-secondary"
							>{relativeTime(topic.last_activity)}</span
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
