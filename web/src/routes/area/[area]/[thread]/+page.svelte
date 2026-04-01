<script lang="ts">
	import { getThread, type ThreadDetail } from '$lib/api/threads';
	import { relativeTime } from '$lib/format';
	import { page } from '$app/state';

	let thread = $state<ThreadDetail | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	$effect(() => {
		const threadId = page.params.thread;
		if (threadId) loadThread(threadId);
	});

	async function loadThread(id: string) {
		loading = true;
		error = null;
		try {
			thread = await getThread(id);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load thread';
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>{thread ? `${thread.title} — Prismoire` : 'Thread — Prismoire'}</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 py-4 text-sm text-text-muted">
	<a href="/areas" class="hover:text-text-secondary">All Areas</a>
	{#if thread}
		<span class="mx-1">/</span>
		<a
			href="/area/{encodeURIComponent(thread.area_slug)}"
			class="hover:text-text-secondary"
		>{thread.area_name}</a
		>
		<span class="mx-1">/</span>
		<span class="text-text-secondary">{thread.title}</span>
	{/if}
</div>

<div class="max-w-4xl mx-auto px-6 pb-16">
	{#if loading}
		<div class="text-center text-text-muted py-12">Loading thread…</div>
	{:else if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else if thread}
		<div class="bg-bg-surface border border-border rounded-md p-5 mb-6">
			<h1 class="text-2xl font-bold leading-tight mb-2">{thread.title}</h1>
			<div class="flex items-center gap-2 mb-3 text-sm">
				<span
					class="font-semibold text-text-primary bg-bg-surface-raised px-2 py-0.5 rounded border border-border"
					>{thread.post.author_name}</span
				>
				<span
					class="text-xs font-bold px-1.5 py-0.5 rounded border border-accent-muted text-accent uppercase tracking-wider"
					>op</span
				>
				<span class="text-text-muted text-xs"
					>{relativeTime(thread.created_at)}</span
				>
			</div>
			<div class="text-base leading-7 whitespace-pre-wrap">{thread.post.body}</div>
		</div>

		{#if thread.reply_count > 0}
			<div class="text-sm text-text-muted py-4">
				{thread.reply_count}
				{thread.reply_count === 1 ? 'reply' : 'replies'}
			</div>
		{:else}
			<div class="text-center text-text-muted py-8">
				No replies yet.
			</div>
		{/if}
	{/if}
</div>
