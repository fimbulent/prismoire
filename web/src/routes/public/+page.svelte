<script lang="ts">
	import { listPublicThreads, type ThreadSummary } from '$lib/api/threads';
	import { relativeTime } from '$lib/format';
	import { session } from '$lib/stores/session.svelte';
	import { goto } from '$app/navigation';
	import Badge from '$lib/components/ui/Badge.svelte';
	import LockIcon from '$lib/components/ui/LockIcon.svelte';
	import UserName from '$lib/components/trust/UserName.svelte';
	import MoreButton from '$lib/components/ui/MoreButton.svelte';

	let threads = $state<ThreadSummary[]>([]);
	let nextCursor = $state<string | null>(null);
	let loadingMore = $state(false);
	let loading = $state(true);
	let error = $state<string | null>(null);

	$effect(() => {
		if (session.loading) return;
		if (session.isLoggedIn) {
			goto('/room/all', { replaceState: true });
			return;
		}
		load();
	});

	async function load() {
		loading = true;
		error = null;
		try {
			const res = await listPublicThreads();
			threads = res.threads;
			nextCursor = res.next_cursor;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load';
		} finally {
			loading = false;
		}
	}

	async function loadMore() {
		if (!nextCursor || loadingMore) return;
		loadingMore = true;
		try {
			const res = await listPublicThreads(nextCursor);
			threads = [...threads, ...res.threads];
			nextCursor = res.next_cursor;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load more';
		} finally {
			loadingMore = false;
		}
	}

	function threadHref(thread: ThreadSummary): string {
		return `/room/${encodeURIComponent(thread.room_slug)}/${thread.id}`;
	}
</script>

<svelte:head>
	<title>Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pb-16">
	{#if loading}
		<div class="text-center text-text-muted py-12">Loading…</div>
	{:else if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else}
		<div class="pt-5 pb-3">
			<h1 class="text-lg font-bold">Public Threads</h1>
		</div>

		{#if threads.length === 0}
			<div class="text-center text-text-muted py-12 border border-border-subtle rounded-md bg-bg-surface">
				No public threads yet.
			</div>
		{:else}
			{#each threads as thread, i (thread.id)}
				<div
					class="px-5 py-4 transition-colors duration-100 hover:bg-bg-hover {i < threads.length - 1 ? 'border-b border-border-subtle' : ''}"
				>
					<div class="flex items-start gap-3">
						<div class="flex-1 min-w-0">
							<div class="mb-1 flex items-center gap-2">
								<Badge>Public</Badge>
								{#if thread.locked}
									<LockIcon />
								{/if}
								<a
									href={threadHref(thread)}
									class="font-semibold text-text-primary no-underline hover:text-link hover:underline"
									>{thread.title}</a
								>
							</div>
							<div class="flex items-center gap-2 text-xs text-text-muted">
								<UserName name={thread.author_name} linked={false} />
								<span>&middot;</span>
								<span>{relativeTime(thread.last_activity ?? thread.created_at)}</span>
								<span>&middot;</span>
								<span>{thread.reply_count} {thread.reply_count === 1 ? 'reply' : 'replies'}</span>
							</div>
						</div>
					</div>
				</div>
			{/each}

			{#if nextCursor}
				<div class="text-center py-6">
					<MoreButton onclick={loadMore} loading={loadingMore}>Load more</MoreButton>
				</div>
			{/if}
		{/if}
	{/if}
</div>
