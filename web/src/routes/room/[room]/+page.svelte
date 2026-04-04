<script lang="ts">
	import { getRoom, type Room } from '$lib/api/rooms';
	import { listThreads, listAllThreads, type ThreadSummary } from '$lib/api/threads';
	import { relativeTime } from '$lib/format';
	import { session } from '$lib/stores/session.svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import LockIcon from '$lib/components/ui/LockIcon.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import TrustBadge from '$lib/components/trust/TrustBadge.svelte';

	let isAll = $derived(page.params.room === 'all');
	let room = $state<Room | null>(null);
	let threads = $state<ThreadSummary[]>([]);
	let nextCursor = $state<string | null>(null);
	let loadingMore = $state(false);
	let loading = $state(true);
	let error = $state<string | null>(null);

	$effect(() => {
		if (session.loading) return;
		if (!session.isLoggedIn) {
			goto('/login', { replaceState: true });
			return;
		}
		const slug = page.params.room;
		if (slug) load(slug);
	});

	async function load(slug: string) {
		loading = true;
		error = null;
		threads = [];
		nextCursor = null;
		try {
			if (slug === 'all') {
				room = null;
				const res = await listAllThreads();
				threads = res.threads;
				nextCursor = res.next_cursor;
			} else {
				const [roomData, threadData] = await Promise.all([
					getRoom(slug),
					listThreads(slug)
				]);
				room = roomData;
				threads = threadData.threads;
				nextCursor = threadData.next_cursor;
			}
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
			const slug = page.params.room!;
			const res =
				slug === 'all' ? await listAllThreads(nextCursor) : await listThreads(slug, nextCursor);
			threads = [...threads, ...res.threads];
			nextCursor = res.next_cursor;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load more';
		} finally {
			loadingMore = false;
		}
	}

	let heading = $derived(isAll ? 'All threads' : room?.name ?? '');

	function threadHref(thread: ThreadSummary): string {
		return `/room/${encodeURIComponent(thread.room_slug)}/${thread.id}`;
	}
</script>

<svelte:head>
	<title>{heading ? `${heading} — Prismoire` : 'Prismoire'}</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pb-16">
	{#if loading}
		<div class="text-center text-text-muted py-12">Loading…</div>
	{:else if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else}
		<div class="pt-5 pb-3 flex items-center justify-between">
			<h1 class="text-lg font-bold">{heading}</h1>
			{#if session.isLoggedIn && !isAll && room && (!room.public || session.isAdmin)}
				<button
					onclick={() => goto(`/room/${encodeURIComponent(room!.slug)}/new`)}
					class="text-sm px-3 py-1.5 rounded-md cursor-pointer border border-accent bg-accent text-bg font-medium hover:opacity-90 shrink-0"
				>
					New Thread
				</button>
			{/if}
		</div>

		{#if threads.length === 0}
			<div
				class="text-center text-text-muted py-12 border border-border-subtle rounded-md bg-bg-surface"
			>
				No threads yet.{#if !isAll} Be the first to start a discussion!{/if}
			</div>
		{:else}
			{#each threads as thread, i (thread.id)}
				<div
					class="px-5 py-4 transition-colors duration-100 hover:bg-bg-hover {i < threads.length - 1 ? 'border-b border-border-subtle' : ''}"
				>
					<div class="flex items-start gap-3">
						<div class="flex-1 min-w-0">
							<div class="mb-1 flex items-center gap-2">
								{#if thread.room_public}
									<Badge>Public</Badge>
								{/if}
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
								<span class="text-text-secondary font-medium">{thread.author_name}</span>
								{#if session.user?.user_id !== thread.author_id}
									<TrustBadge distance={thread.trust_distance} compact />
								{/if}
								<span>&middot;</span>
								<span>{relativeTime(thread.last_activity ?? thread.created_at)}</span>
								<span>&middot;</span>
								<span
									>{thread.reply_count}
									{thread.reply_count === 1 ? 'reply' : 'replies'}</span
								>
								{#if isAll}
									<span>&middot;</span>
									<a
										href="/room/{encodeURIComponent(thread.room_slug)}"
										class="text-accent-muted no-underline hover:underline"
										>{thread.room_name}</a
									>
								{/if}
							</div>
						</div>
					</div>
				</div>
			{/each}

			{#if nextCursor}
				<div class="text-center py-6">
					<button
						onclick={loadMore}
						disabled={loadingMore}
						class="text-sm px-4 py-2 rounded-md border border-border text-text-secondary hover:text-text-primary hover:bg-bg-hover cursor-pointer disabled:opacity-50 disabled:cursor-default transition-colors"
					>
						{loadingMore ? 'Loading…' : 'Load more'}
					</button>
				</div>
			{/if}
		{/if}
	{/if}
</div>
