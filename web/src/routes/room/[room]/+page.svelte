<script lang="ts">
	import { getRoom, type Room } from '$lib/api/rooms';
	import { listThreads, listAllThreads, type ThreadSummary, type ThreadSort } from '$lib/api/threads';
	import { relativeTime } from '$lib/format';
	import { session } from '$lib/stores/session.svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import LockIcon from '$lib/components/ui/LockIcon.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import UserName from '$lib/components/trust/UserName.svelte';
	import MoreButton from '$lib/components/ui/MoreButton.svelte';

	let isAll = $derived(page.params.room === 'all');
	let room = $state<Room | null>(null);
	let threads = $state<ThreadSummary[]>([]);
	let nextCursor = $state<string | null>(null);
	let loadingMore = $state(false);
	let loading = $state(true);
	let error = $state<string | null>(null);
	type SortCategory = 'warm' | 'new' | 'active' | 'trusted' | 'top_trusted';
	type TopTrustedWindow = 'trust_24h' | 'trust_7d' | 'trust_30d' | 'trust_1y' | 'trust_all';
	let sortCategory = $state<SortCategory>('warm');
	let topTrustedWindow = $state<TopTrustedWindow>('trust_30d');
	let sortMode = $derived<ThreadSort>(sortCategory === 'top_trusted' ? topTrustedWindow : sortCategory);

	$effect(() => {
		if (session.loading) return;
		if (!session.isLoggedIn) {
			goto('/login', { replaceState: true });
			return;
		}
		const slug = page.params.room;
		if (slug) load(slug, sortMode);
	});

	async function load(slug: string, sort?: ThreadSort) {
		loading = true;
		error = null;
		threads = [];
		nextCursor = null;
		try {
			if (slug === 'all') {
				room = null;
				const res = await listAllThreads(undefined, sort);
				threads = res.threads;
				nextCursor = res.next_cursor;
			} else {
				const [roomData, threadData] = await Promise.all([
					getRoom(slug),
					listThreads(slug, undefined, sort)
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
				slug === 'all' ? await listAllThreads(nextCursor, sortMode) : await listThreads(slug, nextCursor, sortMode);
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
			<div class="flex items-center gap-3">
				<h1 class="text-lg font-bold">{heading}</h1>
				<select
					bind:value={sortCategory}
					class="font-sans text-xs bg-bg-surface text-text-secondary border border-border rounded-md px-2 py-1 cursor-pointer hover:border-accent-muted focus:outline-none focus:border-accent-muted"
				>
					<option value="warm">Warm</option>
					<option value="new">Newest</option>
					<option value="active">Recently Active</option>
					<option value="trusted">Trusted + Recent</option>
					<option value="top_trusted">Top Trusted</option>
				</select>
				{#if sortCategory === 'top_trusted'}
					<select
						bind:value={topTrustedWindow}
						class="font-sans text-xs bg-bg-surface text-text-secondary border border-border rounded-md px-2 py-1 cursor-pointer hover:border-accent-muted focus:outline-none focus:border-accent-muted"
					>
						<option value="trust_24h">24h</option>
						<option value="trust_7d">7d</option>
						<option value="trust_30d">30d</option>
						<option value="trust_1y">1y</option>
						<option value="trust_all">All time</option>
					</select>
				{/if}
			</div>
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
								<UserName name={thread.author_name} trust={thread.trust} compact linked={session.isLoggedIn} />
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
					<MoreButton onclick={loadMore} loading={loadingMore}>Load more</MoreButton>
				</div>
			{/if}
		{/if}
	{/if}
</div>
