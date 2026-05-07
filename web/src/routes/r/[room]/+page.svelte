<script lang="ts">
	import {
		listThreads,
		listAllThreads,
		loadMoreThreads,
		loadMoreRoomThreads,
		type ThreadSummary,
		type ThreadSort
	} from '$lib/api/threads';
	import { session } from '$lib/stores/session.svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import ThreadListRow from '$lib/components/post/ThreadListRow.svelte';
	import MoreButton from '$lib/components/ui/MoreButton.svelte';
	import Notice from '$lib/components/ui/Notice.svelte';
	import { errorMessage } from '$lib/i18n/errors';

	let { data } = $props();

	let isAll = $derived(page.params.room === 'all');
	let room = $derived(data.room);
	let sortMode = $derived(data.sort);

	// Pagination state: the server load provides page 1. Each load-more
	// call appends to `appended`. SvelteKit clears this automatically when
	// `data` changes (new room or new sort) because the $derived resets.
	let appended = $state<ThreadSummary[]>([]);
	let appendedCursor = $state<string | null>(null);
	let hasLoadedMore = $state(false);
	let loadingMore = $state(false);
	let error = $state<string | null>(null);

	// Reset pagination buffer when server data changes (nav or sort change).
	// `data` is referenced in the $derived so the effect re-fires on updates.
	$effect(() => {
		void data;
		appended = [];
		appendedCursor = null;
		hasLoadedMore = false;
		error = null;
	});

	let threads = $derived([...data.threads, ...appended]);
	let nextCursor = $derived(hasLoadedMore ? appendedCursor : data.nextCursor);

	// Track rendered thread IDs for warm/trusted deduplication. Send the
	// most recent 200 as seen_ids to the server on load-more.
	const MAX_SEEN_IDS = 200;
	let renderedThreadIds = $derived(threads.map((t) => t.id));

	function isWarmCursor(cursor: string): boolean {
		return cursor.startsWith('warm:') || cursor.startsWith('trusted:');
	}

	function sortHref(sort: ThreadSort): string {
		const params = new URLSearchParams(page.url.searchParams);
		if (sort === 'warm') params.delete('sort');
		else params.set('sort', sort);
		const qs = params.toString();
		return `/r/${encodeURIComponent(page.params.room ?? '')}${qs ? '?' + qs : ''}`;
	}

	function handleSortChange(e: Event) {
		const sort = (e.currentTarget as HTMLSelectElement).value as ThreadSort;
		goto(sortHref(sort), { noScroll: true, keepFocus: true });
	}

	async function loadMore() {
		if (!nextCursor || loadingMore) return;
		loadingMore = true;
		try {
			const slug = page.params.room!;
			const cursor = nextCursor;
			let res;

			if (isWarmCursor(cursor)) {
				// Warm/trusted pagination: POST with seen_ids (tail 200).
				const seenIds = renderedThreadIds.slice(-MAX_SEEN_IDS);
				res =
					slug === 'all'
						? await loadMoreThreads(cursor, seenIds)
						: await loadMoreRoomThreads(slug, cursor, seenIds);
			} else {
				// Simple cursor pagination (new/active sorts): GET.
				res =
					slug === 'all'
						? await listAllThreads(cursor, sortMode)
						: await listThreads(slug, cursor, sortMode);
			}

			// Client-side dedup safety net: filter out any threads already rendered.
			const existingIds = new Set(renderedThreadIds);
			const newThreads = res.threads.filter((t) => !existingIds.has(t.id));

			appended = [...appended, ...newThreads];
			appendedCursor = res.next_cursor;
			hasLoadedMore = true;
		} catch (e) {
			error = errorMessage(e, 'Failed to load more');
		} finally {
			loadingMore = false;
		}
	}

	let heading = $derived(isAll ? 'all' : room?.slug ?? page.params.room ?? '');
</script>

<svelte:head>
	<title>{heading} — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pb-16">
	{#if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else}
		<h1 class="sr-only">{heading}</h1>
		<div class="pt-5 pb-3 flex items-center justify-between">
			<div class="text-xs flex items-center gap-1.5 text-text-muted">
				<span>Sort by:</span>
				<select
					value={sortMode}
					onchange={handleSortChange}
					class="font-sans text-xs bg-bg-surface text-text-secondary border border-border rounded-md px-2 py-1 cursor-pointer hover:border-accent-muted focus:outline-none focus:border-accent-muted"
				>
					<option value="warm">Warm</option>
					<option value="new">Newest</option>
					<option value="active">Recently Active</option>
					<option value="trusted">Trusted + Recent</option>
				</select>
			</div>
			{#if session.isLoggedIn && (!room?.is_announcement || session.isAdmin)}
				<button
					onclick={() => goto(isAll ? '/thread/new' : `/thread/new?room=${encodeURIComponent(room?.slug ?? '')}`)}
					class="text-sm px-3 py-1.5 rounded-md cursor-pointer border border-accent bg-accent text-bg font-medium hover:opacity-90 shrink-0"
				>
					New Thread
				</button>
			{/if}
		</div>

		{#if room?.is_announcement && !session.isAdmin}
			<Notice>Only admins can create announcement threads.</Notice>
		{/if}

		{#if threads.length === 0}
			<div
				class="text-center text-text-muted py-12 border border-border-subtle rounded-md bg-bg-surface"
			>
				No threads yet.{#if !isAll} Be the first to start a discussion!{/if}
			</div>
		{:else}
			{#each threads as thread, i (thread.id)}
				<ThreadListRow
					{thread}
					showRoomSlug={isAll}
					isLast={i === threads.length - 1}
					linkedAuthor={session.isLoggedIn}
				/>
			{/each}

			{#if nextCursor}
				<div class="text-center py-6">
					<MoreButton onclick={loadMore} loading={loadingMore}>Load more</MoreButton>
				</div>
			{/if}
		{/if}
	{/if}
</div>
