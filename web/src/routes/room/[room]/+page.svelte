<script lang="ts">
	import {
		listThreads,
		listAllThreads,
		loadMoreThreads,
		loadMoreRoomThreads,
		type ThreadSummary,
		type ThreadSort
	} from '$lib/api/threads';
	import { relativeTime } from '$lib/format';
	import { session } from '$lib/stores/session.svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import LockIcon from '$lib/components/ui/LockIcon.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import UserName from '$lib/components/trust/UserName.svelte';
	import MoreButton from '$lib/components/ui/MoreButton.svelte';

	let { data } = $props();

	let isAll = $derived(page.params.room === 'all');
	let room = $derived(data.room);
	let sortMode = $derived(data.sort);

	// Pagination state: the server load provides page 1. Each load-more
	// call appends to `appended`. SvelteKit clears this automatically when
	// `data` changes (new room or new sort) because the $derived resets.
	let appended = $state<ThreadSummary[]>([]);
	let appendedCursor = $state<string | null>(null);
	let loadingMore = $state(false);
	let error = $state<string | null>(null);

	// Reset pagination buffer when server data changes (nav or sort change).
	// `data` is referenced in the $derived so the effect re-fires on updates.
	$effect(() => {
		void data;
		appended = [];
		appendedCursor = null;
		error = null;
	});

	let threads = $derived([...data.threads, ...appended]);
	let nextCursor = $derived(appendedCursor ?? data.nextCursor);

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
		return `/room/${encodeURIComponent(page.params.room ?? '')}${qs ? '?' + qs : ''}`;
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
	{#if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else}
		<div class="pt-5 pb-3 flex items-center justify-between">
			<div class="flex items-center gap-3">
				<h1 class="text-lg font-bold">{heading}</h1>
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
