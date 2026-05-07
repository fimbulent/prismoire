<script lang="ts">
	import { errorMessage } from '$lib/i18n/errors';
	import {
		searchThreadsMore,
		MAX_SEARCH_SEEN_IDS,
		type ThreadSearchHit
	} from '$lib/api/search';
	import Notice from '$lib/components/ui/Notice.svelte';
	import ThreadListRow from '$lib/components/post/ThreadListRow.svelte';

	let { data } = $props<{
		data: { query: string; threads: ThreadSearchHit[]; nextCursor: string | null };
	}>();

	// Pagination buffer + state. Reset whenever the server load returns
	// new data (query change or back-button navigation), via `$effect`.
	let appended = $state<ThreadSearchHit[]>([]);
	let appendedCursor = $state<string | null>(null);
	let hasLoadedMore = $state(false);
	let loadingMore = $state(false);
	let loadMoreError = $state<string | null>(null);

	$effect(() => {
		void data.query;
		void data.threads;
		appended = [];
		appendedCursor = null;
		hasLoadedMore = false;
		loadMoreError = null;
	});

	let nextCursor = $derived(hasLoadedMore ? appendedCursor : data.nextCursor);
	let threads = $derived([...data.threads, ...appended]);

	// All currently-rendered IDs — sent to the server as `seen_ids` (tail
	// 200) on load-more so the server can drop cross-page duplicates
	// introduced by FTS pool drift between requests.
	let renderedIds = $derived(threads.map((t) => t.id));

	async function loadMore() {
		if (!nextCursor || loadingMore) return;
		loadingMore = true;
		loadMoreError = null;
		try {
			const seenIds = renderedIds.slice(-MAX_SEARCH_SEEN_IDS);
			const res = await searchThreadsMore(data.query, nextCursor, seenIds);
			// Client-side dedup safety net: defence-in-depth against the
			// (rare) case where a row escapes the server-side seen-IDs
			// filter — e.g. if the rendered set ever exceeds 200 and the
			// tail-slice drops the relevant ID from `seen_ids`.
			const existing = new Set(renderedIds);
			const fresh = res.threads.filter((t) => !existing.has(t.id));
			appended = [...appended, ...fresh];
			appendedCursor = res.next_cursor;
			hasLoadedMore = true;
		} catch (e) {
			loadMoreError = errorMessage(e, 'Failed to load more results');
		} finally {
			loadingMore = false;
		}
	}
</script>

{#if !data.query}
	<Notice>Type a query in the search box above to begin.</Notice>
{:else if threads.length === 0}
	<p class="text-text-muted text-sm">No matching threads found.</p>
{:else}
	<div class="space-y-3">
		{#each threads as t (t.id)}
			<ThreadListRow thread={t} variant="card" showRoomSlug />
		{/each}
	</div>
{/if}

{#if loadMoreError}
	<div class="mt-4">
		<Notice>{loadMoreError}</Notice>
	</div>
{/if}

{#if nextCursor && data.query}
	<div class="mt-6 flex justify-center">
		<button
			type="button"
			onclick={loadMore}
			disabled={loadingMore}
			class="px-4 py-2 bg-bg-surface border border-border rounded-md text-sm text-text-secondary hover:text-text-primary hover:border-accent-muted transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
		>
			{loadingMore ? 'Loading…' : 'Load more'}
		</button>
	</div>
{/if}
