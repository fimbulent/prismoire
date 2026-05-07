<script lang="ts">
	import { errorMessage } from '$lib/i18n/errors';
	import { searchUsersMore, MAX_SEARCH_SEEN_IDS, type UserSearchHit } from '$lib/api/search';
	import UserName from '$lib/components/trust/UserName.svelte';
	import Notice from '$lib/components/ui/Notice.svelte';

	let { data } = $props<{
		data: { query: string; users: UserSearchHit[]; nextCursor: string | null };
	}>();

	let appended = $state<UserSearchHit[]>([]);
	let appendedCursor = $state<string | null>(null);
	let hasLoadedMore = $state(false);
	let loadingMore = $state(false);
	let loadMoreError = $state<string | null>(null);

	$effect(() => {
		void data.query;
		void data.users;
		appended = [];
		appendedCursor = null;
		hasLoadedMore = false;
		loadMoreError = null;
	});

	let nextCursor = $derived(hasLoadedMore ? appendedCursor : data.nextCursor);
	let users = $derived([...data.users, ...appended]);

	// All rendered user IDs — sent as `seen_ids` (tail 200) on load-more
	// so the server can drop cross-page duplicates introduced by
	// candidate-pool drift (signups, trust-map changes) between
	// requests.
	let renderedIds = $derived(users.map((u) => u.id));

	async function loadMore() {
		if (!nextCursor || loadingMore) return;
		loadingMore = true;
		loadMoreError = null;
		try {
			const seenIds = renderedIds.slice(-MAX_SEARCH_SEEN_IDS);
			const res = await searchUsersMore(data.query, nextCursor, seenIds);
			// Client-side dedup safety net.
			const existing = new Set(renderedIds);
			const fresh = res.users.filter((u) => !existing.has(u.id));
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
{:else if users.length === 0}
	<p class="text-text-muted text-sm">No matching users found.</p>
{:else}
	<ul class="space-y-2">
		{#each users as u (u.id)}
			<li class="bg-bg-surface border border-border rounded-md px-3 py-2">
				<UserName name={u.display_name} viewer={u.viewer} />
			</li>
		{/each}
	</ul>
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
