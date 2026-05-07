<script lang="ts">
	import { errorMessage } from '$lib/i18n/errors';
	import { searchRoomsMore, MAX_SEARCH_SEEN_IDS, type RoomSearchHit } from '$lib/api/search';
	import Notice from '$lib/components/ui/Notice.svelte';
	import RoomCard from '$lib/components/post/RoomCard.svelte';
	import { favoriteRoom, unfavoriteRoom, type Room } from '$lib/api/rooms';
	import { toast } from '$lib/components/ui/toast.svelte';

	let { data } = $props<{
		data: { query: string; rooms: RoomSearchHit[]; nextCursor: string | null };
	}>();

	let appended = $state<RoomSearchHit[]>([]);
	let appendedCursor = $state<string | null>(null);
	let hasLoadedMore = $state(false);
	let loadingMore = $state(false);
	let loadMoreError = $state<string | null>(null);

	// Per-room optimistic favorited overrides applied on top of the
	// server-supplied `favorited` flag. Reset whenever the server load
	// returns new data.
	let favOverrides = $state<Record<string, boolean>>({});

	$effect(() => {
		void data.query;
		void data.rooms;
		appended = [];
		appendedCursor = null;
		hasLoadedMore = false;
		loadMoreError = null;
		favOverrides = {};
	});

	let nextCursor = $derived(hasLoadedMore ? appendedCursor : data.nextCursor);
	let rooms = $derived(
		[...data.rooms, ...appended].map((r) =>
			r.id in favOverrides ? { ...r, favorited: favOverrides[r.id] } : r
		)
	);

	// All rendered room IDs — sent as `seen_ids` (tail 200) on load-more
	// so the server can drop cross-page duplicates introduced by
	// candidate-pool drift between requests.
	let renderedIds = $derived(rooms.map((r) => r.id));

	async function loadMore() {
		if (!nextCursor || loadingMore) return;
		loadingMore = true;
		loadMoreError = null;
		try {
			const seenIds = renderedIds.slice(-MAX_SEARCH_SEEN_IDS);
			const res = await searchRoomsMore(data.query, nextCursor, seenIds);
			// Client-side dedup safety net.
			const existing = new Set(renderedIds);
			const fresh = res.rooms.filter((r) => !existing.has(r.id));
			appended = [...appended, ...fresh];
			appendedCursor = res.next_cursor;
			hasLoadedMore = true;
		} catch (e) {
			loadMoreError = errorMessage(e, 'Failed to load more results');
		} finally {
			loadingMore = false;
		}
	}

	async function toggleRoomFavorite(room: Room, next: boolean) {
		const previous = room.favorited;
		favOverrides = { ...favOverrides, [room.id]: next };
		try {
			if (next) {
				await favoriteRoom(room.id);
			} else {
				await unfavoriteRoom(room.id);
			}
		} catch (e) {
			favOverrides = { ...favOverrides, [room.id]: previous };
			toast.error(errorMessage(e, 'Failed to update favorite.'));
		}
	}
</script>

{#if !data.query}
	<Notice>Type a query in the search box above to begin.</Notice>
{:else if rooms.length === 0}
	<p class="text-text-muted text-sm">No matching rooms found.</p>
{:else}
	<div class="space-y-3">
		{#each rooms as r (r.id)}
			<RoomCard room={r} onToggleFavorite={toggleRoomFavorite} />
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
