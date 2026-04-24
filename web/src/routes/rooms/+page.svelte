<script lang="ts">
	import { relativeTime } from '$lib/format';
	import { goto, invalidateAll } from '$app/navigation';
	import Autocomplete from '$lib/components/ui/Autocomplete.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import FavoriteStar from '$lib/components/ui/FavoriteStar.svelte';
	import MoreButton from '$lib/components/ui/MoreButton.svelte';
	import Sparkline from '$lib/components/ui/Sparkline.svelte';
	import {
		favoriteRoom,
		unfavoriteRoom,
		reorderFavorites,
		listRoomsMore,
		listFavorites,
		searchRooms,
		type Room,
		type RoomChip
	} from '$lib/api/rooms';
	import { dndzone, type DndEvent } from 'svelte-dnd-action';
	import { flip } from 'svelte/animate';
	import { slide } from 'svelte/transition';
	import { toast } from '$lib/components/ui/toast.svelte';

	let { data } = $props();

	// Main paginated list (sorted by viewer-visible activity) and the
	// dedicated favorites section (in user-defined position order) are
	// both mutable local state seeded directly from the SSR payload.
	// Initializing from `data.*` on the first render means the
	// favorites section's `{#if}` is already truthy by first paint —
	// so `transition:slide` sees no false→true toggle and doesn't fire
	// its intro animation on page load.
	//
	// `svelte-ignore state_referenced_locally` — the warning exists to
	// catch accidental "only the initial prop value is captured" cases.
	// Here it's deliberate: the below $effect re-syncs whenever the
	// server load re-runs (e.g. after invalidateAll following a
	// favorite toggle), so the seeded state is not meant to be live-
	// reactive on its own.
	/* svelte-ignore state_referenced_locally */
	let rooms = $state<Room[]>(data.rooms);
	/* svelte-ignore state_referenced_locally */
	let nextCursor = $state<string | null>(data.nextCursor);
	/* svelte-ignore state_referenced_locally */
	let favorites = $state<Room[]>(data.favorites);

	let loadingMore = $state(false);
	let loadMoreError = $state<string | null>(null);

	// Autocomplete input state. The dropdown is backed by `searchRooms`
	// (the server-side prefix-match endpoint) rather than filtering the
	// already-loaded page — so results include rooms that haven't been
	// paginated in yet. Selecting a row navigates to the room page;
	// this field is not used to filter the main list.
	let searchQuery = $state('');

	// True while the user is mid-drag in the favorites dndzone. Used
	// to disable per-item `in:`/`out:` transitions during drag —
	// svelte-dnd-action manipulates the DOM (cloning the dragged item
	// into the body, and inserting a shadow placeholder where it
	// hovers) and transitions that mutate the item's height mid-drag
	// confuse the library's hit detection, causing neighbors to
	// visually collapse or disappear.
	let dragging = $state(false);

	// Re-sync both lists when the server load re-runs (e.g. after
	// `invalidateAll()` following a favorite toggle elsewhere). We skip
	// the very first invocation so the seeded initial values aren't
	// immediately stomped with an identical copy — which would still
	// count as a mutation from Svelte's perspective.
	let firstEffect = true;
	$effect(() => {
		// Touch all three so changes to any re-run this effect.
		const nextRooms = data.rooms;
		const nextCursorVal = data.nextCursor;
		const nextFavorites = data.favorites;
		if (firstEffect) {
			firstEffect = false;
			return;
		}
		rooms = nextRooms;
		nextCursor = nextCursorVal;
		favorites = nextFavorites;
	});

	async function loadMore() {
		if (!nextCursor || loadingMore) return;
		loadingMore = true;
		loadMoreError = null;
		try {
			const page = await listRoomsMore(nextCursor);
			// Cursor pagination can resurface a room already on a prior
			// page — the activity-sort key can shift between fetches as
			// new visible threads land. Dedupe on the client (mirroring
			// the thread warm-sort pattern in /r/[room]/+page.svelte) so
			// the room doesn't render twice.
			const existingIds = new Set(rooms.map((r) => r.id));
			const newRooms = page.rooms.filter((r) => !existingIds.has(r.id));
			rooms = [...rooms, ...newRooms];
			nextCursor = page.next_cursor;
		} catch (e) {
			loadMoreError = e instanceof Error ? e.message : 'Failed to load more rooms.';
		} finally {
			loadingMore = false;
		}
	}

	/**
	 * Apply a favorited-state flip to both the main paginated list
	 * (keeps the inline star in sync) and the dedicated favorites
	 * section (add / remove row). `room` is the canonical shape
	 * carrying activity + sparkline data.
	 */
	function applyFavoriteLocally(roomId: string, next: boolean) {
		rooms = rooms.map((r) => (r.id === roomId ? { ...r, favorited: next } : r));
		if (next) {
			// Only append if not already present (defensive — avoids a
			// double-add from racing clicks).
			if (!favorites.some((r) => r.id === roomId)) {
				const row = rooms.find((r) => r.id === roomId);
				if (row) favorites = [...favorites, { ...row, favorited: true }];
			}
		} else {
			favorites = favorites.filter((r) => r.id !== roomId);
		}
	}

	async function toggleFavorite(room: Room, next: boolean) {
		const previous = room.favorited;
		applyFavoriteLocally(room.id, next);
		try {
			if (next) {
				await favoriteRoom(room.id);
			} else {
				await unfavoriteRoom(room.id);
			}
			// Re-pull the full favorites list so sparkline/activity data
			// is consistent with a fresh server view (covers e.g. cases
			// where the row we copied from the main list was a stale
			// page-1 copy).
			favorites = await listFavorites();
		} catch (e) {
			// Roll back the optimistic flip.
			applyFavoriteLocally(room.id, previous);
			toast.error(e instanceof Error ? e.message : 'Failed to update favorite.');
		}
	}

	/**
	 * svelte-dnd-action consider-phase: the list has been visually
	 * reordered in-DOM; persist it to local state so FLIP animations
	 * settle. We do NOT hit the server until the finalize event so a
	 * mid-drag reconsideration doesn't trigger a PUT. Flip `dragging`
	 * true so the per-item `in:`/`out:` transitions stay out of the
	 * library's way.
	 */
	function handleDndConsider(e: CustomEvent<DndEvent<Room>>) {
		dragging = true;
		favorites = e.detail.items;
	}

	async function handleDndFinalize(e: CustomEvent<DndEvent<Room>>) {
		dragging = false;
		favorites = e.detail.items;
		const roomIds = favorites.map((r) => r.id);
		try {
			await reorderFavorites(roomIds);
		} catch (err) {
			// Stale view (another tab modified favorites) — the server
			// returns FavoriteSetMismatch and we re-pull to recover.
			await invalidateAll();
			toast.error(err instanceof Error ? err.message : 'Failed to save favorite order.');
		}
	}
</script>

<svelte:head>
	<title>All Rooms — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-4">
	<h1 class="text-xl font-bold">All Rooms</h1>
</div>

<!--
	Two-column layout on lg+: main rooms list on the left, compact
	favorites rail on the right. Below lg, stacked — main first, then
	favorites — so the primary content isn't pushed down by the rail
	on narrow viewports. `items-start` keeps the sidebar from
	stretching to match the main column's height.
-->
<div
	class="max-w-4xl mx-auto px-6 pb-16 flex flex-col lg:flex-row lg:items-start gap-6"
>
	<main class="flex-1 min-w-0">
		<div class="pb-5">
			<Autocomplete
				bind:value={searchQuery}
				fetcher={(q) => searchRooms(q)}
				formatLabel={(r: RoomChip) => r.slug}
				itemKey={(r: RoomChip) => r.id}
				onSelect={(r) => {
					// Clear the field so the slug isn't stuck in the input
					// when the user comes back to this page.
					searchQuery = '';
					goto(`/r/${encodeURIComponent(r.slug)}`);
				}}
				placeholder="Search rooms..."
				inputBgClass="bg-bg-surface"
			>
				{#snippet renderItem(r: RoomChip)}
					<div class="flex items-baseline justify-between gap-3">
						<span class="text-text-primary font-medium">{r.slug}</span>
						<span class="text-xs text-text-muted">
							{r.recent_thread_count}
							{r.recent_thread_count === 1 ? 'thread' : 'threads'}
							{r.activity_window_days >= 7 ? 'this week' : `last ${r.activity_window_days}d`}
						</span>
					</div>
				{/snippet}
			</Autocomplete>
		</div>
		{#if rooms.length === 0}
			<div class="text-center text-text-muted py-12">No rooms yet.</div>
		{:else}
			<div class="space-y-3">
				{#each rooms as room (room.id)}
					<div
						class="border border-border rounded-md p-5 bg-bg-surface transition-[background,border-color] duration-150 hover:bg-bg-hover hover:border-accent-muted"
					>
						<div class="flex items-start gap-3">
							<a
								href="/r/{encodeURIComponent(room.slug)}"
								class="flex-1 min-w-0 no-underline text-text-primary"
							>
								<div class="mb-1.5 flex items-center gap-2">
									<h3 class="text-base font-bold">{room.slug}</h3>
									{#if room.is_announcement}
										<Badge>Announcements</Badge>
									{/if}
								</div>
								<div class="flex items-center gap-4 text-xs text-text-muted">
									<span>
										{room.recent_thread_count}
										{room.recent_thread_count === 1 ? 'thread' : 'threads'}
										{room.activity_window_days >= 7
											? 'this week'
											: `last ${room.activity_window_days}d`}
									</span>
									{#if room.last_visible_activity}
										<span>
											Last active
											<span class="text-text-secondary">
												{relativeTime(room.last_visible_activity)}
											</span>
										</span>
									{/if}
									<Sparkline
										values={room.sparkline}
										label="Thread activity over 7 days"
									/>
								</div>
							</a>
							<FavoriteStar
								favorited={room.favorited}
								onToggle={(next) => toggleFavorite(room, next)}
							/>
						</div>
					</div>
				{/each}
			</div>
			{#if nextCursor}
				<div class="mt-6 flex flex-col items-center gap-2">
					<MoreButton loading={loadingMore} onclick={loadMore}>
						Load more rooms
					</MoreButton>
					{#if loadMoreError}
						<div class="text-danger text-xs">{loadMoreError}</div>
					{/if}
				</div>
			{/if}
		{/if}
	</main>

	<!--
		Compact favorites rail. Always rendered so the layout doesn't
		jump as the user stars/unstars rooms — an empty-state message
		takes the place of the list when there are no favorites yet.
		On lg+ it sits to the right as a fixed-width sidebar; below lg
		it stacks above the main list at full width.
	-->
	<aside
		class="w-full lg:w-56 lg:shrink-0 order-first lg:order-none pb-6 border-b border-border-subtle lg:pb-0 lg:border-b-0"
	>
		<section
			class="border border-border-subtle rounded-md bg-bg-surface-dim px-3 pt-3 pb-3"
		>
			<h2
				class="text-xs uppercase tracking-wider text-text-muted mb-2 font-semibold flex items-center gap-2 px-1"
			>
				<svg
					width="12"
					height="12"
					viewBox="0 0 24 24"
					fill="currentColor"
					aria-hidden="true"
				>
					<polygon
						points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"
					/>
				</svg>
				Favorites
			</h2>
			{#if favorites.length === 0}
				<p class="text-xs text-text-muted leading-relaxed px-1">
					No favorites yet; add favorite rooms to save them as shortcuts.
				</p>
			{:else}
				<div
					use:dndzone={{
						items: favorites,
						flipDurationMs: 150,
						dropTargetStyle: {}
					}}
					onconsider={handleDndConsider}
					onfinalize={handleDndFinalize}
					class="space-y-1"
				>
					{#each favorites as room (room.id)}
						<div
							animate:flip={{ duration: 150 }}
							in:slide|local={{ duration: dragging ? 0 : 200 }}
							out:slide|local={{ duration: dragging ? 0 : 200 }}
							class="flex items-center gap-2 border border-border rounded-md pl-2 pr-0.5 py-1 bg-bg-surface"
						>
							<span
								class="cursor-grab text-text-muted hover:text-text-secondary select-none text-sm leading-none"
								title="Drag to reorder"
								aria-hidden="true">⠿</span
							>
							<a
								href="/r/{encodeURIComponent(room.slug)}"
								class="flex-1 min-w-0 text-sm font-medium text-text-primary no-underline hover:text-accent truncate"
							>
								{room.slug}
							</a>
							<FavoriteStar
								favorited={true}
								onToggle={(next) => toggleFavorite(room, next)}
							/>
						</div>
					{/each}
				</div>
			{/if}
		</section>
	</aside>
</div>
