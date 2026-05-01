<script lang="ts">
	import { page } from '$app/state';
	import { session } from '$lib/stores/session.svelte';
	import { onMount, flushSync, untrack } from 'svelte';
	import type { TabBarEntry } from '$lib/api/rooms';

	let { data, children } = $props();

	// Tab bar is SSR'd in +layout.server.ts so it paints on first byte.
	// The server caps the list (see `TAB_BAR_SLOTS` in rooms.rs); the
	// client may drop further overflow when the viewport is narrow —
	// see ResizeObserver below.
	let rooms = $derived(data.tabBarRooms);

	let currentSlug = $derived(page.params.room);

	// Source list that the trim algorithm measures against. If the room
	// the user is currently viewing isn't in the server payload at all,
	// synthesize a minimal entry and prepend it so the current room
	// always has a tab right after "All". Rooms that ARE in the payload
	// keep their natural position here; the visible-slice derive below
	// rescues them to position 0 only when trim would have hidden them.
	let baseList = $derived.by<TabBarEntry[]>(() => {
		if (currentSlug === 'all' || !currentSlug) return rooms;
		if (rooms.some((r) => r.slug === currentSlug)) return rooms;
		const synthetic: TabBarEntry = {
			slug: currentSlug,
			is_announcement: false,
			favorited: false,
		};
		return [synthetic, ...rooms];
	});

	// How many of `baseList` we actually render. Starts at the full
	// length; `trimToFit()` shrinks it when the row overflows and grows
	// it back when there's headroom.
	let visibleCount = $state<number>(0);

	// Visible slice for the {#each}. If the current room is in
	// `baseList` but past `visibleCount` (trim hid it), pull it to the
	// front and drop the trailing slot so total tab count stays equal
	// to `visibleCount`.
	let visibleRooms = $derived.by(() => {
		const slice = baseList.slice(0, visibleCount);
		if (currentSlug === 'all' || !currentSlug) return slice;
		if (slice.some((r) => r.slug === currentSlug)) return slice;
		const rescued = baseList.find((r) => r.slug === currentSlug);
		if (!rescued) return slice;
		return [rescued, ...slice.slice(0, Math.max(0, visibleCount - 1))];
	});

	let rowEl: HTMLDivElement | undefined = $state();

	/**
	 * Measure the row and trim/expand `visibleCount` so the tab bar
	 * exactly fills the available width without overflowing. We compare
	 * `scrollWidth` to `clientWidth` because the row is
	 * `overflow-x-auto` and will happily scroll rather than reflow.
	 *
	 * `flushSync()` between mutations is required: writing `visibleCount`
	 * alone schedules a render but does not update the DOM, so
	 * `scrollWidth` would read the same pre-change value on every
	 * iteration (this caused the all-tabs-hidden bug on mobile).
	 */
	function trimToFit() {
		if (!rowEl) return;
		if (rowEl.scrollWidth <= rowEl.clientWidth && visibleCount < baseList.length) {
			visibleCount = baseList.length;
			flushSync();
		}
		while (visibleCount > 0 && rowEl.scrollWidth > rowEl.clientWidth) {
			visibleCount -= 1;
			flushSync();
		}
	}

	// Reset to full list and re-measure whenever `baseList` changes
	// (favorite toggle, or navigation that adds/removes the synthetic
	// current-room entry). Without this ResizeObserver alone wouldn't
	// re-fire — the container's width hasn't changed, only its contents
	// have — leaving the tab bar under- or over-trimmed until the next
	// browser resize. `untrack` prevents the reactive writes inside
	// `trimToFit` from re-triggering this effect and causing an
	// infinite loop.
	$effect(() => {
		const nextLen = baseList.length;
		untrack(() => {
			visibleCount = nextLen;
			flushSync();
			trimToFit();
		});
	});

	// Re-fit when navigating between rooms even if `baseList.length`
	// doesn't change (e.g. both old and new rooms are in the payload):
	// the rescue swap can put a wider/narrower slug into the visible
	// slot, so `scrollWidth` may shift without a resize event.
	$effect(() => {
		currentSlug;
		untrack(() => {
			if (!rowEl) return;
			flushSync();
			trimToFit();
		});
	});

	onMount(() => {
		if (!rowEl) return;
		const ro = new ResizeObserver(() => trimToFit());
		ro.observe(rowEl);
		return () => ro.disconnect();
	});
</script>

{#if session.isLoggedIn}
	<div class="bg-bg-surface-dim border-b border-border-subtle">
		<div
			bind:this={rowEl}
			class="max-w-4xl mx-auto px-6 flex items-center gap-0 overflow-x-auto"
		>
			<a
				href="/r/all"
				class="text-sm px-4 py-2.5 border-b-2 whitespace-nowrap transition-colors duration-150
					{currentSlug === 'all'
					? 'text-accent border-accent font-semibold'
					: 'text-text-secondary border-transparent hover:text-text-primary'}"
			>
				all
			</a>
			{#each visibleRooms as room (room.slug)}
				<a
					href="/r/{encodeURIComponent(room.slug)}"
					class="text-sm px-4 py-2.5 border-b-2 whitespace-nowrap transition-colors duration-150
						{currentSlug === room.slug
						? 'text-accent border-accent font-semibold'
						: 'text-text-secondary border-transparent hover:text-text-primary'}"
				>
					{room.slug}
				</a>
			{/each}
			<a
				href="/rooms"
				class="ml-auto text-text-muted text-xs no-underline hover:text-text-secondary hover:underline whitespace-nowrap py-3 pl-4"
			>
				All Rooms
			</a>
		</div>
	</div>
{/if}

{@render children()}
