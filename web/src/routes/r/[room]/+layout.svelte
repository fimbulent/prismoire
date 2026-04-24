<script lang="ts">
	import { page } from '$app/state';
	import { session } from '$lib/stores/session.svelte';
	import { onMount, flushSync, untrack } from 'svelte';

	let { data, children } = $props();

	// Tab bar is SSR'd in +layout.server.ts so it paints on first byte.
	// The server caps the list (see `TAB_BAR_SLOTS` in rooms.rs); the
	// client may drop further overflow when the viewport is narrow —
	// see ResizeObserver below.
	let rooms = $derived(data.tabBarRooms);

	let currentSlug = $derived(page.params.room);

	// How many of the server-provided rooms we actually render. Starts at
	// the full list; `trimToFit()` shrinks it when the row overflows and
	// grows it back when there's headroom.
	let visibleCount = $state<number>(0);
	let visibleRooms = $derived(rooms.slice(0, visibleCount));

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
		if (rowEl.scrollWidth <= rowEl.clientWidth && visibleCount < rooms.length) {
			visibleCount = rooms.length;
			flushSync();
		}
		while (visibleCount > 0 && rowEl.scrollWidth > rowEl.clientWidth) {
			visibleCount -= 1;
			flushSync();
		}
	}

	// Reset to full list and re-measure whenever `rooms` changes (e.g.
	// after `invalidateAll()` following a favorite toggle). Without this
	// ResizeObserver alone wouldn't re-fire — the container's width
	// hasn't changed, only its contents have — leaving the tab bar
	// under- or over-trimmed until the next browser resize. `untrack`
	// prevents the reactive writes inside `trimToFit` from re-triggering
	// this effect and causing an infinite loop.
	$effect(() => {
		const nextLen = rooms.length;
		untrack(() => {
			visibleCount = nextLen;
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
				All
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
