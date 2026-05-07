<!--
	Sectioned autocomplete dropdown for the global search input.

	Fork of `Autocomplete.svelte` rather than a generalisation: the
	keep-verbatim parts (`requestSeq` race-cancellation,
	`committedQuery` stale-response guard, 200ms debounce, the
	pointerdown/Tab close logic) are preserved, but the row-rendering
	is purpose-built for three sections (Rooms, Users, Threads) plus
	a "See all results" footer that links to the dedicated search
	page.

	Wire shape: a single `GET /api/search?q=…` round-trip per
	debounced keystroke, returning `{ rooms, users, threads }` —
	posts are intentionally excluded (see `docs/search.md`).

	## Keyboard

	- ArrowDown / ArrowUp — move highlight across the flattened row
	  list (rooms → users → threads → "see all"). Section headers
	  are not selectable.
	- Enter — navigate to the highlighted row's URL. With no
	  highlight, falls back to `/search/threads?q=<value>`.
	- Escape — close the dropdown.
	- Tab — close the dropdown without selecting; cancels any
	  pending debounced fetch and invalidates in-flight requests.

	## CSP

	All positioning is via Tailwind classes — no inline `style`
	attributes are written anywhere, per the project CSP policy.
-->
<script lang="ts">
	import { onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import {
		searchDropdown,
		type UserHit,
		type RoomHit,
		type SearchDropdownResponse,
		type ThreadHit
	} from '$lib/api/search';
	import UserName from '$lib/components/trust/UserName.svelte';

	interface Props {
		placeholder?: string;
		inputBgClass?: string;
		/**
		 * Called after the autocomplete has navigated the user away —
		 * either via Enter with no highlighted row, the "See all results"
		 * footer, or selection of a result row. Wrappers use this to
		 * tear down surrounding chrome that should not survive the
		 * navigation: `NavSearch` collapses its expanded state and clears
		 * the input so the user lands on the destination with a fresh
		 * search button instead of a populated, still-open dropdown.
		 */
		onNavigate?: () => void;
	}

	let {
		placeholder = 'Search…',
		inputBgClass = 'bg-bg',
		onNavigate
	}: Props = $props();

	// Imperative handles for wrappers that own surrounding chrome (e.g.
	// `NavSearch`, which renders a magnifying-glass toggle and wants to
	// focus the input on expand and clear it on collapse). Exporting
	// these instead of accepting a controlled `value` prop keeps this
	// component's internal state — debouncer, request seq, dropdown
	// visibility — encapsulated.
	export function focus() {
		inputEl?.focus();
	}
	export function isEmpty(): boolean {
		return value.length === 0;
	}
	export function clear() {
		value = '';
		open = false;
		highlightIdx = -1;
		clearTimer();
		// Bump the request seq so any in-flight response from the
		// pre-clear query is discarded when it arrives.
		requestSeq++;
		results = { rooms: [], users: [], threads: [] };
		committedQuery = '';
		loading = false;
	}

	let value = $state('');
	let results = $state<SearchDropdownResponse>({ rooms: [], users: [], threads: [] });
	let loading = $state(false);
	let open = $state(false);
	let highlightIdx = $state(-1);
	/** The query string that produced the current `results`. Guards
	 *  against stale responses clobbering newer ones when the user is
	 *  typing faster than the network round-trip. */
	let committedQuery = $state('');

	const debounceMs = 200;
	const minQueryLength = 1;

	let debounceTimer: ReturnType<typeof setTimeout> | null = null;
	/** Monotonic counter used to ignore responses from in-flight
	 *  requests that were superseded by a newer query. */
	let requestSeq = 0;

	let containerEl = $state<HTMLDivElement | null>(null);
	let inputEl = $state<HTMLInputElement | null>(null);

	/**
	 * Vertical placement of the dropdown. Mirrors the logic in
	 * `Autocomplete.svelte`: open downward by default, flip upward
	 * when there's not enough room below the input. CSP-safe — driven
	 * by Tailwind class swaps in the template, not inline styles. The
	 * threshold matches the dropdown's `max-h-96` (24rem / 384px).
	 */
	let direction = $state<'down' | 'up'>('down');
	const DROPDOWN_MAX_HEIGHT = 384; // matches `max-h-96` Tailwind class

	/**
	 * Horizontal anchoring of the dropdown. Defaults to left-aligned
	 * (the dropdown's left edge sits flush with the input's). When the
	 * dropdown's `min-w-[20rem]` would push the right edge past the
	 * viewport — typically because the input lives in the nav bar at
	 * the right of the screen — we flip the anchor so the dropdown
	 * grows leftward from the input's right edge instead. CSP-safe:
	 * driven by Tailwind class swaps, never inline styles.
	 */
	let horizontalAlign = $state<'left' | 'right'>('left');
	const DROPDOWN_MIN_WIDTH = 320; // matches `min-w-[20rem]` (20rem at 16px root)

	function clearTimer() {
		if (debounceTimer !== null) {
			clearTimeout(debounceTimer);
			debounceTimer = null;
		}
	}

	async function runFetch(query: string) {
		const seq = ++requestSeq;
		loading = true;
		try {
			const items = await searchDropdown(query);
			// If a newer request fired while this one was in flight,
			// discard our results — the newer one owns the UI now.
			if (seq !== requestSeq) return;
			results = items;
			committedQuery = query;
			open = true;
			highlightIdx = -1;
		} catch {
			// Swallow errors quietly — autocomplete suggestions aren't
			// worth showing an error banner over.
			if (seq !== requestSeq) return;
			results = { rooms: [], users: [], threads: [] };
			highlightIdx = -1;
		} finally {
			if (seq === requestSeq) loading = false;
		}
	}

	function scheduleFetch(query: string) {
		clearTimer();
		if (query.length < minQueryLength) {
			results = { rooms: [], users: [], threads: [] };
			highlightIdx = -1;
			loading = false;
			committedQuery = '';
			return;
		}
		debounceTimer = setTimeout(() => {
			void runFetch(query);
		}, debounceMs);
	}

	function onInput(e: Event) {
		const next = (e.target as HTMLInputElement).value;
		value = next;
		open = true;
		scheduleFetch(next.trim());
	}

	function onFocus() {
		if (results.rooms.length + results.users.length + results.threads.length > 0) {
			open = true;
		}
	}

	/// Flat row list used for keyboard nav. Section headers are not
	/// represented here — they are rendered alongside but skipped by
	/// arrow-key traversal.
	type Row =
		| { kind: 'room'; item: RoomHit }
		| { kind: 'user'; item: UserHit }
		| { kind: 'thread'; item: ThreadHit }
		| { kind: 'see_all' };

	const rows = $derived.by<Row[]>(() => {
		const out: Row[] = [];
		for (const r of results.rooms) out.push({ kind: 'room', item: r });
		for (const u of results.users) out.push({ kind: 'user', item: u });
		for (const t of results.threads) out.push({ kind: 'thread', item: t });
		if (committedQuery.trim().length > 0) out.push({ kind: 'see_all' });
		return out;
	});

	const trimmedValue = $derived(value.trim());

	const showDropdown = $derived(
		open &&
			(loading ||
				results.rooms.length > 0 ||
				results.users.length > 0 ||
				results.threads.length > 0 ||
				committedQuery.length > 0)
	);

	const showEmpty = $derived(
		open &&
			!loading &&
			results.rooms.length === 0 &&
			results.users.length === 0 &&
			results.threads.length === 0 &&
			committedQuery.length >= minQueryLength &&
			committedQuery === trimmedValue
	);

	// See `Autocomplete.svelte`'s identical block for the rationale —
	// duplicated here rather than extracted because the two components
	// already diverge in row layout, debouncing, and result shape;
	// pulling the placement helper into a shared file would couple
	// them more tightly than the eight lines saves.
	$effect(() => {
		if (!showDropdown && !showEmpty) return;
		if (!containerEl || typeof window === 'undefined') return;
		const rect = containerEl.getBoundingClientRect();
		const spaceBelow = window.innerHeight - rect.bottom;
		const spaceAbove = rect.top;
		direction =
			spaceBelow < DROPDOWN_MAX_HEIGHT && spaceAbove > spaceBelow ? 'up' : 'down';
		// Horizontal flip: if a left-anchored dropdown at min-width
		// would extend past the viewport's right edge, anchor on the
		// right instead so it grows leftward into available space.
		// The check uses the input's left edge (not the input's full
		// width), so a narrow input — like the nav-bar search — still
		// triggers the flip even when its own bounding box fits.
		const overflowsRight = rect.left + DROPDOWN_MIN_WIDTH > window.innerWidth;
		horizontalAlign = overflowsRight ? 'right' : 'left';
	});

	function urlForRow(row: Row): string {
		switch (row.kind) {
			case 'room':
				return `/r/${encodeURIComponent(row.item.slug)}`;
			case 'user':
				return `/@${encodeURIComponent(row.item.display_name)}`;
			case 'thread':
				return `/r/${encodeURIComponent(row.item.room_slug)}/${encodeURIComponent(row.item.id)}`;
			case 'see_all':
				return `/search/threads?q=${encodeURIComponent(committedQuery)}`;
		}
	}

	async function selectRow(row: Row) {
		const dest = urlForRow(row);
		open = false;
		highlightIdx = -1;
		clearTimer();
		requestSeq++;
		await goto(dest);
		onNavigate?.();
	}

	function onKeydown(e: KeyboardEvent) {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			if (!open) {
				open = true;
				if (rows.length === 0 && !loading && trimmedValue.length >= minQueryLength) {
					void runFetch(trimmedValue);
					return;
				}
			}
			if (rows.length === 0) return;
			highlightIdx = (highlightIdx + 1) % rows.length;
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			if (!open || rows.length === 0) return;
			highlightIdx = highlightIdx <= 0 ? rows.length - 1 : highlightIdx - 1;
		} else if (e.key === 'Enter') {
			e.preventDefault();
			if (highlightIdx >= 0 && highlightIdx < rows.length) {
				void selectRow(rows[highlightIdx]);
			} else if (trimmedValue.length > 0) {
				// No row highlighted: jump straight to the results page.
				open = false;
				clearTimer();
				requestSeq++;
				void goto(`/search/threads?q=${encodeURIComponent(trimmedValue)}`);
				onNavigate?.();
			}
		} else if (e.key === 'Escape') {
			if (open) {
				e.preventDefault();
				open = false;
				highlightIdx = -1;
			}
		} else if (e.key === 'Tab') {
			open = false;
			highlightIdx = -1;
			clearTimer();
			requestSeq++;
			loading = false;
		}
	}

	function onDocumentPointerDown(e: PointerEvent) {
		if (!containerEl) return;
		if (containerEl.contains(e.target as Node)) return;
		open = false;
		highlightIdx = -1;
	}

	$effect(() => {
		if (typeof document === 'undefined') return;
		document.addEventListener('pointerdown', onDocumentPointerDown);
		return () => document.removeEventListener('pointerdown', onDocumentPointerDown);
	});

	onDestroy(clearTimer);

	/// Map a row's kind+index in the flat list to the dropdown's
	/// section label, used for the `aria-` attributes the listbox
	/// pattern wants.
	function rowAriaLabel(row: Row): string {
		switch (row.kind) {
			case 'room':
				return `Room ${row.item.slug}`;
			case 'user':
				return `User ${row.item.display_name}`;
			case 'thread':
				return `Thread ${row.item.title} in ${row.item.room_slug}`;
			case 'see_all':
				return `See all results for ${committedQuery}`;
		}
	}
</script>

<div bind:this={containerEl} class="relative w-full max-w-xs">
	<input
		bind:this={inputEl}
		type="text"
		bind:value
		{placeholder}
		autocomplete="off"
		role="combobox"
		aria-autocomplete="list"
		aria-expanded={showDropdown}
		aria-controls="global-search-listbox"
		oninput={onInput}
		onfocus={onFocus}
		onkeydown={onKeydown}
		class="w-full {inputBgClass} border border-border rounded-md text-text-primary text-sm px-3 py-1.5 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans"
	/>

	{#if showDropdown}
		<ul
			id="global-search-listbox"
			role="listbox"
			class="absolute z-30 max-h-96 overflow-y-auto bg-bg-surface border border-border rounded-md shadow-lg py-1 min-w-[20rem] {direction ===
			'up'
				? 'bottom-full mb-1'
				: 'top-full mt-1'} {horizontalAlign === 'right' ? 'right-0 left-auto' : 'left-0 right-0'}"
		>
			{#if loading && rows.length === 0}
				<li class="px-3 py-2 text-xs text-text-muted">Searching…</li>
			{:else}
				{#if results.rooms.length > 0}
					<li class="px-3 pt-2 pb-1 text-[10px] uppercase tracking-wider text-text-muted font-semibold">
						Rooms
					</li>
					{#each results.rooms as item, i (item.id)}
						{@const flatIdx = i}
						{@const active = highlightIdx === flatIdx}
						<li role="option" aria-selected={active} aria-label={rowAriaLabel(rows[flatIdx])}>
							<button
								type="button"
								tabindex="-1"
								onpointerdown={(e) => {
									e.preventDefault();
									void selectRow(rows[flatIdx]);
								}}
								onmousemove={() => (highlightIdx = flatIdx)}
								class="w-full text-left px-3 py-2 text-sm cursor-pointer font-sans block
									{active ? 'bg-bg-hover text-text-primary' : 'text-text-secondary hover:bg-bg-hover'}"
							>
								<span class="text-accent">{item.slug}</span>
								{#if item.is_announcement}
									<span class="ml-2 text-[10px] uppercase tracking-wider text-text-muted">announcements</span>
								{/if}
							</button>
						</li>
					{/each}
				{/if}

				{#if results.users.length > 0}
					<li class="px-3 pt-2 pb-1 text-[10px] uppercase tracking-wider text-text-muted font-semibold">
						Users
					</li>
					{#each results.users as item, i (item.id)}
						{@const flatIdx = results.rooms.length + i}
						{@const active = highlightIdx === flatIdx}
						<li role="option" aria-selected={active} aria-label={rowAriaLabel(rows[flatIdx])}>
							<button
								type="button"
								tabindex="-1"
								onpointerdown={(e) => {
									e.preventDefault();
									void selectRow(rows[flatIdx]);
								}}
								onmousemove={() => (highlightIdx = flatIdx)}
								class="w-full text-left px-3 py-2 text-sm cursor-pointer font-sans flex items-center gap-1 flex-wrap
									{active ? 'bg-bg-hover text-text-primary' : 'text-text-secondary hover:bg-bg-hover'}"
							>
								<!--
									`linked={false}` because the surrounding `<button>`
									handles navigation; `UserName` still renders the trust
									badge, tag, and self / banned / suspended / deleted
									chrome so the dropdown row carries the same information
									density as the dedicated search results page.
								-->
								<UserName
									name={item.display_name}
									viewer={item.viewer}
									compact
									linked={false}
								/>
							</button>
						</li>
					{/each}
				{/if}

				{#if results.threads.length > 0}
					<li class="px-3 pt-2 pb-1 text-[10px] uppercase tracking-wider text-text-muted font-semibold">
						Threads
					</li>
					{#each results.threads as item, i (item.id)}
						{@const flatIdx = results.rooms.length + results.users.length + i}
						{@const active = highlightIdx === flatIdx}
						<li role="option" aria-selected={active} aria-label={rowAriaLabel(rows[flatIdx])}>
							<button
								type="button"
								tabindex="-1"
								onpointerdown={(e) => {
									e.preventDefault();
									void selectRow(rows[flatIdx]);
								}}
								onmousemove={() => (highlightIdx = flatIdx)}
								class="w-full text-left px-3 py-2 text-sm cursor-pointer font-sans block
									{active ? 'bg-bg-hover text-text-primary' : 'text-text-secondary hover:bg-bg-hover'}"
							>
								<span class="text-text-primary line-clamp-1">{item.title}</span>
								<!--
									`muted` so the author name sits at the secondary
									weight/color of the surrounding "in {room} ·" metadata
									line; `linked={false}` because the outer `<button>`
									owns navigation to the thread, not to the author.
								-->
								<span class="text-xs text-text-muted inline-flex items-center gap-1 flex-wrap">
									in <span class="text-accent-muted">{item.room_slug}</span> ·
									<UserName
										name={item.author_name}
										viewer={item.viewer}
										compact
										muted
										linked={false}
									/>
								</span>
							</button>
						</li>
					{/each}
				{/if}

				{#if committedQuery.trim().length > 0}
					{@const flatIdx = rows.length - 1}
					{@const active = highlightIdx === flatIdx}
					<li
						role="option"
						aria-selected={active}
						aria-label={rowAriaLabel(rows[flatIdx])}
						class="border-t border-border-subtle mt-1 pt-1"
					>
						<button
							type="button"
							tabindex="-1"
							onpointerdown={(e) => {
								e.preventDefault();
								void selectRow(rows[flatIdx]);
							}}
							onmousemove={() => (highlightIdx = flatIdx)}
							class="w-full text-left px-3 py-2 text-sm cursor-pointer font-sans block
								{active ? 'bg-bg-hover text-text-primary' : 'text-text-primary hover:bg-bg-hover'}"
						>
							See all results for "{committedQuery}" →
						</button>
					</li>
				{/if}
			{/if}
		</ul>
	{:else if showEmpty}
		<ul
			id="global-search-listbox"
			role="listbox"
			class="absolute z-30 bg-bg-surface border border-border rounded-md shadow-lg py-1 min-w-[20rem] {direction ===
			'up'
				? 'bottom-full mb-1'
				: 'top-full mt-1'} {horizontalAlign === 'right' ? 'right-0 left-auto' : 'left-0 right-0'}"
		>
			<li class="px-3 py-2 text-xs text-text-muted">No matches</li>
		</ul>
	{/if}
</div>
