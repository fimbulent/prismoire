<!--
	Generic autocomplete text input with a dropdown of async-fetched
	suggestions. Designed to be reusable across any "type to search"
	flow (room pickers, user pickers, etc.).

	## Data flow

	The component owns the query string (bound via `value`) and the
	dropdown UI state. It does not own the list of results — it calls
	`fetcher(query)` whenever the debounced query changes and renders
	whatever that function returns. This keeps the component agnostic
	to transport, auth, and result shape.

	## Props

	- `value` — bindable query string (the text typed into the input).
	- `fetcher` — `(query) => Promise<T[]>`. Called on debounce expiry
	  when the query is non-empty (or on focus if `openOnFocus`).
	- `formatLabel(item)` — the primary visible label for a row AND the
	  string written back into the input when a row is selected.
	- `itemKey(item)` — stable unique key used for `{#each}` tracking.
	- `renderItem` (optional) — custom row snippet. Receives the item;
	  defaults to just showing `formatLabel(item)`.
	- `onSelect(item)` — fires when the user picks a row (click or
	  Enter). The component sets `value = formatLabel(item)` and closes
	  the dropdown before dispatching.
	- `onClear` (optional) — fires when the input is emptied (either by
	  deleting all text or via an explicit clear). Useful for parents
	  that cache a "selected item" separate from the raw query.
	- `onCreate` (optional) — when set, a trailing "Create {query}"
	  row is appended to the dropdown whenever the typed query does
	  not exactly match any result. Fires with the current trimmed
	  query when the row is clicked or selected via Enter. Meant for
	  pickers where the user is allowed to introduce a new value
	  (e.g. posting to a room that does not yet exist).
	- `createLabel` (optional) — formatter for the "Create {query}"
	  row label. Defaults to `` `Create ${q}` ``.
	- `debounceMs` — delay between the last keystroke and the fetch
	  kicking off. Defaults to 200ms, which is the sweet spot between
	  typing-fluency and server load for prefix search.
	- `minQueryLength` — minimum query length before `fetcher` is
	  called. Defaults to 1; set to 0 to prefetch on empty queries
	  (useful when the backend returns a "default" list).
	- `openOnFocus` — when true, fetching triggers on focus even if
	  the query is below `minQueryLength`. Lets callers pre-populate
	  the dropdown the moment the field is focused.
	- `placeholder`, `id`, `disabled`, `required`, `maxlength` — passed
	  through to the input so native form constraints (required-field
	  prompts, max-length enforcement) still fire.
	- `inputBgClass` — background utility class applied to the input.
	  Default `bg-bg`; pass `bg-bg-surface` (or similar) when the
	  surrounding page already uses `bg-bg` for its container so the
	  input pops against it.
	- `inputClass` — any additional classes merged onto the input
	  (e.g. conditional `border-danger` for validation errors).

	## Keyboard

	- ArrowDown / ArrowUp — move highlight within the dropdown. Opens
	  the dropdown if closed.
	- Enter — select the highlighted row (or close if none).
	- Escape — close the dropdown.
	- Tab — close the dropdown without selecting.

	## CSP

	All positioning uses Tailwind classes — no inline `style` attributes
	are written anywhere, per the project CSP policy.
-->
<script lang="ts" generics="T">
	import type { Snippet } from 'svelte';
	import { onDestroy } from 'svelte';

	interface Props {
		value: string;
		fetcher: (query: string) => Promise<T[]>;
		formatLabel: (item: T) => string;
		itemKey: (item: T) => string;
		renderItem?: Snippet<[T]>;
		onSelect?: (item: T) => void;
		onClear?: () => void;
		onCreate?: (query: string) => void;
		createLabel?: (query: string) => string;
		debounceMs?: number;
		minQueryLength?: number;
		openOnFocus?: boolean;
		placeholder?: string;
		id?: string;
		disabled?: boolean;
		required?: boolean;
		maxlength?: number;
		/** Background utility class applied to the input. */
		inputBgClass?: string;
		/** Extra Tailwind classes to merge onto the input element. */
		inputClass?: string;
	}

	let {
		value = $bindable(''),
		fetcher,
		formatLabel,
		itemKey,
		renderItem,
		onSelect,
		onClear,
		onCreate,
		createLabel = (q: string) => `Create ${q}`,
		debounceMs = 200,
		minQueryLength = 1,
		openOnFocus = true,
		placeholder = '',
		id,
		disabled = false,
		required = false,
		maxlength,
		inputBgClass = 'bg-bg',
		inputClass = ''
	}: Props = $props();

	let results = $state<T[]>([]);
	let loading = $state(false);
	let open = $state(false);
	let highlightIdx = $state(-1);
	/** The query string that produced the current `results`. Guards
	 *  against stale responses clobbering newer ones when the user is
	 *  typing faster than the network round-trip. */
	let committedQuery = $state('');

	let debounceTimer: ReturnType<typeof setTimeout> | null = null;
	/** Monotonic counter used to ignore responses from in-flight
	 *  requests that were superseded by a newer query. */
	let requestSeq = 0;

	let containerEl = $state<HTMLDivElement | null>(null);

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
			const items = await fetcher(query);
			// If a newer request fired while this one was in flight,
			// discard our results — the newer one owns the UI now.
			if (seq !== requestSeq) return;
			results = items;
			committedQuery = query;
			open = true;
			highlightIdx = items.length > 0 ? 0 : -1;
		} catch {
			// Swallow errors quietly — autocomplete suggestions aren't
			// worth showing an error banner over. The caller will hear
			// about network problems when they try to submit the form.
			if (seq !== requestSeq) return;
			results = [];
			highlightIdx = -1;
		} finally {
			if (seq === requestSeq) loading = false;
		}
	}

	function scheduleFetch(query: string) {
		clearTimer();
		if (query.length < minQueryLength) {
			// Below the threshold: clear any stale results but don't
			// hit the network. Keep the dropdown closed unless
			// `openOnFocus` kicked in already.
			results = [];
			highlightIdx = -1;
			loading = false;
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
		if (next.trim().length === 0 && onClear) onClear();
		scheduleFetch(next.trim());
	}

	function onFocus() {
		if (disabled) return;
		if (openOnFocus && results.length === 0 && !loading) {
			// Fire immediately (no debounce) so the dropdown populates
			// as soon as the user focuses the field.
			void runFetch(value.trim());
		} else if (results.length > 0) {
			open = true;
		}
	}

	function onKeydown(e: KeyboardEvent) {
		if (disabled) return;
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			if (!open) {
				open = true;
				if (results.length === 0 && !loading) {
					void runFetch(value.trim());
					return;
				}
			}
			if (totalRowCount === 0) return;
			highlightIdx = (highlightIdx + 1) % totalRowCount;
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			if (!open || totalRowCount === 0) return;
			highlightIdx = highlightIdx <= 0 ? totalRowCount - 1 : highlightIdx - 1;
		} else if (e.key === 'Enter') {
			if (!open) return;
			if (highlightIdx >= 0 && highlightIdx < results.length) {
				e.preventDefault();
				selectItem(results[highlightIdx]);
			} else if (createRowVisible && highlightIdx === createRowIdx) {
				e.preventDefault();
				triggerCreate();
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
		}
	}

	function selectItem(item: T) {
		const label = formatLabel(item);
		value = label;
		committedQuery = label;
		open = false;
		highlightIdx = -1;
		clearTimer();
		onSelect?.(item);
	}

	function triggerCreate() {
		const q = value.trim();
		if (!q || !onCreate) return;
		open = false;
		highlightIdx = -1;
		clearTimer();
		onCreate(q);
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

	/// The trimmed query, cached so the template can read it without
	/// re-trimming on every access.
	const trimmedValue = $derived(value.trim());

	/// True when the typed query matches one of the result rows
	/// exactly (case-insensitive). We hide the "Create {q}" row in
	/// that case so the user isn't invited to create a duplicate.
	const hasExactMatch = $derived(
		results.some(
			(r) => formatLabel(r).toLowerCase() === trimmedValue.toLowerCase()
		)
	);

	/// Derived: whether the "Create {q}" row should be appended to
	/// the dropdown. Requires `onCreate`, a non-empty query, a
	/// settled fetch (committedQuery matches the input), and no
	/// exact match among the current results.
	const createRowVisible = $derived(
		open &&
			!loading &&
			typeof onCreate === 'function' &&
			trimmedValue.length > 0 &&
			committedQuery === trimmedValue &&
			committedQuery.length >= minQueryLength &&
			!hasExactMatch
	);

	/// The index assigned to the create row in the virtual row list.
	/// Result rows occupy `[0, results.length)`, and the create row
	/// (when visible) is appended at `results.length`.
	const createRowIdx = $derived(results.length);

	const totalRowCount = $derived(results.length + (createRowVisible ? 1 : 0));

	/// Auto-highlight the create row when it is the only option, so
	/// a user can hit Enter directly without arrowing down first.
	$effect(() => {
		if (createRowVisible && results.length === 0 && highlightIdx !== 0) {
			highlightIdx = 0;
		}
	});

	/// Derived: whether to show the dropdown at all. Open + either
	/// loading, there's a result to render, or the create row is live.
	const showDropdown = $derived(
		open && (loading || results.length > 0 || createRowVisible)
	);
	const showEmpty = $derived(
		open &&
			!loading &&
			results.length === 0 &&
			!createRowVisible &&
			committedQuery.length >= minQueryLength &&
			committedQuery === trimmedValue
	);
</script>

<div bind:this={containerEl} class="relative">
	<input
		{id}
		type="text"
		bind:value
		{placeholder}
		{disabled}
		{required}
		{maxlength}
		autocomplete="off"
		role="combobox"
		aria-autocomplete="list"
		aria-expanded={showDropdown}
		aria-controls={id ? `${id}-listbox` : undefined}
		oninput={onInput}
		onfocus={onFocus}
		onkeydown={onKeydown}
		class="w-full {inputBgClass} border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted font-sans disabled:opacity-50 disabled:cursor-not-allowed {inputClass}"
	/>

	{#if showDropdown}
		<ul
			id={id ? `${id}-listbox` : undefined}
			role="listbox"
			class="absolute z-20 left-0 right-0 mt-1 max-h-64 overflow-y-auto bg-bg-surface border border-border rounded-md shadow-lg py-1"
		>
			{#if loading && results.length === 0}
				<li class="px-3 py-2 text-xs text-text-muted">Searching…</li>
			{:else}
				{#each results as item, i (itemKey(item))}
					{@const active = i === highlightIdx}
					<li role="option" aria-selected={active}>
						<button
							type="button"
							tabindex="-1"
							onpointerdown={(e) => {
								// pointerdown (not click) so the selection
								// fires before the input loses focus and
								// the `pointerdown` outside-listener would
								// close the dropdown.
								e.preventDefault();
								selectItem(item);
							}}
							onmousemove={() => (highlightIdx = i)}
							class="w-full text-left px-3 py-2 text-sm cursor-pointer font-sans block
								{active ? 'bg-bg-hover text-text-primary' : 'text-text-secondary hover:bg-bg-hover'}"
						>
							{#if renderItem}
								{@render renderItem(item)}
							{:else}
								{formatLabel(item)}
							{/if}
						</button>
					</li>
				{/each}
				{#if createRowVisible}
					{@const active = highlightIdx === createRowIdx}
					<li role="option" aria-selected={active} class={results.length > 0 ? 'border-t border-border-subtle mt-1 pt-1' : ''}>
						<button
							type="button"
							tabindex="-1"
							onpointerdown={(e) => {
								e.preventDefault();
								triggerCreate();
							}}
							onmousemove={() => (highlightIdx = createRowIdx)}
							class="w-full text-left px-3 py-2 text-sm cursor-pointer font-sans block
								{active ? 'bg-bg-hover text-accent' : 'text-accent hover:bg-bg-hover'}"
						>
							{createLabel(trimmedValue)}
						</button>
					</li>
				{/if}
			{/if}
		</ul>
	{:else if showEmpty}
		<ul
			id={id ? `${id}-listbox` : undefined}
			role="listbox"
			class="absolute z-20 left-0 right-0 mt-1 bg-bg-surface border border-border rounded-md shadow-lg py-1"
		>
			<li class="px-3 py-2 text-xs text-text-muted">No matches</li>
		</ul>
	{/if}
</div>
