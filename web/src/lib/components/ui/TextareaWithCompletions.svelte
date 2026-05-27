<!--
	Textarea wrapper with compose-time autocomplete for `@username`
	mentions and `/r/slug` room links.

	## Behaviour

	As the user types, the component scans backwards from the caret
	for an active mention/room token:

	- `@` followed by `[\p{L}\p{N}_-]{1,20}` triggers user search.
	- `/r/` followed by `[a-z0-9_]{1,30}` triggers room search.

	Both triggers must sit at the start of the input or immediately
	after whitespace, so naked-`@` patterns inside emails / paths
	(e.g. `foo@bar.com`, `cd ~/dir`) don't fire the popover.

	A space or any out-of-class character closes the popover —
	usernames and room slugs cannot contain spaces, so once the user
	has typed past the token there's nothing to suggest.

	Selecting a row replaces the token with `@{display_name}.{8hex}`
	(the canonical long form — pubkey-prefix suffix selects exactly
	one user even when two share a display-name skeleton, so the
	mention survives a future federated collision without silently
	repointing). Room rows insert `/r/{slug}`. The markdown renderer
	strips the suffix from the visible link text, so readers still
	see `@alice` regardless of which form was typed — see
	`markdown.ts`.

	## API

	Behaves like a plain `<textarea>` for the parent: `value` is
	bindable, all other styling / sizing / a11y props are passed
	through verbatim. Keyboard navigation inside the popover
	(ArrowUp / ArrowDown / Enter / Tab / Escape) is intercepted; all
	other keys propagate to the textarea normally so the parent's
	input/keydown handlers still see them.

	## Positioning

	The popover anchors to the bottom-left of the textarea (not the
	caret). Caret-anchored positioning would need a mirror-div
	measurement pass, which is complex and fragile under the CSP
	policy that forbids inline `style` attributes. Bottom-anchoring
	is good enough for the textareas we care about today (short
	reply / bio composers and the new-thread body).

	## CSP

	No inline `style` attributes. The dropdown uses Tailwind classes
	exclusively; position is `absolute` relative to the wrapper.
-->
<script lang="ts">
	import { onDestroy } from 'svelte';
	import { searchUsers, type UserChip } from '$lib/api/users';
	import { searchRooms, type RoomChip } from '$lib/api/rooms';
	import UserName from '$lib/components/trust/UserName.svelte';

	interface Props {
		value: string;
		class?: string;
		placeholder?: string;
		rows?: number;
		maxlength?: number;
		disabled?: boolean;
		id?: string;
		oninput?: (e: Event) => void;
	}

	let {
		value = $bindable(''),
		class: className = '',
		placeholder = '',
		rows,
		maxlength,
		disabled = false,
		id,
		oninput
	}: Props = $props();

	/** Discriminated suggestion union — keeps the dropdown a single
	 *  render path regardless of which trigger fired. */
	type Suggestion =
		| { kind: 'user'; chip: UserChip }
		| { kind: 'room'; chip: RoomChip };

	/** Active token detected at the caret. `start` / `end` are
	 *  string offsets into `value`; `query` is the characters typed
	 *  after the trigger (the part we send to the search endpoint). */
	type ActiveToken =
		| { kind: 'user'; start: number; end: number; query: string }
		| { kind: 'room'; start: number; end: number; query: string };

	let textareaEl = $state<HTMLTextAreaElement | null>(null);
	let containerEl = $state<HTMLDivElement | null>(null);

	let token = $state<ActiveToken | null>(null);
	let results = $state<Suggestion[]>([]);
	let highlightIdx = $state(-1);
	/** `requestSeq` guard mirrors the pattern in `Autocomplete.svelte`:
	 *  in-flight responses from older queries are discarded when a
	 *  newer query has already started. */
	let requestSeq = 0;
	let debounceTimer: ReturnType<typeof setTimeout> | null = null;
	const DEBOUNCE_MS = 200;

	// Allowed-character regexes mirror the server-side rules:
	//   - usernames: `[\p{L}\p{N}_-]{3,20}` (see `server/src/display_name.rs`)
	//   - room slugs: `[a-z0-9_]{3,30}` (see `server/src/room_name.rs`)
	// At compose time we trigger on 1+ chars (not the full 3-char
	// minimum) so the popover appears as soon as the user has typed
	// anything after `@` / `/r/`.
	const USER_CHAR = /[\p{L}\p{N}_-]/u;
	const ROOM_CHAR = /[a-z0-9_]/;

	const USER_QUERY_MAX = 20;
	const ROOM_QUERY_MAX = 30;

	/**
	 * Scan backwards from the caret to find an active mention/room
	 * token. Returns `null` when no token is active — i.e. the
	 * character immediately before the caret is whitespace or some
	 * other out-of-class character.
	 *
	 * Two separate single-class walks (rather than one combined walk
	 * that admits both `/` and word chars) — combining them lets
	 * unrelated `/`s get pulled into a user-mention candidate and
	 * vice-versa.
	 *
	 * The trigger (`@` or `/r/`) must sit at the start of the input
	 * or immediately after whitespace; this prevents false fires
	 * inside emails (`foo@bar`) and paths (`/usr/r/foo`).
	 */
	function scanToken(text: string, caret: number): ActiveToken | null {
		// --- User mention candidate ---
		let i = caret;
		while (i > 0 && USER_CHAR.test(text[i - 1])) i--;
		// `text[i-1]` is now the first char before the run of
		// username-class characters. If it's `@`, we may have a
		// trigger.
		if (i > 0 && text[i - 1] === '@') {
			const triggerAt = i - 1;
			const startOk = triggerAt === 0 || /\s/.test(text[triggerAt - 1]);
			const query = text.slice(i, caret);
			if (startOk && query.length > 0 && query.length <= USER_QUERY_MAX) {
				return { kind: 'user', start: triggerAt, end: caret, query };
			}
		}

		// --- Room link candidate ---
		i = caret;
		while (i > 0 && ROOM_CHAR.test(text[i - 1])) i--;
		// `text[i-3..i]` should be `/r/` for a valid trigger.
		if (i >= 3 && text.slice(i - 3, i) === '/r/') {
			const triggerAt = i - 3;
			const startOk = triggerAt === 0 || /\s/.test(text[triggerAt - 1]);
			const query = text.slice(i, caret);
			if (startOk && query.length > 0 && query.length <= ROOM_QUERY_MAX) {
				return { kind: 'room', start: triggerAt, end: caret, query };
			}
		}

		return null;
	}

	function clearTimer() {
		if (debounceTimer !== null) {
			clearTimeout(debounceTimer);
			debounceTimer = null;
		}
	}

	/** Close the popover and invalidate any in-flight fetch so a late
	 *  response can't reopen it. */
	function closePopover() {
		token = null;
		results = [];
		highlightIdx = -1;
		clearTimer();
		requestSeq++;
	}

	async function runFetch(active: ActiveToken) {
		const seq = ++requestSeq;
		try {
			let items: Suggestion[];
			if (active.kind === 'user') {
				const users = await searchUsers(active.query);
				// Filter out non-active rows: mention autocomplete
				// should not surface banned / suspended users.
				items = users
					.filter((u) => u.status === 'active')
					.map((chip) => ({ kind: 'user' as const, chip }));
			} else {
				const rooms = await searchRooms(active.query);
				items = rooms.map((chip) => ({ kind: 'room' as const, chip }));
			}
			if (seq !== requestSeq) return; // superseded
			results = items;
			highlightIdx = items.length > 0 ? 0 : -1;
		} catch {
			// Suggestions failing is a soft error — keep the user
			// typing, just don't show a popover.
			if (seq !== requestSeq) return;
			results = [];
			highlightIdx = -1;
		}
	}

	function scheduleFetch(active: ActiveToken) {
		clearTimer();
		debounceTimer = setTimeout(() => {
			void runFetch(active);
		}, DEBOUNCE_MS);
	}

	function handleInput(e: Event) {
		const ta = e.currentTarget as HTMLTextAreaElement;
		value = ta.value;
		updateToken(ta);
		oninput?.(e);
	}

	function updateToken(ta: HTMLTextAreaElement) {
		const caret = ta.selectionStart ?? ta.value.length;
		const next = scanToken(ta.value, caret);
		if (next === null) {
			if (token !== null) closePopover();
			return;
		}
		// If the token kind or query changed, reschedule the fetch.
		const same =
			token !== null &&
			token.kind === next.kind &&
			token.query === next.query &&
			token.start === next.start;
		token = next;
		if (!same) {
			scheduleFetch(next);
		}
	}

	function handleSelectionChange() {
		// Caret moves (arrow keys, mouse click inside the textarea)
		// can break out of an active token. Re-scan whenever the
		// selection might have moved.
		if (textareaEl) updateToken(textareaEl);
	}

	function suggestionLabel(s: Suggestion): string {
		// User picks always insert the canonical long form
		// (`@name.{first-8-hex-of-pubkey}`). Pinning the mention to a
		// specific pubkey at compose time means a future user with the
		// same display-name skeleton can't quietly inherit the link —
		// the suffix is the same routing tiebreaker the URL and the
		// renderer use. Readers still see only `@name`; the markdown
		// renderer strips the suffix from the visible text.
		return s.kind === 'user'
			? `@${s.chip.display_name}.${s.chip.public_key_hex.slice(0, 8)}`
			: `/r/${s.chip.slug}`;
	}

	function suggestionKey(s: Suggestion): string {
		return `${s.kind}:${s.chip.id}`;
	}

	function selectSuggestion(s: Suggestion) {
		if (!textareaEl || !token) return;
		const ta = textareaEl;
		const replacement = suggestionLabel(s);
		const before = value.slice(0, token.start);
		const after = value.slice(token.end);
		// Append a single trailing space so the user can keep typing.
		// Only insert the space when the very next character isn't
		// already whitespace, to avoid stacking spaces if the user
		// is editing mid-paragraph.
		const needsSpace = after.length === 0 || !/\s/.test(after[0]);
		const insertion = replacement + (needsSpace ? ' ' : '');
		const newValue = before + insertion + after;
		value = newValue;
		closePopover();
		// Restore caret to the position immediately after the
		// inserted text (and after the auto-space, if any).
		const newCaret = before.length + insertion.length;
		// Defer the caret restore: Svelte updates the textarea's
		// `value` reactively on the next microtask, and setting
		// `selectionStart` before that would target the stale value.
		queueMicrotask(() => {
			ta.focus();
			ta.setSelectionRange(newCaret, newCaret);
		});
	}

	function handleKeydown(e: KeyboardEvent) {
		if (!token || results.length === 0) {
			// No active popover — let the event bubble normally.
			return;
		}
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			highlightIdx = (highlightIdx + 1) % results.length;
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			highlightIdx = highlightIdx <= 0 ? results.length - 1 : highlightIdx - 1;
		} else if (e.key === 'Enter' || e.key === 'Tab') {
			if (highlightIdx >= 0 && highlightIdx < results.length) {
				e.preventDefault();
				selectSuggestion(results[highlightIdx]);
			}
		} else if (e.key === 'Escape') {
			e.preventDefault();
			closePopover();
		}
	}

	function handleBlur() {
		// Don't close immediately — a click on a popover row blurs
		// the textarea right before firing the click handler. Defer
		// a tick so pointerdown on a row can win the race.
		setTimeout(() => {
			if (typeof document === 'undefined') return;
			if (containerEl && document.activeElement && containerEl.contains(document.activeElement)) {
				return;
			}
			closePopover();
		}, 100);
	}

	onDestroy(clearTimer);

	// Only render the popover once we have results in hand. Showing
	// a "Searching…" placeholder while the fetch is in flight makes
	// empty-result searches flash a popover that immediately closes
	// — visually noisier than just waiting for the (debounced + fast)
	// response to land.
	const showPopover = $derived(token !== null && results.length > 0);
</script>

<div bind:this={containerEl} class="relative">
	<textarea
		bind:this={textareaEl}
		bind:value
		{placeholder}
		{rows}
		{maxlength}
		{disabled}
		{id}
		oninput={handleInput}
		onkeydown={handleKeydown}
		onkeyup={handleSelectionChange}
		onclick={handleSelectionChange}
		onblur={handleBlur}
		class={className}
	></textarea>

	{#if showPopover}
		<ul
			role="listbox"
			class="absolute z-20 left-0 right-0 top-full mt-1 max-h-64 overflow-y-auto bg-bg-surface border border-border rounded-md shadow-lg py-1"
		>
			{#each results as item, i (suggestionKey(item))}
				{@const active = i === highlightIdx}
				<li role="option" aria-selected={active}>
					<button
						type="button"
						tabindex="-1"
						onpointerdown={(e) => {
							// pointerdown (not click) so the selection
							// fires before the textarea's blur handler
							// has a chance to close the popover.
							e.preventDefault();
							selectSuggestion(item);
						}}
						onmousemove={() => (highlightIdx = i)}
						class="w-full text-left px-3 py-2 text-sm cursor-pointer font-sans flex items-center gap-2
							{active ? 'bg-bg-hover' : 'hover:bg-bg-hover'}"
					>
						{#if item.kind === 'user'}
							<!-- linked={false} — the row itself is a button
							     that inserts the mention; the inner anchor
							     would steal the click and navigate away. -->
							<UserName name={item.chip.display_name} pubkeyHex={item.chip.public_key_hex} viewer={item.chip.viewer} linked={false} compact />
						{:else}
							<span class="text-text-primary">/r/{item.chip.slug}</span>
						{/if}
					</button>
				</li>
			{/each}
		</ul>
	{/if}
</div>
