<script lang="ts">
	import { createThread, getThreadsByLink, type ThreadSummary } from '$lib/api/threads';
	import { searchRooms, type RoomChip } from '$lib/api/rooms';
	import Autocomplete from '$lib/components/ui/Autocomplete.svelte';
	import ThreadListRow from '$lib/components/post/ThreadListRow.svelte';
	import { validateRoomSlug } from '$lib/validation/room-name';
	import { errorMessage } from '$lib/i18n/errors';
	import { goto } from '$app/navigation';
	import { slide } from 'svelte/transition';

	const MIN_TITLE = 5;
	const MAX_TITLE = 150;
	const MAX_BODY = 50_000;
	const MAX_LINK = 2048;
	const BODY_COUNTER_THRESHOLD = 40_000;

	let { data } = $props();

	type PostKind = 'text' | 'link';

	// svelte-ignore state_referenced_locally
	let room = $state(data.prefillRoom);
	let title = $state('');
	let body = $state('');
	let link = $state('');
	let kind = $state<PostKind>('text');
	let error = $state<string | null>(null);
	let submitting = $state(false);

	/**
	 * Dupe-suggestion state. Populated when the URL field blurs with a
	 * valid, non-empty link. Cached by trimmed URL so toggling kind or
	 * re-focusing without changing the URL doesn't re-fetch. The
	 * AbortController guards against a fast typist whose earlier blur
	 * response would otherwise overwrite a fresher one.
	 *
	 * `suggestionsForUrl` keys the visible suggestions to the URL they
	 * were fetched for, so as soon as the user edits the URL the panel
	 * disappears — re-blurring repopulates it.
	 */
	let linkSuggestions = $state<ThreadSummary[]>([]);
	let suggestionsForUrl = $state<string | null>(null);
	const suggestionCache = new Map<string, ThreadSummary[]>();
	let suggestionController: AbortController | null = null;

	let visibleSuggestions = $derived(
		kind === 'link' && link.trim() === suggestionsForUrl ? linkSuggestions : []
	);

	async function loadLinkSuggestions(url: string) {
		const cached = suggestionCache.get(url);
		if (cached) {
			linkSuggestions = cached;
			suggestionsForUrl = url;
			return;
		}
		suggestionController?.abort();
		const controller = new AbortController();
		suggestionController = controller;
		try {
			const res = await getThreadsByLink(url, { signal: controller.signal });
			if (controller.signal.aborted) return;
			suggestionCache.set(url, res.threads);
			linkSuggestions = res.threads;
			suggestionsForUrl = url;
		} catch (e) {
			if (e instanceof DOMException && e.name === 'AbortError') return;
			// Suggestions are a hint — swallow other errors so a flaky
			// network doesn't block the user from posting.
			linkSuggestions = [];
			suggestionsForUrl = null;
		}
	}

	function handleLinkBlur() {
		if (kind !== 'link') return;
		const trimmed = link.trim();
		if (!trimmed || linkError) {
			suggestionController?.abort();
			return;
		}
		loadLinkSuggestions(trimmed);
	}

	let roomError = $derived(room.trim() ? validateRoomSlug(room) : null);
	let normalizedRoom = $derived(room.trim().toLowerCase());

	/**
	 * Whether the typed room slug exactly matches an existing room.
	 * `null` means "unknown" — either the slug is empty/invalid, or the
	 * Autocomplete's debounced fetch for this query hasn't settled yet.
	 *
	 * The backend auto-creates a room on thread submit if no room with
	 * the slug exists, so surfacing this lets users notice when they
	 * are about to spawn a new room instead of posting into one they
	 * intended to target. We piggy-back on the Autocomplete's existing
	 * `searchRooms` call (via `onResults`) rather than issuing a second
	 * round-trip.
	 */
	let roomExists = $state<boolean | null>(null);

	$effect(() => {
		// Reset to "unknown" whenever the normalized slug or its
		// validity changes. The Autocomplete's onResults callback (or
		// onSelect) re-populates this once a verdict is available;
		// until then we never want to display a stale answer for a
		// freshly-edited slug.
		normalizedRoom;
		roomError;
		roomExists = null;
	});
	let titleLen = $derived(title.trim().length);
	let bodyLen = $derived(body.trim().length);
	let showBodyCounter = $derived(bodyLen >= BODY_COUNTER_THRESHOLD);
	let bodyRemaining = $derived(MAX_BODY - bodyLen);
	let titleError = $derived.by(() => {
		if (!title.trim()) return null;
		if (titleLen < MIN_TITLE) return `Title must be at least ${MIN_TITLE} characters`;
		if (titleLen > MAX_TITLE) return `Title must be at most ${MAX_TITLE} characters`;
		return null;
	});
	let linkError = $derived.by(() => {
		if (kind !== 'link') return null;
		const trimmed = link.trim();
		if (!trimmed) return null;
		if (trimmed.length > MAX_LINK) return `Link must be at most ${MAX_LINK} characters`;
		const lower = trimmed.toLowerCase();
		if (!lower.startsWith('http://') && !lower.startsWith('https://')) {
			return 'Link must start with http:// or https://';
		}
		return null;
	});

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		const slugError = validateRoomSlug(room);
		if (slugError) {
			error = slugError;
			return;
		}
		if (titleLen < MIN_TITLE || titleLen > MAX_TITLE) {
			error = titleError;
			return;
		}
		if (kind === 'link') {
			if (!link.trim()) {
				error = 'Link cannot be empty';
				return;
			}
			if (linkError) {
				error = linkError;
				return;
			}
		} else {
			if (!body.trim()) {
				error = 'Body cannot be empty';
				return;
			}
		}
		if (bodyLen > MAX_BODY) {
			error = `Body must be at most ${MAX_BODY} characters`;
			return;
		}

		submitting = true;
		error = null;
		try {
			const trimmedBody = body.trim();
			const thread = await createThread({
				room: room.trim().toLowerCase(),
				title: title.trim(),
				body: trimmedBody,
				...(kind === 'link' ? { link: link.trim() } : {})
			});
			goto(`/r/${encodeURIComponent(thread.room_slug)}/${thread.id}`);
		} catch (e) {
			error = errorMessage(e, 'Failed to create thread');
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>New Thread — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<h1 class="text-xl font-bold mb-6">New Thread</h1>

	<form onsubmit={handleSubmit} class="space-y-5">
		{#if error}
			<div
				transition:slide={{ duration: 150 }}
				class="bg-bg-surface border border-danger rounded-md p-3 text-danger text-sm"
			>
				{error}
			</div>
		{/if}

		<div>
			<label for="thread-room" class="block text-sm font-medium text-text-secondary mb-1"
				>Room</label
			>
			<Autocomplete
				id="thread-room"
				bind:value={room}
				fetcher={(q) => searchRooms(q)}
				formatLabel={(r: RoomChip) => r.slug}
				itemKey={(r: RoomChip) => r.id}
				onSelect={() => {
					// Picking from the dropdown is definitionally an
					// existing room — bypass the wait for onResults.
					roomExists = true;
				}}
				onResults={(q, items: RoomChip[]) => {
					// Reuse the Autocomplete's settled fetch to detect
					// whether the current input exactly matches an
					// existing room. Guard against a stale callback
					// whose query no longer reflects what the user has
					// typed (or whose validity has since changed).
					const slug = q.toLowerCase();
					if (roomError || slug !== normalizedRoom) return;
					roomExists = items.some((r) => r.slug === slug);
				}}
				onCreate={() => {
					/* closing the dropdown is the only action needed;
					   the backend auto-creates a room on thread submit
					   if no room with that slug exists. */
				}}
				createLabel={(q) => `Create room: "${q}"`}
				openOnFocus={false}
				required
				maxlength={30}
				disabled={submitting}
				placeholder="e.g. technology, general, meta"
				inputBgClass="bg-bg-surface"
				inputClass={roomError ? 'border-danger' : ''}
				suppressDropdown={!!roomError}
			>
				{#snippet renderItem(r: RoomChip)}
					<div class="flex items-baseline justify-between gap-3">
						<span class="text-text-primary font-medium">{r.slug}</span>
					</div>
				{/snippet}
			</Autocomplete>
			{#if roomError}
				<p transition:slide={{ duration: 150 }} class="text-danger text-xs mt-1">
					{roomError}
				</p>
			{:else if room.trim()}
				<p transition:slide={{ duration: 150 }} class="text-xs text-text-muted mt-1">
					/r/<span class="text-text-secondary"
						>{room.trim().toLowerCase().replace(/[^a-z0-9_]/g, '')}</span
					>
					{#if roomExists === false}
						<span class="text-accent">· New room — will be created when you submit</span>
					{/if}
				</p>
			{/if}
		</div>

		<fieldset class="border-none p-0">
			<legend class="block text-sm font-medium text-text-secondary mb-1">Post type</legend>
			<!--
				Pills + URL share a single visual row. The pill group keeps
				`rounded-l-md` always, and only adds `rounded-r-md` when the
				URL input is hidden. The URL input has `border-l-0` so it
				borrows the pill group's right border instead of stacking
				its own (which would render as a chunky double line).

				Layout uses CSS Grid (not flex) so the slide-axis-x
				transition on the URL input animates correctly. In flex,
				`flex-1`'s `flex-basis: 0%` overrides any inline `width`
				the slide transition tries to write, producing a snap. In
				grid, the URL track is always allocated `minmax(0, 1fr)` —
				the input's animated width is honored, and the row width
				doesn't shift when the input appears or disappears.
			-->
			<div class="grid grid-cols-[auto_minmax(0,1fr)] items-stretch">
				<div
					class="inline-flex border border-border overflow-hidden rounded-l-md"
					class:rounded-r-md={kind !== 'link'}
				>
					<label
						class="text-sm px-3 py-2 cursor-pointer flex items-center {kind === 'text'
							? 'bg-accent text-bg font-medium'
							: 'bg-bg-surface text-text-secondary hover:text-text-primary'}"
					>
						<input
							type="radio"
							name="post-kind"
							value="text"
							bind:group={kind}
							disabled={submitting}
							class="sr-only"
						/>
						Text
					</label>
					<label
						class="text-sm px-3 py-2 cursor-pointer border-l border-border flex items-center {kind === 'link'
							? 'bg-accent text-bg font-medium'
							: 'bg-bg-surface text-text-secondary hover:text-text-primary'}"
					>
						<input
							type="radio"
							name="post-kind"
							value="link"
							bind:group={kind}
							disabled={submitting}
							class="sr-only"
						/>
						Link
					</label>
				</div>
				{#if kind === 'link'}
					<label for="thread-link" class="sr-only">URL</label>
					<input
						id="thread-link"
						type="url"
						bind:value={link}
						onblur={handleLinkBlur}
						maxlength={MAX_LINK}
						required
						autocomplete="off"
						disabled={submitting}
						placeholder="https://example.com/article"
						transition:slide={{ axis: 'x', duration: 150 }}
						class="flex-1 min-w-0 bg-bg-surface border border-l-0 border-border rounded-r-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted"
						class:border-danger={!!linkError}
					/>
				{/if}
			</div>
			{#if linkError}
				<p transition:slide={{ duration: 150 }} class="text-danger text-xs mt-1">
					{linkError}
				</p>
			{/if}
		</fieldset>

		<div>
			<label for="thread-title" class="block text-sm font-medium text-text-secondary mb-1"
				>Title</label
			>
			<input
				id="thread-title"
				type="text"
				bind:value={title}
				maxlength={MAX_TITLE}
				required
				autocomplete="off"
				disabled={submitting}
				placeholder="What is this thread about?"
				class="w-full bg-bg-surface border border-border rounded-md text-text-primary font-prose text-prose px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted"
				class:border-danger={!!titleError}
			/>
			{#if titleError}
				<p transition:slide={{ duration: 150 }} class="text-danger text-xs mt-1">
					{titleError}
				</p>
			{/if}
		</div>

		<div>
			<label for="thread-body" class="block text-sm font-medium text-text-secondary mb-1">
				Body{#if kind === 'link'}<span class="text-text-muted font-normal"> (optional)</span>{/if}
			</label>
			<!--
				Height is driven by `min-height` (toggled via class) rather
				than the `rows` attribute, because `rows` cannot be CSS-
				transitioned. The two min-h values approximately match
				rows=5 / rows=10 at the prose font-size + line-height.
				`resize-y` still works: once the user manually resizes,
				the inline height overrides min-height and subsequent
				kind toggles won't shrink it.
			-->
			<textarea
				id="thread-body"
				bind:value={body}
				placeholder={kind === 'link'
					? 'Optional: add context or commentary in Markdown...'
					: 'Write your post in Markdown...'}
				disabled={submitting}
				class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-prose font-prose px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted resize-y transition-[min-height] duration-200 ease-out {kind === 'link' ? 'min-h-40' : 'min-h-72'}"
				class:border-danger={bodyLen > MAX_BODY}
			></textarea>
			<div class="flex items-center justify-between mt-1">
				<p class="text-xs text-text-muted">Markdown supported</p>
				{#if showBodyCounter}
					<p
						transition:slide={{ duration: 150, axis: 'x' }}
						class="text-xs tabular-nums {bodyRemaining < 0 ? 'text-danger font-medium' : bodyRemaining < 2000 ? 'text-text-secondary' : 'text-text-muted'}"
					>
						{bodyRemaining.toLocaleString()} characters remaining
					</p>
				{/if}
			</div>
		</div>

		{#if visibleSuggestions.length > 0}
			<!--
				Suggestions are informational only — clicking a row
				navigates away, but the user can ignore them and submit
				anyway. `visibleSuggestions` is keyed to the URL they were
				fetched for, so editing the URL hides the panel until the
				next blur repopulates it.
			-->
			<div transition:slide={{ duration: 150 }} class="space-y-2">
				<p class="text-xs text-text-muted">
					This link has been posted before in the following threads:
				</p>
				{#each visibleSuggestions as suggestion (suggestion.id)}
					<ThreadListRow thread={suggestion} variant="card" showRoomSlug />
				{/each}
			</div>
		{/if}

		<div class="flex items-center gap-3">
			<button
				type="submit"
				disabled={submitting ||
					!room.trim() ||
					!title.trim() ||
					(kind === 'text' ? !body.trim() : !link.trim()) ||
					!!roomError ||
					!!titleError ||
					!!linkError ||
					bodyLen > MAX_BODY}
				class="text-sm px-4 py-2 rounded-md cursor-pointer border border-accent bg-accent text-bg font-medium hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
			>
				{submitting ? 'Creating…' : 'Create Thread'}
			</button>
			<button
				type="button"
				onclick={() => history.back()}
				class="text-sm text-text-muted hover:text-text-secondary bg-transparent border-none cursor-pointer font-sans"
			>Cancel</button>
		</div>
	</form>
</div>
