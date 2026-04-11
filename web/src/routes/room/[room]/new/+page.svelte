<script lang="ts">
	import { createThread } from '$lib/api/threads';
	import { errorMessage } from '$lib/i18n/errors';
	import { goto } from '$app/navigation';
	import { slide } from 'svelte/transition';

	const MIN_TITLE = 5;
	const MAX_TITLE = 150;
	const MAX_BODY = 50_000;
	const BODY_COUNTER_THRESHOLD = 40_000;

	let { data } = $props();
	let room = $derived(data.room);

	let title = $state('');
	let body = $state('');
	let error = $state<string | null>(null);
	let submitting = $state(false);

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

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		if (titleLen < MIN_TITLE || titleLen > MAX_TITLE) {
			error = titleError;
			return;
		}
		if (!body.trim()) {
			error = 'Body cannot be empty';
			return;
		}
		if (bodyLen > MAX_BODY) {
			error = `Body must be at most ${MAX_BODY} characters`;
			return;
		}

		submitting = true;
		error = null;
		try {
			const slug = room.slug;
			const req: import('$lib/api/threads').CreateThreadRequest = {
				title: title.trim(),
				body: body.trim()
			};
			const thread = await createThread(slug, req);
			goto(`/room/${encodeURIComponent(slug)}/${thread.id}`);
		} catch (e) {
			error = errorMessage(e, 'Failed to create thread');
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>New Thread — {room.name} — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<h1 class="text-xl font-bold mb-6">New Thread</h1>

	<form onsubmit={handleSubmit} class="space-y-4">
		{#if error}
			<div
				transition:slide={{ duration: 150 }}
				class="bg-bg-surface border border-danger rounded-md p-3 text-danger text-sm"
			>
				{error}
			</div>
		{/if}

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
				class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted"
				class:border-danger={!!titleError}
			/>
			{#if titleError}
				<p transition:slide={{ duration: 150 }} class="text-danger text-xs mt-1">
					{titleError}
				</p>
			{/if}
		</div>

		<div>
			<label for="thread-body" class="block text-sm font-medium text-text-secondary mb-1"
				>Body</label
			>
			<textarea
				id="thread-body"
				bind:value={body}
				placeholder="Write your post in Markdown..."
				rows={10}
				disabled={submitting}
				class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm font-mono px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted resize-y leading-relaxed"
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

		<div class="flex items-center gap-3">
			<button
				type="submit"
				disabled={submitting || !title.trim() || !body.trim() || !!titleError || bodyLen > MAX_BODY}
				class="text-sm px-4 py-2 rounded-md cursor-pointer border border-accent bg-accent text-bg font-medium hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
			>
				{submitting ? 'Creating…' : 'Create Thread'}
			</button>
			<a
				href="/room/{encodeURIComponent(room.slug)}"
				class="text-sm text-text-muted hover:text-text-secondary">Cancel</a
			>
		</div>
	</form>
</div>
