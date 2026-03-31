<script lang="ts">
	import { createTopic } from '$lib/api/topics';
	import { session } from '$lib/stores/session.svelte';
	import { validateTopicName } from '$lib/validation/topic-name';
	import { goto } from '$app/navigation';
	import { slide } from 'svelte/transition';

	const MAX_DESCRIPTION = 300;

	let name = $state('');
	let description = $state('');
	let error = $state<string | null>(null);
	let nameError = $derived(name.trim() ? validateTopicName(name) : null);
	let slug = $derived(name.trim() ? name.trim().toLowerCase().replace(/[ -]/g, '_') : '');
	let descriptionChars = $derived([...description].length);
	let submitting = $state(false);

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		const validationError = validateTopicName(name);
		if (validationError) {
			error = validationError;
			return;
		}
		if (descriptionChars > MAX_DESCRIPTION) {
			error = `Description must be at most ${MAX_DESCRIPTION} characters`;
			return;
		}

		submitting = true;
		error = null;
		try {
			const topic = await createTopic({
				name: name.trim(),
				description: description.trim() || undefined
			});
			goto(`/t/${encodeURIComponent(topic.slug)}`);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to create topic';
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>New Topic — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<h1 class="text-xl font-bold mb-6">New Topic</h1>

	{#if !session.isLoggedIn && !session.loading}
		<div class="text-center text-text-muted py-12">
			<a href="/login" class="text-link hover:text-link-hover">Sign in</a> to create a topic.
		</div>
	{:else}
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
				<label for="topic-name" class="block text-sm font-medium text-text-secondary mb-1"
					>Name</label
				>
				<input
					id="topic-name"
					type="text"
					bind:value={name}
					maxlength={30}
					required
					autocomplete="off"
					disabled={submitting}
					class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted"
					class:border-danger={!!nameError}
				/>
				{#if nameError}
					<p transition:slide={{ duration: 150 }} class="text-danger text-xs mt-1">
						{nameError}
					</p>
				{:else if slug}
					<p transition:slide={{ duration: 150 }} class="text-xs text-text-muted mt-1">
						/t/<span class="text-text-secondary">{slug}</span>
					</p>
				{/if}
			</div>

			<div>
				<label
					for="topic-description"
					class="block text-sm font-medium text-text-secondary mb-1">Description</label
				>
				<textarea
					id="topic-description"
					bind:value={description}
					placeholder="What is this topic about?"
					rows={3}
					disabled={submitting}
					class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted resize-y"
					class:border-danger={descriptionChars > MAX_DESCRIPTION}
				></textarea>
				<p
					class="text-xs mt-1 text-right"
					class:text-text-muted={descriptionChars <= MAX_DESCRIPTION}
					class:text-danger={descriptionChars > MAX_DESCRIPTION}
				>
					{descriptionChars}/{MAX_DESCRIPTION}
				</p>
			</div>

			<div class="flex items-center gap-3">
				<button
					type="submit"
					disabled={submitting || !name.trim() || !!nameError || descriptionChars > MAX_DESCRIPTION}
					class="text-sm px-4 py-2 rounded-md cursor-pointer border border-accent bg-accent text-bg font-medium hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
				>
					{submitting ? 'Creating…' : 'Create Topic'}
				</button>
				<a href="/" class="text-sm text-text-muted hover:text-text-secondary">Cancel</a>
			</div>
		</form>
	{/if}
</div>
