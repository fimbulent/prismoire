<script lang="ts">
	import { createRoom } from '$lib/api/rooms';
	import { session } from '$lib/stores/session.svelte';
	import { validateRoomName } from '$lib/validation/room-name';
	import { errorMessage } from '$lib/i18n/errors';
	import { goto } from '$app/navigation';
	import { slide } from 'svelte/transition';

	const MAX_DESCRIPTION = 300;

	let name = $state('');
	let description = $state('');
	let isPublic = $state(false);
	let error = $state<string | null>(null);
	let nameError = $derived(name.trim() ? validateRoomName(name) : null);
	let slug = $derived(name.trim() ? name.trim().toLowerCase().replace(/[ -]/g, '_') : '');
	let descriptionChars = $derived([...description].length);
	let submitting = $state(false);

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		const validationError = validateRoomName(name);
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
			const req: import('$lib/api/rooms').CreateRoomRequest = {
				name: name.trim(),
				description: description.trim() || undefined
			};
			if (session.isAdmin && isPublic) req.public = true;
			const room = await createRoom(req);
			goto(`/room/${encodeURIComponent(room.slug)}`);
		} catch (e) {
			error = errorMessage(e, 'Failed to create room');
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>New Room — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<h1 class="text-xl font-bold mb-6">New Room</h1>

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
			<label for="room-name" class="block text-sm font-medium text-text-secondary mb-1"
				>Name</label
			>
			<input
				id="room-name"
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
					/room/<span class="text-text-secondary">{slug}</span>
				</p>
			{/if}
		</div>

		<div>
			<label
				for="room-description"
				class="block text-sm font-medium text-text-secondary mb-1">Description</label
			>
			<textarea
				id="room-description"
				bind:value={description}
				placeholder="What is this room about?"
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

		{#if session.isAdmin}
			<div class="flex items-center gap-4">
				<label class="flex items-center gap-1.5 text-xs text-text-secondary cursor-pointer">
					<input type="checkbox" bind:checked={isPublic} disabled={submitting} class="accent-accent" />
					Public room
				</label>
			</div>
			{#if isPublic}
				<p transition:slide={{ duration: 150 }} class="text-xs text-text-muted">
					Public rooms are visible to unauthenticated users. Only admins can create threads in public rooms. Unauthenticated users can see the top-level posts in public rooms, but replies are only visible to authenticated users.
				</p>
			{/if}
		{/if}

		<div class="flex items-center gap-3">
			<button
				type="submit"
				disabled={submitting || !name.trim() || !!nameError || descriptionChars > MAX_DESCRIPTION}
				class="text-sm px-4 py-2 rounded-md cursor-pointer border border-accent bg-accent text-bg font-medium hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
			>
				{submitting ? 'Creating…' : 'Create Room'}
			</button>
			<a href="/" class="text-sm text-text-muted hover:text-text-secondary">Cancel</a>
		</div>
	</form>
</div>
