<script lang="ts">
	import { goto } from '$app/navigation';
	import { slide } from 'svelte/transition';
	import { setupBegin, setupComplete } from '$lib/api/auth';
	import { createPasskey } from '$lib/api/webauthn';
	import { session } from '$lib/stores/session.svelte';
	import { validateDisplayName } from '$lib/validation/display-name';

	let token = $state('');
	let displayName = $state('');
	let error = $state<string | null>(null);
	let nameError = $derived(displayName.trim() ? validateDisplayName(displayName) : null);
	let submitting = $state(false);

	async function handleSetup() {
		if (!token.trim()) {
			error = 'Setup token is required';
			return;
		}
		const validationError = validateDisplayName(displayName);
		if (validationError) {
			error = validationError;
			return;
		}
		error = null;
		submitting = true;

		try {
			const { challenge_id, ...options } = await setupBegin(token.trim(), displayName);
			const credential = await createPasskey(options.publicKey as never);
			const info = await setupComplete(challenge_id, credential);
			session.set(info);
			goto('/');
		} catch (e) {
			error = e instanceof Error ? e.message : 'Setup failed';
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Instance Setup — Prismoire</title>
</svelte:head>

<div class="bg-bg-surface border border-border rounded-md p-8 max-w-sm w-full">
	<h1 class="text-2xl font-bold text-accent mb-1 tracking-wide">Instance Setup</h1>
	<p class="text-text-secondary text-sm mb-6">Create the initial admin account</p>

	<form onsubmit={handleSetup} class="space-y-4">
		<div>
			<label for="setup-token" class="block text-text-secondary text-sm mb-1"
				>Setup Token</label
			>
			<input
				id="setup-token"
				type="password"
				bind:value={token}
				required
				disabled={submitting}
				class="w-full bg-bg-surface-raised border border-border-subtle rounded-md px-3 py-2 text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent"
				placeholder="Paste the setup token"
			/>
		</div>

		<div>
			<label for="display-name" class="block text-text-secondary text-sm mb-1"
				>Display Name</label
			>
			<input
				id="display-name"
				type="text"
				bind:value={displayName}
				required
				minlength={3}
				maxlength={20}
				autocomplete="off"
				disabled={submitting}
				class="w-full bg-bg-surface-raised border border-border-subtle rounded-md px-3 py-2 text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent"
				class:border-danger={!!nameError}
				placeholder="Choose a name"
			/>
			{#if nameError}
				<p transition:slide={{ duration: 150 }} class="text-danger text-xs mt-1">
					{nameError}
				</p>
			{/if}
		</div>

		{#if error}
			<p transition:slide={{ duration: 150 }} class="text-danger text-sm">{error}</p>
		{/if}

		<button
			type="submit"
			disabled={submitting || !token.trim() || !displayName.trim() || !!nameError}
			class="w-full bg-accent text-bg font-semibold rounded-md px-4 py-2 hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-opacity"
		>
			{submitting ? 'Creating passkey…' : 'Create Admin Account'}
		</button>
	</form>
</div>
