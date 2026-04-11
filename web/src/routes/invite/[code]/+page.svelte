<script lang="ts">
	import { goto } from '$app/navigation';
	import { slide } from 'svelte/transition';
	import { signupBegin, signupComplete } from '$lib/api/auth';
	import { createPasskey } from '$lib/api/webauthn';
	import { session } from '$lib/stores/session.svelte';
	import { validateDisplayName } from '$lib/validation/display-name';
	import { errorMessage } from '$lib/i18n/errors';

	let { data } = $props();

	let validation = $derived(data.validation);
	let code = $derived(data.code);
	let displayName = $state('');
	let error = $state<string | null>(null);
	let nameError = $derived(displayName.trim() ? validateDisplayName(displayName) : null);
	let submitting = $state(false);

	async function handleSignup() {
		const validationError = validateDisplayName(displayName);
		if (validationError) {
			error = validationError;
			return;
		}
		error = null;
		submitting = true;

		try {
			const { challenge_id, ...options } = await signupBegin(displayName, code || undefined);

			const credential = await createPasskey(options.publicKey as never);

			await signupComplete(challenge_id, credential);
			await session.refresh();
			await goto('/');
		} catch (e) {
			error = errorMessage(e, 'Signup failed');
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Invite — Prismoire</title>
</svelte:head>

<div class="grid place-items-center p-4 min-h-[calc(100dvh-var(--nav-height))]">
	<div class="bg-bg-surface border border-border rounded-md p-8 max-w-sm w-full text-center">
		{#if validation?.valid}
			<h1 class="text-2xl font-bold text-accent mb-2 tracking-wide">You're Invited</h1>
			<p class="text-text-secondary mb-6">
				<span class="text-text-primary font-medium">{validation.inviter_display_name}</span>
				has invited you to join Prismoire.
			</p>

			<form onsubmit={handleSignup} class="space-y-4 text-left">
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
					disabled={submitting || !displayName.trim() || !!nameError}
					class="w-full bg-accent text-bg font-semibold rounded-md px-4 py-2 hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-opacity"
				>
					{submitting ? 'Creating passkey…' : 'Sign Up with Passkey'}
				</button>
			</form>

			<p class="text-text-muted text-sm mt-4">
				Already have an account?
				<a href="/login" class="text-link hover:text-link-hover">Sign in</a>
			</p>
		{:else}
			<h1 class="text-2xl font-bold text-text-primary mb-2">Invalid Invite</h1>
			<p class="text-text-secondary mb-6">
				This invite link is invalid. It may have expired or been used up.
			</p>
			<a
				href="/login"
				class="inline-block w-full bg-accent text-bg font-semibold rounded-md px-4 py-2 hover:opacity-90 transition-opacity text-center"
			>
				Sign In
			</a>
		{/if}
	</div>
</div>
