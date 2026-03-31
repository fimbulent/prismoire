<script lang="ts">
	import { goto } from '$app/navigation';
	import { slide } from 'svelte/transition';
	import {
		discoverBegin,
		discoverComplete,
		loginBegin,
		loginComplete
	} from '$lib/api/auth';
	import { getPasskey, getPasskeyConditional } from '$lib/api/webauthn';
	import { session } from '$lib/stores/session.svelte';

	let displayName = $state('');
	let error = $state<string | null>(null);
	let submitting = $state(false);

	let conditionalAbort: AbortController | null = null;

	async function startConditionalUI() {
		if (
			!window.PublicKeyCredential ||
			!(await PublicKeyCredential.isConditionalMediationAvailable?.())
		) {
			return;
		}

		try {
			conditionalAbort = new AbortController();
			const { challenge_id, ...options } = await discoverBegin();
			const credential = await getPasskeyConditional(
				options.publicKey as never,
				conditionalAbort.signal
			);

			const info = await discoverComplete(challenge_id, credential);
			session.set(info);
			goto('/');
		} catch {
			// Aborted or unsupported — fall back to manual login
		}
	}

	$effect(() => {
		startConditionalUI();
		return () => conditionalAbort?.abort();
	});

	async function handleLogin() {
		conditionalAbort?.abort();
		error = null;
		submitting = true;

		try {
			const { challenge_id, ...options } = await loginBegin(displayName);

			const credential = await getPasskey(options.publicKey as never);

			const info = await loginComplete(challenge_id, credential);
			session.set(info);
			goto('/');
		} catch (e) {
			error = e instanceof Error ? e.message : 'Login failed';
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Sign In — Prismoire</title>
</svelte:head>

<div class="bg-bg-surface border border-border rounded-md p-8 max-w-sm w-full">
	<h1 class="text-2xl font-bold text-accent mb-1 tracking-wide">Sign In</h1>
	<p class="text-text-secondary text-sm mb-6">Authenticate with your passkey.</p>

	<form onsubmit={handleLogin} class="space-y-4">
		<div>
			<label for="display-name" class="block text-text-secondary text-sm mb-1"
				>Display Name</label
			>
			<input
				id="display-name"
				type="text"
				bind:value={displayName}
				required
				autocomplete="username webauthn"
				disabled={submitting}
				class="w-full bg-bg-surface-raised border border-border-subtle rounded-md px-3 py-2 text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent"
				placeholder="Your display name"
			/>
		</div>

		{#if error}
			<p transition:slide={{ duration: 150 }} class="text-danger text-sm">{error}</p>
		{/if}

		<button
			type="submit"
			disabled={submitting || !displayName.trim()}
			class="w-full bg-accent text-bg font-semibold rounded-md px-4 py-2 hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-opacity"
		>
			{submitting ? 'Authenticating…' : 'Sign In with Passkey'}
		</button>
	</form>

	<p class="text-text-muted text-sm mt-4 text-center">
		No account? <a href="/signup" class="text-link hover:text-link-hover">Create one</a>
	</p>
</div>
