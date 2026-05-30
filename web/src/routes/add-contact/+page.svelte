<script lang="ts">
	import { redeemTrustCode, type RedeemTrustCodeResult } from '$lib/api/users';
	import { canonicalProfilePath } from '$lib/user-url';
	import { errorMessage } from '$lib/i18n/errors';
	import { toast } from '$lib/components/ui/toast.svelte';

	let code = $state('');
	let stance = $state<'trust' | 'distrust'>('trust');

	// `preview` is a dry-run resolution shown before committing; `result`
	// is the committed outcome. Editing the code clears both.
	let preview = $state<RedeemTrustCodeResult | null>(null);
	let result = $state<RedeemTrustCodeResult | null>(null);
	let previewing = $state(false);
	let submitting = $state(false);

	function onCodeInput() {
		preview = null;
		result = null;
	}

	async function handlePreview() {
		const trimmed = code.trim();
		if (trimmed === '') return;
		previewing = true;
		preview = null;
		result = null;
		try {
			preview = await redeemTrustCode({ code: trimmed, dryRun: true });
		} catch (e) {
			toast.error(errorMessage(e, 'Could not read that trust code'));
		} finally {
			previewing = false;
		}
	}

	async function handleSubmit() {
		const trimmed = code.trim();
		if (trimmed === '') return;
		submitting = true;
		try {
			result = await redeemTrustCode({ code: trimmed, type: stance });
			toast.success(
				stance === 'trust'
					? `You now trust ${result.display_name}.`
					: `You now distrust ${result.display_name}.`
			);
		} catch (e) {
			toast.error(errorMessage(e, 'Failed to add contact'));
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Add Contact — Prismoire</title>
</svelte:head>

<div class="max-w-2xl mx-auto px-6 pt-6 pb-16">
	<h1 class="text-lg font-bold mb-1">Add a contact by trust code</h1>
	<p class="text-xs text-text-muted mb-6">
		Paste a trust code someone shared with you to trust (or distrust) them directly, even if they
		live on another instance. Trust codes look like
		<code class="px-1 rounded bg-bg-surface-raised">:trust:name@instance:…</code>.
	</p>

	<section class="bg-bg-surface border border-border rounded-md p-5">
		<label for="trust-code" class="text-xs text-text-muted block mb-1">Trust code</label>
		<textarea
			id="trust-code"
			bind:value={code}
			oninput={onCodeInput}
			rows="3"
			placeholder=":trust:alice@example.org:…"
			class="w-full bg-bg border border-border rounded-md text-text-primary text-xs font-mono px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted resize-y break-all"
		></textarea>

		<div class="flex flex-wrap items-center gap-3 mt-3">
			<button
				type="button"
				onclick={handlePreview}
				disabled={previewing || code.trim() === ''}
				class="font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-border bg-bg text-text-primary font-medium hover:border-accent-muted disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
			>
				{previewing ? 'Reading…' : 'Preview'}
			</button>
		</div>

		{#if preview && !result}
			<div class="mt-4 p-4 bg-bg rounded-md border border-border-subtle">
				<div class="text-sm text-text-primary font-medium break-all">
					{preview.display_name}
				</div>
				<div class="text-xs text-text-muted mt-0.5 break-all">
					{#if preview.is_local}
						A user on this instance.
					{:else if preview.created}
						New contact, homed on <span class="text-text-secondary">{preview.home_domain}</span>.
					{:else}
						Homed on <span class="text-text-secondary">{preview.home_domain}</span> — already
						known here.
					{/if}
				</div>

				<div class="mt-3">
					<div class="text-xs text-text-muted mb-1">Stance</div>
					<div class="flex gap-2">
						<label
							class="inline-flex items-center gap-1.5 text-xs text-text-secondary cursor-pointer select-none border border-border rounded-md px-3 py-1.5"
							class:border-accent={stance === 'trust'}
						>
							<input type="radio" bind:group={stance} value="trust" class="accent-accent" />
							Trust
						</label>
						<label
							class="inline-flex items-center gap-1.5 text-xs text-text-secondary cursor-pointer select-none border border-border rounded-md px-3 py-1.5"
							class:border-danger={stance === 'distrust'}
						>
							<input type="radio" bind:group={stance} value="distrust" class="accent-danger" />
							Distrust
						</label>
					</div>
				</div>

				<button
					type="button"
					onclick={handleSubmit}
					disabled={submitting}
					class="mt-4 font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-accent bg-accent/15 text-accent font-medium hover:bg-accent/25 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
				>
					{submitting
						? 'Adding…'
						: stance === 'trust'
							? `Trust ${preview.display_name}`
							: `Distrust ${preview.display_name}`}
				</button>
			</div>
		{/if}

		{#if result}
			<div class="mt-4 p-4 bg-bg rounded-md border border-border-subtle">
				<div class="text-sm text-text-primary">
					{result.edge_type === 'trust' ? 'Now trusting' : 'Now distrusting'}
					<a
						href={canonicalProfilePath(result.display_name, result.pubkey_hex)}
						class="text-link hover:text-link-hover font-medium break-all"
					>
						{result.display_name}
					</a>
					{#if !result.is_local}
						<span class="text-text-muted">on {result.home_domain}</span>
					{/if}.
				</div>
			</div>
		{/if}
	</section>
</div>
