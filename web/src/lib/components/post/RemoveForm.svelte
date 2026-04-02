<script lang="ts">
	import { slide } from 'svelte/transition';

	interface Props {
		saving?: boolean;
		error?: string | null;
		onsubmit: (reason: string) => void;
		oncancel: () => void;
	}

	let { saving = false, error = null, onsubmit, oncancel }: Props = $props();

	let reason = $state('');
</script>

<div class="mt-3 bg-bg border border-danger rounded-md p-4" transition:slide={{ duration: 150 }}>
	<input
		id="remove-reason"
		type="text"
		bind:value={reason}
		placeholder="Why is this post being removed?"
		class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted"
	/>
	<p class="text-xs text-text-muted mt-1">Removal reason will be public in the <a href="/log" class="text-link hover:text-link-hover">admin log</a>.</p>
	{#if error}
		<div class="text-danger text-xs mt-1">{error}</div>
	{/if}
	<div class="flex gap-2 mt-2">
		<button
			onclick={() => onsubmit(reason)}
			disabled={saving || !reason.trim()}
			class="text-xs px-3 py-1.5 rounded-md border border-danger text-danger hover:bg-bg-hover cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
		>{saving ? 'Removing…' : 'Remove post'}</button>
		<button
			onclick={oncancel}
			disabled={saving}
			class="text-xs px-3 py-1.5 rounded-md border border-border text-text-muted hover:text-text-primary hover:bg-bg-hover cursor-pointer transition-colors"
		>Cancel</button>
	</div>
</div>
