<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		href?: string;
		loading?: boolean;
		disabled?: boolean;
		onclick?: () => void;
		children: Snippet;
	}

	let { href, loading = false, disabled = false, onclick, children }: Props = $props();
</script>

{#if href && !loading}
	<a {href} class="more-button">
		{@render children()}
	</a>
{:else}
	<button
		class="more-button"
		disabled={loading || disabled}
		{onclick}
	>
		{#if loading}
			Loading…
		{:else}
			{@render children()}
		{/if}
	</button>
{/if}

<style>
	.more-button {
		font-family: var(--font-sans, ui-sans-serif, system-ui, sans-serif);
		font-size: 0.75rem;
		color: var(--accent);
		background: var(--bg-surface);
		border: 1px dashed var(--border);
		border-radius: 0.375rem;
		padding: 0.375rem 0.875rem;
		cursor: pointer;
		text-decoration: none;
		display: inline-block;
		transition: background 0.15s, border-color 0.15s;
	}

	.more-button:hover {
		background: var(--bg-surface-raised);
		border-color: var(--accent-muted);
	}

	.more-button:disabled {
		opacity: 0.5;
		cursor: default;
	}
</style>
