<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		text,
		position = 'top',
		children
	}: {
		text: string;
		position?: 'top' | 'bottom';
		children: Snippet;
	} = $props();
</script>

<span class="tooltip-wrapper" data-position={position}>
	{@render children()}
	<span class="tooltip-bubble" role="tooltip">{text}</span>
</span>

<style>
	.tooltip-wrapper {
		position: relative;
		display: inline-flex;
	}

	.tooltip-bubble {
		position: absolute;
		left: 50%;
		transform: translateX(-50%);
		padding: 0.375rem 0.625rem;
		border-radius: 0.375rem;
		background: var(--bg-surface-raised);
		border: 1px solid var(--border);
		color: var(--text-secondary);
		font-size: 0.75rem;
		line-height: 1.4;
		text-transform: none;
		letter-spacing: normal;
		white-space: nowrap;
		pointer-events: none;
		opacity: 0;
		transition: opacity 0.12s ease;
		z-index: 50;
		box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
	}

	.tooltip-wrapper[data-position='top'] .tooltip-bubble {
		bottom: calc(100% + 0.375rem);
	}

	.tooltip-wrapper[data-position='bottom'] .tooltip-bubble {
		top: calc(100% + 0.375rem);
	}

	.tooltip-wrapper:hover .tooltip-bubble {
		opacity: 1;
	}
</style>
