<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		checked = $bindable(false),
		disabled = false,
		children
	}: {
		checked?: boolean;
		disabled?: boolean;
		children?: Snippet;
	} = $props();
</script>

<label class="inline-flex items-center gap-2 text-xs text-text-secondary cursor-pointer {disabled ? 'opacity-50 cursor-not-allowed' : ''}">
	<input
		type="checkbox"
		bind:checked
		{disabled}
		class="checkbox appearance-none size-3.5 rounded border border-border bg-bg-surface cursor-pointer shrink-0
			checked:bg-danger checked:border-danger
			disabled:cursor-not-allowed"
	/>
	{#if children}{@render children()}{/if}
</label>

<style>
	.checkbox:checked {
		background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 14 14' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M11 4.5L5.5 10L3 7.5' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
		background-size: 100% 100%;
		background-position: center;
		background-repeat: no-repeat;
	}
</style>
