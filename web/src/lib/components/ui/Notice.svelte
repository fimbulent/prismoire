<script lang="ts">
	import type { Snippet } from 'svelte';
	import { slide } from 'svelte/transition';

	let { children }: { children: Snippet } = $props();
</script>

<div transition:slide={{ duration: 150 }} class="text-xs text-accent bg-accent/10 border border-accent/20 rounded-md px-4 py-2.5 mb-4">
	{@render children()}
</div>
