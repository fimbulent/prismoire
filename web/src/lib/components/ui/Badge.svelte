<script lang="ts">
	import type { Snippet } from 'svelte';

	let { children }: { children: Snippet } = $props();
</script>

<span class="text-xs font-semibold px-1.5 py-0.5 rounded bg-accent text-bg uppercase tracking-wider shrink-0">{@render children()}</span>
