<script lang="ts">
	import { session } from '$lib/stores/session.svelte';
	import TrustBadge from './TrustBadge.svelte';

	interface Props {
		name: string;
		distance?: number | null;
		compact?: boolean;
		linked?: boolean;
	}

	let { name, distance = null, compact = false, linked = true }: Props = $props();

	let isSelf = $derived(session.user?.display_name === name);
</script>

{#if isSelf}
	<a href="/u/{name}" class="font-semibold text-text-primary bg-bg-surface-raised px-2 py-0.5 rounded border border-border hover:border-accent-muted transition-colors">{name}</a>
{:else if linked}
	<a href="/u/{name}" class="font-semibold text-text-primary hover:underline">{name}</a>
	<TrustBadge {distance} {compact} />
{:else}
	<span class="font-semibold text-text-primary">{name}</span>
{/if}
