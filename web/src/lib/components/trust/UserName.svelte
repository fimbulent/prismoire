<script lang="ts">
	import type { TrustInfo } from '$lib/api/users';
	import { session } from '$lib/stores/session.svelte';
	import TrustBadge from './TrustBadge.svelte';

	interface Props {
		name: string;
		trust?: TrustInfo;
		compact?: boolean;
		linked?: boolean;
	}

	let { name, trust, compact = false, linked = true }: Props = $props();

	let isSelf = $derived(session.user?.display_name === name);
</script>

{#if isSelf}
	<a href="/user/{name}" class="font-semibold text-text-primary bg-bg-surface-raised px-2 py-0.5 rounded border border-border hover:border-accent-muted transition-colors">{name}</a>
{:else if linked}
	<a href="/user/{name}" class="font-semibold text-text-primary hover:underline">{name}</a>
	<TrustBadge {trust} {compact} />
{:else}
	<span class="font-semibold text-text-primary">{name}</span>
{/if}
