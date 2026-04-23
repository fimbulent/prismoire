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
	let status = $derived(trust?.status);
</script>

{#if isSelf}
	<a href="/@{encodeURIComponent(name)}" class="font-semibold text-text-primary bg-bg-surface-raised px-2 py-0.5 rounded border border-border hover:border-accent-muted transition-colors">{name}</a>
{:else if status === 'deleted'}
	<!-- Deleted users: render as an inert, muted chip (no link, no trust badge).
	     The display name is already anonymised server-side to `deleted-<hex>`,
	     so the profile page is intentionally not navigable. -->
	<span class="font-semibold text-text-muted italic line-through">{name}</span>
	<span class="status-badge status-badge-deleted text-xs font-semibold px-1 py-0.5 rounded">deleted</span>
{:else if linked}
	<a href="/@{encodeURIComponent(name)}" class="font-semibold text-text-primary hover:underline {status ? 'line-through opacity-60' : ''}">{name}</a>
	{#if status === 'banned'}
		<span class="status-badge status-badge-banned text-xs font-semibold px-1 py-0.5 rounded">banned</span>
	{:else if status === 'suspended'}
		<span class="status-badge status-badge-suspended text-xs font-semibold px-1 py-0.5 rounded">suspended</span>
	{:else}
		<TrustBadge {trust} {compact} />
	{/if}
{:else}
	<span class="font-semibold text-text-primary">{name}</span>
{/if}

<style>
	.status-badge-banned { color: var(--danger); background: color-mix(in srgb, var(--danger) 12%, transparent); }
	.status-badge-suspended { color: var(--text-muted); background: color-mix(in srgb, var(--text-muted) 12%, transparent); }
	.status-badge-deleted { color: var(--text-muted); background: color-mix(in srgb, var(--text-muted) 12%, transparent); }
</style>
