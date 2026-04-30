<script lang="ts">
	import type { UserViewerInfo } from '$lib/api/users';
	import { session } from '$lib/stores/session.svelte';
	import TrustBadge from './TrustBadge.svelte';

	interface Props {
		name: string;
		viewer?: UserViewerInfo;
		compact?: boolean;
		muted?: boolean;
		linked?: boolean;
	}

	let { name, viewer, compact = false, muted = false, linked = true }: Props = $props();

	let isSelf = $derived(session.user?.display_name === name);
	let status = $derived(viewer?.status);
	// Viewer's private tag for this user (max 35 graphemes, plain text).
	// Only rendered for non-self, non-deleted users — matches the
	// server-side suppression rules in `UserViewerInfo::build`.
	let tag = $derived(viewer?.tag ?? null);

	// Muted mode dials the username back to medium weight + secondary
	// color so it recedes into chrome rather than competing with
	// adjacent content.
	let nameClass = $derived(
		muted ? 'font-medium text-text-secondary' : 'font-semibold text-text-primary'
	);
</script>

{#if isSelf}
	<a href="/@{encodeURIComponent(name)}" class="{nameClass} bg-bg-surface-raised px-2 py-0.5 rounded border border-border hover:border-accent-muted transition-colors">{name}</a>
{:else if status === 'deleted'}
	<!-- Deleted users: render as an inert, muted chip (no link, no trust badge).
	     The display name is already anonymised server-side to `deleted-<hex>`,
	     so the profile page is intentionally not navigable. -->
	<span class="font-semibold text-text-muted italic line-through">{name}</span>
	<span class="status-badge status-badge-deleted text-xs font-semibold px-1 py-0.5 rounded">deleted</span>
{:else if linked}
	<a href="/@{encodeURIComponent(name)}" class="{nameClass} hover:underline {status ? 'line-through opacity-60' : ''}">{name}</a>
	{#if tag}
		<span class="text-xs text-text-muted italic" title="Your private tag for this user">({tag})</span>
	{/if}
	{#if status === 'banned'}
		<span class="status-badge status-badge-banned text-xs font-semibold px-1 py-0.5 rounded">banned</span>
	{:else if status === 'suspended'}
		<span class="status-badge status-badge-suspended text-xs font-semibold px-1 py-0.5 rounded">suspended</span>
	{:else}
		<TrustBadge {viewer} {compact} />
	{/if}
{:else}
	<span class={nameClass}>{name}</span>
{/if}

<style>
	.status-badge-banned { color: var(--danger); background: color-mix(in srgb, var(--danger) 12%, transparent); }
	.status-badge-suspended { color: var(--text-muted); background: color-mix(in srgb, var(--text-muted) 12%, transparent); }
	.status-badge-deleted { color: var(--text-muted); background: color-mix(in srgb, var(--text-muted) 12%, transparent); }
</style>
