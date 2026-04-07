<script lang="ts">
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { getTrustEdges, type TrustEdgeUser } from '$lib/api/users';
	import { session } from '$lib/stores/session.svelte';
	import UserName from '$lib/components/trust/UserName.svelte';

	let username = $derived(page.params.username ?? '');
	let directionSlug = $derived(page.params.direction ?? '');
	let apiDirection = $derived(
		directionSlug === 'trusted-by' ? 'trusted_by' as const : 'trusts' as const
	);

	let users = $state<TrustEdgeUser[]>([]);
	let total = $state(0);
	let capped = $state(false);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let title = $derived(directionSlug === 'trusts' ? 'Trusts given' : 'Trusted by');

	$effect(() => {
		if (session.loading) return;
		if (!session.isLoggedIn) {
			goto('/login');
			return;
		}
		if (directionSlug !== 'trusts' && directionSlug !== 'trusted-by') {
			error = 'Invalid direction';
			loading = false;
			return;
		}
		loadEdges();
	});

	async function loadEdges() {
		loading = true;
		error = null;
		try {
			const res = await getTrustEdges(username, apiDirection);
			users = res.users;
			total = res.total;
			capped = res.capped;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load';
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>{title} — {username} — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 py-8">
	<div class="mb-4">
		<a href="/u/{username}" class="text-xs text-accent hover:underline">← Back to profile</a>
	</div>

	<h1 class="text-xl font-bold mb-1">{title}</h1>
	<p class="text-sm text-text-muted mb-6">
		{#if directionSlug === 'trusts'}
			Users that {username} trusts
		{:else}
			Users who trust {username}
		{/if}
		({total} total{#if capped}, showing closest 500{/if})
	</p>

	{#if loading}
		<div class="text-center text-text-muted py-16">Loading…</div>
	{:else if error}
		<div class="text-center text-danger py-16">{error}</div>
	{:else if users.length === 0}
		<div class="text-center text-text-muted py-8 border border-border-subtle rounded-md bg-bg-surface text-sm">
			No users.
		</div>
	{:else}
		<div class="bg-bg-surface border border-border rounded-md divide-y divide-border-subtle">
			{#each users as user}
				<div class="px-4 py-2.5 flex items-center gap-2 min-w-0">
					<UserName name={user.display_name} distance={user.trust_distance} compact />
				</div>
			{/each}
		</div>
	{/if}
</div>
