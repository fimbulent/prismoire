<script lang="ts">
	import UserName from '$lib/components/trust/UserName.svelte';
	import { session } from '$lib/stores/session.svelte';

	let { data } = $props();

	let title = $derived(data.direction === 'trusts' ? 'Trusts given' : 'Trusted by');
	// Restricted (banned/suspended) viewers can't follow links to other
	// profiles — they're only allowed on their own profile surface.
	let viewerRestricted = $derived(session.isRestricted);
</script>

<svelte:head>
	<title>{title} — {data.username} — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 py-8">
	<div class="mb-4">
		<a href="/user/{data.username}" class="text-xs text-accent hover:underline">← Back to profile</a>
	</div>

	<h1 class="text-xl font-bold mb-1">{title}</h1>
	<p class="text-sm text-text-muted mb-6">
		{#if data.direction === 'trusts'}
			Users that {data.username} trusts
		{:else}
			Users who trust {data.username}
		{/if}
		({data.total} total{#if data.capped}, showing closest 500{/if})
	</p>

	{#if data.users.length === 0}
		<div class="text-center text-text-muted py-8 border border-border-subtle rounded-md bg-bg-surface text-sm">
			No users.
		</div>
	{:else}
		<div class="bg-bg-surface border border-border rounded-md divide-y divide-border-subtle">
			{#each data.users as user}
				<div class="px-4 py-2.5 flex items-center gap-2 min-w-0">
					<UserName name={user.display_name} trust={user.trust} compact linked={!viewerRestricted} />
				</div>
			{/each}
		</div>
	{/if}
</div>
