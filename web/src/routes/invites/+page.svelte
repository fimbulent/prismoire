<script lang="ts">
	import { goto } from '$app/navigation';
	import { slide } from 'svelte/transition';
	import {
		createInvite,
		listInvites,
		listInvitedUsers,
		revokeInvite,
		type Invite,
		type InvitedUser
	} from '$lib/api/invites';
	import { relativeTime } from '$lib/format';
	import { session } from '$lib/stores/session.svelte';

	let invites = $state<Invite[]>([]);
	let invitedUsers = $state<InvitedUser[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let creating = $state(false);
	let createError = $state<string | null>(null);
	let copiedId = $state<string | null>(null);

	let maxUsesPreset = $state<string>('1');
	let expiryPreset = $state<string>('30d');

	const expiryOptions = [
		{ label: '1 hour', value: '1h', seconds: 3600 },
		{ label: '24 hours', value: '24h', seconds: 86400 },
		{ label: '7 days', value: '7d', seconds: 604800 },
		{ label: '30 days', value: '30d', seconds: 2592000 },
		{ label: 'Never', value: 'never', seconds: null }
	];

	$effect(() => {
		if (session.loading) return;
		if (!session.isLoggedIn) {
			goto('/login');
			return;
		}
		load();
	});

	async function load() {
		loading = true;
		error = null;
		try {
			[invites, invitedUsers] = await Promise.all([listInvites(), listInvitedUsers()]);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load invites';
		} finally {
			loading = false;
		}
	}

	async function handleCreate() {
		creating = true;
		createError = null;
		try {
			const parsedMaxUses = maxUsesPreset === 'unlimited' ? null : parseInt(maxUsesPreset, 10);

			const preset = expiryOptions.find((o) => o.value === expiryPreset);
			const expiresInSeconds = preset?.seconds ?? null;

			const invite = await createInvite({
				max_uses: parsedMaxUses,
				expires_in_seconds: expiresInSeconds
			});
			invites = [invite, ...invites];
			copyLink(invite);
		} catch (e) {
			createError = e instanceof Error ? e.message : 'Failed to create invite';
		} finally {
			creating = false;
		}
	}

	async function handleRevoke(id: string) {
		try {
			await revokeInvite(id);
			invites = invites.map((i) => (i.id === id ? { ...i, revoked: true } : i));
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to revoke invite';
		}
	}

	function inviteLink(code: string): string {
		return `${window.location.origin}/invite/${code}`;
	}

	function copyLink(invite: Invite) {
		navigator.clipboard.writeText(inviteLink(invite.code));
		copiedId = invite.id;
		setTimeout(() => {
			if (copiedId === invite.id) copiedId = null;
		}, 2000);
	}

	function isExpired(invite: Invite): boolean {
		if (!invite.expires_at) return false;
		return new Date(invite.expires_at) < new Date();
	}

	function isExhausted(invite: Invite): boolean {
		if (invite.max_uses === null) return false;
		return invite.use_count >= invite.max_uses;
	}

	function isActive(invite: Invite): boolean {
		return !invite.revoked && !isExpired(invite) && !isExhausted(invite);
	}

	function statusLabel(invite: Invite): string {
		if (invite.revoked) return 'Revoked';
		if (isExpired(invite)) return 'Expired';
		if (isExhausted(invite)) return 'Used up';
		return 'Active';
	}

	function usesLabel(invite: Invite): string {
		if (invite.max_uses === null) return `${invite.use_count} uses (unlimited)`;
		return `${invite.use_count} / ${invite.max_uses} uses`;
	}

	function expiryLabel(invite: Invite): string {
		if (!invite.expires_at) return 'Never expires';
		if (isExpired(invite)) return `Expired ${relativeTime(invite.expires_at)}`;
		return `Expires ${relativeTime(invite.expires_at)}`;
	}
</script>

<svelte:head>
	<title>Invites — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<h1 class="text-lg font-bold mb-4">Invite Links</h1>

	<div class="bg-bg-surface border border-border rounded-md p-4 mb-6">
		<h2 class="text-sm font-semibold text-text-secondary mb-3">Create Invite Link</h2>
		<div class="flex flex-wrap items-end gap-3">
			<div>
				<label for="max-uses" class="block text-xs text-text-muted mb-1">Max uses</label>
				<select
					id="max-uses"
					bind:value={maxUsesPreset}
					disabled={creating}
					class="bg-bg-surface-raised border border-border-subtle rounded-md px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent"
				>
					<option value="1">1</option>
					<option value="5">5</option>
					<option value="10">10</option>
					<option value="25">25</option>
					<option value="100">100</option>
					<option value="unlimited">Unlimited</option>
				</select>
			</div>
			<div>
				<label for="expiry" class="block text-xs text-text-muted mb-1">Expires in</label>
				<select
					id="expiry"
					bind:value={expiryPreset}
					disabled={creating}
					class="bg-bg-surface-raised border border-border-subtle rounded-md px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent"
				>
					{#each expiryOptions as opt}
						<option value={opt.value}>{opt.label}</option>
					{/each}
				</select>
			</div>
			<button
				onclick={handleCreate}
				disabled={creating}
				class="bg-accent text-bg font-semibold rounded-md px-4 py-1.5 text-sm hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-opacity cursor-pointer"
			>
				{creating ? 'Creating…' : 'Create Link'}
			</button>
		</div>
		{#if createError}
			<p transition:slide={{ duration: 150 }} class="text-danger text-xs mt-2">{createError}</p>
		{/if}
	</div>

	{#if loading}
		<div class="text-center text-text-muted py-12">Loading…</div>
	{:else if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else if invites.length === 0}
		<div
			class="text-center text-text-muted py-12 border border-border-subtle rounded-md bg-bg-surface"
		>
			No invite links yet. Create one above.
		</div>
	{:else}
		<div class="space-y-2">
			{#each invites as invite (invite.id)}
				<div
					class="bg-bg-surface border rounded-md px-4 py-3"
					class:border-border={isActive(invite)}
					class:border-border-subtle={!isActive(invite)}
					class:opacity-60={!isActive(invite)}
				>
					<div class="flex items-center justify-between gap-3">
						<div class="min-w-0 flex-1">
							<div class="flex items-center gap-2 text-sm">
								<code class="text-text-primary font-mono text-xs truncate">
									{inviteLink(invite.code)}
								</code>
								<span
									class="text-xs px-1.5 py-0.5 rounded"
									class:bg-success={isActive(invite)}
									class:text-bg={isActive(invite)}
									class:bg-bg-surface-raised={!isActive(invite)}
									class:text-text-muted={!isActive(invite)}
								>
									{statusLabel(invite)}
								</span>
							</div>
							<div class="flex items-center gap-3 text-xs text-text-muted mt-1">
								<span>{usesLabel(invite)}</span>
								{#if !isExhausted(invite)}
									<span>{expiryLabel(invite)}</span>
								{/if}
								<span>Created {relativeTime(invite.created_at)}</span>
							</div>
							{#if invite.users.length > 0}
								<div class="mt-2 text-xs text-text-muted">
									Used by:
									{#each invite.users as invitedUser, i}
										<span class="text-text-secondary">{invitedUser.display_name}</span>{#if i < invite.users.length - 1},
										{/if}
									{/each}
								</div>
							{/if}
						</div>
						<div class="flex items-center gap-2 shrink-0">
							{#if isActive(invite)}
								<button
									onclick={() => copyLink(invite)}
									class="text-xs px-2 py-1 rounded border border-border-subtle text-text-secondary hover:text-text-primary hover:bg-bg-hover transition-colors cursor-pointer"
								>
									{copiedId === invite.id ? 'Copied!' : 'Copy'}
								</button>
							{/if}
							{#if isActive(invite)}
								<button
									onclick={() => handleRevoke(invite.id)}
									class="text-xs px-2 py-1 rounded border border-border-subtle text-text-secondary hover:text-danger hover:border-danger transition-colors cursor-pointer"
								>
									Revoke
								</button>
							{/if}
						</div>
					</div>
				</div>
			{/each}
		</div>
	{/if}

	{#if invitedUsers.length > 0}
		<h2 class="text-lg font-bold mt-8 mb-4">Invited Users</h2>
		<div class="bg-bg-surface border border-border rounded-md divide-y divide-border-subtle">
			{#each invitedUsers as user}
				<div class="px-4 py-2.5 flex items-center justify-between text-sm">
					<span class="text-text-primary">{user.display_name}</span>
					<span class="text-text-muted text-xs">Joined {relativeTime(user.created_at)}</span>
				</div>
			{/each}
		</div>
	{/if}
</div>
