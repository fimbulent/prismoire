<script lang="ts">
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { slide } from 'svelte/transition';
	import {
		getUserProfile,
		getTrustDetail,
		getActivity,
		updateBio,
		trustUser,
		revokeTrust,
		blockUser,
		revokeBlock,
		type UserProfile,
		type TrustDetailResponse,
		type ActivityItem
	} from '$lib/api/users';
	import { relativeTime } from '$lib/format';
	import { session } from '$lib/stores/session.svelte';
	import TrustBadge from '$lib/components/trust/TrustBadge.svelte';
	import UserName from '$lib/components/trust/UserName.svelte';
	import Markdown from '$lib/components/ui/Markdown.svelte';
	import Tooltip from '$lib/components/ui/Tooltip.svelte';
	import MoreButton from '$lib/components/ui/MoreButton.svelte';

	let username = $derived(page.params.username ?? '');

	let profile = $state<UserProfile | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let trustDetail = $state<TrustDetailResponse | null>(null);
	let trustLoading = $state(false);
	let trustLoaded = $state(false);
	let trustOpen = $state(false);

	let activityItems = $state<ActivityItem[]>([]);
	let activityCursor = $state<string | null>(null);
	let activityFilter = $state<string>('all');
	let activityLoading = $state(false);

	let moreMenuOpen = $state(false);
	let moreMenuEl = $state<HTMLElement | null>(null);

	let editingBio = $state(false);
	let bioText = $state('');
	let bioSaving = $state(false);
	let bioError = $state<string | null>(null);

	let actionLoading = $state(false);

	$effect(() => {
		if (session.loading) return;
		if (!session.isLoggedIn) {
			goto('/login');
			return;
		}
		loadProfile();
	});

	$effect(() => {
		if (!moreMenuOpen) return;
		function handleClickOutside(e: MouseEvent) {
			if (moreMenuEl && !moreMenuEl.contains(e.target as Node)) {
				moreMenuOpen = false;
			}
		}
		function handleEscape(e: KeyboardEvent) {
			if (e.key === 'Escape') moreMenuOpen = false;
		}
		document.addEventListener('click', handleClickOutside, true);
		document.addEventListener('keydown', handleEscape);
		return () => {
			document.removeEventListener('click', handleClickOutside, true);
			document.removeEventListener('keydown', handleEscape);
		};
	});

	async function loadProfile() {
		loading = true;
		error = null;
		trustDetail = null;
		trustLoaded = false;
		trustOpen = false;
		try {
			profile = await getUserProfile(username);
			loadActivity(true);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load profile';
		} finally {
			loading = false;
		}
	}

	async function loadActivity(reset: boolean) {
		activityLoading = true;
		try {
			const cursor = reset ? undefined : activityCursor ?? undefined;
			const res = await getActivity(username, activityFilter, cursor);
			if (reset) {
				activityItems = res.items;
			} else {
				activityItems = [...activityItems, ...res.items];
			}
			activityCursor = res.next_cursor;
		} catch {
			// silently fail for activity
		} finally {
			activityLoading = false;
		}
	}

	async function refreshAfterAction() {
		trustLoaded = false;
		const promises: Promise<void>[] = [
			getUserProfile(username).then((p) => { profile = p; })
		];
		if (trustOpen) promises.push(refreshTrustDetail());
		await Promise.all(promises);
	}

	async function refreshTrustDetail() {
		trustLoading = true;
		try {
			trustDetail = await getTrustDetail(username);
		} catch {
			// silently fail
		} finally {
			trustLoading = false;
			trustLoaded = true;
		}
	}

	async function toggleTrustDetails() {
		if (trustOpen) {
			trustOpen = false;
			return;
		}
		if (trustLoaded) {
			trustOpen = true;
			return;
		}
		await refreshTrustDetail();
		trustOpen = true;
	}

	function handleFilterChange(filter: string) {
		activityFilter = filter;
		activityCursor = null;
		loadActivity(true);
	}

	async function handleTrust() {
		if (!profile || actionLoading) return;
		actionLoading = true;
		try {
			if (profile.you_trust) {
				await revokeTrust(username);
				profile.you_trust = false;
			} else {
				await trustUser(username);
				profile.you_trust = true;
				profile.you_block = false;
			}
			await refreshAfterAction();
		} catch {
			// silently fail
		} finally {
			actionLoading = false;
		}
	}

	async function handleBlock() {
		if (!profile || actionLoading) return;
		actionLoading = true;
		moreMenuOpen = false;
		try {
			if (profile.you_block) {
				await revokeBlock(username);
				profile.you_block = false;
			} else {
				await blockUser(username);
				profile.you_block = true;
				profile.you_trust = false;
			}
			await refreshAfterAction();
		} catch {
			// silently fail
		} finally {
			actionLoading = false;
		}
	}

	function startEditBio() {
		bioText = profile?.bio ?? '';
		editingBio = true;
		bioError = null;
	}

	async function saveBio() {
		bioSaving = true;
		bioError = null;
		try {
			const value = bioText.trim() || null;
			await updateBio(username, value);
			if (profile) profile.bio = value;
			editingBio = false;
		} catch (e) {
			bioError = e instanceof Error ? e.message : 'Failed to save bio';
		} finally {
			bioSaving = false;
		}
	}

	function cancelEditBio() {
		editingBio = false;
		bioError = null;
	}

	function joinMethodLabel(method: string): string {
		if (method === 'invite') return 'via invite';
		if (method === 'admin') return 'as admin';
		if (method === 'steam_key') return 'via key';
		return '';
	}

</script>

<svelte:head>
	<title>{loading ? 'Profile' : profile?.display_name ?? 'Not Found'} — Prismoire</title>
</svelte:head>

{#if loading}
	<div class="text-center text-text-muted py-16">Loading…</div>
{:else if error}
	<div class="text-center text-danger py-16">{error}</div>
{:else if profile}
	<div class="max-w-4xl mx-auto px-6 py-8">

		<!-- Profile Header -->
		<div class="bg-bg-surface border border-border rounded-md p-6 mb-6">
			<div class="flex items-start justify-between gap-4 mb-4">
				<div class="flex items-center gap-3">
					<div class="w-14 h-14 rounded-full bg-bg-surface-raised border border-border flex items-center justify-center text-2xl font-bold text-accent">
						{profile.display_name.charAt(0)}
					</div>
					<div>
						<div class="flex items-center gap-2">
							<h1 class="text-2xl font-bold leading-tight">{profile.display_name}</h1>
							{#if !profile.is_self}
								<TrustBadge trust={profile.trust} />
							{/if}
							{#if profile.role === 'admin'}
								<span class="text-xs px-1.5 py-0.5 rounded font-semibold bg-accent text-bg">Admin</span>
							{/if}
						</div>
						<div class="text-sm text-text-muted mt-0.5">
							Joined {relativeTime(profile.created_at)} {joinMethodLabel(profile.signup_method)}
						</div>
					</div>
				</div>

				{#if !profile.is_self}
					<div class="flex gap-2">
						<button
							onclick={handleTrust}
							disabled={actionLoading}
							class="text-sm px-4 py-2 rounded-md cursor-pointer font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed {profile.you_trust ? 'border border-border bg-transparent text-text-secondary hover:bg-bg-hover' : 'border border-accent bg-accent text-bg hover:opacity-90'}"
						>
							{profile.you_trust ? 'Trusted' : 'Trust'}
						</button>
						<div class="relative" bind:this={moreMenuEl}>
							<button
								onclick={() => (moreMenuOpen = !moreMenuOpen)}
								class="text-sm px-3 py-2 rounded-md cursor-pointer border border-border bg-transparent text-text-muted font-medium hover:bg-bg-hover hover:text-text-secondary transition-colors"
								title="More options"
							>⋯</button>
							{#if moreMenuOpen}
								<div class="absolute right-0 top-full mt-1 w-40 bg-bg-surface border border-border rounded-md shadow-lg py-1 z-50">
									<button
										onclick={handleBlock}
										class="w-full text-left px-3 py-2 text-sm cursor-pointer transition-colors {profile.you_block ? 'text-text-secondary hover:bg-bg-hover hover:text-text-primary' : 'text-danger hover:bg-bg-hover'}"
									>
										{profile.you_block ? 'Unblock' : 'Block'}
									</button>
								</div>
							{/if}
						</div>
					</div>
				{/if}
			</div>

			<!-- Blocked banner -->
			{#if !profile.is_self && profile.you_block}
				<div class="flex items-center justify-between gap-3 px-4 py-3 rounded-md blocked-badge border border-danger/20 mb-4">
					<span class="text-sm text-danger">You have blocked this user.</span>
					<button
						onclick={handleBlock}
						disabled={actionLoading}
						class="text-xs px-3 py-1.5 rounded-md cursor-pointer font-medium border border-danger/30 text-danger hover:bg-danger/10 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
					>Unblock</button>
				</div>
			{/if}

			<!-- Bio -->
			{#if profile.is_self && editingBio}
				<div transition:slide={{ duration: 150 }} class="mb-5">
					<textarea
						bind:value={bioText}
						class="w-full bg-bg-surface-raised border border-border-subtle rounded-md px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent resize-none"
						rows={3}
						maxlength={500}
						placeholder="Write a short bio…"
					></textarea>
					<div class="flex items-center gap-2 mt-2">
						<button
							onclick={saveBio}
							disabled={bioSaving}
							class="text-xs px-3 py-1.5 rounded bg-accent text-bg font-medium hover:opacity-90 disabled:opacity-50 cursor-pointer"
						>{bioSaving ? 'Saving…' : 'Save'}</button>
						<button
							onclick={cancelEditBio}
							class="text-xs px-3 py-1.5 rounded border border-border text-text-secondary hover:bg-bg-hover cursor-pointer"
						>Cancel</button>
						{#if bioError}
							<span class="text-xs text-danger">{bioError}</span>
						{/if}
						<span class="text-xs text-text-muted ml-auto">{bioText.length}/500</span>
					</div>
				</div>
			{:else if profile.bio}
				<div class="text-[0.95rem] leading-7 text-text-secondary mb-5">
					<Markdown source={profile.bio} profile="bio" />
				</div>
				{#if profile.is_self}
					<button
						onclick={startEditBio}
						class="text-xs text-accent hover:underline cursor-pointer bg-transparent border-none mb-3"
					>Edit bio</button>
				{/if}
			{:else if profile.is_self}
				<button
					onclick={startEditBio}
					class="text-xs text-accent hover:underline cursor-pointer bg-transparent border-none mb-3"
				>Add a bio</button>
			{/if}

			<!-- Trust Details (collapsible) -->
			<div class="trust-details-inline" class:open={trustOpen}>
				<button class="trust-details-footer" onclick={toggleTrustDetails} disabled={trustLoading}>
					Trust details
					{#if trustLoading}
						<svg class="trust-details-spinner" width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M8 1a7 7 0 1 0 7 7" /></svg>
					{:else}
						<svg class="trust-details-chevron" width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 4 10 8 6 12" /></svg>
					{/if}
				</button>
				{#if trustOpen}
					<div transition:slide={{ duration: 200 }}>
				{#if trustDetail}
					<div class="flex pt-4">
						<div class="flex-1 text-center min-w-0">
							<div class="stat-value">{trustDetail.reads}</div>
							<div class="stat-label">Can see <Tooltip text="Users whose content they can see" position="bottom"><span class="trust-score-hint">?</span></Tooltip></div>
						</div>
						<div class="flex-1 text-center min-w-0">
							<div class="stat-value">{trustDetail.readers}</div>
							<div class="stat-label">Seen by <Tooltip text="Users who can see their content" position="bottom"><span class="trust-score-hint">?</span></Tooltip></div>
						</div>
						<div class="flex-1 text-center min-w-0">
							<div class="stat-value">{trustDetail.blocks_issued}</div>
							<div class="stat-label">Blocks issued</div>
						</div>
					</div>

					{#if !profile.is_self}
						<!-- Your trust in user -->
						<div class="border-t border-border-subtle mt-4 pt-4">
							<h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">Your trust</h2>
							<div class="flex items-center gap-3 mb-3">
								<TrustBadge trust={trustDetail.trust} />
								<Tooltip text={trustDetail.trust_score != null ? `Computed from trust and block relationships. Raw score: ${trustDetail.trust_score.toFixed(2)}` : 'No trust path exists to this user'}>
									<span class="trust-score-hint">?</span>
								</Tooltip>
							</div>

							{#if trustDetail.paths.length > 0 || trustDetail.score_reductions.length > 0}
								<div class="text-sm text-text-secondary leading-relaxed space-y-1">
									{#each trustDetail.paths as path}
										<div class="flex items-center gap-2 flex-wrap">
											<span class="text-text-muted text-xs">▲</span>
											{#if path.type === 'direct'}
												<span class="text-text-muted">Direct trust</span>
											{:else if path.type === '2hop' && path.via}
												<span class="text-text-muted">via</span>
												<UserName name={path.via.display_name} trust={path.via.trust} compact />
												<span class="text-text-muted">→ {profile.display_name}</span>
											{:else if path.type === '3hop' && path.via && path.via2}
												<span class="text-text-muted">via</span>
												<UserName name={path.via.display_name} trust={path.via.trust} compact />
												<span class="text-text-muted">→</span>
												<UserName name={path.via2.display_name} trust={path.via2.trust} compact />
												<span class="text-text-muted">→ {profile.display_name}</span>
											{/if}
										</div>
									{/each}
									{#each trustDetail.score_reductions as reduction}
										<div class="flex items-center gap-2 flex-wrap">
											<span class="text-text-muted text-xs">▼</span>
											<span class="text-text-muted">Trusts</span>
											<UserName name={reduction.display_name} trust={{ distance: null, blocked: true }} compact />
										</div>
									{/each}
								</div>
							{/if}
						</div>
					{/if}

					<!-- Trust lists -->
					<div class="grid grid-cols-2 gap-4 mt-4 pt-4 border-t border-border-subtle">
						<div>
							<h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">{profile.is_self ? 'You trust' : 'Trusts given'} ({trustDetail.trusts_total})</h2>
							<div class="space-y-2">
								{#each trustDetail.trusts as user}
									<div class="flex items-center gap-2 min-w-0">
										<UserName name={user.display_name} trust={user.trust} compact />
									</div>
								{/each}
								{#if trustDetail.trusts_total > trustDetail.trusts.length}
									<MoreButton href="/user/{username}/trust-edges/trusts">Show all {trustDetail.trusts_total}</MoreButton>
								{/if}
							</div>
						</div>

						<div>
							<h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">Trusted by ({trustDetail.trusted_by_total})</h2>
							<div class="space-y-2">
								{#each trustDetail.trusted_by as user}
									<div class="flex items-center gap-2 min-w-0">
										<UserName name={user.display_name} trust={user.trust} compact />
									</div>
								{/each}
								{#if trustDetail.trusted_by_total > trustDetail.trusted_by.length}
									<MoreButton href="/user/{username}/trust-edges/trusted-by">Show all {trustDetail.trusted_by_total}</MoreButton>
								{/if}
							</div>
						</div>
					</div>
				{/if}
					</div>
				{/if}
			</div>
		</div>

		<!-- Recent Activity -->
		<h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">Recent activity</h2>

		<!-- Filter tabs -->
		<div class="flex gap-1 mb-4">
			{#each [['all', 'All'], ['threads', 'Threads'], ['comments', 'Comments']] as [value, label]}
				<button
					onclick={() => handleFilterChange(value)}
					class="text-xs px-3 py-1.5 rounded-md cursor-pointer transition-colors {activityFilter === value ? 'bg-bg-surface-raised text-text-primary font-semibold border border-border' : 'text-text-muted hover:text-text-secondary hover:bg-bg-hover border border-transparent'}"
				>{label}</button>
			{/each}
		</div>

		{#if activityItems.length === 0 && !activityLoading}
			<div class="text-center text-text-muted py-8 border border-border-subtle rounded-md bg-bg-surface text-sm">
				No activity yet.
			</div>
		{:else}
			<div class="space-y-3 mb-6">
				{#each activityItems as item (item.post_id + item.created_at)}
					<div class="bg-bg-surface border border-border rounded-md p-4">
						<div class="flex items-center gap-2 text-xs text-text-muted mb-1">
							{#if item.type === 'thread_started'}
								<span>Started thread in</span>
								<a href="/room/{item.room_slug}" class="text-link hover:underline">{item.room_name}</a>
							{:else}
								<span>Replied in</span>
								<a href="/room/{item.room_slug}/{item.thread_id}?post={item.post_id}" class="text-link hover:underline">{item.thread_title}</a>
							{/if}
							<span class="ml-auto">{relativeTime(item.created_at)}</span>
						</div>
						{#if item.type === 'thread_started'}
							<a href="/room/{item.room_slug}/{item.thread_id}" class="text-[0.95rem] text-text-primary hover:underline font-medium leading-snug">{item.thread_title}</a>
						{/if}
						<div class="text-[0.95rem] leading-7 text-text-secondary mt-1">
							<Markdown source={item.body} profile={item.type === 'thread_started' ? 'full' : 'reply'} />
						</div>
					</div>
				{/each}

				{#if activityCursor}
					<div class="text-center">
						<MoreButton onclick={() => loadActivity(false)} loading={activityLoading}>Load more activity</MoreButton>
					</div>
				{/if}
			</div>
		{/if}
	</div>
{/if}

<style>
	.trust-details-footer {
		cursor: pointer;
		user-select: none;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.25rem;
		font-size: 0.75rem;
		color: var(--text-muted);
		border: none;
		background: none;
		border-top: 1px dashed var(--border-subtle);
		margin-top: 1rem;
		padding: 0.625rem 0.75rem 0;
		width: 100%;
		transition: color 0.15s;
	}

	.trust-details-footer:hover {
		color: var(--accent);
	}

	.trust-details-footer::-webkit-details-marker {
		display: none;
	}

	.trust-details-footer:disabled {
		opacity: 1;
		cursor: wait;
	}

	.trust-details-spinner {
		flex-shrink: 0;
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin {
		to { transform: rotate(360deg); }
	}

	.trust-details-chevron {
		transition: transform 0.15s ease;
		flex-shrink: 0;
	}

	.trust-details-inline.open .trust-details-footer {
		color: var(--text-secondary);
	}

	.trust-details-inline.open .trust-details-chevron {
		transform: rotate(90deg);
	}

	.stat-label {
		font-size: 0.7rem;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-muted);
	}

	.stat-value {
		font-size: 1.25rem;
		font-weight: 600;
		color: var(--text-primary);
	}

	.trust-score-hint {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 1rem;
		height: 1rem;
		border-radius: 50%;
		border: 1px solid var(--border-subtle);
		font-size: 0.625rem;
		color: var(--text-muted);
		cursor: help;
		user-select: none;
	}

	.blocked-badge {
		background: color-mix(in srgb, var(--danger) 12%, transparent);
	}
</style>
