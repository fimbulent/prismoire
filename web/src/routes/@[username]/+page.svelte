<script lang="ts">
	import { page } from '$app/state';
	import { slide } from 'svelte/transition';
	import {
		getUserProfile,
		getTrustDetail,
		getActivity,
		updateBio,
		setTrustEdge,
		deleteTrustEdge,
		setUserTag,
		clearUserTag,
		type UserProfile,
		type TrustDetailResponse,
		type ActivityItem
	} from '$lib/api/users';
	import { relativeTime } from '$lib/format';
	import TrustBadge from '$lib/components/trust/TrustBadge.svelte';
	import UserName from '$lib/components/trust/UserName.svelte';
	import Markdown from '$lib/components/ui/Markdown.svelte';
	import Tooltip from '$lib/components/ui/Tooltip.svelte';
	import MoreButton from '$lib/components/ui/MoreButton.svelte';
	import Notice from '$lib/components/ui/Notice.svelte';
	import ProfileActivityPost from '$lib/components/post/ProfileActivityPost.svelte';
	import { errorMessage } from '$lib/i18n/errors';
	import { session } from '$lib/stores/session.svelte';
	import { formatDistanceToNowStrict } from 'date-fns';
	import {
		suspendUser,
		banUser,
		unbanUser,
		unsuspendUser,
		adminRevokeInvites,
		adminGrantInvites,
		adminRemoveBio
	} from '$lib/api/admin';
	import Checkbox from '$lib/components/ui/Checkbox.svelte';

	let { data } = $props();

	let username = $derived(page.params.username ?? '');

	// Profile is local $state because trust_stance and bio are mutated in
	// place after server actions. The re-sync $effect below picks up new
	// server data when navigating between profiles.
	// svelte-ignore state_referenced_locally
	let profile = $state<UserProfile>(structuredClone(data.profile));

	let trustDetail = $state<TrustDetailResponse | null>(null);
	let trustLoading = $state(false);
	let trustLoaded = $state(false);
	let trustOpen = $state(false);

	// Activity pagination. The filter tab lives in `?filter=` so server
	// load always returns the correct initial page; the client only needs
	// an append buffer for load-more.
	let activityFilter = $derived(data.filter);
	let appendedActivity = $state<ActivityItem[]>([]);
	let appendedActivityCursor = $state<string | null>(null);
	let activityLoading = $state(false);

	let editingBio = $state(false);
	let bioText = $state('');
	let bioSaving = $state(false);
	let bioError = $state<string | null>(null);

	// Viewer's private tag for this profile. Editing is hidden for self,
	// for the deleted account branch (which doesn't render anything
	// editable), and for restricted viewers (who can't reach other
	// profiles in the first place). Limit mirrors the server's
	// MAX_TAG_GRAPHEMES, counted as grapheme clusters (not UTF-16 code
	// units) so the count and truncation match what the server enforces.
	const TAG_MAX = 35;
	let editingTag = $state(false);
	let tagText = $state('');
	let tagSaving = $state(false);
	let tagError = $state<string | null>(null);

	// Grapheme-cluster counting via Intl.Segmenter (widely supported as
	// of 2024). Falls back to code-point counting (still better than the
	// raw .length UTF-16 count) when Segmenter is unavailable.
	function countGraphemes(s: string): number {
		if (typeof Intl !== 'undefined' && 'Segmenter' in Intl) {
			const seg = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
			let n = 0;
			for (const _ of seg.segment(s)) n++;
			return n;
		}
		return [...s].length;
	}

	function truncateGraphemes(s: string, max: number): string {
		if (typeof Intl !== 'undefined' && 'Segmenter' in Intl) {
			const seg = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
			let result = '';
			let n = 0;
			for (const { segment } of seg.segment(s)) {
				if (n >= max) break;
				result += segment;
				n++;
			}
			return result;
		}
		return [...s].slice(0, max).join('');
	}

	let tagGraphemes = $derived(countGraphemes(tagText));

	let actionLoading = $state(false);
	let actionError = $state<string | null>(null);

	// Re-sync on navigation to a different profile (or filter change):
	// re-clone server data and reset lazy/append-buffer client state.
	$effect(() => {
		void data;
		profile = structuredClone(data.profile);
		trustDetail = null;
		trustLoaded = false;
		trustOpen = false;
		appendedActivity = [];
		appendedActivityCursor = null;
		editingBio = false;
		bioError = null;
		editingTag = false;
		tagError = null;
		actionError = null;
		adminOpen = false;
		adminAction = null;
		adminError = null;
	});

	let activityItems = $derived([...data.activity, ...appendedActivity]);
	let activityCursor = $derived(appendedActivityCursor ?? data.activityCursor);

	function activityKey(item: ActivityItem): string {
		return item.post_id + item.created_at;
	}

	async function loadMoreActivity() {
		if (!activityCursor || activityLoading) return;
		activityLoading = true;
		try {
			const res = await getActivity(username, activityFilter, activityCursor);
		    // Offset pagination can return items we've already rendered if
            // the dataset shifted between fetches (new activity inserted).
            // Dedup by key to keep the keyed {#each} block happy.
			const seen = new Set(activityItems.map(activityKey));
			const fresh = res.items.filter((i) => !seen.has(activityKey(i)));
			appendedActivity = [...appendedActivity, ...fresh];
			appendedActivityCursor = res.next_cursor;
		} catch {
			// silently fail for activity
		} finally {
			activityLoading = false;
		}
	}

	function filterHref(filter: string): string {
		const params = new URLSearchParams(page.url.searchParams);
		if (filter === 'all') params.delete('filter');
		else params.set('filter', filter);
		const qs = params.toString();
		return `/@${encodeURIComponent(username)}${qs ? '?' + qs : ''}`;
	}

	async function refreshAfterAction() {
		trustLoaded = false;
		const promises: Promise<void>[] = [
			getUserProfile(username).then((p) => {
				profile = p;
			})
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

	async function handleStance(stance: 'trust' | 'distrust' | 'neutral') {
		if (actionLoading) return;
		if (stance === profile.trust_stance) return;
		actionLoading = true;
		actionError = null;
		try {
			if (stance === 'neutral') {
				await deleteTrustEdge(username);
			} else {
				await setTrustEdge(username, stance);
			}
			profile.trust_stance = stance;
			await refreshAfterAction();
		} catch {
			actionError = 'Something went wrong. Try again.';
		} finally {
			actionLoading = false;
		}
	}

	function startEditBio() {
		bioText = profile.bio ?? '';
		editingBio = true;
		bioError = null;
	}

	async function saveBio() {
		bioSaving = true;
		bioError = null;
		try {
			const value = bioText.trim() || null;
			await updateBio(username, value);
			profile.bio = value;
			editingBio = false;
		} catch (e) {
			bioError = errorMessage(e, 'Failed to save bio');
		} finally {
			bioSaving = false;
		}
	}

	function cancelEditBio() {
		editingBio = false;
		bioError = null;
	}

	function startEditTag() {
		tagText = profile.viewer.tag ?? '';
		editingTag = true;
		tagError = null;
	}

	function cancelEditTag() {
		editingTag = false;
		tagError = null;
	}

	async function saveTag() {
		tagSaving = true;
		tagError = null;
		try {
			const value = tagText.trim();
			if (value === '') {
				await clearUserTag(username);
				profile.viewer = { ...profile.viewer, tag: null };
			} else {
				await setUserTag(username, value);
				profile.viewer = { ...profile.viewer, tag: value };
			}
			editingTag = false;
		} catch (e) {
			tagError = errorMessage(e, 'Failed to save tag');
		} finally {
			tagSaving = false;
		}
	}

	function joinMethodLabel(method: string): string {
		if (method === 'invite') return 'via invite';
		if (method === 'admin') return 'as admin';
		if (method === 'steam_key') return 'via key';
		return '';
	}

	// When the viewer themselves is banned/suspended, the UI locks down:
	// other users aren't linkable (they can't reach other profiles), bio
	// editing is hidden, and recent-activity items don't link out. The
	// server-side guards mirror all of this, so the UI changes here are
	// just so a restricted user doesn't see dead buttons that 403.
	let viewerRestricted = $derived(session.isRestricted);
	let suspensionNotice = $derived.by(() => {
		if (!session.isSuspended) return null;
		const until = session.suspendedUntil;
		if (!until) return 'for the time being';
		const when = new Date(until);
		if (Number.isNaN(when.getTime())) return 'for the time being';
		return formatDistanceToNowStrict(when, { addSuffix: false });
	});

	// Display-name h1 sizing tiers: shrink the heading for longer names so
	// `name + badges` doesn't overflow the profile-card header on tight
	// viewports. Display names are bounded at 20 graphemes server-side
	// (`server/src/display_name.rs`), so the buckets only need to cover
	// 3–20. Counted by code-unit length here, which over-counts surrogate
	// pairs (a 2-codepoint emoji-like char looks like length 2) — that's
	// fine, since wider glyphs *should* fall to the smaller bucket sooner.
	let displayNameSizeClass = $derived(
		profile.display_name.length <= 14
			? 'text-2xl'
			: profile.display_name.length <= 17
				? 'text-xl'
				: 'text-lg'
	);

	let isAdmin = $derived(session.isAdmin && !profile.is_self && profile.role !== 'admin');
	let adminOpen = $state(false);
	let adminAction = $state<'suspend' | 'ban' | 'invites' | 'bio' | null>(null);
	let adminReason = $state('');
	let adminDuration = $state('1d');
	let adminBanTree = $state(false);
	let adminRevokeInv = $state(false);
	let adminSaving = $state(false);
	let adminError = $state<string | null>(null);

	function resetAdminForm() {
		adminAction = null;
		adminReason = '';
		adminDuration = '1d';
		adminBanTree = false;
		adminRevokeInv = false;
		adminError = null;
	}

	async function adminRefresh() {
		profile = await getUserProfile(username);
		resetAdminForm();
	}

	async function confirmSuspend() {
		const reason = adminReason.trim();
		if (!reason) { adminError = 'Reason is required'; return; }
		adminSaving = true;
		adminError = null;
		try {
			await suspendUser(profile.id, reason, adminDuration);
			if (adminRevokeInv) {
				try { await adminRevokeInvites(profile.id, reason); } catch { /* already revoked */ }
			}
			await adminRefresh();
		} catch (e) {
			adminError = errorMessage(e, 'Suspend failed');
		} finally {
			adminSaving = false;
		}
	}

	async function confirmBan() {
		const reason = adminReason.trim();
		if (!reason) { adminError = 'Reason is required'; return; }
		adminSaving = true;
		adminError = null;
		try {
			await banUser(profile.id, reason, adminBanTree);
			await adminRefresh();
		} catch (e) {
			adminError = errorMessage(e, 'Ban failed');
		} finally {
			adminSaving = false;
		}
	}

	async function handleUnsuspend() {
		adminSaving = true;
		adminError = null;
		try {
			await unsuspendUser(profile.id);
			await adminRefresh();
		} catch (e) {
			adminError = errorMessage(e, 'Unsuspend failed');
		} finally {
			adminSaving = false;
		}
	}

	async function handleUnban() {
		const reason = adminReason.trim();
		if (!reason) { adminError = 'Reason is required'; return; }
		adminSaving = true;
		adminError = null;
		try {
			await unbanUser(profile.id, reason);
			await adminRefresh();
		} catch (e) {
			adminError = errorMessage(e, 'Unban failed');
		} finally {
			adminSaving = false;
		}
	}

	async function handleToggleInvites() {
		const reason = adminReason.trim();
		if (!reason) { adminError = 'Reason is required'; return; }
		adminSaving = true;
		adminError = null;
		try {
			if (profile.can_invite) {
				await adminRevokeInvites(profile.id, reason);
			} else {
				await adminGrantInvites(profile.id, reason);
			}
			await adminRefresh();
		} catch (e) {
			adminError = errorMessage(e, 'Failed');
		} finally {
			adminSaving = false;
		}
	}

	async function handleRemoveBio() {
		const reason = adminReason.trim();
		if (!reason) { adminError = 'Reason is required'; return; }
		adminSaving = true;
		adminError = null;
		try {
			await adminRemoveBio(profile.id, reason);
			await adminRefresh();
		} catch (e) {
			adminError = errorMessage(e, 'Failed to remove bio');
		} finally {
			adminSaving = false;
		}
	}

</script>

<svelte:head>
	<title>{profile.display_name} — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 py-8">

	{#if viewerRestricted && profile.is_self}
		<Notice>
			{#if session.isBanned}
				Your account has been banned. You can view your own profile and manage your settings, but no other parts of Prismoire are available to you.
			{:else if suspensionNotice}
				Your account has been suspended for {suspensionNotice}. While suspended, you can view your own profile and manage your settings, but no other parts of Prismoire are available to you.
			{:else}
				Your account has been suspended. You can view your own profile and manage your settings, but no other parts of Prismoire are available to you.
			{/if}
		</Notice>
	{/if}

	<!-- Profile Header -->
	<div class="bg-bg-surface border border-border rounded-md p-6 mb-6">
		<div class="flex flex-wrap items-start justify-between gap-4 mb-4">
			<div class="flex items-start gap-3">
				<div class="w-14 h-14 rounded-full bg-bg-surface-raised border border-border flex items-center justify-center text-2xl font-bold text-accent">
					{profile.display_name.charAt(0)}
				</div>
				<div class="min-w-0">
					<div class="flex flex-wrap items-center gap-2">
						<h1 class="{displayNameSizeClass} font-bold leading-tight {profile.viewer.status ? 'line-through opacity-60' : ''}">{profile.display_name}</h1>
						{#if profile.viewer.status === 'deleted'}
							<span class="status-badge status-badge-deleted text-xs font-semibold px-1.5 py-0.5 rounded">Deleted</span>
						{:else if profile.viewer.status === 'banned'}
							<span class="status-badge status-badge-banned text-xs font-semibold px-1.5 py-0.5 rounded">Banned</span>
						{:else if profile.viewer.status === 'suspended'}
							<span class="status-badge status-badge-suspended text-xs font-semibold px-1.5 py-0.5 rounded">Suspended</span>
						{:else if !profile.is_self}
							<TrustBadge viewer={profile.viewer} />
						{/if}
						{#if profile.role === 'admin'}
							<span class="text-xs px-1.5 py-0.5 rounded font-semibold bg-accent text-bg">Admin</span>
						{/if}
					</div>
					<!-- Private tag — only the viewer ever sees it; the tagged
					     user is never told. Hidden for self-views, deleted
					     accounts, and restricted viewers (whose UI is locked
					     down anyway). Sits between the display name and the
					     "Joined …" line so it reads as a viewer-private label
					     attached to the identity. -->
					{#if !profile.is_self && !viewerRestricted && profile.viewer.status !== 'deleted'}
						<div class="flex flex-wrap items-center gap-2 mt-1 text-sm">
							{#if editingTag}
								<input
									type="text"
									bind:value={tagText}
									oninput={() => {
										if (countGraphemes(tagText) > TAG_MAX) {
											tagText = truncateGraphemes(tagText, TAG_MAX);
										}
									}}
									placeholder="e.g. Alice from work"
									class="flex-1 min-w-0 max-w-xs bg-bg-surface-raised border border-border-subtle rounded-md px-2 py-1 text-sm text-text-primary focus:outline-none focus:border-accent"
								/>
								<button
									onclick={saveTag}
									disabled={tagSaving}
									class="text-xs px-3 py-1 rounded bg-accent text-bg font-medium hover:opacity-90 disabled:opacity-50 cursor-pointer"
								>{tagSaving ? 'Saving…' : 'Save'}</button>
								<button
									onclick={cancelEditTag}
									class="text-xs px-3 py-1 rounded border border-border text-text-secondary hover:bg-bg-hover cursor-pointer"
								>Cancel</button>
								<span class="text-xs text-text-muted">{tagGraphemes}/{TAG_MAX}</span>
								{#if tagError}
									<span class="text-xs text-danger basis-full">{tagError}</span>
								{/if}
							{:else if profile.viewer.tag}
								<span class="italic text-text-secondary">{profile.viewer.tag}</span>
								<button
									onclick={startEditTag}
									class="text-xs text-accent hover:underline cursor-pointer bg-transparent border-none"
								>Edit</button>
								<Tooltip
									text="A private label only you can see. Useful for remembering who someone is — e.g. their name elsewhere, where you met, or shared context."
									position="bottom"
								><span class="trust-score-hint">?</span></Tooltip>
							{:else}
								<button
									onclick={startEditTag}
									class="text-xs text-accent hover:underline cursor-pointer bg-transparent border-none"
								>Add private tag</button>
								<Tooltip
									text="A private label only you can see. Useful for remembering who someone is — e.g. their name elsewhere, where you met, or shared context. The tagged user is never told."
									position="bottom"
								><span class="trust-score-hint">?</span></Tooltip>
							{/if}
						</div>
					{/if}

					<div class="text-sm text-text-muted mt-0.5">
						Joined {relativeTime(profile.created_at)} {joinMethodLabel(profile.signup_method)}
					</div>
				</div>
			</div>

			{#if !profile.is_self}
				<!-- On mobile the parent row wraps the trust block onto its
				     own line; left-aligned buttons in their natural width
				     leave a hard-to-read patch of empty whitespace next to
				     them. Force the block to full width below `md:` so the
				     stance group can stretch and the buttons share that
				     width equally (see `.trust-stance-btn` media query). At
				     `md:` and up, revert to the original right-hugging
				     compact shape. -->
				<div class="flex flex-col gap-1 w-full md:w-auto items-stretch md:items-end">
					<div class="trust-stance-group">
						<button
							onclick={() => handleStance('distrust')}
							disabled={actionLoading}
							class="trust-stance-btn {profile.trust_stance === 'distrust' ? 'active-distrust' : ''}"
						>Distrust</button>
						<button
							onclick={() => handleStance('neutral')}
							disabled={actionLoading}
							class="trust-stance-btn {profile.trust_stance === 'neutral' ? 'active-neutral' : ''}"
						>Neutral</button>
						<button
							onclick={() => handleStance('trust')}
							disabled={actionLoading}
							class="trust-stance-btn {profile.trust_stance === 'trust' ? 'active-trust' : ''}"
						>Trust</button>
					</div>
					{#if actionError}
						<span class="text-xs text-danger">{actionError}</span>
					{/if}
				</div>
			{/if}
		</div>

		{#if !profile.is_self && profile.trust_stance === 'distrust'}
			<div class="flex items-center gap-3 px-4 py-3 rounded-md distrusted-badge border border-danger/20 mb-4">
				<span class="text-sm text-danger">You have distrusted this user.</span>
			</div>
		{/if}

		<!-- Bio -->
		{#if profile.is_self && editingBio && !viewerRestricted}
			<div transition:slide={{ duration: 150 }} class="mb-5">
				<textarea
					bind:value={bioText}
					class="w-full bg-bg-surface-raised border border-border-subtle rounded-md px-3 py-2 text-prose text-text-primary font-prose focus:outline-none focus:border-accent resize-none"
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
			<div class="text-prose leading-7 text-text-secondary mb-5">
				<Markdown source={profile.bio} profile="bio" />
			</div>
			{#if profile.is_self && !viewerRestricted}
				<button
					onclick={startEditBio}
					class="text-xs text-accent hover:underline cursor-pointer bg-transparent border-none mb-3"
				>Edit bio</button>
			{/if}
		{:else if profile.is_self && !viewerRestricted}
			<button
				onclick={startEditBio}
				class="text-xs text-accent hover:underline cursor-pointer bg-transparent border-none mb-3"
			>Add a bio</button>
		{/if}

		<!-- Admin Actions (collapsible) -->
		{#if isAdmin}
			<div class="admin-actions-inline" class:open={adminOpen}>
				<button class="admin-actions-toggle" onclick={() => { adminOpen = !adminOpen; if (!adminOpen) resetAdminForm(); }}>
					Admin actions
					<svg class="admin-actions-chevron" width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 4 10 8 6 12" /></svg>
				</button>
				{#if adminOpen}
					<div transition:slide={{ duration: 200 }}>
						<div class="pt-4 space-y-3">
							{#key adminAction}<div transition:slide={{ duration: 150 }}>
							{#if !adminAction}
								<div class="flex gap-2 flex-wrap">
									{#if profile.viewer.status === 'banned'}
										<button onclick={() => { adminAction = 'ban'; }} class="admin-action-btn admin-action-btn-primary">Unban</button>
									{:else if profile.viewer.status === 'suspended'}
										<button onclick={handleUnsuspend} disabled={adminSaving} class="admin-action-btn admin-action-btn-primary">{adminSaving ? 'Unsuspending…' : 'Unsuspend'}</button>
										<button onclick={() => { adminAction = 'ban'; }} class="admin-action-btn admin-action-btn-danger">Ban</button>
									{:else}
										<button onclick={() => { adminAction = 'suspend'; }} class="admin-action-btn admin-action-btn-danger">Suspend</button>
										<button onclick={() => { adminAction = 'ban'; }} class="admin-action-btn admin-action-btn-danger-strong">Ban</button>
									{/if}
									<button onclick={() => { adminAction = 'invites'; }} class="admin-action-btn admin-action-btn-muted">
										{profile.can_invite ? 'Revoke invites' : 'Grant invites'}
									</button>
									{#if profile.bio}
										<button onclick={() => { adminAction = 'bio'; }} class="admin-action-btn admin-action-btn-muted">Remove bio</button>
									{/if}
								</div>
							{:else if adminAction === 'suspend'}
								<div>
									<div class="text-xs font-semibold text-text-secondary mb-2">Suspend {profile.display_name} — reason (public)</div>
									<input
										type="text"
										bind:value={adminReason}
										placeholder="Reason for suspension"
										class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted mb-2"
									/>
									<div class="flex items-center gap-2 mb-2">
										<span class="text-xs text-text-muted">Duration:</span>
										<select
											bind:value={adminDuration}
											class="font-sans text-xs bg-bg text-text-secondary border border-border rounded-md px-2 py-1 cursor-pointer hover:border-accent-muted focus:outline-none focus:border-accent-muted"
										>
											<option value="1d">1 day</option>
											<option value="3d">3 days</option>
											<option value="1w">1 week</option>
											<option value="2w">2 weeks</option>
											<option value="1m">1 month</option>
										</select>
									</div>
									<div class="mb-2">
										<Checkbox bind:checked={adminRevokeInv}>Also revoke invite privileges</Checkbox>
									</div>
									{#if adminError}
										<div class="text-danger text-xs mb-2">{adminError}</div>
									{/if}
									<div class="flex gap-2">
										<button onclick={confirmSuspend} disabled={adminSaving || !adminReason.trim()} class="admin-action-btn admin-action-btn-danger">{adminSaving ? 'Suspending…' : 'Confirm suspension'}</button>
										<button onclick={resetAdminForm} disabled={adminSaving} class="admin-action-btn admin-action-btn-cancel">Cancel</button>
									</div>
								</div>
							{:else if adminAction === 'ban'}
								<div>
									{#if profile.viewer.status === 'banned'}
										<div class="text-xs font-semibold text-text-secondary mb-2">Unban {profile.display_name} — reason (public)</div>
										<input
											type="text"
											bind:value={adminReason}
											placeholder="Reason for unban"
											class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted mb-2"
										/>
										{#if adminError}
											<div class="text-danger text-xs mb-2">{adminError}</div>
										{/if}
										<div class="flex gap-2">
											<button onclick={handleUnban} disabled={adminSaving || !adminReason.trim()} class="admin-action-btn admin-action-btn-primary">{adminSaving ? 'Unbanning…' : 'Confirm unban'}</button>
											<button onclick={resetAdminForm} disabled={adminSaving} class="admin-action-btn admin-action-btn-cancel">Cancel</button>
										</div>
									{:else}
										<div class="text-xs font-semibold text-text-secondary mb-2">Ban {profile.display_name} — reason (public)</div>
										<input
											type="text"
											bind:value={adminReason}
											placeholder="Reason for ban"
											class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted mb-2"
										/>
										<div class="mb-2">
											<Checkbox bind:checked={adminBanTree}>Also ban all users in their downstream invite tree</Checkbox>
										</div>
										{#if adminError}
											<div class="text-danger text-xs mb-2">{adminError}</div>
										{/if}
										<div class="flex gap-2">
											<button onclick={confirmBan} disabled={adminSaving || !adminReason.trim()} class="admin-action-btn admin-action-btn-danger-strong">{adminSaving ? 'Banning…' : 'Confirm ban'}</button>
											<button onclick={resetAdminForm} disabled={adminSaving} class="admin-action-btn admin-action-btn-cancel">Cancel</button>
										</div>
									{/if}
								</div>
							{:else if adminAction === 'invites'}
								<div>
									<div class="text-xs font-semibold text-text-secondary mb-2">{profile.can_invite ? 'Revoke' : 'Grant'} invite privileges for {profile.display_name} — reason (public)</div>
									<input
										type="text"
										bind:value={adminReason}
										placeholder="Reason"
										class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted mb-2"
									/>
									{#if adminError}
										<div class="text-danger text-xs mb-2">{adminError}</div>
									{/if}
									<div class="flex gap-2">
										<button onclick={handleToggleInvites} disabled={adminSaving || !adminReason.trim()} class="admin-action-btn admin-action-btn-muted">{adminSaving ? 'Saving…' : (profile.can_invite ? 'Confirm revoke' : 'Confirm grant')}</button>
										<button onclick={resetAdminForm} disabled={adminSaving} class="admin-action-btn admin-action-btn-cancel">Cancel</button>
									</div>
								</div>
							{:else if adminAction === 'bio'}
								<div>
									<div class="text-xs font-semibold text-text-secondary mb-2">Remove bio for {profile.display_name} — reason (public)</div>
									<input
										type="text"
										bind:value={adminReason}
										placeholder="Reason for removing bio"
										class="w-full bg-bg border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted mb-2"
									/>
									{#if adminError}
										<div class="text-danger text-xs mb-2">{adminError}</div>
									{/if}
									<div class="flex gap-2">
										<button onclick={handleRemoveBio} disabled={adminSaving || !adminReason.trim()} class="admin-action-btn admin-action-btn-muted">{adminSaving ? 'Removing…' : 'Confirm remove'}</button>
										<button onclick={resetAdminForm} disabled={adminSaving} class="admin-action-btn admin-action-btn-cancel">Cancel</button>
									</div>
								</div>
							{/if}
							{#if adminError && !adminAction}
								<div class="text-danger text-xs">{adminError}</div>
							{/if}
							</div>{/key}
						</div>
					</div>
				{/if}
			</div>
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
						<div class="stat-value">{trustDetail.distrusts_issued}</div>
						<div class="stat-label">Distrusts issued</div>
					</div>
				</div>

				{#if !profile.is_self}
					<!-- Your trust in user -->
					<div class="border-t border-border-subtle mt-4 pt-4">
						<h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">Your trust</h2>
						<div class="flex items-center gap-3 mb-3">
							<TrustBadge viewer={trustDetail.viewer} />
							<Tooltip text={trustDetail.trust_score != null ? `Computed from trust and distrust relationships. Raw score: ${trustDetail.trust_score.toFixed(2)}` : 'No trust path exists to this user'}>
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
											<UserName name={path.via.display_name} viewer={path.via.viewer} compact linked={!viewerRestricted} />
											<span class="text-text-muted">→ {profile.display_name}</span>
										{:else if path.type === '3hop' && path.via && path.via2}
											<span class="text-text-muted">via</span>
											<UserName name={path.via.display_name} viewer={path.via.viewer} compact linked={!viewerRestricted} />
											<span class="text-text-muted">→</span>
											<UserName name={path.via2.display_name} viewer={path.via2.viewer} compact linked={!viewerRestricted} />
											<span class="text-text-muted">→ {profile.display_name}</span>
										{/if}
									</div>
								{/each}
								{#each trustDetail.score_reductions as reduction}
									<div class="flex items-center gap-2 flex-wrap">
										<span class="text-text-muted text-xs">▼</span>
										<span class="text-text-muted">Trusts</span>
										<UserName name={reduction.display_name} viewer={{ distance: null, distrusted: true }} compact linked={!viewerRestricted} />
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
									<UserName name={user.display_name} viewer={user.viewer} compact linked={!viewerRestricted} />
								</div>
							{/each}
							{#if trustDetail.trusts_total > trustDetail.trusts.length}
								<MoreButton href="/@{username}/trust-edges/trusts">Show all {trustDetail.trusts_total}</MoreButton>
							{/if}
						</div>
					</div>

					<div>
						<h2 class="text-sm font-semibold uppercase tracking-wider text-text-muted mb-3">Trusted by ({trustDetail.trusted_by_total})</h2>
						<div class="space-y-2">
							{#each trustDetail.trusted_by as user}
								<div class="flex items-center gap-2 min-w-0">
									<UserName name={user.display_name} viewer={user.viewer} compact linked={!viewerRestricted} />
								</div>
							{/each}
							{#if trustDetail.trusted_by_total > trustDetail.trusted_by.length}
								<MoreButton href="/@{username}/trust-edges/trusted-by">Show all {trustDetail.trusted_by_total}</MoreButton>
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

	{#if data.activityAdminOverride}
		<Notice>
			You're seeing this activity as an admin. {profile.display_name} doesn't trust you enough to normally see these posts.
		</Notice>
	{/if}

	<!-- Filter tabs -->
	<div class="flex gap-1 mb-4">
		{#each [['all', 'All'], ['threads', 'Threads'], ['comments', 'Comments']] as [value, label]}
			<a
				href={filterHref(value)}
				data-sveltekit-noscroll
				data-sveltekit-keepfocus
				class="text-xs px-3 py-1.5 rounded-md cursor-pointer transition-colors no-underline {activityFilter === value ? 'bg-bg-surface-raised text-text-primary font-semibold border border-border' : 'text-text-muted hover:text-text-secondary hover:bg-bg-hover border border-transparent'}"
			>{label}</a>
		{/each}
	</div>

	{#if activityItems.length === 0 && !activityLoading}
		<div class="text-center text-text-muted py-8 border border-border-subtle rounded-md bg-bg-surface text-sm">
			No activity yet.
		</div>
	{:else}
		<div class="space-y-3 mb-6">
			{#each activityItems as item (item.post_id + item.created_at)}
				<ProfileActivityPost {item} {viewerRestricted} />
				{/each}

			{#if activityCursor}
				<div class="text-center">
					<MoreButton onclick={loadMoreActivity} loading={activityLoading}>Load more activity</MoreButton>
				</div>
			{/if}
		</div>
	{/if}
</div>

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

	.distrusted-badge {
		background: color-mix(in srgb, var(--danger) 12%, transparent);
	}

	.status-badge-banned { color: var(--danger); background: color-mix(in srgb, var(--danger) 12%, transparent); }
	.status-badge-suspended { color: var(--text-muted); background: color-mix(in srgb, var(--text-muted) 12%, transparent); }
	.status-badge-deleted { color: var(--text-muted); background: color-mix(in srgb, var(--text-muted) 12%, transparent); }

	.admin-actions-toggle {
		cursor: pointer;
		user-select: none;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.25rem;
		font-size: 0.75rem;
		color: var(--danger);
		border: none;
		background: none;
		border-top: 1px dashed var(--border-subtle);
		margin-top: 1rem;
		padding: 0.625rem 0.75rem 0;
		width: 100%;
		transition: color 0.15s;
		opacity: 0.7;
	}

	.admin-actions-toggle:hover { opacity: 1; }

	.admin-actions-chevron {
		transition: transform 0.15s ease;
		flex-shrink: 0;
	}

	.admin-actions-inline.open .admin-actions-chevron {
		transform: rotate(90deg);
	}

	.admin-actions-inline.open .admin-actions-toggle {
		opacity: 1;
	}

	.admin-action-btn {
		font-family: inherit;
		font-size: 0.75rem;
		font-weight: 500;
		padding: 0.375rem 0.75rem;
		border-radius: 0.375rem;
		cursor: pointer;
		border: 1px solid;
		transition: background 0.15s, opacity 0.15s;
	}

	.admin-action-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.admin-action-btn-danger {
		border-color: var(--danger);
		color: var(--danger);
		background: color-mix(in srgb, var(--danger) 8%, transparent);
	}

	.admin-action-btn-danger:hover:not(:disabled) { background: color-mix(in srgb, var(--danger) 16%, transparent); }

	.admin-action-btn-danger-strong {
		border-color: var(--danger);
		color: var(--danger);
		background: color-mix(in srgb, var(--danger) 15%, transparent);
	}

	.admin-action-btn-danger-strong:hover:not(:disabled) { background: color-mix(in srgb, var(--danger) 24%, transparent); }

	.admin-action-btn-primary {
		border-color: var(--accent);
		color: var(--accent);
		background: color-mix(in srgb, var(--accent) 8%, transparent);
	}

	.admin-action-btn-primary:hover:not(:disabled) { background: color-mix(in srgb, var(--accent) 16%, transparent); }

	.admin-action-btn-muted {
		border-color: var(--border);
		color: var(--text-secondary);
		background: transparent;
	}

	.admin-action-btn-muted:hover:not(:disabled) { background: var(--bg-hover); color: var(--text-primary); }

	.admin-action-btn-cancel {
		border-color: var(--border);
		color: var(--text-muted);
		background: transparent;
	}

	.admin-action-btn-cancel:hover:not(:disabled) { background: var(--bg-hover); color: var(--text-primary); }

	.trust-stance-group {
		display: flex;
		border: 1px solid var(--border);
		border-radius: 0.375rem;
		overflow: hidden;
	}

	.trust-stance-btn {
		font-size: 0.8125rem;
		padding: 0.375rem 0.75rem;
		cursor: pointer;
		font-weight: 500;
		border: none;
		background: transparent;
		color: var(--text-muted);
		transition: background 0.15s, color 0.15s;
	}

	.trust-stance-btn:not(:last-child) {
		border-right: 1px solid var(--border);
	}

	.trust-stance-btn:hover:not(:disabled) {
		background: var(--bg-hover);
		color: var(--text-secondary);
	}

	.trust-stance-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.trust-stance-btn.active-trust {
		background: var(--accent);
		color: var(--bg);
	}

	.trust-stance-btn.active-neutral {
		background: var(--bg-surface-raised);
		color: var(--text-primary);
	}

	.trust-stance-btn.active-distrust {
		background: var(--danger);
		color: var(--bg);
	}

	/* On mobile, the wrapper stretches to full width (see the
	   `w-full md:w-auto items-stretch md:items-end` classes on the
	   trust block above). Without this rule the three buttons would
	   keep their natural widths and leave a ragged right edge. With
	   `flex: 1`, each button takes an equal third of the row so the
	   group reads as a balanced segmented control. Above `md:` the
	   wrapper collapses back to its compact right-hugging shape and
	   the buttons resume their content-sized width. */
	@media (max-width: 767px) {
		.trust-stance-btn {
			flex: 1;
		}
	}
</style>
