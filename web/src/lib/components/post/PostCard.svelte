<script lang="ts">
	import {
		editPost,
		retractPost,
		getPostRevisions,
		type PostResponse,
		type RevisionHistoryResponse
	} from '$lib/api/threads';
	import { relativeTime } from '$lib/format';
	import { session } from '$lib/stores/session.svelte';
	import TrustBadge from '$lib/components/trust/TrustBadge.svelte';

	import type { Snippet } from 'svelte';

	interface Props {
		post: PostResponse;
		onreply?: (postId: string) => void;
		onremove?: (postId: string) => void;
		extraActions?: Snippet;
	}

	let { post, onreply, onremove, extraActions }: Props = $props();

	let editingPostId = $state<string | null>(null);
	let editBody = $state('');
	let editError = $state<string | null>(null);
	let editSaving = $state(false);

	let retractConfirmId = $state<string | null>(null);
	let retractError = $state<string | null>(null);
	let retracting = $state(false);

	let historyPostId = $state<string | null>(null);
	let historyData = $state<RevisionHistoryResponse | null>(null);
	let historyLoading = $state(false);
	let historyError = $state<string | null>(null);
	let viewingRevisions = $state<Record<string, number>>({});

	function isPostAuthor(): boolean {
		return session.user !== null && session.user.user_id === post.author_id;
	}

	function startEditing() {
		editingPostId = post.id;
		editBody = post.body;
		editError = null;
	}

	function cancelEditing() {
		editingPostId = null;
		editBody = '';
		editError = null;
	}

	async function saveEdit() {
		editSaving = true;
		editError = null;
		try {
			const updated = await editPost(post.id, editBody);
			post.body = updated.body;
			post.edited_at = updated.edited_at;
			post.revision = updated.revision;
			post.retracted_at = updated.retracted_at;
			editingPostId = null;
			editBody = '';
			historyData = null;
			historyPostId = null;
			delete viewingRevisions[post.id];
		} catch (e) {
			editError = e instanceof Error ? e.message : 'Failed to save edit';
		} finally {
			editSaving = false;
		}
	}

	async function confirmRetract() {
		retracting = true;
		retractError = null;
		try {
			await retractPost(post.id);
			post.retracted_at = new Date().toISOString();
			post.body = '';
			retractConfirmId = null;
		} catch (e) {
			retractError = e instanceof Error ? e.message : 'Failed to retract post';
		} finally {
			retracting = false;
		}
	}

	async function toggleHistory() {
		if (historyPostId === post.id) {
			historyPostId = null;
			return;
		}
		if (!historyData || historyData.post_id !== post.id) {
			historyLoading = true;
			historyError = null;
			try {
				historyData = await getPostRevisions(post.id);
			} catch (e) {
				historyError = e instanceof Error ? e.message : 'Failed to load history';
			} finally {
				historyLoading = false;
			}
		}
		historyPostId = post.id;
	}

	function selectRevision(revision: number, total: number) {
		if (revision === total - 1) {
			delete viewingRevisions[post.id];
			viewingRevisions = viewingRevisions;
		} else {
			viewingRevisions = { ...viewingRevisions, [post.id]: revision };
		}
		historyPostId = null;
	}

	function getDisplayBody(): string {
		const rev = viewingRevisions[post.id];
		if (rev !== undefined && historyData && historyData.post_id === post.id) {
			const found = historyData.revisions.find((r) => r.revision === rev);
			return found?.body ?? post.body;
		}
		return post.body;
	}

	function getViewingOldLabel(): string | null {
		const rev = viewingRevisions[post.id];
		if (rev === undefined || !historyData || historyData.post_id !== post.id) return null;
		if (rev >= historyData.revisions.length - 1) return null;
		return revisionLabel(rev, historyData.revisions.length).toLowerCase();
	}

	function revisionLabel(revision: number, total: number): string {
		if (revision === total - 1) return 'Latest';
		if (revision === 0) return 'Original';
		return `Edit ${revision}`;
	}

	function handleClickOutside(event: MouseEvent) {
		const target = event.target as HTMLElement;
		if (!target.closest('.history-dropdown')) {
			historyPostId = null;
		}
	}
</script>

<svelte:document onclick={handleClickOutside} />

<!-- Header -->
<div class="flex items-center gap-2 mb-2 text-sm">
	{#if post.is_op}
		<span class="font-semibold text-text-primary bg-bg-surface-raised px-2 py-0.5 rounded border border-border">{post.author_name}</span>
		{#if session.user?.user_id !== post.author_id}
			<TrustBadge distance={post.trust_distance} />
		{/if}
		<span class="text-xs font-bold px-1.5 py-0.5 rounded border border-accent-muted text-accent uppercase tracking-wider">op</span>
	{:else}
		<span class="font-semibold text-text-primary">{post.author_name}</span>
		{#if session.user?.user_id !== post.author_id}
			<TrustBadge distance={post.trust_distance} />
		{/if}
	{/if}
	<span class="text-text-muted text-xs">{relativeTime(post.created_at)}</span>
	{#if post.retracted_at && post.body !== '[removed by admin]'}
		<span class="text-text-muted text-xs italic">retracted {relativeTime(post.retracted_at)}</span>
	{:else if post.retracted_at}
		<span class="text-text-muted text-xs italic">removed {relativeTime(post.retracted_at)}</span>
	{:else if post.edited_at}
		<span class="relative history-dropdown">
			<button
				onclick={(e: MouseEvent) => { e.stopPropagation(); toggleHistory(); }}
				class="bg-transparent border-none text-text-muted text-xs italic cursor-pointer font-sans py-0 px-0 hover:text-text-secondary"
			>edited {relativeTime(post.edited_at)}</button>
			{#if historyPostId === post.id}
				<div class="absolute left-0 top-6 bg-bg-surface-raised border border-border rounded-md py-1 min-w-48 shadow-lg z-10">
					{#if historyLoading}
						<div class="px-3 py-1.5 text-xs text-text-muted">Loading…</div>
					{:else if historyError}
						<div class="px-3 py-1.5 text-xs text-danger">{historyError}</div>
					{:else if historyData}
						{#each [...historyData.revisions].reverse() as rev}
							{@const viewing = viewingRevisions[post.id]}
							{@const isActive = viewing === rev.revision || (viewing === undefined && rev.revision === historyData.revisions.length - 1)}
							<button
								onclick={() => selectRevision(rev.revision, historyData!.revisions.length)}
								class="block w-full text-left bg-transparent border-none px-3 py-1.5 text-xs cursor-pointer font-sans hover:bg-bg-hover hover:text-text-primary {isActive ? 'text-text-primary' : 'text-text-secondary'}"
							>
								<span class="font-semibold">{revisionLabel(rev.revision, historyData.revisions.length)}</span>
								<span class="text-text-muted ml-1">{relativeTime(rev.created_at)}</span>
								{#if isActive}
									<span class="text-accent ml-1">✓</span>
								{/if}
							</button>
						{/each}
					{/if}
				</div>
			{/if}
		</span>
	{/if}
</div>

<!-- Body -->
{#if post.retracted_at && post.body === '[removed by admin]'}
	<div class="text-text-muted italic">[removed by admin]</div>
{:else if post.retracted_at}
	<div class="text-text-muted italic">[retracted]</div>
{:else if editingPostId === post.id}
	<div class="space-y-3">
		<textarea
			bind:value={editBody}
			class="w-full min-h-32 bg-bg border border-border rounded-md p-3 text-base leading-7 resize-y focus:outline-none focus:border-accent-muted font-mono text-sm"
		></textarea>
		{#if editError}
			<div class="text-danger text-sm">{editError}</div>
		{/if}
		<div class="flex gap-2">
			<button
				onclick={saveEdit}
				disabled={editSaving || editBody.trim() === ''}
				class="px-3 py-1.5 text-sm font-medium rounded-md bg-accent text-bg hover:opacity-90 disabled:opacity-50"
			>{editSaving ? 'Saving…' : 'Save'}</button>
			<button
				onclick={cancelEditing}
				disabled={editSaving}
				class="px-3 py-1.5 text-sm font-medium rounded-md border border-border text-text-secondary hover:bg-bg-surface-raised disabled:opacity-50"
			>Cancel</button>
		</div>
	</div>
{:else}
	{@const oldLabel = getViewingOldLabel()}
	{#if oldLabel}
		<div class="text-xs text-accent-muted mb-2">
			Viewing {oldLabel} ·
			<button
				onclick={() => { delete viewingRevisions[post.id]; viewingRevisions = viewingRevisions; historyPostId = null; }}
				class="bg-transparent border-none text-accent cursor-pointer text-xs font-sans p-0 hover:text-text-primary underline underline-offset-2"
			>back to latest</button>
		</div>
	{/if}
	<div class="text-base leading-7 whitespace-pre-wrap">{getDisplayBody()}</div>
{/if}

<!-- Actions -->
<div class="mt-2.5 flex gap-4">
	{#if !post.retracted_at && post.parent_id !== null && onreply}
		<button
			onclick={() => onreply(post.id)}
			class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-text-secondary"
		>Reply</button>
	{/if}
	{#if isPostAuthor() && !post.retracted_at && editingPostId !== post.id}
		<button
			onclick={startEditing}
			class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-text-secondary"
		>Edit</button>
		{#if retractConfirmId === post.id}
			<span class="flex items-center gap-2 text-xs">
				<span class="text-text-muted">Retract?</span>
				<button
					onclick={confirmRetract}
					disabled={retracting}
					class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-danger disabled:opacity-50"
				>{retracting ? 'Retracting…' : 'Confirm'}</button>
				<button
					onclick={() => { retractConfirmId = null; retractError = null; }}
					disabled={retracting}
					class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-text-secondary disabled:opacity-50"
				>Cancel</button>
			</span>
		{:else}
			<button
				onclick={() => (retractConfirmId = post.id)}
				class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-text-secondary"
			>Retract</button>
		{/if}
	{/if}
	{#if !post.retracted_at && onremove}
		<button
			onclick={() => onremove(post.id)}
			class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-danger"
		>Remove</button>
	{/if}
	{#if extraActions}
		{@render extraActions()}
	{/if}
</div>
{#if retractError && retractConfirmId === post.id}
	<div class="text-danger text-xs mt-1">{retractError}</div>
{/if}
