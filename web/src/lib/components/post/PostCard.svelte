<script lang="ts">
	import {
		editPost,
		retractPost,
		getPostRevisions,
		type PostResponse,
		type RevisionHistoryResponse
	} from '$lib/api/threads';
	import { reportPost, type ReportReason } from '$lib/api/admin';
	import { relativeTime } from '$lib/format';
	import { session } from '$lib/stores/session.svelte';
	import UserName from '$lib/components/trust/UserName.svelte';
	import Markdown from '$lib/components/ui/Markdown.svelte';
	import { errorMessage } from '$lib/i18n/errors';
	import { slide } from 'svelte/transition';

	import type { Snippet } from 'svelte';

	interface Props {
		post: PostResponse;
		onreply?: (postId: string) => void;
		onremove?: (postId: string) => void;
		extraActions?: Snippet;
		compact?: boolean;
	}

	let { post, onreply, onremove, extraActions, compact = false }: Props = $props();

	let editingPostId = $state<string | null>(null);
	let editBody = $state('');
	let editError = $state<string | null>(null);
	let editSaving = $state(false);

	let editMaxBody = $derived(post.parent_id === null ? 50_000 : 10_000);
	let editCounterThreshold = $derived(post.parent_id === null ? 40_000 : 8_000);
	let editBodyLen = $derived(editBody.trim().length);
	let showEditCounter = $derived(editingPostId !== null && editBodyLen >= editCounterThreshold);
	let editRemaining = $derived(editMaxBody - editBodyLen);

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
			editError = errorMessage(e, 'Failed to save edit');
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
			retractError = errorMessage(e, 'Failed to retract post');
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
				historyError = errorMessage(e, 'Failed to load history');
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

	let showReportForm = $state(false);
	let reportReason = $state<ReportReason>('spam');
	let reportDetail = $state('');
	let reportError = $state<string | null>(null);
	let reportSaving = $state(false);
	let reportSuccess = $state(false);

	function canReport(): boolean {
		return session.isLoggedIn && !isPostAuthor() && !post.retracted_at;
	}

	async function submitReport() {
		reportSaving = true;
		reportError = null;
		try {
			await reportPost(post.id, reportReason, reportDetail.trim() || undefined);
			reportSuccess = true;
			showReportForm = false;
			reportDetail = '';
		} catch (e) {
			reportError = errorMessage(e, 'Failed to submit report');
		} finally {
			reportSaving = false;
		}
	}

	function cancelReport() {
		showReportForm = false;
		reportError = null;
		reportDetail = '';
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
	<UserName name={post.author_name} trust={post.trust} linked={session.isLoggedIn} />
	{#if post.is_op}
		<span class="text-xs font-bold px-1.5 py-0.5 rounded border border-accent-muted text-accent uppercase tracking-wider">op</span>
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
		{#if showEditCounter}
			<p
				transition:slide={{ duration: 150, axis: 'x' }}
				class="text-xs tabular-nums {editRemaining < 0 ? 'text-danger font-medium' : editRemaining < 2000 ? 'text-text-secondary' : 'text-text-muted'}"
			>
				{editRemaining.toLocaleString()} characters remaining
			</p>
		{/if}
		<div class="flex gap-2">
			<button
				onclick={saveEdit}
				disabled={editSaving || editBody.trim() === '' || editBodyLen > editMaxBody}
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
	<Markdown source={getDisplayBody()} profile={post.parent_id === null ? 'full' : 'reply'} />
{/if}

{#if !compact}
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
	{#if canReport() && !reportSuccess}
		<button
			onclick={() => { showReportForm = !showReportForm; }}
			class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-text-secondary"
		>Report</button>
	{:else if reportSuccess}
		<span class="text-xs text-text-muted py-1">Reported</span>
	{/if}
	{#if extraActions}
		{@render extraActions()}
	{/if}
</div>
{#if retractError && retractConfirmId === post.id}
	<div class="text-danger text-xs mt-1">{retractError}</div>
{/if}
{#if showReportForm}
	<div class="mt-3 bg-bg border border-border rounded-md p-4" transition:slide={{ duration: 150 }}>
		<div class="text-xs font-semibold text-text-secondary mb-2">Report this post</div>
		<div class="flex flex-wrap gap-2 mb-3">
			{#each [['spam', 'Spam'], ['rules_violation', 'Rules violation'], ['illegal_content', 'Illegal content'], ['other', 'Other']] as [value, label]}
				<button
					onclick={() => { reportReason = value as ReportReason; }}
					class="text-xs px-2.5 py-1 rounded-md border cursor-pointer font-sans transition-colors
						{reportReason === value ? 'border-accent text-accent bg-bg-surface' : 'border-border text-text-muted bg-transparent hover:text-text-secondary hover:bg-bg-hover'}"
				>{label}</button>
			{/each}
		</div>
		<input
			type="text"
			bind:value={reportDetail}
			placeholder="Additional details (optional)"
			class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted mb-3"
		/>
		{#if reportError}
			<div class="text-danger text-xs mb-2">{reportError}</div>
		{/if}
		<div class="flex gap-2">
			<button
				onclick={submitReport}
				disabled={reportSaving}
				class="text-xs px-3 py-1.5 rounded-md border border-danger text-danger hover:bg-bg-hover cursor-pointer font-sans font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
			>{reportSaving ? 'Submitting…' : 'Submit report'}</button>
			<button
				onclick={cancelReport}
				disabled={reportSaving}
				class="text-xs px-3 py-1.5 rounded-md border border-border text-text-muted hover:text-text-primary hover:bg-bg-hover cursor-pointer font-sans transition-colors"
			>Cancel</button>
		</div>
	</div>
{/if}
{/if}
