<script lang="ts">
	import {
		getThread,
		editPost,
		retractPost,
		getPostRevisions,
		type ThreadDetail,
		type RevisionHistoryResponse
	} from '$lib/api/threads';
	import { relativeTime } from '$lib/format';
	import { session } from '$lib/stores/session.svelte';
	import { page } from '$app/state';

	let thread = $state<ThreadDetail | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let editing = $state(false);
	let editBody = $state('');
	let editError = $state<string | null>(null);
	let editSaving = $state(false);

	let retractConfirm = $state(false);
	let retractError = $state<string | null>(null);
	let retracting = $state(false);

	let historyMenuOpen = $state(false);
	let historyData = $state<RevisionHistoryResponse | null>(null);
	let historyLoading = $state(false);
	let historyError = $state<string | null>(null);
	let viewingRevision = $state<number | null>(null);

	let displayBody = $derived.by(() => {
		if (!thread) return '';
		if (viewingRevision !== null && historyData) {
			const rev = historyData.revisions.find((r) => r.revision === viewingRevision);
			return rev?.body ?? thread.post.body;
		}
		return thread.post.body;
	});

	let viewingOldLabel = $derived.by(() => {
		if (viewingRevision === null || !historyData) return null;
		if (viewingRevision >= historyData.revisions.length - 1) return null;
		return revisionLabel(viewingRevision, historyData.revisions.length).toLowerCase();
	});

	$effect(() => {
		const threadId = page.params.thread;
		if (threadId) loadThread(threadId);
	});

	async function loadThread(id: string) {
		loading = true;
		error = null;
		try {
			thread = await getThread(id);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load thread';
		} finally {
			loading = false;
		}
	}

	function startEditing() {
		if (!thread) return;
		editBody = thread.post.body;
		editError = null;
		editing = true;
	}

	function cancelEditing() {
		editing = false;
		editBody = '';
		editError = null;
	}

	async function saveEdit() {
		if (!thread) return;
		editSaving = true;
		editError = null;
		try {
			const updated = await editPost(thread.post.id, editBody);
			thread.post = updated;
			editing = false;
			editBody = '';
			historyData = null;
			historyMenuOpen = false;
			viewingRevision = null;
		} catch (e) {
			editError = e instanceof Error ? e.message : 'Failed to save edit';
		} finally {
			editSaving = false;
		}
	}

	async function confirmRetract() {
		if (!thread) return;
		retracting = true;
		retractError = null;
		try {
			await retractPost(thread.post.id);
			thread.post.retracted_at = new Date().toISOString();
			thread.post.body = '';
			retractConfirm = false;
		} catch (e) {
			retractError = e instanceof Error ? e.message : 'Failed to retract post';
		} finally {
			retracting = false;
		}
	}

	async function toggleHistoryMenu() {
		if (!thread) return;
		if (historyMenuOpen) {
			historyMenuOpen = false;
			return;
		}
		if (!historyData) {
			historyLoading = true;
			historyError = null;
			try {
				historyData = await getPostRevisions(thread.post.id);
			} catch (e) {
				historyError = e instanceof Error ? e.message : 'Failed to load history';
			} finally {
				historyLoading = false;
			}
		}
		historyMenuOpen = true;
	}

	function selectRevision(revision: number) {
		viewingRevision = revision;
		historyMenuOpen = false;
	}

	function viewLatest() {
		viewingRevision = null;
		historyMenuOpen = false;
	}

	function revisionLabel(revision: number, total: number): string {
		if (revision === total - 1) return 'Latest';
		if (revision === 0) return 'Original';
		return `Edit ${revision}`;
	}

	function handleClickOutside(event: MouseEvent) {
		const target = event.target as HTMLElement;
		if (!target.closest('.history-dropdown')) {
			historyMenuOpen = false;
		}
	}

	let isAuthor = $derived(
		session.user !== null && thread !== null && session.user.user_id === thread.post.author_id
	);
</script>

<svelte:document onclick={handleClickOutside} />

<svelte:head>
	<title>{thread ? `${thread.title} — Prismoire` : 'Thread — Prismoire'}</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	{#if loading}
		<div class="text-center text-text-muted py-12">Loading thread…</div>
	{:else if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else if thread}
		<div class="bg-bg-surface border border-border rounded-md p-5 mb-6">
			<h1 class="text-2xl font-bold leading-tight mb-2">{thread.title}</h1>
			<div class="flex items-center gap-2 mb-3 text-sm">
				<span
					class="font-semibold text-text-primary bg-bg-surface-raised px-2 py-0.5 rounded border border-border"
					>{thread.post.author_name}</span
				>
				<span
					class="text-xs font-bold px-1.5 py-0.5 rounded border border-accent-muted text-accent uppercase tracking-wider"
					>op</span
				>
				<span class="text-text-muted text-xs"
					>{relativeTime(thread.created_at)}</span
				>
				{#if thread.post.edited_at && !thread.post.retracted_at}
					<span class="relative history-dropdown">
						<button
							onclick={(e: MouseEvent) => {
								e.stopPropagation();
								toggleHistoryMenu();
							}}
							class="bg-transparent border-none text-text-muted text-xs italic cursor-pointer font-sans py-0 px-0 hover:text-text-secondary"
							>edited {relativeTime(thread.post.edited_at)}</button
						>
						{#if historyMenuOpen}
							<div class="absolute left-0 top-6 bg-bg-surface-raised border border-border rounded-md py-1 min-w-48 shadow-lg z-10">
								{#if historyLoading}
									<div class="px-3 py-1.5 text-xs text-text-muted">Loading…</div>
								{:else if historyError}
									<div class="px-3 py-1.5 text-xs text-danger">{historyError}</div>
								{:else if historyData}
									{#each [...historyData.revisions].reverse() as rev}
										{@const isActive = viewingRevision === rev.revision || (viewingRevision === null && rev.revision === historyData.revisions.length - 1)}
										<button
											onclick={() => {
												if (rev.revision === historyData!.revisions.length - 1) {
													viewLatest();
												} else {
													selectRevision(rev.revision);
												}
											}}
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

			{#if thread.post.retracted_at}
				<div class="text-text-muted italic">[retracted {relativeTime(thread.post.retracted_at)}]</div>
			{:else if editing}
				<div class="space-y-3">
					<textarea
						bind:value={editBody}
						class="w-full min-h-32 bg-bg-base border border-border rounded-md p-3 text-base leading-7 resize-y focus:outline-none focus:border-accent"
					></textarea>
					{#if editError}
						<div class="text-danger text-sm">{editError}</div>
					{/if}
					<div class="flex gap-2">
						<button
							onclick={saveEdit}
							disabled={editSaving || editBody.trim() === ''}
							class="px-3 py-1.5 text-sm font-medium rounded-md bg-accent text-bg-base hover:opacity-90 disabled:opacity-50"
						>
							{editSaving ? 'Saving…' : 'Save'}
						</button>
						<button
							onclick={cancelEditing}
							disabled={editSaving}
							class="px-3 py-1.5 text-sm font-medium rounded-md border border-border text-text-secondary hover:bg-bg-surface-raised disabled:opacity-50"
						>
							Cancel
						</button>
					</div>
				</div>
			{:else}
				{#if viewingOldLabel}
					<div class="text-xs text-accent-muted mb-2">
						Viewing {viewingOldLabel} ·
						<button
							onclick={viewLatest}
							class="bg-transparent border-none text-accent cursor-pointer text-xs font-sans p-0 hover:text-text-primary underline underline-offset-2"
						>back to latest</button>
					</div>
				{/if}
				<div class="text-base leading-7 whitespace-pre-wrap">{displayBody}</div>
			{/if}

			<div class="mt-2.5 flex gap-4">
				<button class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-text-secondary">Reply</button>
				{#if isAuthor && !thread.post.retracted_at && !editing}
					<button
						onclick={startEditing}
						class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-text-secondary"
					>
						Edit
					</button>
					{#if retractConfirm}
						<span class="flex items-center gap-2 text-xs">
							<span class="text-text-muted">Retract?</span>
							<button
								onclick={confirmRetract}
								disabled={retracting}
								class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-danger disabled:opacity-50"
							>
								{retracting ? 'Retracting…' : 'Confirm'}
							</button>
							<button
								onclick={() => {
									retractConfirm = false;
									retractError = null;
								}}
								disabled={retracting}
								class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-text-secondary disabled:opacity-50"
							>
								Cancel
							</button>
						</span>
					{:else}
						<button
							onclick={() => (retractConfirm = true)}
							class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-text-secondary"
						>
							Retract
						</button>
					{/if}
				{/if}
			</div>
			{#if retractError}
				<div class="text-danger text-xs mt-1">{retractError}</div>
			{/if}
		</div>

		{#if thread.reply_count > 0}
			<div class="text-sm text-text-muted py-4">
				{thread.reply_count}
				{thread.reply_count === 1 ? 'reply' : 'replies'}
			</div>
		{:else}
			<div class="text-center text-text-muted py-8">
				No replies yet.
			</div>
		{/if}
	{/if}
</div>
