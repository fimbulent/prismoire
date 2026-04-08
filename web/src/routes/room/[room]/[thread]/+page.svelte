<script lang="ts">
	import {
		getThread,
		replyToThread,
		type ThreadDetail,
		type PostResponse,
		type ThreadDetailSort
	} from '$lib/api/threads';
	import {
		lockThread, unlockThread, removePost
	} from '$lib/api/admin';
	import { page } from '$app/state';
	import { pushState } from '$app/navigation';
	import { fade, slide } from 'svelte/transition';
	import PostCard from '$lib/components/post/PostCard.svelte';
	import ReplyForm from '$lib/components/post/ReplyForm.svelte';
	import RemoveForm from '$lib/components/post/RemoveForm.svelte';
	import ReplyTree from '$lib/components/post/ReplyTree.svelte';
	import LockIcon from '$lib/components/ui/LockIcon.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import { session } from '$lib/stores/session.svelte';
	import { goto } from '$app/navigation';

	let thread = $state<ThreadDetail | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let sortMode = $state<ThreadDetailSort>('trust');

	let replyingToId = $state<string | null>(null);
	let replyError = $state<string | null>(null);
	let replySaving = $state(false);

	let topLevelBody = $state('');
	let topLevelError = $state<string | null>(null);
	let topLevelSaving = $state(false);

	const MAX_REPLY_BODY = 10_000;
	const REPLY_COUNTER_THRESHOLD = 8_000;
	let topLevelBodyLen = $derived(topLevelBody.trim().length);
	let showTopLevelCounter = $derived(topLevelBodyLen >= REPLY_COUNTER_THRESHOLD);
	let topLevelRemaining = $derived(MAX_REPLY_BODY - topLevelBodyLen);

	const MAX_DEPTH = 4;
	let viewRootStack = $state<string[]>([]);

	let viewRoot = $derived.by(() => {
		if (!thread || viewRootStack.length === 0) return null;
		const id = viewRootStack[viewRootStack.length - 1];
		return findPost(thread.post, id);
	});

	function pushViewRoot(id: string) {
		viewRootStack = [...viewRootStack, id];
		pushState('', { viewRootStack: [...viewRootStack] });
	}

	function popViewRoot() {
		history.back();
	}

	// Guard: wait for the session store to finish loading before fetching the
	// thread. Without this, a hard refresh races — the fetch fires before the
	// session cookie is available, the catch block sees !session.isLoggedIn
	// (still loading), and incorrectly redirects to /login.
	//
	// We also track lastLoadedThreadId so the effect doesn't re-fire (and
	// reset viewRootStack) when session.loading transitions from true→false
	// for the *same* thread. Only a change in the route param triggers a
	// fresh load.
	let lastLoadedThreadId = $state<string | null>(null);

	$effect(() => {
		if (session.loading) return;
		const threadId = page.params.thread;
		if (threadId && threadId !== lastLoadedThreadId) {
			lastLoadedThreadId = threadId;
			viewRootStack = [];
			loadThread(threadId);
		}
	});

	async function loadThread(id: string, sort?: ThreadDetailSort) {
		loading = true;
		error = null;
		try {
			thread = await getThread(id, sort);
			if (!session.isLoggedIn && !thread.room_public) {
				goto('/login', { replaceState: true });
				return;
			}
		} catch (e) {
			if (!session.isLoggedIn) {
				goto('/login', { replaceState: true });
				return;
			}
			error = e instanceof Error ? e.message : 'Failed to load thread';
		} finally {
			loading = false;
		}
	}

	function startReplying(postId: string) {
		replyingToId = postId;
		replyError = null;
	}

	function cancelReplying() {
		replyingToId = null;
		replyError = null;
	}

	async function submitReply(body: string) {
		if (!thread || !replyingToId) return;
		replySaving = true;
		replyError = null;
		try {
			const newPost = await replyToThread(thread.id, replyingToId, body);
			insertReply(thread.post, newPost);
			thread.reply_count += 1;
			thread = thread;
			replyingToId = null;
		} catch (e) {
			replyError = e instanceof Error ? e.message : 'Failed to post reply';
		} finally {
			replySaving = false;
		}
	}

	async function submitTopLevelReply() {
		if (!thread) return;
		topLevelSaving = true;
		topLevelError = null;
		try {
			const newPost = await replyToThread(thread.id, thread.post.id, topLevelBody);
			insertReply(thread.post, newPost);
			thread.reply_count += 1;
			thread = thread;
			topLevelBody = '';
		} catch (e) {
			topLevelError = e instanceof Error ? e.message : 'Failed to post reply';
		} finally {
			topLevelSaving = false;
		}
	}

	function insertReply(root: PostResponse, newPost: PostResponse) {
		if (root.id === newPost.parent_id) {
			root.children = [...root.children, newPost];
			return true;
		}
		for (const child of root.children) {
			if (insertReply(child, newPost)) return true;
		}
		return false;
	}

	function findPost(root: PostResponse, id: string): PostResponse | null {
		if (root.id === id) return root;
		for (const child of root.children) {
			const found = findPost(child, id);
			if (found) return found;
		}
		return null;
	}

	function handlePopState() {
		viewRootStack = page.state.viewRootStack ?? [];
	}

	let adminError = $state<string | null>(null);
	let lockReasonInput = $state('');
	let showLockForm = $state(false);
	let removeTarget = $state<string | null>(null);
	let removeError = $state<string | null>(null);
	let removeSaving = $state(false);

	async function handleLock() {
		if (!thread) return;
		adminError = null;
		try {
			if (thread.locked) {
				await unlockThread(thread.id);
				thread.locked = false;
			} else {
				const reason = lockReasonInput.trim();
				if (!reason) {
					adminError = 'Reason is required to lock a thread';
					return;
				}
				await lockThread(thread.id, reason);
				thread.locked = true;
				showLockForm = false;
				lockReasonInput = '';
			}
		} catch (e) {
			adminError = e instanceof Error ? e.message : 'Action failed';
		}
	}

	async function handleRemovePost(reason: string) {
		if (!removeTarget) return;
		removeError = null;
		removeSaving = true;
		try {
			await removePost(removeTarget, reason);
			function markRemoved(post: PostResponse): boolean {
				if (post.id === removeTarget) {
					post.retracted_at = new Date().toISOString();
					post.body = '[removed by admin]';
					return true;
				}
				for (const child of post.children) {
					if (markRemoved(child)) return true;
				}
				return false;
			}
			if (thread) markRemoved(thread.post);
			thread = thread;
			removeTarget = null;
		} catch (e) {
			removeError = e instanceof Error ? e.message : 'Action failed';
		} finally {
			removeSaving = false;
		}
	}

	function cancelRemove() {
		removeTarget = null;
		removeError = null;
	}
</script>

<svelte:window onpopstate={handlePopState} />

<svelte:head>
	<title>{thread ? `${thread.title} — Prismoire` : 'Thread — Prismoire'}</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	{#if loading}
		<div class="text-center text-text-muted py-12">Loading thread…</div>
	{:else if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else if thread}
		<!-- OP -->
		<div class="bg-bg-surface border border-border rounded-md p-5 mb-6">
			<h1 class="text-2xl font-bold leading-tight mb-2 flex items-center gap-2">
				{thread.title}
				{#if thread.room_public}
					<Badge>Public</Badge>
				{/if}
				{#if thread.locked}
					<LockIcon class="w-5 h-5" />
				{/if}
			</h1>
			<PostCard post={thread.post} onreply={thread.locked ? undefined : startReplying} onremove={session.isAdmin ? (postId) => { removeTarget = postId; removeError = null; } : undefined}>
				{#snippet extraActions()}
					{#if session.isAdmin && thread}
						{#if thread.locked}
							<button
								onclick={handleLock}
								class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-text-secondary"
							>Unlock</button>
						{:else}
							<button
								onclick={() => { showLockForm = !showLockForm; }}
								class="bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans py-1 hover:text-text-secondary"
							>Lock</button>
						{/if}
					{/if}
				{/snippet}
			</PostCard>

			{#if session.isAdmin && showLockForm && !thread.locked}
				<div class="mt-3 bg-bg border border-border rounded-md p-4" transition:slide={{ duration: 150 }}>
					<input
						id="lock-reason"
						type="text"
						bind:value={lockReasonInput}
						placeholder="Why is this thread being locked?"
						class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted"
					/>
					<p class="text-xs text-text-muted mt-1">Lock reason will be public in the <a href="/log" class="text-link hover:text-link-hover">admin log</a>.</p>
					<div class="flex gap-2 mt-2">
						<button
							onclick={handleLock}
							disabled={!lockReasonInput.trim()}
							class="text-xs px-3 py-1.5 rounded-md border border-danger text-danger hover:bg-bg-hover cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
						>Lock thread</button>
						<button
							onclick={() => { showLockForm = false; lockReasonInput = ''; }}
							class="text-xs px-3 py-1.5 rounded-md border border-border text-text-muted hover:text-text-primary hover:bg-bg-hover cursor-pointer transition-colors"
						>Cancel</button>
					</div>
				</div>
			{/if}

			{#if removeTarget === thread.post.id}
				<RemoveForm saving={removeSaving} error={removeError} onsubmit={handleRemovePost} oncancel={cancelRemove} />
			{/if}

			{#if adminError}
				<div class="mt-3 text-danger text-sm">{adminError}</div>
			{/if}
		</div>

		{#if thread.room_public && !thread.locked}
			<div transition:slide={{ duration: 150 }} class="text-xs text-accent bg-accent/10 border border-accent/20 rounded-md px-4 py-2.5 mb-4">This post is readable to the public, but replies to this post are visible only to trusted users.</div>
		{/if}

		{#if !session.isLoggedIn}
			<div class="text-center py-8">
				<a href="/login" class="text-link hover:text-link-hover">Sign in</a> to see replies and join the discussion.
			</div>
		{:else if viewRoot}
			<!-- Re-rooted view -->
			<button
				onclick={popViewRoot}
				class="bg-transparent border-none text-accent cursor-pointer text-xs font-sans mb-2 py-0 px-0 hover:text-text-primary"
			>&larr; {viewRootStack.length <= 1 ? 'Back to full thread' : 'Previous comments'}</button>

			<div class="py-4 border-b border-border-subtle">
				<PostCard post={viewRoot} onreply={thread.locked ? undefined : startReplying} onremove={session.isAdmin ? (postId) => { removeTarget = postId; removeError = null; } : undefined} />
				{#if replyingToId === viewRoot.id}
					<ReplyForm saving={replySaving} error={replyError} onsubmit={submitReply} oncancel={cancelReplying} />
				{/if}
				{#if removeTarget === viewRoot.id}
					<RemoveForm saving={removeSaving} error={removeError} onsubmit={handleRemovePost} oncancel={cancelRemove} />
				{/if}
				{#if viewRoot.children.length > 0}
					<ReplyTree
						parentId={viewRoot.id}
						children={viewRoot.children}
						maxDepth={MAX_DEPTH}
						{replyingToId}
						{replySaving}
						{replyError}
						onreply={thread.locked ? undefined : startReplying}
						oncancelreply={cancelReplying}
						onsubmitreply={submitReply}
						oncontinuethread={(post) => pushViewRoot(post.id)}
						onremove={session.isAdmin ? (postId) => { removeTarget = postId; removeError = null; } : undefined}
						removeTargetId={removeTarget}
						{removeSaving}
						{removeError}
						onsubmitremove={handleRemovePost}
						oncancelremove={cancelRemove}
					/>
				{/if}
			</div>
		{:else}
			<!-- Replies -->
			{#if thread.post.children.length > 0}
				<div class="text-xs mb-2 flex items-center gap-1.5 text-text-muted">
					<span>Sort by:</span>
					<select
						bind:value={sortMode}
						onchange={async () => { if (thread) { const t = await getThread(thread.id, sortMode); thread.post.children = t.post.children; thread.reply_count = t.reply_count; } }}
						class="font-sans text-xs bg-bg-surface text-text-secondary border border-border rounded-md px-2 py-1 cursor-pointer hover:border-accent-muted focus:outline-none focus:border-accent-muted"
					>
						<option value="trust">Trust</option>
						<option value="new">New</option>
					</select>
				</div>

				{#each thread.post.children as reply (reply.id)}
					<div class="py-4 border-b border-border-subtle">
						<PostCard post={reply} onreply={thread.locked ? undefined : startReplying} onremove={session.isAdmin ? (postId) => { removeTarget = postId; removeError = null; } : undefined} />
						{#if replyingToId === reply.id}
							<ReplyForm saving={replySaving} error={replyError} onsubmit={submitReply} oncancel={cancelReplying} />
						{/if}
						{#if removeTarget === reply.id}
							<RemoveForm saving={removeSaving} error={removeError} onsubmit={handleRemovePost} oncancel={cancelRemove} />
						{/if}
						{#if reply.children.length > 0}
							<ReplyTree
								parentId={reply.id}
								children={reply.children}
								maxDepth={MAX_DEPTH}
								{replyingToId}
								{replySaving}
								{replyError}
								onreply={thread.locked ? undefined : startReplying}
								oncancelreply={cancelReplying}
								onsubmitreply={submitReply}
								oncontinuethread={(post) => pushViewRoot(post.id)}
								onremove={session.isAdmin ? (postId) => { removeTarget = postId; removeError = null; } : undefined}
								removeTargetId={removeTarget}
								{removeSaving}
								{removeError}
								onsubmitremove={handleRemovePost}
								oncancelremove={cancelRemove}
							/>
						{/if}
					</div>
				{/each}
			{:else}
				<div class="text-center text-text-muted py-8">No replies yet.</div>
			{/if}
		{/if}

		<!-- Bottom reply form -->
		{#if session.isLoggedIn && !viewRoot && !thread.locked}
		<div class="pt-8">
			<textarea
				bind:value={topLevelBody}
				class="w-full min-h-24 bg-bg-surface border border-border rounded-md text-text-primary font-mono text-sm p-3 resize-y leading-relaxed focus:outline-none focus:border-accent-muted placeholder:text-text-muted"
				placeholder="Reply to thread..."
			></textarea>
			{#if topLevelError}
				<div class="text-danger text-sm mt-1">{topLevelError}</div>
			{/if}
			<div class="mt-2 flex justify-end gap-3 items-center">
				<span class="text-xs text-text-muted mr-auto">Markdown supported</span>
				{#if showTopLevelCounter}
					<span
						transition:slide={{ duration: 150, axis: 'x' }}
						class="text-xs tabular-nums {topLevelRemaining < 0 ? 'text-danger font-medium' : topLevelRemaining < 2000 ? 'text-text-secondary' : 'text-text-muted'}"
					>
						{topLevelRemaining.toLocaleString()} characters remaining
					</span>
				{/if}
				{#if topLevelBody.trim() !== ''}
					<button
						transition:fade={{ duration: 150 }}
						onclick={() => { topLevelBody = ''; topLevelError = null; }}
						disabled={topLevelSaving}
						class="font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-border bg-transparent text-text-secondary font-medium hover:bg-bg-hover hover:text-text-primary disabled:opacity-50"
					>Cancel</button>
				{/if}
				<button
					onclick={submitTopLevelReply}
					disabled={topLevelSaving || topLevelBody.trim() === '' || topLevelBodyLen > MAX_REPLY_BODY}
					class="font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-accent bg-accent text-bg font-medium hover:opacity-90 disabled:opacity-50 transition-opacity duration-150"
				>{topLevelSaving ? 'Posting…' : 'Post reply'}</button>
			</div>
		</div>
		{/if}
	{/if}
</div>
