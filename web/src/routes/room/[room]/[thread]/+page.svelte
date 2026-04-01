<script lang="ts">
	import {
		getThread,
		replyToThread,
		type ThreadDetail,
		type PostResponse
	} from '$lib/api/threads';
	import { page } from '$app/state';
	import { pushState } from '$app/navigation';
	import { fade } from 'svelte/transition';
	import PostCard from '$lib/components/post/PostCard.svelte';
	import ReplyForm from '$lib/components/post/ReplyForm.svelte';
	import ReplyTree from '$lib/components/post/ReplyTree.svelte';

	let thread = $state<ThreadDetail | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let replyingToId = $state<string | null>(null);
	let replyError = $state<string | null>(null);
	let replySaving = $state(false);

	let topLevelBody = $state('');
	let topLevelError = $state<string | null>(null);
	let topLevelSaving = $state(false);

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

	$effect(() => {
		const threadId = page.params.thread;
		if (threadId) {
			loadThread(threadId);
			viewRootStack = [];
		}
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
			<h1 class="text-2xl font-bold leading-tight mb-2">{thread.title}</h1>
			<PostCard post={thread.post} onreply={startReplying} />
		</div>

		{#if viewRoot}
			<!-- Re-rooted view -->
			<button
				onclick={popViewRoot}
				class="bg-transparent border-none text-accent cursor-pointer text-xs font-sans mb-2 py-0 px-0 hover:text-text-primary"
			>&larr; {viewRootStack.length <= 1 ? 'Back to full thread' : 'Previous comments'}</button>

			<div class="py-4 border-b border-border-subtle">
				<PostCard post={viewRoot} onreply={startReplying} />
				{#if replyingToId === viewRoot.id}
					<ReplyForm saving={replySaving} error={replyError} onsubmit={submitReply} oncancel={cancelReplying} />
				{/if}
				{#if viewRoot.children.length > 0}
					<ReplyTree
						parentId={viewRoot.id}
						children={viewRoot.children}
						maxDepth={MAX_DEPTH}
						{replyingToId}
						{replySaving}
						{replyError}
						onreply={startReplying}
						oncancelreply={cancelReplying}
						onsubmitreply={submitReply}
						oncontinuethread={(post) => pushViewRoot(post.id)}
					/>
				{/if}
			</div>
		{:else}
			<!-- Replies -->
			{#if thread.post.children.length > 0}
				<div class="text-xs mb-2 flex items-center gap-1.5 text-text-muted">
					<span>Sort by:</span>
					<select class="font-sans text-xs bg-bg-surface text-text-secondary border border-border rounded-md px-2 py-1 cursor-pointer hover:border-accent-muted focus:outline-none focus:border-accent-muted">
						<option>Trust</option>
						<option>Chronological</option>
					</select>
				</div>

				{#each thread.post.children as reply (reply.id)}
					<div class="py-4 border-b border-border-subtle">
						<PostCard post={reply} onreply={startReplying} />
						{#if replyingToId === reply.id}
							<ReplyForm saving={replySaving} error={replyError} onsubmit={submitReply} oncancel={cancelReplying} />
						{/if}
						{#if reply.children.length > 0}
							<ReplyTree
								parentId={reply.id}
								children={reply.children}
								maxDepth={MAX_DEPTH}
								{replyingToId}
								{replySaving}
								{replyError}
								onreply={startReplying}
								oncancelreply={cancelReplying}
								onsubmitreply={submitReply}
								oncontinuethread={(post) => pushViewRoot(post.id)}
							/>
						{/if}
					</div>
				{/each}
			{:else}
				<div class="text-center text-text-muted py-8">No replies yet.</div>
			{/if}
		{/if}

		<!-- Bottom reply form -->
		{#if !viewRoot}
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
					disabled={topLevelSaving || topLevelBody.trim() === ''}
					class="font-sans text-sm px-4 py-2 rounded-md cursor-pointer border border-accent bg-accent text-bg font-medium hover:opacity-90 disabled:opacity-50 transition-opacity duration-150"
				>{topLevelSaving ? 'Posting…' : 'Post reply'}</button>
			</div>
		</div>
		{/if}
	{/if}
</div>
