<script lang="ts">
	import {
		getThreadReplies,
		getThreadSubtree,
		replyToThread,
		type ThreadDetail,
		type PostResponse,
		type ThreadDetailSort
	} from '$lib/api/threads';
	import {
		lockThread, unlockThread, removePost
	} from '$lib/api/admin';
	import { page } from '$app/state';
	import { pushState, goto } from '$app/navigation';
	import { fade, slide } from 'svelte/transition';
	import PostCard from '$lib/components/post/PostCard.svelte';
	import ReplyForm from '$lib/components/post/ReplyForm.svelte';
	import RemoveForm from '$lib/components/post/RemoveForm.svelte';
	import ReplyTree from '$lib/components/post/ReplyTree.svelte';
	import LockIcon from '$lib/components/ui/LockIcon.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import Notice from '$lib/components/ui/Notice.svelte';
	import MoreButton from '$lib/components/ui/MoreButton.svelte';
	import { session } from '$lib/stores/session.svelte';
	import { errorMessage } from '$lib/i18n/errors';
	import { tick } from 'svelte';

	let { data } = $props();

	// Thread tree is mutated locally (reply, remove, load more, continue
	// subtree). Seed from server data and re-seed whenever SvelteKit re-runs
	// the server load (nav, sort change, focus change). The initial-value
	// warnings from svelte-check are false positives — the $effect below
	// reassigns both on every data update.
	// svelte-ignore state_referenced_locally
	let thread = $state<ThreadDetail>(structuredClone(data.thread));
	let sortMode = $derived(data.sort);
	// svelte-ignore state_referenced_locally
	let renderedTopLevelIds = $state(new Set<string>(data.thread.post.children.map((c) => c.id)));

	$effect(() => {
		thread = structuredClone(data.thread);
		renderedTopLevelIds = new Set(data.thread.post.children.map((c) => c.id));
		viewRootStack = [];
		if (data.thread.focused_post_id) {
			tick().then(() => scrollToFocusedPost(data.thread.focused_post_id!));
		}
	});

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
		if (viewRootStack.length === 0) return null;
		const id = viewRootStack[viewRootStack.length - 1];
		return findPost(thread.post, id);
	});

	let loadingMoreReplies = $state(false);

	function pushViewRoot(id: string) {
		viewRootStack = [...viewRootStack, id];
		pushState('', { viewRootStack: [...viewRootStack] });
	}

	function popViewRoot() {
		viewRootStack = viewRootStack.slice(0, -1);
		history.back();
	}

	function sortHref(sort: ThreadDetailSort): string {
		const params = new URLSearchParams(page.url.searchParams);
		if (sort === 'trust') params.delete('sort');
		else params.set('sort', sort);
		const qs = params.toString();
		return `${page.url.pathname}${qs ? '?' + qs : ''}`;
	}

	function handleSortChange(e: Event) {
		const sort = (e.currentTarget as HTMLSelectElement).value as ThreadDetailSort;
		goto(sortHref(sort), { noScroll: true, keepFocus: true });
	}

	function scrollToFocusedPost(focusId: string) {
		const depth = findPostDepth(thread.post, focusId, 0);
		if (depth !== null && depth > MAX_DEPTH) {
			const ancestorId = findAncestorAtDepth(thread.post, focusId, depth, MAX_DEPTH);
			if (ancestorId) {
				pushViewRoot(ancestorId);
			}
		}

		requestAnimationFrame(() => {
			const el = document.getElementById(`post-${focusId}`);
			if (el) {
				el.scrollIntoView({ behavior: 'smooth', block: 'center' });
				el.classList.add('post-highlight');
				setTimeout(() => el.classList.remove('post-highlight'), 2000);
			}
		});
	}

	function findPostDepth(root: PostResponse, targetId: string, currentDepth: number): number | null {
		if (root.id === targetId) return currentDepth;
		for (const child of root.children) {
			const found = findPostDepth(child, targetId, currentDepth + 1);
			if (found !== null) return found;
		}
		return null;
	}

	// Find the ancestor ~MAX_DEPTH levels above the target so the target is
	// visible within the re-rooted view.
	function findAncestorAtDepth(
		root: PostResponse,
		targetId: string,
		targetDepth: number,
		maxDepth: number
	): string | null {
		const desiredRootDepth = targetDepth - maxDepth;
		if (desiredRootDepth <= 0) return null;
		return findPostAtDepth(root, targetId, 0, desiredRootDepth);
	}

	// Walk toward the target; return the post ID at the desired depth along
	// the path.
	function findPostAtDepth(
		root: PostResponse,
		targetId: string,
		currentDepth: number,
		desiredDepth: number
	): string | null {
		if (root.id === targetId) {
			return currentDepth >= desiredDepth ? root.id : null;
		}
		for (const child of root.children) {
			const found = findPostAtDepth(child, targetId, currentDepth + 1, desiredDepth);
			if (found !== null) {
				return currentDepth === desiredDepth ? root.id : found;
			}
		}
		return null;
	}

	async function loadMoreReplies() {
		if (loadingMoreReplies) return;
		loadingMoreReplies = true;
		try {
			// In focused-view responses, an extra top-level reply on the focus
			// path may be appended out of sort order; `top_level_loaded` tells
			// us how many sort-ordered children are rendered so load-more picks
			// up at the right offset without skipping the next reply.
			const offset = thread.top_level_loaded ?? thread.post.children.length;
			const res = await getThreadReplies(thread.id, offset, sortMode);
			const newReplies = res.replies.filter((r) => !renderedTopLevelIds.has(r.id));
			for (const r of newReplies) {
				renderedTopLevelIds.add(r.id);
			}
			thread.post.children = [...thread.post.children, ...newReplies];
			// Advance the sort-ordered cursor so subsequent load-more calls
			// paginate from the right position instead of reusing the stale
			// offset set in the initial focused response.
			if (thread.top_level_loaded !== undefined) {
				thread.top_level_loaded += res.replies.length;
			}
			thread.has_more_replies = res.has_more;
			thread.reply_count += newReplies.reduce(
				(n, r) => n + 1 + countDescendants(r),
				0
			);
			thread = thread;
		} catch {
		} finally {
			loadingMoreReplies = false;
		}
	}

	function countDescendants(post: PostResponse): number {
		let count = post.children.length;
		for (const child of post.children) {
			count += countDescendants(child);
		}
		return count;
	}

	async function handleContinueThread(post: PostResponse) {
		try {
			const res = await getThreadSubtree(thread.id, post.id, sortMode);
			replaceSubtree(thread.post, post.id, res.post);
			thread = thread;
		} catch {
		}
		pushViewRoot(post.id);
	}

	function replaceSubtree(root: PostResponse, targetId: string, replacement: PostResponse): boolean {
		for (let i = 0; i < root.children.length; i++) {
			if (root.children[i].id === targetId) {
				root.children[i] = replacement;
				return true;
			}
			if (replaceSubtree(root.children[i], targetId, replacement)) return true;
		}
		return false;
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
		if (!replyingToId) return;
		replySaving = true;
		replyError = null;
		try {
			const newPost = await replyToThread(thread.id, replyingToId, body);
			insertReply(thread.post, newPost);
			if (newPost.parent_id === thread.post.id) {
				renderedTopLevelIds.add(newPost.id);
			}
			thread.reply_count += 1;
			thread = thread;
			replyingToId = null;
		} catch (e) {
			replyError = errorMessage(e, 'Failed to post reply');
		} finally {
			replySaving = false;
		}
	}

	async function submitTopLevelReply() {
		topLevelSaving = true;
		topLevelError = null;
		try {
			const newPost = await replyToThread(thread.id, thread.post.id, topLevelBody);
			insertReply(thread.post, newPost);
			renderedTopLevelIds.add(newPost.id);
			thread.reply_count += 1;
			thread = thread;
			topLevelBody = '';
		} catch (e) {
			topLevelError = errorMessage(e, 'Failed to post reply');
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

	// Fallback for browser back/forward buttons (popViewRoot handles the
	// in-app button case). page.state may be stale when this fires (SvelteKit
	// hasn't updated it yet), so read from history.state directly. SvelteKit
	// stores pushState user state under the 'sveltekit:states' key.
	function handlePopState() {
		const states = (history.state as Record<string, unknown>)?.['sveltekit:states'] as Record<string, unknown> | undefined;
		viewRootStack = (states?.viewRootStack as string[]) ?? [];
	}

	let adminError = $state<string | null>(null);
	let lockReasonInput = $state('');
	let showLockForm = $state(false);
	let removeTarget = $state<string | null>(null);
	let removeError = $state<string | null>(null);
	let removeSaving = $state(false);

	async function handleLock() {
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
			adminError = errorMessage(e, 'Action failed');
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
			markRemoved(thread.post);
			thread = thread;
			removeTarget = null;
		} catch (e) {
			removeError = errorMessage(e, 'Action failed');
		} finally {
			removeSaving = false;
		}
	}

	function cancelRemove() {
		removeTarget = null;
		removeError = null;
	}

	let focusedPostId = $derived(thread.focused_post_id ?? null);
</script>

<svelte:window onpopstate={handlePopState} />

<svelte:head>
	<title>{thread.title} — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	{#if focusedPostId}
			<div class="mb-4">
				<a
					href="/r/{thread.room_slug}/{thread.id}"
					class="text-xs text-accent hover:text-text-primary"
				>&larr; View full thread</a>
			</div>
		{/if}

		<!-- OP -->
		<div class="bg-bg-surface border border-border rounded-md p-5 mb-6">
			<h1 class="text-2xl font-bold leading-tight mb-2 flex items-center gap-2">
				{thread.title}
				{#if thread.is_announcement}
					<Badge>Public</Badge>
				{/if}
				{#if thread.locked}
					<LockIcon class="w-5 h-5" />
				{/if}
			</h1>
			<div id="post-{thread.post.id}">
				<PostCard post={thread.post} onreply={thread.locked ? undefined : startReplying} onremove={session.isAdmin ? (postId) => { removeTarget = postId; removeError = null; } : undefined}>
					{#snippet extraActions()}
						{#if session.isAdmin}
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
			</div>

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

		{#if thread.is_announcement && !thread.locked}
			<Notice>This post is readable to the public, but replies to this post are visible only to trusted users.</Notice>
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
				<div id="post-{viewRoot.id}">
					<PostCard post={viewRoot} onreply={thread.locked ? undefined : startReplying} onremove={session.isAdmin ? (postId) => { removeTarget = postId; removeError = null; } : undefined} />
				</div>
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
						oncontinuethread={handleContinueThread}
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
			{#if thread.post.children.length > 0 || thread.has_more_replies}
				<div class="text-xs mb-2 flex items-center gap-1.5 text-text-muted">
					<span>{thread.total_reply_count} {thread.total_reply_count === 1 ? 'reply' : 'replies'}</span>
					<span class="mx-1">·</span>
					<span>Sort by:</span>
					<select
						value={sortMode}
						onchange={handleSortChange}
						class="font-sans text-xs bg-bg-surface text-text-secondary border border-border rounded-md px-2 py-1 cursor-pointer hover:border-accent-muted focus:outline-none focus:border-accent-muted"
					>
						<option value="trust">Trust</option>
						<option value="new">New</option>
					</select>
				</div>

				{#each thread.post.children as reply (reply.id)}
					<div class="py-4 border-b border-border-subtle">
						<div id="post-{reply.id}">
							<PostCard post={reply} onreply={thread.locked ? undefined : startReplying} onremove={session.isAdmin ? (postId) => { removeTarget = postId; removeError = null; } : undefined} />
						</div>
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
								oncontinuethread={handleContinueThread}
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

				{#if thread.has_more_replies}
					<div class="py-4 text-center">
						<MoreButton onclick={loadMoreReplies} loading={loadingMoreReplies}>Load more replies</MoreButton>
					</div>
				{/if}
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
</div>

<style>
	:global(.post-highlight) {
		animation: highlight-pulse 2s ease-out;
	}

	@keyframes highlight-pulse {
		0% { outline: 2px solid var(--accent); outline-offset: 4px; }
		70% { outline: 2px solid var(--accent); outline-offset: 4px; }
		100% { outline: 2px solid transparent; outline-offset: 4px; }
	}
</style>
