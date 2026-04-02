<script lang="ts">
	import type { PostResponse } from '$lib/api/threads';
	import PostCard from './PostCard.svelte';
	import ReplyForm from './ReplyForm.svelte';
	import RemoveForm from './RemoveForm.svelte';
	import ReplyTree from './ReplyTree.svelte';
	import { slide } from 'svelte/transition';

	interface Props {
		parentId: string;
		children: PostResponse[];
		depth?: number;
		maxDepth?: number;
		replyingToId?: string | null;
		replySaving?: boolean;
		replyError?: string | null;
		onreply?: (postId: string) => void;
		oncancelreply?: () => void;
		onsubmitreply?: (body: string) => void;
		oncontinuethread?: (post: PostResponse) => void;
		onremove?: (postId: string) => void;
		removeTargetId?: string | null;
		removeSaving?: boolean;
		removeError?: string | null;
		onsubmitremove?: (reason: string) => void;
		oncancelremove?: () => void;
	}

	let {
		parentId,
		children,
		depth = 1,
		maxDepth = 4,
		replyingToId = null,
		replySaving = false,
		replyError = null,
		onreply,
		oncancelreply,
		onsubmitreply,
		oncontinuethread,
		onremove,
		removeTargetId = null,
		removeSaving = false,
		removeError = null,
		onsubmitremove,
		oncancelremove
	}: Props = $props();

	let collapsedIds = $state(new Set<string>());

	function toggleCollapse(id: string) {
		const next = new Set(collapsedIds);
		if (next.has(id)) {
			next.delete(id);
		} else {
			next.add(id);
		}
		collapsedIds = next;
	}

	function countDescendants(post: PostResponse): number {
		let count = post.children.length;
		for (const child of post.children) {
			count += countDescendants(child);
		}
		return count;
	}

	let collapsed = $derived(collapsedIds.has(parentId));
</script>

<div class="ml-6 relative reply-nesting">
	<button
		onclick={() => toggleCollapse(parentId)}
		class="collapse-line {collapsed ? 'collapsed' : ''}"
		aria-label={collapsed ? 'Expand comments' : 'Collapse comments'}
	></button>
	{#if collapsed}
		{@const total = children.reduce((n, c) => n + 1 + countDescendants(c), 0)}
		<div class="pl-4 py-2" transition:slide={{ duration: 150 }}>
			<button
				onclick={() => toggleCollapse(parentId)}
				class="text-xs text-text-muted hover:text-text-secondary cursor-pointer bg-transparent border-none font-sans p-0"
			>{total} {total === 1 ? 'comment' : 'comments'} hidden</button>
		</div>
	{:else}
		<div transition:slide={{ duration: 200 }}>
			{#each children as reply (reply.id)}
				<div class="pl-4 py-3">
					<PostCard post={reply} {onreply} {onremove} />
					{#if replyingToId === reply.id && oncancelreply && onsubmitreply}
						<ReplyForm saving={replySaving} error={replyError} onsubmit={onsubmitreply} oncancel={oncancelreply} />
					{/if}
					{#if removeTargetId === reply.id && oncancelremove && onsubmitremove}
						<RemoveForm saving={removeSaving} error={removeError} onsubmit={onsubmitremove} oncancel={oncancelremove} />
					{/if}
					{#if reply.children.length > 0}
						{#if depth >= maxDepth}
							{@const descendants = countDescendants(reply)}
							<div class="py-2">
								<button
									onclick={() => oncontinuethread?.(reply)}
									class="font-sans text-xs text-accent bg-bg-surface border border-dashed border-border rounded-md px-3.5 py-1.5 cursor-pointer hover:bg-bg-surface-raised hover:border-accent-muted transition-colors"
								>{descendants} more {descendants === 1 ? 'reply' : 'replies'}</button>
							</div>
						{:else}
							<ReplyTree
								parentId={reply.id}
								children={reply.children}
								depth={depth + 1}
								{maxDepth}
								{replyingToId}
								{replySaving}
								{replyError}
								{onreply}
								{oncancelreply}
								{onsubmitreply}
								{oncontinuethread}
								{onremove}
								{removeTargetId}
								{removeSaving}
								{removeError}
								{onsubmitremove}
								{oncancelremove}
							/>
						{/if}
					{/if}
				</div>
			{/each}
		</div>
	{/if}
</div>

<style>
	.collapse-line {
		position: absolute;
		left: 0;
		top: 0;
		bottom: 0;
		width: 16px;
		padding: 0;
		border: none;
		background: transparent;
		cursor: pointer;
		z-index: 1;
	}

	.collapse-line::before {
		content: '';
		position: absolute;
		left: 0;
		top: 0.5rem;
		bottom: 0;
		width: 2px;
		background: var(--border-subtle);
		transition: background 0.15s;
	}

	.collapse-line:hover::before {
		background: var(--accent);
	}

	.collapse-line.collapsed::before {
		top: 0;
		bottom: 0;
	}
</style>
