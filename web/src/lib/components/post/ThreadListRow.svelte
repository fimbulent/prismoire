<!--
	One row in a thread listing.

	Used in two call sites today:
	- `/r/[room]` — borderless rows separated by `border-b`, hover-tinted.
	- `/search/threads` — each row a self-contained bordered card.

	The component renders the full meta strip (announcement badge, lock
	icon, optional link-post host, author + trust badge, time, reply
	count, and optional room slug) in both variants — search results
	share the room view's information density rather than being a
	stripped-down sibling.
-->
<script lang="ts">
	import Badge from '$lib/components/ui/Badge.svelte';
	import LockIcon from '$lib/components/ui/LockIcon.svelte';
	import ExternalLinkIcon from '$lib/components/ui/ExternalLinkIcon.svelte';
	import UserName from '$lib/components/trust/UserName.svelte';
	import { linkHost } from '$lib/utils/url';
	import { relativeTime } from '$lib/format';
	import { smartypants } from '$lib/typography';
	import type { UserViewerInfo } from '$lib/api/users';

	/**
	 * Subset of `ThreadSummary` / `ThreadSearchHit` that this row needs.
	 * Both API shapes structurally satisfy this — the row component
	 * accepts either without a wrapper.
	 */
	export interface ThreadRowData {
		id: string;
		title: string;
		author_name: string;
		/** Lowercase-hex pubkey of the thread's OP author. Used to build
		 * the canonical `/@username.{8hex}` link on the author chip. */
		author_public_key_hex: string;
		viewer: UserViewerInfo;
		room_slug: string;
		is_announcement: boolean;
		locked: boolean;
		link_url: string | null;
		last_activity: string | null;
		created_at: string;
		reply_count: number;
	}

	interface Props {
		thread: ThreadRowData;
		/**
		 * `inline` renders the row with no outer border; the parent
		 * draws separators (used by `/r/[room]`). `card` wraps the
		 * row in a bordered surface (used by `/search`).
		 */
		variant?: 'inline' | 'card';
		/** When true, append the room slug to the meta strip. */
		showRoomSlug?: boolean;
		/** When true, the bottom border is suppressed (last row in a list). */
		isLast?: boolean;
		/** Whether to wrap the author name in a `/@…` link. */
		linkedAuthor?: boolean;
	}

	let {
		thread,
		variant = 'inline',
		showRoomSlug = false,
		isLast = false,
		linkedAuthor = true
	}: Props = $props();

	let href = $derived(`/r/${encodeURIComponent(thread.room_slug)}/${encodeURIComponent(thread.id)}`);
	let roomHref = $derived(`/r/${encodeURIComponent(thread.room_slug)}`);
</script>

{#if variant === 'card'}
	<div class="bg-bg-surface border border-border rounded-md p-4">
		{@render body()}
	</div>
{:else}
	<div
		class="px-5 py-4 transition-colors duration-100 hover:bg-bg-hover {!isLast
			? 'border-b border-border-subtle'
			: ''}"
	>
		{@render body()}
	</div>
{/if}

{#snippet body()}
	<div class="flex items-start gap-3">
		<div class="flex-1 min-w-0">
			{#if thread.is_announcement || thread.locked}
				<div class="mb-1 flex items-center gap-2">
					{#if thread.is_announcement}
						<Badge>Announcements</Badge>
					{/if}
					{#if thread.locked}
						<LockIcon />
					{/if}
				</div>
			{/if}
			<div class="mb-1 max-w-measure">
				<a
					{href}
					class="font-prose text-prose leading-snug font-semibold text-text-primary no-underline hover:text-link hover:underline"
				>
					{smartypants(thread.title)}
				</a>
				{#if thread.link_url}
					<a
						href={thread.link_url}
						target="_blank"
						rel="nofollow ugc noopener noreferrer"
						class="ml-1.5 text-xs text-text-muted whitespace-nowrap no-underline hover:text-link hover:underline"
					>
						<ExternalLinkIcon />
						{linkHost(thread.link_url)}
					</a>
				{/if}
			</div>
			<!--
				Two-atom layout: [username] [time · replies · room].
				`flex-wrap` lets the row break onto a second line on
				narrow viewports, and the only valid break point is
				between the two children — the right group is wrapped
				in `whitespace-nowrap` so time/replies/room stay
				together and never break mid-content.
			-->
			<div class="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-text-muted">
				<span class="whitespace-nowrap">
					<UserName
						name={thread.author_name}
						pubkeyHex={thread.author_public_key_hex}
						viewer={thread.viewer}
						compact
						muted
						linked={linkedAuthor}
					/>
				</span>
				<div class="inline-flex items-center gap-2 whitespace-nowrap">
					<span>{relativeTime(thread.last_activity ?? thread.created_at)}</span>
					<span>&middot;</span>
					<a {href} class="no-underline hover:text-text-secondary hover:underline">
						{thread.reply_count}
						{thread.reply_count === 1 ? 'reply' : 'replies'}
					</a>
					{#if showRoomSlug}
						<span>&middot;</span>
						<a
							href={roomHref}
							class="text-accent-muted no-underline hover:underline"
						>
							{thread.room_slug}
						</a>
					{/if}
				</div>
			</div>
		</div>
	</div>
{/snippet}
