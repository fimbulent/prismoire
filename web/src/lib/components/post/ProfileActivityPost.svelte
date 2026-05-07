<!--
	One row in the user-profile recent-activity feed.

	Two-column layout on md+ screens:
	- Left rail: a "Started thread in {room}" / "Replied in {thread}"
	  context line plus the relative timestamp.
	- Right column: for thread-started rows, the thread title as a link
	  above the body; for reply rows, just the body.

	When the viewer's trust in the profile owner is low enough that the
	profile page is rendered in restricted mode (`viewerRestricted`),
	links to the room and thread are replaced with plain spans so the
	row still reads coherently without offering navigation into content
	the viewer can't see anyway.
-->
<script lang="ts">
	import Markdown from '$lib/components/ui/Markdown.svelte';
	import { relativeTime } from '$lib/format';
	import { smartypants } from '$lib/typography';
	import type { ActivityItem } from '$lib/api/users';

	interface Props {
		item: ActivityItem;
		/**
		 * When true, suppresses links to the room and thread. The
		 * profile owner has restricted the viewer's reach, so the body
		 * is shown without click targets that would 404 or 403.
		 */
		viewerRestricted?: boolean;
	}

	let { item, viewerRestricted = false }: Props = $props();
</script>

<div class="bg-bg-surface border border-border rounded-md p-4 md:flex md:gap-6">
	<div
		class="flex items-center gap-2 text-xs text-text-muted mb-1 md:mb-0 md:flex-col md:items-start md:gap-1 md:w-40 md:shrink-0"
	>
		{#if item.type === 'thread_started'}
			<span>Started thread in</span>
			{#if viewerRestricted}
				<span class="text-text-secondary">{item.room_slug}</span>
			{:else}
				<a href="/r/{item.room_slug}" class="text-link hover:underline">{item.room_slug}</a>
			{/if}
		{:else}
			<span>Replied in</span>
			{#if viewerRestricted}
				<span class="text-text-secondary">{smartypants(item.thread_title)}</span>
			{:else}
				<a
					href="/r/{item.room_slug}/{item.thread_id}?post={item.post_id}"
					class="text-link hover:underline"
				>
					{smartypants(item.thread_title)}
				</a>
			{/if}
		{/if}
		<span class="ml-auto md:ml-0">{relativeTime(item.created_at)}</span>
	</div>
	<div class="md:max-w-measure md:flex-1 md:min-w-0">
		{#if item.type === 'thread_started'}
			{#if viewerRestricted}
				<span class="font-prose text-prose text-text-primary font-medium leading-snug">
					{smartypants(item.thread_title)}
				</span>
			{:else}
				<a
					href="/r/{item.room_slug}/{item.thread_id}"
					class="font-prose text-prose text-text-primary hover:underline font-medium leading-snug"
				>
					{smartypants(item.thread_title)}
				</a>
			{/if}
		{/if}
		<div class="text-prose leading-7 text-text-secondary mt-1">
			<Markdown source={item.body} profile={item.type === 'thread_started' ? 'full' : 'reply'} />
		</div>
	</div>
</div>
