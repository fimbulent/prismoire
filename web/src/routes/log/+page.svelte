<script lang="ts">
	import { getAdminLog, type AdminLogEntry } from '$lib/api/admin';
	import { relativeTime } from '$lib/format';
	import MoreButton from '$lib/components/ui/MoreButton.svelte';
	import { errorMessage } from '$lib/i18n/errors';

	let { data } = $props();

	let appended = $state<AdminLogEntry[]>([]);
	let appendedCursor = $state<string | null>(null);
	let hasLoadedMore = $state(false);
	let loadingMore = $state(false);
	let error = $state<string | null>(null);

	$effect(() => {
		void data;
		appended = [];
		appendedCursor = null;
		hasLoadedMore = false;
		error = null;
	});

	let entries = $derived([...data.entries, ...appended]);
	let nextCursor = $derived(hasLoadedMore ? appendedCursor : data.nextCursor);

	const actionLabels: Record<string, string> = {
		lock_thread: 'locked thread',
		unlock_thread: 'unlocked thread',
		remove_post: 'removed a post in',
		merge_room: 'merged room',
		delete_room: 'deleted room',
		ban_user: 'banned',
		unban_user: 'unbanned',
		suspend_user: 'suspended',
		unsuspend_user: 'unsuspended',
		revoke_invites: 'revoked invites for',
		grant_invites: 'granted invites for'
	};

	async function loadMore() {
		if (!nextCursor || loadingMore) return;
		loadingMore = true;
		try {
			const res = await getAdminLog(nextCursor);
			appended = [...appended, ...res.entries];
			appendedCursor = res.next_cursor;
			hasLoadedMore = true;
		} catch (e) {
			error = errorMessage(e, 'Failed to load more');
		} finally {
			loadingMore = false;
		}
	}

	function actionLabel(action: string): string {
		return actionLabels[action] ?? action;
	}
</script>

<svelte:head>
	<title>Admin Log — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<h1 class="text-lg font-bold mb-4">Admin Log</h1>

	{#if error}
		<div class="text-center text-danger py-12">{error}</div>
	{:else if entries.length === 0}
		<div class="text-center text-text-muted py-12 border border-border-subtle rounded-md bg-bg-surface">
			No admin actions recorded.
		</div>
	{:else}
		<div class="space-y-0">
			{#each entries as entry (entry.id)}
				<div class="px-4 py-3 border-b border-border-subtle">
					<div class="flex items-start gap-2 text-sm">
						<span class="font-semibold text-text-primary">{entry.admin_name}</span>
						<span class="text-text-secondary">{actionLabel(entry.action)}</span>
						{#if entry.target_user_name}
							<a href="/user/{entry.target_user_name}" class="font-semibold text-text-primary hover:underline">{entry.target_user_name}</a>
						{/if}
						{#if entry.thread_title}
							<a
								href={entry.room_slug && entry.thread_id
									? `/room/${entry.room_slug}/${entry.thread_id}`
									: entry.room_slug
										? `/room/${entry.room_slug}`
										: '/room/all'}
								class="text-link hover:text-link-hover font-medium truncate max-w-xs"
								title={entry.thread_title}
							>{entry.thread_title}</a>
						{/if}
						{#if entry.room_slug && entry.action !== 'remove_post'}
							<span class="text-text-secondary">in {entry.room_slug}</span>
						{/if}
					</div>
					{#if entry.reason}
						<div class="mt-1 text-xs text-text-muted italic">
							Reason: {entry.reason}
						</div>
					{/if}
					<div class="text-xs text-text-muted mt-1">
						{relativeTime(entry.created_at)}
					</div>
				</div>
			{/each}
		</div>

		{#if nextCursor}
			<div class="text-center py-6">
				<MoreButton onclick={loadMore} loading={loadingMore}>Load more</MoreButton>
			</div>
		{/if}
	{/if}
</div>
