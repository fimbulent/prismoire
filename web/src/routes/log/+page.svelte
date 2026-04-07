<script lang="ts">
	import { getAdminLog, type AdminLogEntry } from '$lib/api/admin';
	import { relativeTime } from '$lib/format';
	import { session } from '$lib/stores/session.svelte';
	import { goto } from '$app/navigation';
	import MoreButton from '$lib/components/ui/MoreButton.svelte';

	let entries = $state<AdminLogEntry[]>([]);
	let nextCursor = $state<string | null>(null);
	let loading = $state(true);
	let loadingMore = $state(false);
	let error = $state<string | null>(null);

	const actionLabels: Record<string, string> = {
		lock_thread: 'Locked thread',
		unlock_thread: 'Unlocked thread',
		remove_post: 'Removed post',
		merge_room: 'Merged room',
		delete_room: 'Deleted room'
	};

	$effect(() => {
		if (session.loading) return;
		if (!session.isLoggedIn) {
			goto('/login');
			return;
		}
		load();
	});

	async function load() {
		loading = true;
		error = null;
		try {
			const res = await getAdminLog();
			entries = res.entries;
			nextCursor = res.next_cursor;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load admin log';
		} finally {
			loading = false;
		}
	}

	async function loadMore() {
		if (!nextCursor || loadingMore) return;
		loadingMore = true;
		try {
			const res = await getAdminLog(nextCursor);
			entries = [...entries, ...res.entries];
			nextCursor = res.next_cursor;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load more';
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

	{#if loading}
		<div class="text-center text-text-muted py-12">Loading…</div>
	{:else if error}
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
						{#if entry.thread_title}
							<a
								href="/room/all"
								class="text-link hover:text-link-hover font-medium truncate max-w-xs"
								title={entry.thread_title}
							>{entry.thread_title}</a>
						{/if}
						{#if entry.room_name}
							<span class="text-text-secondary">in {entry.room_name}</span>
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
