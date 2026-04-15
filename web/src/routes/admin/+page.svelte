<script lang="ts">
	import {
		getAdminReports,
		dismissReport,
		actionReport,
		removePost,
		suspendUser,
		banUser,
		adminRevokeInvites,
		type ReportResponse
	} from '$lib/api/admin';
	import { relativeTime } from '$lib/format';
	import { session } from '$lib/stores/session.svelte';
	import UserName from '$lib/components/trust/UserName.svelte';
	import Markdown from '$lib/components/ui/Markdown.svelte';
	import MoreButton from '$lib/components/ui/MoreButton.svelte';
	import Checkbox from '$lib/components/ui/Checkbox.svelte';
	import { errorMessage } from '$lib/i18n/errors';
	import { slide } from 'svelte/transition';

	let { data } = $props();

	let activeTab = $state<'overview' | 'reports'>('reports');
	// svelte-ignore state_referenced_locally
	let reports = $state<ReportResponse[]>(data.reports);
	// svelte-ignore state_referenced_locally
	let nextCursor = $state<string | null>(data.nextCursor);
	// svelte-ignore state_referenced_locally
	let pendingCount = $state(data.pendingReports);
	let statusFilter = $state<'pending' | 'dismissed' | 'actioned'>('pending');

	$effect(() => {
		reports = data.reports;
		nextCursor = data.nextCursor;
		pendingCount = data.pendingReports;
	});

	let loadingMore = $state(false);
	let loadError = $state<string | null>(null);
	let actionErrors = $state<Record<string, string>>({});
	let actionInProgress = $state<Record<string, boolean>>({});

	let removeTargetReportId = $state<string | null>(null);
	let removeReason = $state('');
	let removeError = $state<string | null>(null);
	let removeSaving = $state(false);

	let suspendTargetReportId = $state<string | null>(null);
	let suspendReason = $state('');
	let suspendDuration = $state('1d');
	let suspendRevokeInvites = $state(false);
	let suspendError = $state<string | null>(null);
	let suspendSaving = $state(false);

	let banTargetReportId = $state<string | null>(null);
	let banReason = $state('');
	let banTree = $state(false);
	let banError = $state<string | null>(null);
	let banSaving = $state(false);

	const REASON_LABELS: Record<string, string> = {
		spam: 'Spam',
		rules_violation: 'Rules violation',
		illegal_content: 'Illegal content',
		other: 'Other'
	};

	async function loadMore() {
		if (!nextCursor || loadingMore) return;
		loadingMore = true;
		loadError = null;
		try {
			const res = await getAdminReports(statusFilter, nextCursor);
			reports = [...reports, ...res.reports];
			nextCursor = res.next_cursor;
		} catch (e) {
			loadError = errorMessage(e, 'Failed to load reports');
		} finally {
			loadingMore = false;
		}
	}

	async function changeStatusFilter(status: 'pending' | 'dismissed' | 'actioned') {
		statusFilter = status;
		loadingMore = true;
		loadError = null;
		try {
			const res = await getAdminReports(status);
			reports = res.reports;
			nextCursor = res.next_cursor;
		} catch (e) {
			loadError = errorMessage(e, 'Failed to load reports');
		} finally {
			loadingMore = false;
		}
	}

	async function handleDismiss(report: ReportResponse) {
		actionInProgress = { ...actionInProgress, [report.id]: true };
		delete actionErrors[report.id];
		actionErrors = actionErrors;
		try {
			await dismissReport(report.id);
			reports = reports.filter((r) => r.post_id !== report.post_id);
			pendingCount = Math.max(0, pendingCount - report.report_count);
		} catch (e) {
			actionErrors = { ...actionErrors, [report.id]: errorMessage(e, 'Failed to dismiss') };
		} finally {
			actionInProgress = { ...actionInProgress, [report.id]: false };
		}
	}

	function startRemovePost(report: ReportResponse) {
		removeTargetReportId = report.id;
		const label = REASON_LABELS[report.reason] ?? report.reason;
		removeReason = report.detail ? `${label}: ${report.detail}` : label;
		removeError = null;
	}

	async function confirmRemovePost(report: ReportResponse) {
		const reason = removeReason.trim();
		if (!reason) {
			removeError = 'Reason is required';
			return;
		}
		removeSaving = true;
		removeError = null;
		try {
			await removePost(report.post_id, reason);
			await actionReport(report.id);
			reports = reports.filter((r) => r.post_id !== report.post_id);
			pendingCount = Math.max(0, pendingCount - report.report_count);
			removeTargetReportId = null;
		} catch (e) {
			removeError = errorMessage(e, 'Action failed');
		} finally {
			removeSaving = false;
		}
	}

	function startSuspendUser(report: ReportResponse) {
		suspendTargetReportId = report.id;
		const label = REASON_LABELS[report.reason] ?? report.reason;
		suspendReason = report.detail ? `${label}: ${report.detail}` : label;
		suspendDuration = '1d';
		suspendRevokeInvites = false;
		suspendError = null;
	}

	async function confirmSuspendUser(report: ReportResponse) {
		const reason = suspendReason.trim();
		if (!reason) {
			suspendError = 'Reason is required';
			return;
		}
		suspendSaving = true;
		suspendError = null;
		try {
			await suspendUser(report.post_author_id, reason, suspendDuration);
			if (suspendRevokeInvites) {
				try {
					await adminRevokeInvites(report.post_author_id, reason);
				} catch {
					// Ignore if already revoked
				}
			}
			await actionReport(report.id);
			reports = reports.filter((r) => r.post_id !== report.post_id);
			pendingCount = Math.max(0, pendingCount - report.report_count);
			suspendTargetReportId = null;
		} catch (e) {
			suspendError = errorMessage(e, 'Suspend failed');
		} finally {
			suspendSaving = false;
		}
	}

	function startBanUser(report: ReportResponse) {
		banTargetReportId = report.id;
		const label = REASON_LABELS[report.reason] ?? report.reason;
		banReason = report.detail ? `${label}: ${report.detail}` : label;
		banTree = false;
		banError = null;
	}

	async function confirmBanUser(report: ReportResponse) {
		const reason = banReason.trim();
		if (!reason) {
			banError = 'Reason is required';
			return;
		}
		banSaving = true;
		banError = null;
		try {
			await banUser(report.post_author_id, reason, banTree);
			await actionReport(report.id);
			reports = reports.filter((r) => r.post_id !== report.post_id);
			pendingCount = Math.max(0, pendingCount - report.report_count);
			banTargetReportId = null;
		} catch (e) {
			banError = errorMessage(e, 'Ban failed');
		} finally {
			banSaving = false;
		}
	}
</script>

<svelte:head>
	<title>Admin Dashboard — Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<h1 class="text-xl font-bold mb-4">Admin Dashboard</h1>

	<div class="flex border-b border-border gap-1 overflow-x-auto mb-6">
		<button
			onclick={() => { activeTab = 'overview'; }}
			class="font-sans text-sm px-4 py-2 border-none bg-transparent cursor-pointer border-b-2 transition-colors whitespace-nowrap
				{activeTab === 'overview' ? 'text-accent border-b-accent font-semibold' : 'text-text-muted border-b-transparent hover:text-text-secondary'}"
		>Overview</button>
		<button
			onclick={() => { activeTab = 'reports'; }}
			class="font-sans text-sm px-4 py-2 border-none bg-transparent cursor-pointer border-b-2 transition-colors whitespace-nowrap
				{activeTab === 'reports' ? 'text-accent border-b-accent font-semibold' : 'text-text-muted border-b-transparent hover:text-text-secondary'}"
		>
			Reports
			{#if pendingCount > 0}
				<span class="inline-flex items-center justify-center text-xs font-bold rounded-full px-1.5 py-0.5 ml-1 bg-danger/20 text-danger min-w-5">
					{pendingCount}
				</span>
			{/if}
		</button>
	</div>

	{#if activeTab === 'overview'}
		<div class="text-center text-text-muted py-12">
			<p class="text-sm">Dashboard overview coming soon.</p>
		</div>
	{:else if activeTab === 'reports'}
		<div class="flex items-center justify-between mb-4">
			<div class="text-sm text-text-secondary">
				{#if statusFilter === 'pending'}
					{pendingCount} {pendingCount === 1 ? 'report' : 'reports'} pending review
				{:else}
					{reports.length} {statusFilter} {reports.length === 1 ? 'report' : 'reports'}
				{/if}
			</div>
			<select
				value={statusFilter}
				onchange={(e) => changeStatusFilter((e.currentTarget as HTMLSelectElement).value as 'pending' | 'dismissed' | 'actioned')}
				class="font-sans text-xs bg-bg-surface text-text-secondary border border-border rounded-md px-2 py-1 cursor-pointer hover:border-accent-muted focus:outline-none focus:border-accent-muted"
			>
				<option value="pending">Pending</option>
				<option value="dismissed">Dismissed</option>
				<option value="actioned">Actioned</option>
			</select>
		</div>

		{#if loadError}
			<div class="text-center text-danger py-6">
				<p class="text-sm">{loadError}</p>
			</div>
		{:else if reports.length === 0}
			<div class="text-center text-text-muted py-12">
				<p class="text-sm">No {statusFilter} reports.</p>
			</div>
		{:else}
			{#each reports as report (report.id)}
				<div class="bg-bg-surface border border-border rounded-md p-5 mb-4">
					<div class="flex items-center flex-wrap gap-2 mb-2 text-xs text-text-muted">
						<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded font-semibold text-xs bg-danger/15 text-danger">Reported</span>
						<span>by</span>
						<a href="/user/{report.reporter_name}" class="text-link no-underline hover:underline font-semibold">{report.reporter_name}</a>
						{#if report.report_count > 1}
							<span>and {report.report_count - 1} {report.report_count - 1 === 1 ? 'other' : 'others'}</span>
						{/if}
						<span class="ml-auto">{relativeTime(report.created_at)}</span>
					</div>
					<div class="text-xs text-text-muted mb-3">
						Reason: <span class="text-text-secondary">{REASON_LABELS[report.reason] ?? report.reason}</span>
						{#if report.detail}
							— <span class="text-text-secondary italic">{report.detail}</span>
						{/if}
					</div>

					<div class="bg-bg border border-border-subtle rounded-md p-4 mb-3">
						<div class="flex items-center gap-2 mb-2 text-sm">
							<a href="/user/{report.post_author_name}" class="font-semibold text-text-primary no-underline hover:underline">{report.post_author_name}</a>
							<span class="text-text-muted text-xs">{relativeTime(report.post_created_at)}</span>
							<span class="text-text-muted text-xs ml-auto">
								in <a href="/room/{report.room_slug}" class="text-link no-underline hover:underline">{report.room_slug}</a>
								· <a href="/room/{report.room_slug}/{report.thread_id}?post={report.post_id}" class="text-link no-underline hover:underline">thread</a>
							</span>
						</div>
						<div class="text-sm leading-7 text-text-secondary">
							<Markdown source={report.post_body} profile="reply" />
						</div>
					</div>

					{#if statusFilter === 'pending'}
						{#if removeTargetReportId === report.id}
							<div class="mt-3 bg-bg border border-border rounded-md p-4" transition:slide={{ duration: 150 }}>
								<div class="text-xs font-semibold text-text-secondary mb-2">Remove post — reason (public)</div>
								<input
									type="text"
									bind:value={removeReason}
									placeholder="Why is this post being removed?"
									class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted mb-2"
								/>
								{#if removeError}
									<div class="text-danger text-xs mb-2">{removeError}</div>
								{/if}
								<div class="flex gap-2">
									<button
										onclick={() => confirmRemovePost(report)}
										disabled={removeSaving || !removeReason.trim()}
										class="text-xs px-3 py-1.5 rounded-md border border-danger text-danger hover:bg-bg-hover cursor-pointer font-sans font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
									>{removeSaving ? 'Removing…' : 'Confirm removal'}</button>
									<button
										onclick={() => { removeTargetReportId = null; removeError = null; }}
										disabled={removeSaving}
										class="text-xs px-3 py-1.5 rounded-md border border-border text-text-muted hover:text-text-primary hover:bg-bg-hover cursor-pointer font-sans transition-colors"
									>Cancel</button>
								</div>
							</div>
						{:else if suspendTargetReportId === report.id}
							<div class="mt-3 bg-bg border border-border rounded-md p-4" transition:slide={{ duration: 150 }}>
								<div class="text-xs font-semibold text-text-secondary mb-2">Suspend {report.post_author_name} — reason (public)</div>
								<input
									type="text"
									bind:value={suspendReason}
									placeholder="Reason for suspension"
									class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted mb-2"
								/>
								<div class="flex items-center gap-2 mb-2">
									<span class="text-xs text-text-muted">Duration:</span>
									<select
										bind:value={suspendDuration}
										class="font-sans text-xs bg-bg-surface text-text-secondary border border-border rounded-md px-2 py-1 cursor-pointer hover:border-accent-muted focus:outline-none focus:border-accent-muted"
									>
										<option value="1d">1 day</option>
										<option value="3d">3 days</option>
										<option value="1w">1 week</option>
										<option value="2w">2 weeks</option>
										<option value="1m">1 month</option>
									</select>
								</div>
								<div class="mb-2">
									<Checkbox bind:checked={suspendRevokeInvites}>Also revoke invite privileges</Checkbox>
								</div>
								{#if suspendError}
									<div class="text-danger text-xs mb-2">{suspendError}</div>
								{/if}
								<div class="flex gap-2">
									<button
										onclick={() => confirmSuspendUser(report)}
										disabled={suspendSaving || !suspendReason.trim()}
										class="text-xs px-3 py-1.5 rounded-md border border-danger text-danger hover:bg-bg-hover cursor-pointer font-sans font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
									>{suspendSaving ? 'Suspending…' : 'Confirm suspension'}</button>
									<button
										onclick={() => { suspendTargetReportId = null; suspendError = null; }}
										disabled={suspendSaving}
										class="text-xs px-3 py-1.5 rounded-md border border-border text-text-muted hover:text-text-primary hover:bg-bg-hover cursor-pointer font-sans transition-colors"
									>Cancel</button>
								</div>
							</div>
						{:else if banTargetReportId === report.id}
							<div class="mt-3 bg-bg border border-border rounded-md p-4" transition:slide={{ duration: 150 }}>
								<div class="text-xs font-semibold text-text-secondary mb-2">Ban {report.post_author_name} — reason (public)</div>
								<input
									type="text"
									bind:value={banReason}
									placeholder="Reason for ban"
									class="w-full bg-bg-surface border border-border rounded-md text-text-primary text-sm px-3 py-2 focus:outline-none focus:border-accent-muted placeholder:text-text-muted mb-2"
								/>
								<div class="mb-2">
									<Checkbox bind:checked={banTree}>Also ban all users their downstream invite tree</Checkbox>
								</div>
								{#if banError}
									<div class="text-danger text-xs mb-2">{banError}</div>
								{/if}
								<div class="flex gap-2">
									<button
										onclick={() => confirmBanUser(report)}
										disabled={banSaving || !banReason.trim()}
										class="text-xs px-3 py-1.5 rounded-md border border-danger text-danger hover:bg-bg-hover cursor-pointer font-sans font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
									>{banSaving ? 'Banning…' : 'Confirm ban'}</button>
									<button
										onclick={() => { banTargetReportId = null; banError = null; }}
										disabled={banSaving}
										class="text-xs px-3 py-1.5 rounded-md border border-border text-text-muted hover:text-text-primary hover:bg-bg-hover cursor-pointer font-sans transition-colors"
									>Cancel</button>
								</div>
							</div>
						{:else}
							<div class="flex gap-2 flex-wrap">
								<button
									onclick={() => handleDismiss(report)}
									disabled={actionInProgress[report.id]}
									class="font-sans text-xs px-3 py-1.5 rounded-md cursor-pointer border border-border bg-transparent text-text-secondary font-medium hover:bg-bg-hover hover:text-text-primary disabled:opacity-50 transition-colors"
								>{actionInProgress[report.id] ? 'Dismissing…' : 'Dismiss'}</button>
								<button
									onclick={() => startRemovePost(report)}
									class="font-sans text-xs px-3 py-1.5 rounded-md cursor-pointer border border-danger text-danger font-medium hover:bg-bg-hover bg-danger/8 transition-colors"
								>Remove Post</button>
								<button
									onclick={() => startSuspendUser(report)}
									class="font-sans text-xs px-3 py-1.5 rounded-md cursor-pointer border border-danger text-danger font-medium hover:bg-bg-hover bg-danger/8 transition-colors"
								>Suspend User</button>
								<button
									onclick={() => startBanUser(report)}
									class="font-sans text-xs px-3 py-1.5 rounded-md cursor-pointer border border-danger text-danger font-medium hover:bg-bg-hover bg-danger/15 transition-colors"
								>Ban User</button>
							</div>
						{/if}
						{#if actionErrors[report.id]}
							<div class="text-danger text-xs mt-2">{actionErrors[report.id]}</div>
						{/if}
					{:else}
						<div class="text-xs text-text-muted">
							{report.status === 'dismissed' ? 'Dismissed' : 'Actioned'}
							{#if report.resolved_by_name}
								by <span class="text-text-secondary font-semibold">{report.resolved_by_name}</span>
							{/if}
							{#if report.resolved_at}
								{relativeTime(report.resolved_at)}
							{/if}
						</div>
					{/if}
				</div>
			{/each}

			{#if nextCursor}
				<div class="py-4 text-center">
					<MoreButton onclick={loadMore} loading={loadingMore}>Load more</MoreButton>
				</div>
			{/if}
		{/if}
	{/if}
</div>
