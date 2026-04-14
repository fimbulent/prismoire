import { throwApiError, type FetchFn } from './auth';

export interface AdminLogEntry {
	id: string;
	admin_id: string;
	admin_name: string;
	action: string;
	thread_id: string | null;
	thread_title: string | null;
	post_id: string | null;
	room_id: string | null;
	room_slug: string | null;
	reason: string | null;
	created_at: string;
}

export interface AdminLogResponse {
	entries: AdminLogEntry[];
	next_cursor: string | null;
}

interface FetchOpts {
	fetch?: FetchFn;
}

export async function getAdminLog(
	cursor?: string,
	opts: FetchOpts = {}
): Promise<AdminLogResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams();
	if (cursor) params.set('cursor', cursor);
	const qs = params.toString();
	const res = await f(`/api/admin/log${qs ? `?${qs}` : ''}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function lockThread(
	threadId: string,
	reason: string,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/admin/threads/${encodeURIComponent(threadId)}/lock`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ reason })
	});
	if (!res.ok) await throwApiError(res);
}

export async function unlockThread(threadId: string, opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/admin/threads/${encodeURIComponent(threadId)}/lock`, {
		method: 'DELETE'
	});
	if (!res.ok) await throwApiError(res);
}

export async function removePost(
	postId: string,
	reason: string,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/admin/posts/${encodeURIComponent(postId)}`, {
		method: 'DELETE',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ reason })
	});
	if (!res.ok) await throwApiError(res);
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

export type ReportReason = 'spam' | 'rules_violation' | 'illegal_content' | 'other';

export interface ReportResponse {
	id: string;
	post_id: string;
	post_body: string;
	post_author_id: string;
	post_author_name: string;
	post_created_at: string;
	thread_id: string;
	thread_title: string;
	room_slug: string;
	reporter_id: string;
	reporter_name: string;
	reason: ReportReason;
	detail: string | null;
	status: string;
	created_at: string;
	resolved_by_name: string | null;
	resolved_at: string | null;
	report_count: number;
}

export interface ReportListResponse {
	reports: ReportResponse[];
	next_cursor: string | null;
}

export interface DashboardResponse {
	pending_reports: number;
}

export async function reportPost(
	postId: string,
	reason: ReportReason,
	detail?: string,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/posts/${encodeURIComponent(postId)}/report`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ reason, detail: detail || null })
	});
	if (!res.ok) await throwApiError(res);
}

export async function getAdminReports(
	status: string = 'pending',
	cursor?: string,
	opts: FetchOpts = {}
): Promise<ReportListResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams();
	params.set('status', status);
	if (cursor) params.set('cursor', cursor);
	const qs = params.toString();
	const res = await f(`/api/admin/reports${qs ? `?${qs}` : ''}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function dismissReport(reportId: string, opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/admin/reports/${encodeURIComponent(reportId)}/dismiss`, {
		method: 'POST'
	});
	if (!res.ok) await throwApiError(res);
}

export async function actionReport(reportId: string, opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/admin/reports/${encodeURIComponent(reportId)}/action`, {
		method: 'POST'
	});
	if (!res.ok) await throwApiError(res);
}

export async function getAdminDashboard(opts: FetchOpts = {}): Promise<DashboardResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/admin/dashboard');
	if (!res.ok) await throwApiError(res);
	return res.json();
}
