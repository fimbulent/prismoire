import { throwApiError, type FetchFn } from './auth';

export interface AdminLogEntry {
	id: string;
	admin_id: string;
	admin_name: string;
	action: string;
	target_user_id: string | null;
	target_user_name: string | null;
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

export interface BanResponse {
	banned_users: { id: string; display_name: string }[];
	snapshot_edges: number;
}

export async function suspendUser(
	userId: string,
	reason: string,
	duration: string,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/admin/users/${encodeURIComponent(userId)}/suspend`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ reason, duration })
	});
	if (!res.ok) await throwApiError(res);
}

export async function banUser(
	userId: string,
	reason: string,
	banTree: boolean = false,
	opts: FetchOpts = {}
): Promise<BanResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/admin/users/${encodeURIComponent(userId)}/ban`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ reason, ban_tree: banTree })
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function adminRevokeInvites(
	userId: string,
	reason: string,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/admin/users/${encodeURIComponent(userId)}/invites`, {
		method: 'DELETE',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ reason })
	});
	if (!res.ok) await throwApiError(res);
}

export async function adminGrantInvites(
	userId: string,
	reason: string,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/admin/users/${encodeURIComponent(userId)}/invites`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ reason })
	});
	if (!res.ok) await throwApiError(res);
}

export async function unbanUser(
	userId: string,
	reason: string,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/admin/users/${encodeURIComponent(userId)}/ban`, {
		method: 'DELETE',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ reason })
	});
	if (!res.ok) await throwApiError(res);
}

export async function unsuspendUser(
	userId: string,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/admin/users/${encodeURIComponent(userId)}/suspend`, {
		method: 'DELETE'
	});
	if (!res.ok) await throwApiError(res);
}

export async function getAdminDashboard(opts: FetchOpts = {}): Promise<DashboardResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/admin/dashboard');
	if (!res.ok) await throwApiError(res);
	return res.json();
}

// ---------------------------------------------------------------------------
// Admin overview
// ---------------------------------------------------------------------------

export interface DayCount {
	date: string;
	count: number;
}

export interface WeekCount {
	week_start: string;
	count: number;
}

export interface TrustGraphStats {
	trust_edges: number;
	distrust_edges: number;
	avg_trusts_per_user: number;
	avg_distrusts_per_user: number;
	last_rebuild_at: string | null;
	bfs_cache_hit_rate: number | null;
	bfs_total_lookups: number;
	graph_load_ms_p50: number | null;
	graph_load_ms_p95: number | null;
	graph_load_ms_p99: number | null;
}

export interface SessionStats {
	active_sessions: number;
	logins_today: number;
	failed_auth_24h: number;
}

export interface AdminOverviewResponse {
	total_users: number;
	new_users_7d: number;
	active_users_7d: number;
	active_users_prev_7d: number;
	posts_today: number;
	posts_7d: number;
	threads_today: number;
	threads_7d: number;
	total_rooms: number;
	empty_rooms: number;
	pending_reports: number;
	oldest_pending_report_at: string | null;
	trust: TrustGraphStats;
	sessions: SessionStats;
	posts_per_day: DayCount[];
	new_users_per_week: WeekCount[];
}

export async function getAdminOverview(opts: FetchOpts = {}): Promise<AdminOverviewResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/admin/overview');
	if (!res.ok) await throwApiError(res);
	return res.json();
}

// ---------------------------------------------------------------------------
// Per-route request stats
// ---------------------------------------------------------------------------

export interface RouteStatsResponse {
	method: string;
	path: string;
	total_24h: number;
	success_24h: number;
	client_error_24h: number;
	server_error_24h: number;
	latency_ms_p50_24h: number | null;
	latency_ms_p95_24h: number | null;
	latency_ms_p99_24h: number | null;
	total_all: number;
	success_all: number;
	client_error_all: number;
	server_error_all: number;
}

export interface RouteListResponse {
	routes: RouteStatsResponse[];
}

export async function getAdminRoutes(opts: FetchOpts = {}): Promise<RouteListResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/admin/routes');
	if (!res.ok) await throwApiError(res);
	return res.json();
}

// ---------------------------------------------------------------------------
// Watchlists
// ---------------------------------------------------------------------------

export interface UserChip {
	id: string;
	display_name: string;
	status: 'active' | 'suspended' | 'banned';
}

export interface DistrustedUserRow {
	user: UserChip;
	inbound_distrusts: number;
	inbound_trusts: number;
	ratio: number | null;
}

export interface RatioRow {
	user: UserChip;
	inbound_distrusts: number;
	inbound_trusts: number;
	ratio: number | null;
	post_count: number;
	joined_at: string;
}

export interface BanAdjacentRow {
	user: UserChip;
	banned_trusts: number;
	total_trusts: number;
	hit_rate: number | null;
}

export interface WatchlistThresholds {
	min_inbound_distrusts: number;
	min_inbound_edges_for_ratio: number;
	min_trusts_issued_for_ban_adjacent: number;
	limit_per_list: number;
}

export interface WatchlistsResponse {
	thresholds: WatchlistThresholds;
	most_distrusted: DistrustedUserRow[];
	distrust_trust_ratio: RatioRow[];
	ban_adjacent_trusters: BanAdjacentRow[];
}

export async function getAdminWatchlists(opts: FetchOpts = {}): Promise<WatchlistsResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/admin/watchlists');
	if (!res.ok) await throwApiError(res);
	return res.json();
}
