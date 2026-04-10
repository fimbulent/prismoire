import { throwApiError, type FetchFn } from './auth';

export interface TrustInfo {
	distance: number | null;
	distrusted: boolean;
}

export interface UserProfile {
	display_name: string;
	created_at: string;
	signup_method: string;
	bio: string | null;
	role: string;
	is_self: boolean;
	trust_stance: 'trust' | 'distrust' | 'neutral';
	trust: TrustInfo;
	trust_score: number | null;
}

export interface TrustUserRef {
	display_name: string;
	trust: TrustInfo;
}

export interface TrustPathResponse {
	type: string;
	via: TrustUserRef | null;
	via2: TrustUserRef | null;
}

export interface ScoreReduction {
	display_name: string;
	reason: string;
}

export interface TrustEdgeUser {
	display_name: string;
	trust: TrustInfo;
}

export interface TrustDetailResponse {
	trusts_given: number;
	trusts_received: number;
	distrusts_issued: number;
	reads: number;
	readers: number;
	trust_score: number | null;
	trust: TrustInfo;
	paths: TrustPathResponse[];
	score_reductions: ScoreReduction[];
	trusts: TrustEdgeUser[];
	trusts_total: number;
	trusted_by: TrustEdgeUser[];
	trusted_by_total: number;
}

export interface TrustEdgesResponse {
	users: TrustEdgeUser[];
	total: number;
	capped: boolean;
}

export interface ActivityItem {
	type: string;
	post_id: string;
	thread_id: string;
	thread_title: string;
	room_name: string;
	room_slug: string;
	body: string;
	created_at: string;
}

export interface ActivityResponse {
	items: ActivityItem[];
	next_cursor: string | null;
}

interface FetchOpts {
	fetch?: FetchFn;
}

export async function getUserProfile(
	username: string,
	opts: FetchOpts = {}
): Promise<UserProfile> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function getTrustDetail(
	username: string,
	opts: FetchOpts = {}
): Promise<TrustDetailResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}/trust`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function getActivity(
	username: string,
	filter: string = 'all',
	cursor?: string,
	opts: FetchOpts = {}
): Promise<ActivityResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams({ filter });
	if (cursor) params.set('cursor', cursor);
	const res = await f(
		`/api/users/${encodeURIComponent(username)}/activity?${params.toString()}`
	);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function getTrustEdges(
	username: string,
	direction: 'trusts' | 'trusted_by',
	opts: FetchOpts = {}
): Promise<TrustEdgesResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams({ direction });
	const res = await f(
		`/api/users/${encodeURIComponent(username)}/trust/edges?${params.toString()}`
	);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function updateBio(
	username: string,
	bio: string | null,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}`, {
		method: 'PATCH',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ bio })
	});
	if (!res.ok) await throwApiError(res);
}

export async function setTrustEdge(
	username: string,
	edgeType: 'trust' | 'distrust',
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}/trust-edge`, {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ type: edgeType })
	});
	if (!res.ok) await throwApiError(res);
}

export async function deleteTrustEdge(
	username: string,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}/trust-edge`, {
		method: 'DELETE'
	});
	if (!res.ok) await throwApiError(res);
}
