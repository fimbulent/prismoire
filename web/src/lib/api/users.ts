import type { ApiError } from './auth';

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
	you_trust: boolean;
	you_distrust: boolean;
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

export async function getUserProfile(username: string): Promise<UserProfile> {
	const res = await fetch(`/api/users/${encodeURIComponent(username)}`);
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function getTrustDetail(username: string): Promise<TrustDetailResponse> {
	const res = await fetch(`/api/users/${encodeURIComponent(username)}/trust`);
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function getActivity(
	username: string,
	filter: string = 'all',
	cursor?: string
): Promise<ActivityResponse> {
	const params = new URLSearchParams({ filter });
	if (cursor) params.set('cursor', cursor);
	const res = await fetch(
		`/api/users/${encodeURIComponent(username)}/activity?${params.toString()}`
	);
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function getTrustEdges(
	username: string,
	direction: 'trusts' | 'trusted_by'
): Promise<TrustEdgesResponse> {
	const params = new URLSearchParams({ direction });
	const res = await fetch(
		`/api/users/${encodeURIComponent(username)}/trust/edges?${params.toString()}`
	);
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function updateBio(username: string, bio: string | null): Promise<void> {
	const res = await fetch(`/api/users/${encodeURIComponent(username)}`, {
		method: 'PATCH',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ bio })
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
}

export async function trustUser(username: string): Promise<void> {
	const res = await fetch(`/api/users/${encodeURIComponent(username)}/trust`, {
		method: 'POST'
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
}

export async function revokeTrust(username: string): Promise<void> {
	const res = await fetch(`/api/users/${encodeURIComponent(username)}/trust`, {
		method: 'DELETE'
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
}

export async function distrustUser(username: string): Promise<void> {
	const res = await fetch(`/api/users/${encodeURIComponent(username)}/distrust`, {
		method: 'POST'
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
}

export async function revokeDistrust(username: string): Promise<void> {
	const res = await fetch(`/api/users/${encodeURIComponent(username)}/distrust`, {
		method: 'DELETE'
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
}
