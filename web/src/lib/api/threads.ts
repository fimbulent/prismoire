import type { ApiError } from './auth';

export interface ThreadSummary {
	id: string;
	title: string;
	author_id: string;
	author_name: string;
	area_id: string;
	area_name: string;
	area_slug: string;
	created_at: string;
	pinned: boolean;
	locked: boolean;
	reply_count: number;
	last_activity: string | null;
}

export interface ThreadListResponse {
	threads: ThreadSummary[];
	next_cursor: string | null;
}

export interface PostResponse {
	id: string;
	author_id: string;
	author_name: string;
	body: string;
	created_at: string;
	revision: number;
	is_op: boolean;
}

export interface ThreadDetail {
	id: string;
	title: string;
	author_id: string;
	author_name: string;
	area_id: string;
	area_name: string;
	area_slug: string;
	created_at: string;
	pinned: boolean;
	locked: boolean;
	post: PostResponse;
	reply_count: number;
}

export interface CreateThreadRequest {
	title: string;
	body: string;
}

export async function listThreads(
	areaIdOrSlug: string,
	cursor?: string
): Promise<ThreadListResponse> {
	const params = new URLSearchParams();
	if (cursor) params.set('cursor', cursor);
	const qs = params.toString();
	const res = await fetch(
		`/api/areas/${encodeURIComponent(areaIdOrSlug)}/threads${qs ? `?${qs}` : ''}`
	);
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function listAllThreads(cursor?: string): Promise<ThreadListResponse> {
	const params = new URLSearchParams();
	if (cursor) params.set('cursor', cursor);
	const qs = params.toString();
	const res = await fetch(`/api/threads${qs ? `?${qs}` : ''}`);
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function getThread(id: string): Promise<ThreadDetail> {
	const res = await fetch(`/api/threads/${encodeURIComponent(id)}`);
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function createThread(
	areaIdOrSlug: string,
	req: CreateThreadRequest
): Promise<ThreadDetail> {
	const res = await fetch(`/api/areas/${encodeURIComponent(areaIdOrSlug)}/threads`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(req)
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}
