import type { ApiError } from './auth';

export interface ThreadSummary {
	id: string;
	title: string;
	author_id: string;
	author_name: string;
	room_id: string;
	room_name: string;
	room_slug: string;
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
	parent_id: string | null;
	author_id: string;
	author_name: string;
	body: string;
	created_at: string;
	edited_at: string | null;
	revision: number;
	is_op: boolean;
	retracted_at: string | null;
	children: PostResponse[];
}

export interface ThreadDetail {
	id: string;
	title: string;
	author_id: string;
	author_name: string;
	room_id: string;
	room_name: string;
	room_slug: string;
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
	roomIdOrSlug: string,
	cursor?: string
): Promise<ThreadListResponse> {
	const params = new URLSearchParams();
	if (cursor) params.set('cursor', cursor);
	const qs = params.toString();
	const res = await fetch(
		`/api/rooms/${encodeURIComponent(roomIdOrSlug)}/threads${qs ? `?${qs}` : ''}`
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

export async function editPost(postId: string, body: string): Promise<PostResponse> {
	const res = await fetch(`/api/posts/${encodeURIComponent(postId)}`, {
		method: 'PATCH',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ body })
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function retractPost(postId: string): Promise<void> {
	const res = await fetch(`/api/posts/${encodeURIComponent(postId)}`, {
		method: 'DELETE'
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
}

export interface RevisionResponse {
	revision: number;
	body: string;
	created_at: string;
}

export interface RevisionHistoryResponse {
	post_id: string;
	author_id: string;
	author_name: string;
	retracted_at: string | null;
	revisions: RevisionResponse[];
}

export async function getPostRevisions(postId: string): Promise<RevisionHistoryResponse> {
	const res = await fetch(`/api/posts/${encodeURIComponent(postId)}/revisions`);
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function replyToThread(
	threadId: string,
	parentId: string,
	body: string
): Promise<PostResponse> {
	const res = await fetch(`/api/threads/${encodeURIComponent(threadId)}/posts`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ parent_id: parentId, body })
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function createThread(
	roomIdOrSlug: string,
	req: CreateThreadRequest
): Promise<ThreadDetail> {
	const res = await fetch(`/api/rooms/${encodeURIComponent(roomIdOrSlug)}/threads`, {
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
