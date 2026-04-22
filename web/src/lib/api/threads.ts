import { throwApiError, type FetchFn } from './auth';
import type { TrustInfo } from './users';

export interface ThreadSummary {
	id: string;
	title: string;
	author_id: string;
	author_name: string;
	room_id: string;
	room_slug: string;
	created_at: string;
	locked: boolean;
	is_announcement: boolean;
	reply_count: number;
	last_activity: string | null;
	trust: TrustInfo;
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
	trust: TrustInfo;
	has_more_children?: boolean;
}

export interface ThreadDetail {
	id: string;
	title: string;
	author_id: string;
	author_name: string;
	room_id: string;
	room_slug: string;
	created_at: string;
	locked: boolean;
	is_announcement: boolean;
	post: PostResponse;
	reply_count: number;
	total_reply_count: number;
	has_more_replies?: boolean;
	focused_post_id?: string;
	/** Number of sort-ordered top-level replies already rendered. Present only
	 * when focused-view pagination appended an extra out-of-order reply; use
	 * this (not `post.children.length`) as the offset for load-more. */
	top_level_loaded?: number;
}

export interface SubtreeResponse {
	post: PostResponse;
}

export interface RepliesPageResponse {
	replies: PostResponse[];
	has_more: boolean;
}

export interface CreateThreadRequest {
	room: string;
	title: string;
	body: string;
}

interface FetchOpts {
	fetch?: FetchFn;
}

export async function listThreads(
	roomIdOrSlug: string,
	cursor?: string,
	sort?: ThreadSort,
	opts: FetchOpts = {}
): Promise<ThreadListResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams();
	if (cursor) params.set('cursor', cursor);
	if (sort) params.set('sort', sort);
	const qs = params.toString();
	const res = await f(
		`/api/rooms/${encodeURIComponent(roomIdOrSlug)}/threads${qs ? `?${qs}` : ''}`
	);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function listAllThreads(
	cursor?: string,
	sort?: ThreadSort,
	opts: FetchOpts = {}
): Promise<ThreadListResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams();
	if (cursor) params.set('cursor', cursor);
	if (sort) params.set('sort', sort);
	const qs = params.toString();
	const res = await f(`/api/threads${qs ? `?${qs}` : ''}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function listPublicThreads(
	cursor?: string,
	opts: FetchOpts = {}
): Promise<ThreadListResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams();
	if (cursor) params.set('cursor', cursor);
	const qs = params.toString();
	const res = await f(`/api/threads/public${qs ? `?${qs}` : ''}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export type ThreadSort = 'warm' | 'new' | 'active' | 'trusted';

export interface WarmPaginationRequest {
	cursor: string;
	seen_ids: string[];
}

/** Load more threads using warm/trusted pagination (POST). */
export async function loadMoreThreads(
	cursor: string,
	seenIds: string[],
	opts: FetchOpts = {}
): Promise<ThreadListResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/threads/more', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ cursor, seen_ids: seenIds })
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}

/** Load more threads in a room using warm/trusted pagination (POST). */
export async function loadMoreRoomThreads(
	roomIdOrSlug: string,
	cursor: string,
	seenIds: string[],
	opts: FetchOpts = {}
): Promise<ThreadListResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/rooms/${encodeURIComponent(roomIdOrSlug)}/threads/more`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ cursor, seen_ids: seenIds })
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}
export type ThreadDetailSort = 'trust' | 'new';

export async function getThread(
	id: string,
	sort?: ThreadDetailSort,
	focusPostId?: string,
	opts: FetchOpts = {}
): Promise<ThreadDetail> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams();
	if (sort && sort !== 'trust') params.set('sort', sort);
	if (focusPostId) params.set('focus', focusPostId);
	const qs = params.toString();
	const res = await f(`/api/threads/${encodeURIComponent(id)}${qs ? `?${qs}` : ''}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function getThreadReplies(
	id: string,
	offset: number,
	sort?: ThreadDetailSort,
	opts: FetchOpts = {}
): Promise<RepliesPageResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams({ offset: String(offset) });
	if (sort && sort !== 'trust') params.set('sort', sort);
	const res = await f(`/api/threads/${encodeURIComponent(id)}/replies?${params.toString()}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function getThreadSubtree(
	threadId: string,
	postId: string,
	sort?: ThreadDetailSort,
	opts: FetchOpts = {}
): Promise<SubtreeResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams();
	if (sort && sort !== 'trust') params.set('sort', sort);
	const qs = params.toString();
	const res = await f(
		`/api/threads/${encodeURIComponent(threadId)}/subtree/${encodeURIComponent(postId)}${qs ? `?${qs}` : ''}`
	);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function editPost(
	postId: string,
	body: string,
	opts: FetchOpts = {}
): Promise<PostResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/posts/${encodeURIComponent(postId)}`, {
		method: 'PATCH',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ body })
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function retractPost(postId: string, opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/posts/${encodeURIComponent(postId)}`, {
		method: 'DELETE'
	});
	if (!res.ok) await throwApiError(res);
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

export async function getPostRevisions(
	postId: string,
	opts: FetchOpts = {}
): Promise<RevisionHistoryResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/posts/${encodeURIComponent(postId)}/revisions`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function replyToThread(
	threadId: string,
	parentId: string,
	body: string,
	opts: FetchOpts = {}
): Promise<PostResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/threads/${encodeURIComponent(threadId)}/posts`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ parent_id: parentId, body })
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function createThread(
	req: CreateThreadRequest,
	opts: FetchOpts = {}
): Promise<ThreadDetail> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/threads', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(req)
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}
