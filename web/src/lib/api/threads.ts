import { throwApiError, type FetchFn } from './auth';
import type { UserViewerInfo } from './users';

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
	viewer: UserViewerInfo;
	/** External URL for "link posts". `null` means a regular text post. */
	link_url: string | null;
}

export interface ThreadListResponse {
	threads: ThreadSummary[];
	next_cursor: string | null;
}

/**
 * Per-revision attachment binding surfaced on an OP `PostResponse`
 * (`docs/attachments.md` §4 / §9). The server projects the post's
 * latest-revision attachment array into this shape so the frontend
 * has filename, MIME, size, and stable position without a second
 * round trip.
 */
export interface AttachmentResponse {
	/** Lower-case hex SHA-256 of the blob, used to build the
	 * `/api/attachments/{hash}` URL. */
	content_hash: string;
	/** Sanitized display filename (download UI label + Content-Disposition). */
	filename: string;
	/** Canonical MIME from the upload classifier. Whether the
	 * attachment renders inline or as a chip is now decided by the
	 * post body's `![](filename)` references — only image MIMEs are
	 * eligible (`docs/attachments.md` §3). */
	mime: string;
	/** Stored size in bytes (post-re-encode for images). */
	size: number;
	/** 0..N-1 stable display order within the array. */
	position: number;
}

/**
 * Request-side wire shape for binding an already-uploaded blob to a
 * post revision. `content_hash` is the lowercase hex returned by
 * `POST /api/attachments`; `filename` must already be canonical per
 * server-side FILENAME_RULES. Inline-vs-download intent is not part of
 * the bind wire shape — the server derives it from `![](filename)`
 * references in the post body.
 */
export interface AttachmentBindRef {
	content_hash: string;
	filename: string;
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
	viewer: UserViewerInfo;
	has_more_children?: boolean;
	/** True when the post's author is in the viewer's distrust set but the
	 * post is shown anyway because the viewer has a descendant reply in this
	 * subtree. Render a small hint next to the author explaining why a
	 * distrusted user's post is visible. */
	distrust_scaffold?: boolean;
	/** Per-revision attachments for OP posts. Omitted by the server when
	 * empty; treat `undefined` as the empty array. Replies never carry
	 * attachments. */
	attachments?: AttachmentResponse[];
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
	/** External URL for "link posts". `null` means a regular text post. */
	link_url: string | null;
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
	/** Optional for link posts; required for text posts. */
	body: string;
	/** When set, this is a link post. Must be http(s) and ≤ 2048 chars. */
	link?: string;
	/** Attachment bindings (0..3). Empty / omitted = no attachments. */
	attachments?: AttachmentBindRef[];
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
	attachments: AttachmentBindRef[] = [],
	opts: FetchOpts = {}
): Promise<PostResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/posts/${encodeURIComponent(postId)}`, {
		method: 'PATCH',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ body, attachments })
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

/**
 * Per-revision attachment entry returned by `GET /api/posts/:id/revisions`.
 *
 * Decoded from the revision's signed CBOR payload, so this is the
 * authoritative record of what the author bound to that specific
 * revision — independent of the live `post_attachments` projection,
 * which §6.1 set-diff prunes across all revisions when an attachment
 * is removed in a later edit. The `available` flag distinguishes
 * "still bound and servable" from "removed later or blob missing":
 *
 *  - `available: true`  — render normally (img / download chip).
 *  - `available: false` — render a `[attachment removed]` placeholder;
 *                         the `/api/attachments/{hash}` URL would 404.
 */
export interface RevisionAttachmentEntry {
	content_hash: string;
	filename: string;
	mime: string;
	size: number;
	position: number;
	available: boolean;
}

export interface RevisionResponse {
	revision: number;
	body: string;
	created_at: string;
	/** Attachments signed into this revision, with availability flag.
	 * Empty when the revision has been retracted (payload erased) or
	 * when the post is a reply (replies cannot carry attachments). */
	attachments: RevisionAttachmentEntry[];
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

export interface ByLinkResponse {
	threads: ThreadSummary[];
}

/**
 * Look up existing threads that share a normalized form of the given URL,
 * for the "is this a dupe?" suggestion panel on the new-thread page.
 *
 * The server normalizes both the input URL and the indexed
 * `link_url_normalized` column via the same function, so scheme (http/https)
 * and a leading `www.` collapse; deeper differences (path, query, fragment)
 * do not. Results are visibility-filtered against the caller's trust state,
 * so a thread the caller couldn't read elsewhere will not surface here.
 *
 * Empty / malformed / over-long URLs return an empty list rather than an
 * error — the panel is a hint, not a validator.
 */
export async function getThreadsByLink(
	url: string,
	opts: FetchOpts & { signal?: AbortSignal } = {}
): Promise<ByLinkResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams({ url });
	const res = await f(`/api/threads/by-link?${params.toString()}`, { signal: opts.signal });
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
