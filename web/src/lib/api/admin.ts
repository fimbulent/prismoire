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
