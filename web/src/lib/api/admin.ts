import type { ApiError } from './auth';

export interface AdminLogEntry {
	id: string;
	admin_id: string;
	admin_name: string;
	action: string;
	thread_id: string | null;
	thread_title: string | null;
	post_id: string | null;
	room_id: string | null;
	room_name: string | null;
	reason: string | null;
	created_at: string;
}

export interface AdminLogResponse {
	entries: AdminLogEntry[];
	next_cursor: string | null;
}

export async function getAdminLog(cursor?: string): Promise<AdminLogResponse> {
	const params = new URLSearchParams();
	if (cursor) params.set('cursor', cursor);
	const qs = params.toString();
	const res = await fetch(`/api/admin/log${qs ? `?${qs}` : ''}`);
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function lockThread(threadId: string, reason: string): Promise<void> {
	const res = await fetch(`/api/admin/threads/${encodeURIComponent(threadId)}/lock`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ reason })
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
}

export async function unlockThread(threadId: string): Promise<void> {
	const res = await fetch(`/api/admin/threads/${encodeURIComponent(threadId)}/lock`, {
		method: 'DELETE'
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
}

export async function removePost(postId: string, reason: string): Promise<void> {
	const res = await fetch(`/api/admin/posts/${encodeURIComponent(postId)}`, {
		method: 'DELETE',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ reason })
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
}

