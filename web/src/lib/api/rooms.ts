import { throwApiError, type FetchFn } from './auth';

export interface Room {
	id: string;
	slug: string;
	is_announcement: boolean;
	created_by: string;
	created_by_name: string;
	created_at: string;
	thread_count: number;
	post_count: number;
	last_activity: string | null;
}

export interface RoomListResponse {
	rooms: Room[];
}

interface FetchOpts {
	fetch?: FetchFn;
}

export async function listRooms(opts: FetchOpts = {}): Promise<Room[]> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/rooms');
	if (!res.ok) await throwApiError(res);
	const data: RoomListResponse = await res.json();
	return data.rooms;
}

export async function getRoom(idOrSlug: string, opts: FetchOpts = {}): Promise<Room> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/rooms/${encodeURIComponent(idOrSlug)}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export interface RoomSummary {
	slug: string;
	is_announcement: boolean;
}

export async function topRooms(opts: FetchOpts = {}): Promise<RoomSummary[]> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/rooms/top');
	if (!res.ok) await throwApiError(res);
	const data: { rooms: RoomSummary[] } = await res.json();
	return data.rooms;
}

/**
 * Lightweight room row returned by the autocomplete search endpoint.
 * Carries slug + thread/post counts so the dropdown can show "slug
 * (N threads, M posts)" without needing the heavier {@link Room} shape.
 */
export interface RoomChip {
	id: string;
	slug: string;
	is_announcement: boolean;
	thread_count: number;
	post_count: number;
}

/**
 * Prefix-search active rooms for an autocomplete dropdown.
 *
 * An empty `query` returns the most-recently-active rooms so the
 * dropdown is non-empty as soon as the user focuses the field.
 */
export async function searchRooms(
	query: string,
	limit = 10,
	opts: FetchOpts = {}
): Promise<RoomChip[]> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams();
	if (query) params.set('q', query);
	params.set('limit', String(limit));
	const res = await f(`/api/rooms/search?${params.toString()}`);
	if (!res.ok) await throwApiError(res);
	const data: { rooms: RoomChip[] } = await res.json();
	return data.rooms;
}
