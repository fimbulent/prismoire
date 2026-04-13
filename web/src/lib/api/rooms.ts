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
