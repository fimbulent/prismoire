import type { ApiError } from './auth';

export interface Room {
	id: string;
	name: string;
	slug: string;
	description: string;
	public: boolean;
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

export interface CreateRoomRequest {
	name: string;
	description?: string;
	public?: boolean;
}

export async function listRooms(): Promise<Room[]> {
	const res = await fetch('/api/rooms');
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	const data: RoomListResponse = await res.json();
	return data.rooms;
}

export async function getRoom(idOrName: string): Promise<Room> {
	const res = await fetch(`/api/rooms/${encodeURIComponent(idOrName)}`);
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export interface RoomSummary {
	slug: string;
	name: string;
	public: boolean;
}

export async function topRooms(): Promise<RoomSummary[]> {
	const res = await fetch('/api/rooms/top');
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	const data: { rooms: RoomSummary[] } = await res.json();
	return data.rooms;
}

export async function createRoom(req: CreateRoomRequest): Promise<Room> {
	const res = await fetch('/api/rooms', {
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
