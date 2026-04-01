import type { ApiError } from './auth';

export interface Area {
	id: string;
	name: string;
	slug: string;
	description: string;
	created_by: string;
	created_by_name: string;
	created_at: string;
	thread_count: number;
	post_count: number;
	last_activity: string | null;
}

export interface AreaListResponse {
	areas: Area[];
}

export interface CreateAreaRequest {
	name: string;
	description?: string;
}

export async function listAreas(): Promise<Area[]> {
	const res = await fetch('/api/areas');
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	const data: AreaListResponse = await res.json();
	return data.areas;
}

export async function getArea(idOrName: string): Promise<Area> {
	const res = await fetch(`/api/areas/${encodeURIComponent(idOrName)}`);
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export interface AreaSummary {
	slug: string;
	name: string;
}

export async function topAreas(): Promise<AreaSummary[]> {
	const res = await fetch('/api/areas/top');
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	const data: { areas: AreaSummary[] } = await res.json();
	return data.areas;
}

export async function createArea(req: CreateAreaRequest): Promise<Area> {
	const res = await fetch('/api/areas', {
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
