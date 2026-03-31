import type { ApiError } from './auth';

export interface Topic {
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

export interface TopicListResponse {
	topics: Topic[];
}

export interface CreateTopicRequest {
	name: string;
	description?: string;
}

export async function listTopics(): Promise<Topic[]> {
	const res = await fetch('/api/topics');
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	const data: TopicListResponse = await res.json();
	return data.topics;
}

export async function getTopic(idOrName: string): Promise<Topic> {
	const res = await fetch(`/api/topics/${encodeURIComponent(idOrName)}`);
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function createTopic(req: CreateTopicRequest): Promise<Topic> {
	const res = await fetch('/api/topics', {
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
