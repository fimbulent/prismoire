import type { ApiError } from './auth';

export interface InviteUser {
	display_name: string;
	created_at: string;
}

export interface Invite {
	id: string;
	code: string;
	max_uses: number | null;
	use_count: number;
	expires_at: string | null;
	revoked: boolean;
	created_at: string;
	users: InviteUser[];
}

export interface InviteListResponse {
	invites: Invite[];
}

export interface InviteValidation {
	valid: boolean;
	inviter_display_name: string | null;
}

export interface CreateInviteRequest {
	max_uses?: number | null;
	expires_in_seconds?: number | null;
}

export async function createInvite(req: CreateInviteRequest): Promise<Invite> {
	const res = await fetch('/api/invites', {
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

export async function listInvites(): Promise<Invite[]> {
	const res = await fetch('/api/invites');
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	const data: InviteListResponse = await res.json();
	return data.invites;
}

export async function validateInvite(code: string): Promise<InviteValidation> {
	const res = await fetch(`/api/invites/${encodeURIComponent(code)}/validate`);
	if (!res.ok) {
		return { valid: false, inviter_display_name: null };
	}
	return res.json();
}

export interface InvitedUser {
	display_name: string;
	created_at: string;
}

export async function listInvitedUsers(): Promise<InvitedUser[]> {
	const res = await fetch('/api/invites/users');
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	const data: { users: InvitedUser[] } = await res.json();
	return data.users;
}

export async function revokeInvite(id: string): Promise<void> {
	const res = await fetch(`/api/invites/${encodeURIComponent(id)}`, {
		method: 'DELETE'
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
}
