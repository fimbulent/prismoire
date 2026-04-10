import { throwApiError, type FetchFn } from './auth';

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

interface FetchOpts {
	fetch?: FetchFn;
}

export async function createInvite(
	req: CreateInviteRequest,
	opts: FetchOpts = {}
): Promise<Invite> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/invites', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(req)
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function listInvites(opts: FetchOpts = {}): Promise<Invite[]> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/invites');
	if (!res.ok) await throwApiError(res);
	const data: InviteListResponse = await res.json();
	return data.invites;
}

export async function validateInvite(
	code: string,
	opts: FetchOpts = {}
): Promise<InviteValidation> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/invites/${encodeURIComponent(code)}/validate`);
	if (!res.ok) {
		return { valid: false, inviter_display_name: null };
	}
	return res.json();
}

export interface InvitedUser {
	display_name: string;
	created_at: string;
}

export async function listInvitedUsers(opts: FetchOpts = {}): Promise<InvitedUser[]> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/invites/users');
	if (!res.ok) await throwApiError(res);
	const data: { users: InvitedUser[] } = await res.json();
	return data.users;
}

export async function revokeInvite(id: string, opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/invites/${encodeURIComponent(id)}`, {
		method: 'DELETE'
	});
	if (!res.ok) await throwApiError(res);
}
