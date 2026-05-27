import { throwApiError, type FetchFn } from './auth';
import type { AttachmentResponse } from './threads';

/**
 * Per-viewer envelope serialized on the wire as the `"viewer"` field
 * nested inside whatever response references a user (post author,
 * thread OP, trust edge target, etc.). Carries every per-viewer fact
 * about that user — trust distance, distrust flag, account status,
 * and the viewer's optional private tag.
 *
 * `tag` is the viewer's private label for this user (max 35 grapheme
 * clusters). It is set/cleared via {@link setUserTag} / {@link clearUserTag}
 * and is never visible to the tagged user. Absent when the viewer has
 * not tagged this user, suppressed for deleted users, and never present
 * for the viewer themselves.
 */
export interface UserViewerInfo {
	distance: number | null;
	distrusted: boolean;
	status?: 'banned' | 'suspended' | 'deleted';
	tag?: string | null;
}

export interface UserProfile {
	id: string;
	display_name: string;
	created_at: string;
	signup_method: string;
	bio: string | null;
	role: string;
	is_self: boolean;
	can_invite: boolean;
	trust_stance: 'trust' | 'distrust' | 'neutral';
	viewer: UserViewerInfo;
	trust_score: number | null;
}

export interface TrustUserRef {
	display_name: string;
	viewer: UserViewerInfo;
}

export interface TrustPathResponse {
	type: string;
	via: TrustUserRef | null;
	via2: TrustUserRef | null;
}

export interface ScoreReduction {
	display_name: string;
	reason: string;
}

export interface TrustEdgeUser {
	display_name: string;
	viewer: UserViewerInfo;
}

export interface TrustDetailResponse {
	trusts_given: number;
	trusts_received: number;
	distrusts_issued: number;
	reads: number;
	readers: number;
	trust_score: number | null;
	viewer: UserViewerInfo;
	paths: TrustPathResponse[];
	score_reductions: ScoreReduction[];
	trusts: TrustEdgeUser[];
	trusts_total: number;
	trusted_by: TrustEdgeUser[];
	trusted_by_total: number;
}

export interface TrustEdgesResponse {
	users: TrustEdgeUser[];
	total: number;
	capped: boolean;
}

export interface ActivityItem {
	type: string;
	post_id: string;
	thread_id: string;
	thread_title: string;
	room_slug: string;
	body: string;
	created_at: string;
	/** Attachments bound to the post's latest revision. Omitted by the
	 * server when empty; treat `undefined` as the empty array. Only
	 * thread-OP rows can carry attachments — reply rows always omit. */
	attachments?: AttachmentResponse[];
}

export interface ActivityResponse {
	items: ActivityItem[];
	next_cursor: string | null;
	/** True when the viewer is an admin who only sees these posts via the
	 * admin carve-out (the target's trust in them doesn't meet threshold).
	 * The profile page shows a notice to make this visible. */
	admin_override: boolean;
}

interface FetchOpts {
	fetch?: FetchFn;
}

export async function getUserProfile(
	username: string,
	opts: FetchOpts = {}
): Promise<UserProfile> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

/**
 * Lightweight user row returned by the autocomplete search endpoint.
 * Intentionally stripped down compared to {@link UserProfile} — just
 * enough to render a dropdown row and drive a preview card. Callers
 * that need the full profile should fetch {@link getUserProfile} after
 * the row is selected.
 */
export interface UserChip {
	id: string;
	display_name: string;
	status: 'active' | 'banned' | 'suspended' | 'deleted';
	role: string;
}

/**
 * Prefix-search active users by display name for an autocomplete
 * dropdown. Matching uses the confusable-safe skeleton on the server so
 * case + homoglyph variants collapse into the same result set.
 *
 * An empty `query` returns an empty array — the server treats this as
 * "no search requested" rather than "list all users", since unbounded
 * user listings are not exposed.
 */
export async function searchUsers(
	query: string,
	limit = 10,
	opts: FetchOpts = {}
): Promise<UserChip[]> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams();
	if (query) params.set('q', query);
	params.set('limit', String(limit));
	const res = await f(`/api/users/search?${params.toString()}`);
	if (!res.ok) await throwApiError(res);
	const data: { users: UserChip[] } = await res.json();
	return data.users;
}

/**
 * One match in a `/api/users/{name}/resolve` response. The
 * `public_key_hex` is the full lowercase hex of the user's
 * 32-byte public key; the first 8 chars form the canonical
 * `@username.{pubkey-prefix}` suffix.
 */
export interface ResolveMatch {
	id: string;
	display_name: string;
	public_key_hex: string;
	/** `null` when the user is homed locally; otherwise lowercase-hex
	 *  of the home-instance pubkey for an instance-hint badge. */
	home_instance_hex: string | null;
	status: 'active' | 'banned' | 'suspended' | 'deleted';
}

export type ResolveResponse =
	| { kind: 'unique'; user: ResolveMatch }
	| { kind: 'ambiguous'; matches: ResolveMatch[] };

/**
 * Resolve `/@username` and `/@username.{8hex}` URL shapes to either a
 * single user (`unique`) or a candidate list (`ambiguous`). 404 when
 * no user matches. See `docs/federation-impl-plan.md` Phase 9.5
 * username routing.
 */
export async function resolveUsername(
	username: string,
	opts: FetchOpts = {}
): Promise<ResolveResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}/resolve`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function getTrustDetail(
	username: string,
	opts: FetchOpts = {}
): Promise<TrustDetailResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}/trust`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function getActivity(
	username: string,
	filter: string = 'all',
	cursor?: string,
	opts: FetchOpts = {}
): Promise<ActivityResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams({ filter });
	if (cursor) params.set('cursor', cursor);
	const res = await f(
		`/api/users/${encodeURIComponent(username)}/activity?${params.toString()}`
	);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function getTrustEdges(
	username: string,
	direction: 'trusts' | 'trusted_by',
	opts: FetchOpts = {}
): Promise<TrustEdgesResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams({ direction });
	const res = await f(
		`/api/users/${encodeURIComponent(username)}/trust/edges?${params.toString()}`
	);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function updateBio(
	username: string,
	bio: string | null,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}`, {
		method: 'PATCH',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ bio })
	});
	if (!res.ok) await throwApiError(res);
}

export async function setTrustEdge(
	username: string,
	edgeType: 'trust' | 'distrust',
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}/trust-edge`, {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ type: edgeType })
	});
	if (!res.ok) await throwApiError(res);
}

export async function deleteTrustEdge(
	username: string,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}/trust-edge`, {
		method: 'DELETE'
	});
	if (!res.ok) await throwApiError(res);
}

/**
 * Attach (or replace) the viewer's private tag for `username`. Tags are
 * strictly viewer-scoped — only the caller sees them, the tagged user
 * is never told. Max 35 grapheme clusters (enforced server-side).
 *
 * Sending an empty string deletes the tag (matches the explicit
 * {@link clearUserTag} DELETE endpoint).
 */
export async function setUserTag(
	username: string,
	tag: string,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}/tag`, {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ tag })
	});
	if (!res.ok) await throwApiError(res);
}

/**
 * Remove the viewer's private tag for `username`. Idempotent — succeeds
 * whether or not a tag was previously set.
 */
export async function clearUserTag(
	username: string,
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/users/${encodeURIComponent(username)}/tag`, {
		method: 'DELETE'
	});
	if (!res.ok) await throwApiError(res);
}
