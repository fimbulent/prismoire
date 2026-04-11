export interface SessionInfo {
	user_id: string;
	display_name: string;
	role: string;
	theme: string;
}

export interface AuthBeginResponse {
	challenge_id: string;
	[key: string]: unknown;
}

/**
 * Stable machine-readable error code union matching the Rust
 * `ErrorCode` enum in `server/src/error.rs`. Every non-2xx API
 * response carries one of these in the `code` field.
 *
 * Keep this in sync with the Rust enum — adding or renaming a variant
 * is a breaking change to the wire contract.
 */
export type ErrorCode =
	// Auth / session
	| 'unauthenticated'
	| 'forbidden'
	| 'invalid_challenge'
	| 'passkey_ceremony_failed'
	| 'user_not_found'
	| 'no_credentials'
	| 'invalid_display_name'
	| 'display_name_taken'
	| 'invalid_signature'
	| 'not_own_profile'
	// Invites
	| 'invite_not_found'
	| 'invite_expired'
	| 'invite_invalid'
	| 'invite_exhausted'
	| 'invite_required'
	| 'invite_max_uses_invalid'
	| 'invite_expiry_invalid'
	// Setup
	| 'setup_already_complete'
	| 'setup_token_invalid'
	| 'setup_token_missing'
	// Rooms
	| 'room_not_found'
	| 'invalid_room_name'
	| 'room_description_too_long'
	| 'room_already_exists'
	| 'public_room_admin_only'
	// Threads
	| 'thread_not_found'
	| 'thread_locked'
	| 'thread_already_locked'
	| 'thread_not_locked'
	| 'invalid_cursor'
	| 'invalid_sort_mode'
	| 'seen_ids_exceeded'
	// Posts
	| 'post_not_found'
	| 'invalid_post_body'
	| 'invalid_thread_title'
	| 'post_retracted'
	| 'post_already_retracted'
	| 'not_post_author'
	| 'parent_thread_mismatch'
	| 'parent_retracted'
	// Trust
	| 'self_trust_edge'
	| 'no_trust_edge'
	| 'invalid_trust_direction'
	// Misc user
	| 'bio_too_long'
	// Admin
	| 'admin_required'
	| 'reason_required'
	// Settings
	| 'invalid_theme'
	// Catch-all
	| 'bad_request'
	| 'rate_limited'
	| 'internal';

/**
 * Wire shape of a non-2xx API response.
 *
 * `code` is the stable machine-readable identifier new clients should
 * branch on. `error` is a legacy free-form string kept for one
 * release so clients that haven't migrated still render something
 * reasonable. `fields` is an optional per-field validation map used
 * by form endpoints.
 */
export interface ApiError {
	error?: string;
	code?: ErrorCode;
	fields?: Record<string, ErrorCode>;
}

/**
 * Error thrown by API client functions when the server returns a
 * non-2xx response. Carries the HTTP status, the stable machine
 * `code` (when the server provides one), an optional per-field
 * validation map, and the legacy free-form message.
 *
 * UI code should prefer `errorMessage(e)` (from `$lib/i18n/errors`)
 * over reading `e.message` directly — the latter is the legacy
 * server string and will be dropped once all clients are on the
 * `code` contract.
 */
export class ApiRequestError extends Error {
	status: number;
	code: ErrorCode;
	fields?: Record<string, ErrorCode>;
	constructor(
		status: number,
		message: string,
		code: ErrorCode = 'internal',
		fields?: Record<string, ErrorCode>
	) {
		super(message);
		this.name = 'ApiRequestError';
		this.status = status;
		this.code = code;
		this.fields = fields;
	}
}

/**
 * Parse an error response body and throw an {@link ApiRequestError}.
 * Callers should invoke this immediately after `if (!res.ok)`.
 *
 * Prefers the structured `code` / `fields` fields when present and
 * falls back to the legacy `error` string (or the HTTP status text)
 * so it still works against older server builds.
 */
export async function throwApiError(res: Response): Promise<never> {
	let message = res.statusText || `HTTP ${res.status}`;
	let code: ErrorCode = 'internal';
	let fields: Record<string, ErrorCode> | undefined;
	try {
		const err = (await res.json()) as ApiError;
		if (err && typeof err.error === 'string') message = err.error;
		if (err && typeof err.code === 'string') code = err.code;
		if (err && err.fields && typeof err.fields === 'object') fields = err.fields;
	} catch {
		// response body was not JSON — keep the fallback message
	}
	throw new ApiRequestError(res.status, message, code, fields);
}

export type FetchFn = typeof fetch;

interface FetchOpts {
	fetch?: FetchFn;
}

async function apiPost<T>(url: string, body: unknown, f: FetchFn = globalThis.fetch): Promise<T> {
	const res = await f(url, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body)
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function signupBegin(
	displayName: string,
	inviteCode?: string,
	opts: FetchOpts = {}
): Promise<AuthBeginResponse> {
	return apiPost(
		'/api/auth/signup/begin',
		{
			display_name: displayName,
			invite_code: inviteCode || null
		},
		opts.fetch
	);
}

export async function signupComplete(
	challengeId: string,
	credential: Credential,
	opts: FetchOpts = {}
): Promise<SessionInfo> {
	return apiPost(
		'/api/auth/signup/complete',
		{
			challenge_id: challengeId,
			credential
		},
		opts.fetch
	);
}

export async function loginBegin(
	displayName: string,
	opts: FetchOpts = {}
): Promise<AuthBeginResponse> {
	return apiPost('/api/auth/login/begin', { display_name: displayName }, opts.fetch);
}

export async function discoverBegin(opts: FetchOpts = {}): Promise<AuthBeginResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/auth/discover/begin');
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function discoverComplete(
	challengeId: string,
	credential: Credential,
	opts: FetchOpts = {}
): Promise<SessionInfo> {
	return apiPost(
		'/api/auth/discover/complete',
		{
			challenge_id: challengeId,
			credential
		},
		opts.fetch
	);
}

export async function loginComplete(
	challengeId: string,
	credential: Credential,
	opts: FetchOpts = {}
): Promise<SessionInfo> {
	return apiPost(
		'/api/auth/login/complete',
		{
			challenge_id: challengeId,
			credential
		},
		opts.fetch
	);
}

/**
 * Fetch the current session.
 *
 * Returns `null` **only** when the server explicitly says the session
 * is invalid (HTTP 401). Any other non-2xx response — 429 from the
 * per-session rate limiter, 5xx from a transient Axum outage, a
 * network error — is surfaced as an {@link ApiRequestError} so the
 * caller can distinguish "genuinely logged out" from "couldn't reach
 * the auth service right now" and avoid booting a logged-in user to
 * `/login` on a transient blip.
 */
export async function getSession(opts: FetchOpts = {}): Promise<SessionInfo | null> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/auth/session');
	if (res.status === 401) return null;
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function logout(opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	await f('/api/auth/logout', { method: 'POST' });
}

export interface SetupStatus {
	needs_setup: boolean;
}

export async function getSetupStatus(opts: FetchOpts = {}): Promise<SetupStatus> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/setup/status');
	return res.json();
}

export async function setupBegin(
	token: string,
	displayName: string,
	opts: FetchOpts = {}
): Promise<AuthBeginResponse> {
	return apiPost(
		'/api/setup/begin',
		{
			token,
			display_name: displayName
		},
		opts.fetch
	);
}

export async function setupComplete(
	challengeId: string,
	credential: Credential,
	opts: FetchOpts = {}
): Promise<SessionInfo> {
	return apiPost(
		'/api/setup/complete',
		{
			challenge_id: challengeId,
			credential
		},
		opts.fetch
	);
}
