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

export interface ApiError {
	error: string;
}

/**
 * Error thrown by API client functions when the server returns a
 * non-2xx response. Carries the HTTP status so server-side loads can
 * branch on it to map to the right `kitError` / `redirect`.
 *
 * IMPORTANT: `message` is currently the raw server-provided error
 * string. Client-side callers pipe it straight into the UI, which
 * means the Rust backend is implicitly responsible for ensuring every
 * `ApiError` it emits is safe to show to the user. See
 * `docs/fix-errors.md` for the plan to migrate this to a structured
 * `{code, fields?}` contract.
 */
export class ApiRequestError extends Error {
	status: number;
	constructor(status: number, message: string) {
		super(message);
		this.name = 'ApiRequestError';
		this.status = status;
	}
}

/**
 * Parse an error response body and throw an {@link ApiRequestError}.
 * Callers should invoke this immediately after `if (!res.ok)`.
 */
export async function throwApiError(res: Response): Promise<never> {
	let message = res.statusText || `HTTP ${res.status}`;
	try {
		const err = (await res.json()) as ApiError;
		if (err && typeof err.error === 'string') message = err.error;
	} catch {
		// response body was not JSON — keep the fallback message
	}
	throw new ApiRequestError(res.status, message);
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
