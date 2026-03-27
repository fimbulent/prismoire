export interface SessionInfo {
	user_id: string;
	display_name: string;
}

export interface AuthBeginResponse {
	challenge_id: string;
	[key: string]: unknown;
}

export interface ApiError {
	error: string;
}

async function apiPost<T>(url: string, body: unknown): Promise<T> {
	const res = await fetch(url, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body)
	});
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function signupBegin(
	displayName: string,
	inviteCode?: string
): Promise<AuthBeginResponse> {
	return apiPost('/api/auth/signup/begin', {
		display_name: displayName,
		invite_code: inviteCode || null
	});
}

export async function signupComplete(
	challengeId: string,
	credential: Credential
): Promise<SessionInfo> {
	return apiPost('/api/auth/signup/complete', {
		challenge_id: challengeId,
		credential
	});
}

export async function loginBegin(displayName: string): Promise<AuthBeginResponse> {
	return apiPost('/api/auth/login/begin', { display_name: displayName });
}

export async function discoverBegin(): Promise<AuthBeginResponse> {
	const res = await fetch('/api/auth/discover/begin');
	if (!res.ok) {
		const err: ApiError = await res.json();
		throw new Error(err.error);
	}
	return res.json();
}

export async function discoverComplete(
	challengeId: string,
	credential: Credential
): Promise<SessionInfo> {
	return apiPost('/api/auth/discover/complete', {
		challenge_id: challengeId,
		credential
	});
}

export async function loginComplete(
	challengeId: string,
	credential: Credential
): Promise<SessionInfo> {
	return apiPost('/api/auth/login/complete', {
		challenge_id: challengeId,
		credential
	});
}

export async function getSession(): Promise<SessionInfo | null> {
	const res = await fetch('/api/auth/session');
	if (!res.ok) return null;
	return res.json();
}

export async function logout(): Promise<void> {
	await fetch('/api/auth/logout', { method: 'POST' });
}
