import { throwApiError, type FetchFn } from './auth';
import type { ThemeId } from '$lib/themes';

export interface UserSettings {
	theme: ThemeId;
}

interface FetchOpts {
	fetch?: FetchFn;
}

export async function getSettings(opts: FetchOpts = {}): Promise<UserSettings> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/settings');
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function updateSettings(
	settings: Partial<UserSettings>,
	opts: FetchOpts = {}
): Promise<UserSettings> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/settings', {
		method: 'PATCH',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(settings)
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}
