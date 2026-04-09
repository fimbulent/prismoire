import type { ThemeId } from '$lib/themes';

export interface UserSettings {
	theme: ThemeId;
}

export async function getSettings(): Promise<UserSettings> {
	const res = await fetch('/api/settings');
	if (!res.ok) throw new Error('failed to load settings');
	return res.json();
}

export async function updateSettings(settings: Partial<UserSettings>): Promise<UserSettings> {
	const res = await fetch('/api/settings', {
		method: 'PATCH',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(settings)
	});
	if (!res.ok) throw new Error('failed to update settings');
	return res.json();
}
