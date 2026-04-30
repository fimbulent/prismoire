// Admin log: requires an authenticated session. Non-admins get a 403.
// Anonymous visitors are short-circuited to /login before the API call.
// `throwMappedLoadError` then handles upstream errors: 401 redirects
// to /login (session expired mid-request), 403 → "Forbidden", 429 →
// "Slow down", anything else → generic 500.

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getAdminLog } from '$lib/api/admin';
import { throwMappedLoadError } from '$lib/api/load-error';

export const load: PageServerLoad = async ({ parent, fetch }) => {
	const { session, sessionError } = await parent();
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	if (!session) {
		throw redirect(307, '/login');
	}
	try {
		const res = await getAdminLog(undefined, { fetch });
		return {
			entries: res.entries,
			nextCursor: res.next_cursor
		};
	} catch (e) {
		throwMappedLoadError(e, { fallback: 'Failed to load admin log', unauthRedirect: '/login' });
	}
};
