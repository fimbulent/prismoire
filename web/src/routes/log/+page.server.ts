// Admin log: requires an authenticated session. Non-admins get a 403.
// We map API errors to user-friendly pages rather than forwarding raw
// server messages:
//   401  → redirect to /login (session expired)
//   403  → "Forbidden" error page
//   else → generic 500
//
// Anonymous visitors are short-circuited to /login before we even try
// the API call so they get a friendlier flow.

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getAdminLog } from '$lib/api/admin';
import { ApiRequestError } from '$lib/api/auth';

export const load: PageServerLoad = async ({ parent, fetch }) => {
	const { session } = await parent();
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
		if (e instanceof ApiRequestError) {
			if (e.status === 401) throw redirect(307, '/login');
			if (e.status === 403) throw kitError(403, 'Forbidden');
		}
		throw kitError(500, 'Failed to load admin log');
	}
};
