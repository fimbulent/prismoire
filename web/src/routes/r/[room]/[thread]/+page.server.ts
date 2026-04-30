// Thread detail: fetches the thread server-side so the OP + initial reply
// page render on first byte. Anonymous users are allowed to see public
// threads (the server returns a trimmed payload in that case) and are
// redirected to /login for non-public threads. Sort mode and focus post
// live in the URL (?sort=, ?post=) for shareability.

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getThread, type ThreadDetailSort } from '$lib/api/threads';
import { throwMappedLoadError } from '$lib/api/load-error';

const VALID_SORTS: ThreadDetailSort[] = ['trust', 'new'];

function parseSort(raw: string | null): ThreadDetailSort {
	return VALID_SORTS.includes(raw as ThreadDetailSort)
		? (raw as ThreadDetailSort)
		: 'trust';
}

export const load: PageServerLoad = async ({ parent, fetch, params, url }) => {
	const { session, sessionError } = await parent();
	// If we couldn't determine session state at all, surface a 503
	// rather than treating the user as anonymous (which would either
	// downgrade them to the public payload or boot them to /login on
	// a private thread). See web/src/routes/+layout.server.ts.
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	const sort = parseSort(url.searchParams.get('sort'));
	const focus = url.searchParams.get('post') ?? undefined;

	try {
		const thread = await getThread(params.thread, sort, focus, { fetch });
		// Non-public threads require authentication.
		if (!session && !thread.is_announcement) {
			throw redirect(307, '/login');
		}
		return { thread, sort };
	} catch (e) {
		// Anonymous viewers can only see public threads; any error fetching
		// a non-public thread for them means "log in to find out", not
		// "this thread is broken" — so short-circuit to /login before the
		// generic mapper runs. (This deliberately collapses 404 and 401
		// into the same outcome for anonymous viewers so we don't leak
		// the existence of private threads.)
		if (!session) {
			throw redirect(307, '/login');
		}
		throwMappedLoadError(e, {
			fallback: 'Failed to load thread',
			notFound: 'Thread not found',
			unauthRedirect: '/login'
		});
	}
};
