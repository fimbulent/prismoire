// Shared `/search/*` server load. Performs the auth check + query
// extraction once for every per-kind sub-route (threads / posts /
// users / rooms), so each `+page.server.ts` only owns the API call
// for its own kind.

import { redirect, error as kitError } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ parent, url }) => {
	const { session, sessionError } = await parent();
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	if (!session) {
		throw redirect(307, '/login');
	}

	const query = (url.searchParams.get('q') ?? '').trim();
	return { query };
};
