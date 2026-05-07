// `/search/threads?q=…&cursor=…` — first page of thread results.
// Auth + query extraction happen in the parent `+layout.server.ts`.

import type { PageServerLoad } from './$types';
import { searchThreads } from '$lib/api/search';
import { throwMappedLoadError } from '$lib/api/load-error';

export const load: PageServerLoad = async ({ parent, fetch, url }) => {
	const { query } = await parent();
	const cursor = url.searchParams.get('cursor');

	if (!query) {
		return { threads: [], nextCursor: null };
	}

	try {
		const res = await searchThreads(query, { fetch, cursor });
		return { threads: res.threads, nextCursor: res.next_cursor };
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Search failed',
			unauthRedirect: '/login'
		});
	}
};
