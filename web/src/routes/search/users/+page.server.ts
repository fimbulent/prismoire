// `/search/users?q=…&cursor=…` — first page of user results.
// Auth + query extraction happen in the parent `+layout.server.ts`.

import type { PageServerLoad } from './$types';
import { searchUsers } from '$lib/api/search';
import { throwMappedLoadError } from '$lib/api/load-error';

export const load: PageServerLoad = async ({ parent, fetch, url }) => {
	const { query } = await parent();
	const cursor = url.searchParams.get('cursor');

	if (!query) {
		return { users: [], nextCursor: null };
	}

	try {
		const res = await searchUsers(query, { fetch, cursor });
		return { users: res.users, nextCursor: res.next_cursor };
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Search failed',
			unauthRedirect: '/login'
		});
	}
};
