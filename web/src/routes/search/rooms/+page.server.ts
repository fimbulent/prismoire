// `/search/rooms?q=…&cursor=…` — first page of room results.
// Auth + query extraction happen in the parent `+layout.server.ts`.

import type { PageServerLoad } from './$types';
import { searchRooms } from '$lib/api/search';
import { throwMappedLoadError } from '$lib/api/load-error';

export const load: PageServerLoad = async ({ parent, fetch, url }) => {
	const { query } = await parent();
	const cursor = url.searchParams.get('cursor');

	if (!query) {
		return { rooms: [], nextCursor: null };
	}

	try {
		const res = await searchRooms(query, { fetch, cursor });
		return { rooms: res.rooms, nextCursor: res.next_cursor };
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Search failed',
			unauthRedirect: '/login'
		});
	}
};
