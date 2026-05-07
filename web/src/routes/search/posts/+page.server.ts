// `/search/posts?q=…&cursor=…` — first page of post results.
// Auth + query extraction happen in the parent `+layout.server.ts`.

import type { PageServerLoad } from './$types';
import { searchPosts } from '$lib/api/search';
import { throwMappedLoadError } from '$lib/api/load-error';

export const load: PageServerLoad = async ({ parent, fetch, url }) => {
	const { query } = await parent();
	const cursor = url.searchParams.get('cursor');

	if (!query) {
		return { posts: [], nextCursor: null };
	}

	try {
		const res = await searchPosts(query, { fetch, cursor });
		return { posts: res.posts, nextCursor: res.next_cursor };
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Search failed',
			unauthRedirect: '/login'
		});
	}
};
