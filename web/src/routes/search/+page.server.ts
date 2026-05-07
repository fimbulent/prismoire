// `/search?q=…` redirects to the threads sub-route, the default kind.
// Per-kind results live at `/search/{threads,posts,users,rooms}` so each
// tab is bookmarkable and back/forward behave naturally.

import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ url }) => {
	const query = (url.searchParams.get('q') ?? '').trim();
	const target = query ? `/search/threads?q=${encodeURIComponent(query)}` : '/search/threads';
	throw redirect(307, target);
};
