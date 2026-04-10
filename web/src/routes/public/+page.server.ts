// Public threads listing: the anonymous landing destination. Logged-in
// users are redirected to /room/all so they see the full trust-filtered
// feed instead. Anonymous visitors get the initial page fetched
// server-side so the first paint has content.

import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { listPublicThreads } from '$lib/api/threads';

export const load: PageServerLoad = async ({ parent, fetch }) => {
	const { session } = await parent();
	if (session) {
		throw redirect(307, '/room/all');
	}
	const res = await listPublicThreads(undefined, { fetch });
	return {
		threads: res.threads,
		nextCursor: res.next_cursor
	};
};
