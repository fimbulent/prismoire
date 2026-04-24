// Rooms listing page: requires an authenticated session. The server load
// redirects anonymous users to /login and prefetches the first page of
// rooms plus the viewer's favorites so the first render is fully
// populated (no client-side loading spinner).

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { listRooms, listFavorites } from '$lib/api/rooms';

export const load: PageServerLoad = async ({ parent, fetch }) => {
	const { session, sessionError } = await parent();
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	if (!session) {
		throw redirect(307, '/login');
	}
	// Run both fetches in parallel — the rooms listing and the
	// favorites list have no dependency on each other.
	const [page, favorites] = await Promise.all([
		listRooms({ fetch }),
		listFavorites({ fetch })
	]);
	return {
		rooms: page.rooms,
		nextCursor: page.next_cursor,
		favorites
	};
};
