// Rooms listing page: requires an authenticated session. The server load
// redirects anonymous users to /login and prefetches the room list so the
// first render is fully populated (no client-side loading spinner).

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { listRooms } from '$lib/api/rooms';

export const load: PageServerLoad = async ({ parent, fetch }) => {
	const { session, sessionError } = await parent();
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	if (!session) {
		throw redirect(307, '/login');
	}
	const rooms = await listRooms({ fetch });
	return { rooms };
};
