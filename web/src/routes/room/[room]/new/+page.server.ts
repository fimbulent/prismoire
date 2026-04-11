// New-thread form: requires an authenticated session and needs the
// target room so the page can render its name/slug. Load both
// server-side and redirect anonymous visitors to /login.

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getRoom } from '$lib/api/rooms';

export const load: PageServerLoad = async ({ parent, fetch, params }) => {
	const { session, sessionError } = await parent();
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	if (!session) {
		throw redirect(307, '/login');
	}
	try {
		const room = await getRoom(params.room, { fetch });
		return { room };
	} catch {
		throw kitError(404, 'Room not found');
	}
};
