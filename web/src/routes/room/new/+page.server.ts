// New-room form: requires an authenticated session. The page itself
// only submits; no data to pre-load. `sessionError` means the auth
// service was unreachable — render a 503 instead of redirecting to
// /login (see web/src/routes/+layout.server.ts for context).

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ parent }) => {
	const { session, sessionError } = await parent();
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	if (!session) {
		throw redirect(307, '/login');
	}
};
