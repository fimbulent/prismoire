// Settings: requires an authenticated session. No data to load — the
// page only mutates (theme selection) — so we just gate on the session
// and redirect anonymous visitors to /login. A `sessionError` from the
// root layout means we couldn't actually decide whether the user is
// logged in (rate limit / 5xx on /api/auth/session); surface a 503
// rather than silently logging them out.

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
