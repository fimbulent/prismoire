// Settings: requires an authenticated session. No data to load — the
// page only mutates (theme selection) — so we just gate on the session
// and redirect anonymous visitors to /login.

import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ parent }) => {
	const { session } = await parent();
	if (!session) {
		throw redirect(307, '/login');
	}
};
