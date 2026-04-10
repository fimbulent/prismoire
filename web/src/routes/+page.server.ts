// The landing page is a pure redirect: logged-in users go to `/room/all`,
// anonymous visitors go to `/public`. Doing this on the server means the
// browser follows a 307 directly and never renders an intermediate shell.
// Uses `+page.server.ts` (not `+page.ts`) because the redirect decision
// depends on the session cookie, which is only meaningful on the server.

import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ parent }) => {
	const { session } = await parent();
	if (session) {
		throw redirect(307, '/room/all');
	}
	throw redirect(307, '/public');
};
