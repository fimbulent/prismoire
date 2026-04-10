// New-room form: requires an authenticated session. The page itself
// only submits; no data to pre-load.

import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ parent }) => {
	const { session } = await parent();
	if (!session) {
		throw redirect(307, '/login');
	}
};
