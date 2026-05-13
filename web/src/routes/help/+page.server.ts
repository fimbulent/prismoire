// /help is a redirect to the first sub-page. Mirrors the pattern in the
// root +page.server.ts so the browser follows a 307 directly without
// rendering an intermediate shell.

import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async () => {
	throw redirect(307, '/help/about');
};
