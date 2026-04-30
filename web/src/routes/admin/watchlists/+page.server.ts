import type { PageServerLoad } from './$types';
import { getAdminWatchlists } from '$lib/api/admin';
import { throwMappedLoadError } from '$lib/api/load-error';

/// Admin → Watchlists tab. Auth is enforced by `admin/+layout.server.ts`.
export const load: PageServerLoad = async ({ fetch }) => {
	try {
		const watchlists = await getAdminWatchlists({ fetch });
		return { watchlists };
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Failed to load watchlists',
			unauthRedirect: '/login'
		});
	}
};
