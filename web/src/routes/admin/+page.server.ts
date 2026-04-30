import type { PageServerLoad } from './$types';
import { getAdminOverview } from '$lib/api/admin';
import { throwMappedLoadError } from '$lib/api/load-error';

/// Admin → Overview tab. Auth is enforced by `+layout.server.ts`; this
/// loader only fetches the overview payload.
export const load: PageServerLoad = async ({ fetch }) => {
	try {
		const overview = await getAdminOverview({ fetch });
		return { overview };
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Failed to load admin overview',
			unauthRedirect: '/login'
		});
	}
};
