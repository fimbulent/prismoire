import type { PageServerLoad } from './$types';
import { getAdminReports } from '$lib/api/admin';
import { throwMappedLoadError } from '$lib/api/load-error';

/// Admin → Reports tab. Auth is enforced by `admin/+layout.server.ts`.
export const load: PageServerLoad = async ({ fetch }) => {
	try {
		const reports = await getAdminReports('pending', undefined, { fetch });
		return {
			reports: reports.reports,
			nextCursor: reports.next_cursor
		};
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Failed to load admin reports',
			unauthRedirect: '/login'
		});
	}
};
