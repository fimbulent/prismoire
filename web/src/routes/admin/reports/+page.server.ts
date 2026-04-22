import { error as kitError, redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getAdminReports } from '$lib/api/admin';
import { ApiRequestError } from '$lib/api/auth';

/// Admin → Reports tab. Auth is enforced by `admin/+layout.server.ts`.
export const load: PageServerLoad = async ({ fetch }) => {
	try {
		const reports = await getAdminReports('pending', undefined, { fetch });
		return {
			reports: reports.reports,
			nextCursor: reports.next_cursor
		};
	} catch (e) {
		if (e instanceof ApiRequestError) {
			if (e.status === 401) throw redirect(307, '/login');
			if (e.status === 403) throw kitError(403, 'Forbidden');
		}
		throw kitError(500, 'Failed to load admin reports');
	}
};
