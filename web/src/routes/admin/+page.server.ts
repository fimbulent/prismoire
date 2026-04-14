import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getAdminReports, getAdminDashboard } from '$lib/api/admin';
import { ApiRequestError } from '$lib/api/auth';

export const load: PageServerLoad = async ({ parent, fetch }) => {
	const { session, sessionError } = await parent();
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	if (!session) {
		throw redirect(307, '/login');
	}
	if (session.role !== 'admin') {
		throw kitError(403, 'Forbidden');
	}
	try {
		const [reports, dashboard] = await Promise.all([
			getAdminReports('pending', undefined, { fetch }),
			getAdminDashboard({ fetch })
		]);
		return {
			reports: reports.reports,
			nextCursor: reports.next_cursor,
			pendingReports: dashboard.pending_reports
		};
	} catch (e) {
		if (e instanceof ApiRequestError) {
			if (e.status === 401) throw redirect(307, '/login');
			if (e.status === 403) throw kitError(403, 'Forbidden');
		}
		throw kitError(500, 'Failed to load admin dashboard');
	}
};
