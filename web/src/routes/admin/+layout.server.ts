import { redirect, error as kitError } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';
import { getAdminDashboard } from '$lib/api/admin';
import { ApiRequestError } from '$lib/api/auth';

/// Shared admin gate + pending-report count for the tab badge.
///
/// Every `/admin/*` page sits under this layout, so auth is enforced once
/// and the (cheap) pending-reports query powers the tab badge on every
/// sub-route without each page reloading it.
export const load: LayoutServerLoad = async ({ parent, fetch, depends }) => {
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

	// Let page-level actions invalidate the pending-reports badge with
	// `invalidate('admin:dashboard')`.
	depends('admin:dashboard');

	try {
		const dashboard = await getAdminDashboard({ fetch });
		return { pendingReports: dashboard.pending_reports };
	} catch (e) {
		if (e instanceof ApiRequestError) {
			if (e.status === 401) throw redirect(307, '/login');
			if (e.status === 403) throw kitError(403, 'Forbidden');
		}
		throw kitError(500, 'Failed to load admin dashboard');
	}
};
