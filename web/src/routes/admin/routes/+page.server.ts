import type { PageServerLoad } from './$types';
import { getAdminRoutes } from '$lib/api/admin';
import { throwMappedLoadError } from '$lib/api/load-error';
import { routeMetrics } from '$lib/server/route-metrics';

/// Admin → Routes tab. Auth is enforced by `admin/+layout.server.ts`.
///
/// Surfaces two stacked tables:
/// - **API routes** — fetched from Axum's `/api/admin/routes`.
/// - **Web routes** — read directly from the in-process Node recorder
///   in `$lib/server/route-metrics`, populated by the `handle` hook in
///   `src/hooks.server.ts`. Both views are 24h rolling windows scoped
///   to their respective process; counters reset on restart.
export const load: PageServerLoad = async ({ fetch }) => {
	try {
		const data = await getAdminRoutes({ fetch });
		return {
			routes: data.routes,
			webRoutes: routeMetrics.snapshot()
		};
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Failed to load route stats',
			unauthRedirect: '/login'
		});
	}
};
