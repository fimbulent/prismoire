import type { PageServerLoad } from './$types';
import { getAdminConfig, getAdminOverview } from '$lib/api/admin';
import { throwMappedLoadError } from '$lib/api/load-error';

/// Admin → Config tab. Auth is enforced by `admin/+layout.server.ts`.
///
/// Loads the singleton `instance_config` row so the page can render
/// the current rebuild-schedule values and the source-code URL. The
/// admin overview is fetched in parallel so the trust-graph cache
/// budget field can show the live cache hit rate inline, giving the
/// operator a signal about whether the current budget is enough. Edits
/// go through `PATCH /api/admin/config` from the client.
export const load: PageServerLoad = async ({ fetch }) => {
	try {
		const [config, overview] = await Promise.all([
			getAdminConfig({ fetch }),
			getAdminOverview({ fetch })
		]);
		return { config, overview };
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Failed to load instance config',
			unauthRedirect: '/login'
		});
	}
};
