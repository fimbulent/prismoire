import type { PageServerLoad } from './$types';
import { listPeers } from '$lib/api/federation';
import { throwMappedLoadError } from '$lib/api/load-error';

/// Admin → Federation tab. Auth is enforced by `admin/+layout.server.ts`.
///
/// Loads this instance's identity plus every peer row so the page can
/// render the peer table and the operator's own domain + fingerprint.
/// The two-stage federate flow (preview → initiate), accept, and
/// defederate all run client-side against `/api/admin/federation/*`.
export const load: PageServerLoad = async ({ fetch }) => {
	try {
		const { instance, peers, peering_suggestions } = await listPeers({ fetch });
		return { instance, peers, peeringSuggestions: peering_suggestions };
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Failed to load federation peers',
			unauthRedirect: '/login'
		});
	}
};
