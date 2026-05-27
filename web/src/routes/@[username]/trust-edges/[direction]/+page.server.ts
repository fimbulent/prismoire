// Trust-edges list: requires an authenticated session. Validates the
// direction slug (trusts | trusted-by), maps it to the API enum, and
// loads the edge list server-side so the page is fully rendered on
// first byte.

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getTrustEdges, resolveUsername } from '$lib/api/users';
import { throwMappedLoadError } from '$lib/api/load-error';

export const load: PageServerLoad = async ({ parent, fetch, params }) => {
	const { session, sessionError } = await parent();
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	if (!session) {
		throw redirect(307, '/login');
	}
	if (params.direction !== 'trusts' && params.direction !== 'trusted-by') {
		throw kitError(404, 'Invalid direction');
	}
	const apiDirection = params.direction === 'trusted-by' ? 'trusted_by' : 'trusts';
	// `/api/users/{pubkey_hex}/trust/edges` is pubkey-keyed; resolve the
	// typed name (bare or dotted long form) to its pubkey first.
	try {
		const resolution = await resolveUsername(params.username, { fetch });
		if (resolution.kind === 'ambiguous') {
			throw redirect(303, `/@${encodeURIComponent(params.username)}/disambiguate`);
		}
		const res = await getTrustEdges(resolution.user.public_key_hex, apiDirection, { fetch });
		return {
			users: res.users,
			total: res.total,
			capped: res.capped,
			direction: params.direction,
			username: params.username
		};
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Failed to load trust edges',
			notFound: 'User not found',
			unauthRedirect: '/login'
		});
	}
};
