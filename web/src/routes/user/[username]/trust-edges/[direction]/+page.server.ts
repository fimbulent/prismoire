// Trust-edges list: requires an authenticated session. Validates the
// direction slug (trusts | trusted-by), maps it to the API enum, and
// loads the edge list server-side so the page is fully rendered on
// first byte.

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getTrustEdges } from '$lib/api/users';
import { ApiRequestError } from '$lib/api/auth';

export const load: PageServerLoad = async ({ parent, fetch, params }) => {
	const { session } = await parent();
	if (!session) {
		throw redirect(307, '/login');
	}
	if (params.direction !== 'trusts' && params.direction !== 'trusted-by') {
		throw kitError(404, 'Invalid direction');
	}
	const apiDirection = params.direction === 'trusted-by' ? 'trusted_by' : 'trusts';
	try {
		const res = await getTrustEdges(params.username, apiDirection, { fetch });
		return {
			users: res.users,
			total: res.total,
			capped: res.capped,
			direction: params.direction,
			username: params.username
		};
	} catch (e) {
		if (e instanceof ApiRequestError && e.status === 404) {
			throw kitError(404, 'User not found');
		}
		throw kitError(500, 'Failed to load trust edges');
	}
};
