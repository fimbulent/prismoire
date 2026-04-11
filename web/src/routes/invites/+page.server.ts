// Invites management: requires an authenticated session. Loads both the
// invite link list and the invited-user list in parallel so the whole
// page renders on first byte. Create/revoke remain client-driven since
// they mutate in-place.

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { listInvites, listInvitedUsers } from '$lib/api/invites';

export const load: PageServerLoad = async ({ parent, fetch }) => {
	const { session, sessionError } = await parent();
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	if (!session) {
		throw redirect(307, '/login');
	}
	try {
		const [invites, invitedUsers] = await Promise.all([
			listInvites({ fetch }),
			listInvitedUsers({ fetch })
		]);
		return { invites, invitedUsers };
	} catch {
		throw kitError(500, 'Failed to load invites');
	}
};
