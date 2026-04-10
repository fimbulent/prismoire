// Invite acceptance: validate the invite code server-side so the "valid
// / invalid" branch is decided on first byte. The signup form itself
// still runs in the browser because WebAuthn credential creation needs
// the navigator.credentials API.

import type { PageServerLoad } from './$types';
import { validateInvite } from '$lib/api/invites';

export const load: PageServerLoad = async ({ fetch, params }) => {
	const validation = await validateInvite(params.code, { fetch });
	return { validation, code: params.code };
};
