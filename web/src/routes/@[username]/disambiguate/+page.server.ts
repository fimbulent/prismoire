// Disambiguation page: multiple users share the bare display name's
// skeleton. The profile loader redirects here on `Ambiguous`. The page
// renders one row per match with the canonical long-form link, an
// instance hint (when the user is homed elsewhere), and the wire-facing
// status (so banned/suspended/deleted rows are recognisable).
//
// Reached at `/@{username}/disambiguate`. `params.username` is taken as
// the bare name — any `.{8hex}` suffix would have already filtered the
// resolve dispatch down to a unique row at the profile loader. If the
// resolve here comes back `Unique`, we redirect to the canonical long
// form so a stale disambiguate URL still lands the user on the right
// profile.

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { resolveUsername } from '$lib/api/users';
import { throwMappedLoadError } from '$lib/api/load-error';

export const load: PageServerLoad = async ({ parent, fetch, params }) => {
	const { session, sessionError } = await parent();
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	if (!session) {
		throw redirect(307, '/login');
	}

	let resolution;
	try {
		resolution = await resolveUsername(params.username, { fetch });
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Failed to load profile',
			notFound: 'User not found',
			unauthRedirect: '/login'
		});
	}

	if (resolution.kind === 'unique') {
		// Only one user matches — disambiguation isn't needed. Bounce
		// to the canonical long-form profile URL.
		const suffix = resolution.user.public_key_hex.slice(0, 8);
		throw redirect(
			303,
			`/@${encodeURIComponent(resolution.user.display_name)}.${suffix}`
		);
	}

	return {
		bareName: params.username,
		matches: resolution.matches
	};
};
