// User profile: requires an authenticated session. Loads the profile plus
// the first page of activity server-side so the header + recent activity
// render on first byte. Trust details are fetched lazily on the client when
// the user expands the collapsible section, since most visitors never open
// it and the query is comparatively expensive.
//
// The activity filter tab lives in `?filter=` so it's shareable and
// back-button friendly, matching the sort-in-URL pattern used by the
// room/thread pages.

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getUserProfile, getActivity } from '$lib/api/users';
import { ApiRequestError } from '$lib/api/auth';

const VALID_FILTERS = ['all', 'threads', 'comments'] as const;
type ActivityFilter = (typeof VALID_FILTERS)[number];

function parseFilter(raw: string | null): ActivityFilter {
	return VALID_FILTERS.includes(raw as ActivityFilter)
		? (raw as ActivityFilter)
		: 'all';
}

export const load: PageServerLoad = async ({ parent, fetch, params, url }) => {
	const { session } = await parent();
	if (!session) {
		throw redirect(307, '/login');
	}
	const filter = parseFilter(url.searchParams.get('filter'));
	try {
		const [profile, activity] = await Promise.all([
			getUserProfile(params.username, { fetch }),
			getActivity(params.username, filter, undefined, { fetch })
		]);
		return {
			profile,
			activity: activity.items,
			activityCursor: activity.next_cursor,
			filter
		};
	} catch (e) {
		if (e instanceof ApiRequestError && e.status === 404) {
			throw kitError(404, 'User not found');
		}
		throw kitError(500, 'Failed to load profile');
	}
};
