// User profile: requires an authenticated session. Loads the profile plus
// the first page of activity server-side so the header + recent activity
// render on first byte. Trust details are fetched lazily on the client when
// the user expands the collapsible section, since most visitors never open
// it and the query is comparatively expensive.
//
// The activity filter tab lives in `?filter=` so it's shareable and
// back-button friendly, matching the sort-in-URL pattern used by the
// room/thread pages.
//
// Phase 9.5 (federation): the route accepts both the bare `/@alice` and
// the long form `/@alice.{8hex}` (pubkey-prefix suffix). The loader
// resolves the typed name first:
//
//   - Ambiguous (multiple users share a skeleton) → redirect to the
//     disambiguation page, which renders a row per match.
//   - Unique bare form → redirect to the canonical long form so the
//     address bar stabilizes against a future skeleton collision.
//   - Unique long form → load the profile + activity normally.
//
// The unique-long-form path emits a `<link rel="canonical">` in the page
// `<head>` (see `+page.svelte`) so external links to the bare form survive
// a later collision without silently changing meaning.

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getUserProfile, getActivity, resolveUsername } from '$lib/api/users';
import { throwMappedLoadError } from '$lib/api/load-error';

const VALID_FILTERS = ['all', 'threads', 'comments'] as const;
type ActivityFilter = (typeof VALID_FILTERS)[number];

function parseFilter(raw: string | null): ActivityFilter {
	return VALID_FILTERS.includes(raw as ActivityFilter)
		? (raw as ActivityFilter)
		: 'all';
}

/// Split a path segment like `alice.a1b2c3d4` into the bare name and
/// the optional 8-lowercase-hex pubkey-prefix suffix. Mirrors
/// `server/src/users.rs::parse_username_with_suffix` — keep these
/// two in sync if either side ever loosens the suffix grammar.
function splitUsernameSuffix(raw: string): { name: string; suffix: string | null } {
	const dot = raw.lastIndexOf('.');
	if (dot < 0) return { name: raw, suffix: null };
	const candidate = raw.slice(dot + 1);
	if (candidate.length === 8 && /^[0-9a-f]{8}$/.test(candidate)) {
		return { name: raw.slice(0, dot), suffix: candidate };
	}
	return { name: raw, suffix: null };
}

export const load: PageServerLoad = async ({ parent, fetch, params, url }) => {
	const { session, sessionError } = await parent();
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	if (!session) {
		throw redirect(307, '/login');
	}
	const filter = parseFilter(url.searchParams.get('filter'));
	const { name: bareName, suffix } = splitUsernameSuffix(params.username);

	// Step 1: resolve the typed identifier. The dispatch handles bare
	// vs. long form internally; we only need its discriminated result
	// to decide how to route from here.
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

	if (resolution.kind === 'ambiguous') {
		// Multiple users share the skeleton and either no suffix was
		// supplied or the suffix matched more than one row (which
		// shouldn't happen with the 8-hex prefix, but handle
		// defensively). The disambiguation page renders the list.
		throw redirect(303, `/@${encodeURIComponent(bareName)}/disambiguate`);
	}

	const canonicalSuffix = resolution.user.public_key_hex.slice(0, 8);
	const canonicalPath = `/@${encodeURIComponent(resolution.user.display_name)}.${canonicalSuffix}`;

	// Step 2: redirect short → long form so the address bar always
	// shows the canonical long form. Even when the name is currently
	// unique, a future federation event could turn it ambiguous;
	// stabilizing the URL now means external links keep resolving to
	// the same user.
	if (!suffix) {
		throw redirect(303, `${canonicalPath}${url.search}`);
	}

	// Suffix mismatch (e.g. typo) is already a 404 from the server —
	// resolution would have been NotFound. Reaching here means the
	// suffix matched the unique row.

	try {
		const [profile, activity] = await Promise.all([
			getUserProfile(resolution.user.display_name, { fetch }),
			getActivity(resolution.user.display_name, filter, undefined, { fetch })
		]);
		return {
			profile,
			activity: activity.items,
			activityCursor: activity.next_cursor,
			activityAdminOverride: activity.admin_override,
			filter,
			canonicalPath
		};
	} catch (e) {
		throwMappedLoadError(e, {
			fallback: 'Failed to load profile',
			notFound: 'User not found',
			unauthRedirect: '/login'
		});
	}
};
