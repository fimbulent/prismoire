// Root server load: resolves the current session and setup status once per
// request. Every page in the app reads `data.session` / `data.needsSetup`
// through `+layout.svelte`, so SSR can render authenticated views and the
// correct theme on the very first byte (no FOUC, no loading flash).
//
// `handleFetch` (src/hooks.server.ts) rewrites `/api/*` to the internal Axum
// URL and forwards the session cookie, so the same call works on the server
// as it does in the browser.

import { redirect } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';
import { ApiRequestError, getSession, getSetupStatus, type SessionInfo } from '$lib/api/auth';
import type { ThemeId } from '$lib/themes';

/**
 * Banned/suspended users may visit only their own profile (and its
 * sub-routes such as trust edge lists) and `/settings`. Everything else
 * is redirected back to their profile so the UI stays locked in the
 * restricted state the moderation action intended.
 */
function isAllowedForRestricted(pathname: string, session: SessionInfo): boolean {
	const ownProfile = `/user/${encodeURIComponent(session.display_name)}`;
	if (pathname === ownProfile || pathname.startsWith(`${ownProfile}/`)) return true;
	if (pathname === '/settings' || pathname.startsWith('/settings/')) return true;
	return false;
}

export const load: LayoutServerLoad = async ({ fetch, cookies, locals, url }) => {
	const setupStatus = await getSetupStatus({ fetch }).catch(() => ({ needs_setup: false }));

	// Only hit /api/auth/session when a session cookie is actually present.
	// Saves a network round-trip per anonymous request.
	//
	// Three distinct outcomes, which gated page loads must treat
	// differently (see any `+page.server.ts` that checks `session`):
	//
	//   1. No cookie at all                → session=null, sessionError=false
	//      The user is anonymous. Gated routes should redirect to /login.
	//   2. Cookie present, 401 from Axum   → session=null, sessionError=false
	//      The session is genuinely invalid/expired. Also redirect.
	//   3. Cookie present, 429/5xx/network → session=null, sessionError=true
	//      We couldn't decide. Gated routes should surface a 503 error
	//      page rather than boot a likely-logged-in user to /login
	//      (which discards whatever they were doing and lies about the
	//      cause of the failure).
	//
	// Case 3 is what this branch is for: `getSession` throws on
	// non-401 non-2xx so the root load can tell the difference. See
	// the docstring on `getSession` for the rationale.
	const hasSessionCookie = cookies.get('prismoire_session') !== undefined;
	let session: Awaited<ReturnType<typeof getSession>> = null;
	let sessionError = false;
	if (hasSessionCookie) {
		try {
			session = await getSession({ fetch });
		} catch (e) {
			if (e instanceof ApiRequestError) {
				sessionError = true;
			} else {
				// Network / unexpected error — treat as transient too.
				sessionError = true;
			}
		}
	}

	// Gate restricted (banned/suspended) users to their own profile and
	// settings. Done here rather than in each page's load so a new route
	// can't accidentally be reachable to restricted users.
	if (session && (session.status === 'banned' || session.status === 'suspended')) {
		if (!isAllowedForRestricted(url.pathname, session)) {
			throw redirect(307, `/user/${encodeURIComponent(session.display_name)}`);
		}
	}

	// Propagate the resolved theme back to `handle` in `hooks.server.ts`,
	// which substitutes `%theme%` in `src/app.html` via `transformPageChunk`
	// so SSR emits `<html data-theme="...">` on first byte. Falls back to
	// the default already seeded in `handle` when there is no session.
	if (session?.theme) {
		locals.theme = session.theme as ThemeId;
	}

	return {
		session,
		sessionError,
		needsSetup: setupStatus.needs_setup
	};
};
