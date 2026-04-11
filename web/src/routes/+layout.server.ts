// Root server load: resolves the current session and setup status once per
// request. Every page in the app reads `data.session` / `data.needsSetup`
// through `+layout.svelte`, so SSR can render authenticated views and the
// correct theme on the very first byte (no FOUC, no loading flash).
//
// `handleFetch` (src/hooks.server.ts) rewrites `/api/*` to the internal Axum
// URL and forwards the session cookie, so the same call works on the server
// as it does in the browser.

import type { LayoutServerLoad } from './$types';
import { ApiRequestError, getSession, getSetupStatus } from '$lib/api/auth';
import type { ThemeId } from '$lib/themes';

export const load: LayoutServerLoad = async ({ fetch, cookies, locals }) => {
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
