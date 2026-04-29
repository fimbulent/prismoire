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
	const ownProfile = `/@${encodeURIComponent(session.display_name)}`;
	if (pathname === ownProfile || pathname.startsWith(`${ownProfile}/`)) return true;
	if (pathname === '/settings' || pathname.startsWith('/settings/')) return true;
	return false;
}

export const load: LayoutServerLoad = async ({ fetch, cookies, locals, url, setHeaders }) => {
	// Every SSR response in this app is session-dependent: gated pages
	// branch on the auth cookie, /` redirects authed → /r/all vs anon →
	// /public, even /public itself renders different chrome depending on
	// whether the viewer is signed in. Caching any of this — even
	// heuristically by a browser or a PWA shell warming `start_url` — is
	// a correctness bug: a logged-out 307 → /public served from cache
	// would prevent a subsequently-logged-in PWA cold launch from ever
	// reaching /r/all without a manual refresh (observed in production).
	//
	// `no-store` (not just `no-cache`) so intermediaries and the PWA
	// shell don't even retain a copy to revalidate. Long-cached
	// fingerprinted bundles under /_app/immutable/* are served by Caddy
	// with their own headers and aren't affected by this. Pages that are
	// genuinely safe to share across viewers (none today) can override
	// by calling `setHeaders({ 'cache-control': ... })` from their own
	// load.
	setHeaders({ 'cache-control': 'no-store' });

	const setupStatus = await getSetupStatus({ fetch }).catch(() => ({ needs_setup: false }));

	// Instance-level bootstrap: if no admin exists yet, every page must
	// funnel to /setup. Done here (not in +layout.svelte) so the redirect
	// happens on the server and the user never sees a flash of the
	// requested page before the client-side `goto('/setup')` fires.
	if (setupStatus.needs_setup && url.pathname !== '/setup') {
		throw redirect(307, '/setup');
	}

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
			throw redirect(307, `/@${encodeURIComponent(session.display_name)}`);
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
