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
import { canonicalProfilePath } from '$lib/user-url';
import type { ThemeId } from '$lib/themes';
import type { FontId } from '$lib/fonts';

/**
 * Banned/suspended users may visit only their own profile (and its
 * sub-routes such as trust edge lists) and `/settings`. Everything else
 * is redirected back to their profile so the UI stays locked in the
 * restricted state the moderation action intended.
 *
 * The pathname check covers both the canonical long form
 * (`/@alice.{8hex}`) and the bare form (`/@alice`) — the latter still
 * exists transiently because the profile loader is what redirects bare
 * → long form. If a restricted user types the bare URL straight into
 * the address bar, the loader would otherwise have to run first to
 * issue the bare-to-long redirect; allowing both here keeps the gate
 * working in one hop.
 */
function isAllowedForRestricted(pathname: string, session: SessionInfo): boolean {
	const bareProfile = `/@${encodeURIComponent(session.display_name)}`;
	const longProfile = canonicalProfilePath(session.display_name, session.public_key_hex);
	if (pathname === bareProfile || pathname.startsWith(`${bareProfile}/`)) return true;
	if (pathname === longProfile || pathname.startsWith(`${longProfile}/`)) return true;
	if (pathname === '/settings' || pathname.startsWith('/settings/')) return true;
	return false;
}

export const load: LayoutServerLoad = async ({ fetch, cookies, locals, url, setHeaders }) => {
	// Every SSR response in this app is session-dependent: gated pages
	// branch on the auth cookie, `/` redirects authed → /r/all vs anon →
	// /public, and even /public itself renders different chrome depending
	// on whether the viewer is signed in. On top of that, the trust-graph
	// model means two authenticated viewers can see materially different
	// content for the same URL. Caching any of this at the browser or an
	// intermediary risks one viewer's render leaking to another.
	//
	// `no-store` (not just `no-cache`) so nothing retains a copy at all —
	// in particular, this opts the page out of bfcache, which would
	// otherwise restore a fully-rendered authenticated view after the
	// user has logged out (a real concern on shared devices). The bfcache
	// UX cost (back-button re-fetches instead of instant-restores) is
	// the price we pay for that guarantee.
	//
	// Long-cached fingerprinted bundles under /_app/immutable/* are
	// served by Caddy with their own headers and aren't affected. Pages
	// that are genuinely safe to share across viewers (none today) can
	// override by calling `setHeaders({ 'cache-control': ... })` from
	// their own load.
	setHeaders({ 'cache-control': 'no-store' });

	const setupStatus = await getSetupStatus({ fetch }).catch(() => ({
		needs_setup: false,
		source_repo_url: null
	}));

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
			throw redirect(307, canonicalProfilePath(session.display_name, session.public_key_hex));
		}
	}

	// Propagate the resolved theme + prose font back to `handle` in
	// `hooks.server.ts`, which substitutes `%theme%` / `%font%` in
	// `src/app.html` via `transformPageChunk` so SSR emits
	// `<html data-theme="..." data-font="...">` on first byte. Falls
	// back to the defaults already seeded in `handle` when there is
	// no session.
	if (session?.theme) {
		locals.theme = session.theme as ThemeId;
	}
	if (session?.font) {
		locals.font = session.font as FontId;
	}

	return {
		session,
		sessionError,
		needsSetup: setupStatus.needs_setup,
		sourceRepoUrl: setupStatus.source_repo_url
	};
};
