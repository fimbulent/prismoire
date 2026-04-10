// Root server load: resolves the current session and setup status once per
// request. Every page in the app reads `data.session` / `data.needsSetup`
// through `+layout.svelte`, so SSR can render authenticated views and the
// correct theme on the very first byte (no FOUC, no loading flash).
//
// `handleFetch` (src/hooks.server.ts) rewrites `/api/*` to the internal Axum
// URL and forwards the session cookie, so the same call works on the server
// as it does in the browser.

import type { LayoutServerLoad } from './$types';
import { getSession, getSetupStatus } from '$lib/api/auth';

export const load: LayoutServerLoad = async ({ fetch, cookies }) => {
	const setupStatus = await getSetupStatus({ fetch }).catch(() => ({ needs_setup: false }));

	// Only hit /api/auth/session when a session cookie is actually present.
	// Saves a network round-trip per anonymous request.
	const hasSessionCookie = cookies.get('prismoire_session') !== undefined;
	const session = hasSessionCookie ? await getSession({ fetch }).catch(() => null) : null;

	return {
		session,
		needsSetup: setupStatus.needs_setup
	};
};
