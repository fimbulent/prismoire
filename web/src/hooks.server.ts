// Server-side hook that rewrites same-origin `/api/*` fetches issued from
// SvelteKit `load` functions to the internal Axum URL. Client-side fetches
// never reach this hook — they go straight from the browser to Caddy.
//
// Deployment invariant: the Node process's `ORIGIN` env var must equal the
// Axum server's `webauthn.rp_origin` config value. Both represent "the
// public URL of this instance". We re-attach that origin to the rewritten
// Request so Axum's CSRF middleware (server/src/middleware/csrf.rs) sees
// the expected origin on non-safe methods. If `ORIGIN` and `rp_origin`
// drift, every non-GET server-side fetch will 403 — which is a loud,
// immediate failure, but still a config trap worth knowing about.
//
// The NixOS module wires this automatically: `systemd.services.prismoire-web`
// sets `ORIGIN = cfg.rpOrigin;` from the same option used for Axum's
// `webauthn.rp_origin`.

import type { Handle, HandleFetch, HandleServerError } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import { ApiRequestError } from '$lib/api/auth';
import { DEFAULT_THEME } from '$lib/themes';

const API_URL = env.API_URL ?? 'http://127.0.0.1:3000';

export const handleFetch: HandleFetch = async ({ event, request, fetch }) => {
	const url = new URL(request.url);
	if (url.origin === event.url.origin && url.pathname.startsWith('/api/')) {
		const internal = new URL(url.pathname + url.search, API_URL);
		const headers = new Headers(request.headers);
		const cookie = event.request.headers.get('cookie');
		if (cookie) headers.set('cookie', cookie);
		// Preserve the public origin so Axum's CSRF middleware accepts
		// non-safe methods. See the invariant note at the top of this file.
		headers.set('origin', event.url.origin);
		return fetch(new Request(internal, { ...request, headers }));
	}
	return fetch(request);
};

// Root `<html>` placeholder substituted via `transformPageChunk`.
// Kept as a narrow, well-known token so the replacement is O(1) and
// scoped strictly to the `data-theme` attribute on the outer `<html>`
// tag emitted by `src/app.html`.
const THEME_PLACEHOLDER = '%theme%';

export const handle: Handle = async ({ event, resolve }) => {
	// Default until the root layout load resolves the session-backed
	// theme. `event.locals.theme` is mutable from `+layout.server.ts`
	// and read (just below) after the loads have run.
	event.locals.theme = DEFAULT_THEME;

	return resolve(event, {
		transformPageChunk: ({ html }) => html.replace(THEME_PLACEHOLDER, event.locals.theme)
	});
};

/**
 * Centralised server-side error handler. Any unexpected error thrown
 * from a `load` function (anything that isn't a `redirect` or `kitError`)
 * lands here. We:
 *
 *   1. Log a structured line with the request id, route, and — for
 *      `ApiRequestError` — the upstream HTTP status and raw server
 *      message. This is the ONE place raw backend messages are allowed
 *      to appear in logs.
 *   2. Return a generic, non-sensitive message to the client so the
 *      backend internals never surface in the error page.
 */
export const handleError: HandleServerError = ({ error, event, status, message }) => {
	const errorId = crypto.randomUUID();
	const route = event.route.id ?? event.url.pathname;

	if (error instanceof ApiRequestError) {
		console.error(`[${errorId}] ${route}: upstream ${error.status} ${error.message}`);
	} else if (error instanceof Error) {
		console.error(`[${errorId}] ${route}: ${error.stack ?? error.message}`);
	} else {
		console.error(`[${errorId}] ${route}:`, error);
	}

	// `status` / `message` are populated by SvelteKit when the caller
	// used `kitError(...)`; pass those through so the error page shows
	// the intended user-facing text. For anything else we show a
	// generic 500.
	return {
		message: status && status < 500 ? message : 'Something went wrong',
		errorId
	};
};
