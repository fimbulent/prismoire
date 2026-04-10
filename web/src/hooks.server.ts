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

import type { Handle, HandleFetch } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';

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

export const handle: Handle = async ({ event, resolve }) => {
	return resolve(event);
};
