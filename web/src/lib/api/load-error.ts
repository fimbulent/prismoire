// Centralized mapper from upstream `ApiRequestError` to a SvelteKit
// `kitError` / `redirect` for use inside server `load` functions.
//
// Before this helper, every loader hand-rolled its own status branching
// in the `catch` block, with the predictable result that 429s from the
// per-IP / per-session rate limiter were uniformly missing — they fell
// through to the generic 500 fallback, so the network tab showed a
// real 429 from Axum but the rendered error page was a 500. See the
// "API Error Flow" section of `web/CLAUDE.md` for how this fits into
// the broader error contract.
//
// The helper handles the universally-relevant statuses (403, 429, 5xx
// fallback) unconditionally, and the route-specific ones (401 redirect,
// 404 with a domain-appropriate message) opt-in via options. Anything
// not an `ApiRequestError` (e.g. a network error, a thrown string)
// also falls through to the 500 fallback so callers don't need to
// type-narrow at the call site.

import { error as kitError, redirect } from '@sveltejs/kit';
import { ApiRequestError } from './auth';

export interface LoadErrorOpts {
	/** Message used for the 500 fallback when no specific status matches. */
	fallback: string;
	/**
	 * If set, a 404 from the API becomes `kitError(404, notFound)`. Omit
	 * for routes whose API endpoints have no meaningful 404 (e.g. admin
	 * dashboards) — an unexpected 404 then falls through to the 500
	 * fallback, which is louder and easier to spot in logs.
	 */
	notFound?: string;
	/**
	 * If set, a 401 from the API redirects to this path (typically
	 * `/login`). Most gated loaders should set `'/login'` so a session
	 * expiring mid-request lands the user at re-auth in one hop rather
	 * than at an interstitial "Sign in required" page they then have
	 * to click through. Leave unset only for routes that are genuinely
	 * partially-public — those get a 401 page instead, so the viewer
	 * isn't yanked away from content they were reading.
	 */
	unauthRedirect?: string;
}

/**
 * Map an upstream API error from a SvelteKit server `load` into the
 * appropriate `kitError` / `redirect`. Always throws — the return type
 * is `never` so TypeScript treats the call as an exit point in a
 * `catch` block.
 *
 * Status mapping:
 * - 401 → `redirect(307, opts.unauthRedirect)` if set, else `kitError(401, '')`
 *         (empty message lets `+error.svelte` render its "Sign in required" copy)
 * - 403 → `kitError(403, 'Forbidden')`
 * - 404 → `kitError(404, opts.notFound)` if set, else falls through to 500
 *         (so an unexpected 404 from a route with no meaningful "not found"
 *         is louder in logs rather than silently absorbed)
 * - 429 → `kitError(429, '')` — empty message lets `+error.svelte`
 *         render its curated "Slow down" variant copy
 * - anything else (including non-`ApiRequestError`) → `kitError(500, opts.fallback)`
 */
export function throwMappedLoadError(e: unknown, opts: LoadErrorOpts): never {
	if (e instanceof ApiRequestError) {
		if (e.status === 401) {
			if (opts.unauthRedirect) throw redirect(307, opts.unauthRedirect);
			throw kitError(401, '');
		}
		if (e.status === 403) throw kitError(403, 'Forbidden');
		if (e.status === 404 && opts.notFound) throw kitError(404, opts.notFound);
		if (e.status === 429) throw kitError(429, '');
	}
	throw kitError(500, opts.fallback);
}
