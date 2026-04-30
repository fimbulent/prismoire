// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces

import type { SessionInfo } from '$lib/api/auth';
import type { ThemeId } from '$lib/themes';
import type { FontId } from '$lib/fonts';

declare global {
	namespace App {
		interface Error {
			message: string;
			errorId?: string;
		}
		/**
		 * Request-scoped values stashed by `handle` in `hooks.server.ts`
		 * and read back by `transformPageChunk` / layout loads. Everything
		 * here must be set per-request (never at module scope) because
		 * the Node adapter serves concurrent requests from one process.
		 */
		interface Locals {
			/**
			 * Theme id resolved for the current request. Set in
			 * `handle` before `resolve` is called, then read by
			 * `transformPageChunk` to write the initial `data-theme`
			 * attribute on `<html>` and by `+layout.server.ts` to
			 * populate `session.theme` without a second API call.
			 */
			theme: ThemeId;
			/**
			 * Prose-font id resolved for the current request. Same
			 * lifecycle as `theme` — seeded with the default in
			 * `handle`, overridden from the session in
			 * `+layout.server.ts`, written into `<html data-font="…">`
			 * by `transformPageChunk` so SSR renders post-body prose
			 * in the user's chosen face on first byte.
			 */
			font: FontId;
		}
		/**
		 * Shape of the data returned by the root `+layout.server.ts`
		 * load (merged into every page's `data`). Keeping this typed
		 * means `$page.data.session` is no longer `any` at call sites
		 * like `src/lib/stores/session.svelte.ts`.
		 */
		interface PageData {
			session: SessionInfo | null;
			/**
			 * `true` when the root layout load tried to resolve the
			 * session cookie but Axum returned a non-401 non-2xx
			 * response (rate limit, 5xx, network error). Gated page
			 * loads should check this before redirecting to `/login`
			 * — a transient upstream failure should surface as a 503
			 * error page, not a silent logout. `false` when either
			 * there is no cookie, or the cookie was explicitly
			 * rejected as invalid by Axum (HTTP 401).
			 */
			sessionError: boolean;
			needsSetup: boolean;
		}
		interface PageState {
			viewRootStack?: string[];
		}
		// interface Platform {}
	}
}

export {};
