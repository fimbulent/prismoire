// SSR-safe prose-font facade. Mirrors `theme.svelte.ts` exactly: the
// authoritative font id comes from the server-resolved session
// (`page.data.session?.font`). On the client we keep an optional
// local override so a font click in the settings page applies
// instantly without waiting for the API round-trip — that override
// lives in `browser`-gated module scope and is therefore SSR-safe.

import { browser } from '$app/environment';
import { page } from '$app/state';
import { applyFont, DEFAULT_FONT, type FontId } from '$lib/fonts';

let clientOverride = $state<FontId | null>(null);

export const font = {
	get current(): FontId {
		if (clientOverride !== null) return clientOverride;
		const fromSession = page.data.session?.font as FontId | undefined;
		return fromSession ?? DEFAULT_FONT;
	},

	/**
	 * Apply a font immediately in the browser. The server-side update
	 * (via `updateSettings`) is the caller's responsibility; once the
	 * subsequent `invalidateAll()` re-resolves the session, the
	 * override can be cleared by calling `clearOverride()`.
	 */
	set(id: FontId): void {
		if (!browser) return;
		clientOverride = id;
		applyFont(id);
	},

	clearOverride(): void {
		clientOverride = null;
	}
};
