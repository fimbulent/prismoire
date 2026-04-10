// SSR-safe theme facade. The authoritative theme id comes from the
// server-resolved session (`page.data.session?.theme`). On the client
// we keep an optional local override so a theme click in the settings
// page can apply instantly without waiting for the API round-trip —
// that override lives in `browser`-gated module scope, which is only
// ever touched in the browser and is therefore safe.

import { browser } from '$app/environment';
import { page } from '$app/state';
import { applyTheme, DEFAULT_THEME, type ThemeId } from '$lib/themes';

let clientOverride = $state<ThemeId | null>(null);

export const theme = {
	get current(): ThemeId {
		if (clientOverride !== null) return clientOverride;
		const fromSession = page.data.session?.theme as ThemeId | undefined;
		return fromSession ?? DEFAULT_THEME;
	},

	/**
	 * Apply a theme immediately in the browser. The server-side
	 * update (via `updateSettings`) is the caller's responsibility;
	 * once the subsequent `invalidateAll()` re-resolves the session,
	 * the override can be cleared by calling `clearOverride()`.
	 */
	set(id: ThemeId): void {
		if (!browser) return;
		clientOverride = id;
		applyTheme(id);
	},

	clearOverride(): void {
		clientOverride = null;
	}
};
