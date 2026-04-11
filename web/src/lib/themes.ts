// Theme catalogue: the list of palette ids exposed to the settings
// picker plus a small `applyTheme` helper that flips the `data-theme`
// attribute on `<html>` at runtime.
//
// Palette CSS variables live in `src/app.css` under
// `[data-theme="<id>"]` selectors — this file is only the runtime
// metadata the picker needs (id + display name). Keep the id set here
// in sync with the blocks in `app.css`.

export type ThemeId =
	| 'rose-pine'
	| 'nord'
	| 'everforest'
	| 'midnight-blue'
	| 'warm-ember'
	| 'stone'
	| 'moss'
	| 'coral'
	| 'blueprint';

export interface ThemeMeta {
	id: ThemeId;
	name: string;
}

export const themes: ThemeMeta[] = [
	{ id: 'rose-pine', name: 'Rosé Pine' },
	{ id: 'nord', name: 'Nord' },
	{ id: 'everforest', name: 'Everforest' },
	{ id: 'midnight-blue', name: 'Midnight Blue' },
	{ id: 'warm-ember', name: 'Warm Ember' },
	{ id: 'stone', name: 'Stone' },
	{ id: 'moss', name: 'Moss' },
	{ id: 'coral', name: 'Coral' },
	{ id: 'blueprint', name: 'Blueprint' }
];

export const DEFAULT_THEME: ThemeId = 'rose-pine';

/**
 * Apply a theme in the browser by flipping the `data-theme` attribute on
 * `<html>`. Each palette is defined as a `[data-theme="<id>"]` block in
 * `src/app.css`, so switching themes is a single attribute write — no
 * CSSOM `setProperty` calls and no `style="..."` attribute. This keeps
 * us clear of `style-src-attr` under our nonce-based CSP (Firefox
 * enforces `style-src-attr` on property-level CSSOM assignment too, so
 * we cannot rely on `element.style.setProperty` being "safe by spec").
 *
 * Server-side, `src/hooks.server.ts` sets the initial `data-theme`
 * attribute via `transformPageChunk` so SSR renders the correct palette
 * on first byte.
 */
export function applyTheme(id: ThemeId): void {
	if (typeof document === 'undefined') return;
	document.documentElement.setAttribute('data-theme', id);
}
