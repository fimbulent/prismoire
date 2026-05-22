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
	| 'rose-pine-moon'
	| 'rose-pine-dawn'
	| 'gruvbox-dark'
	| 'gruvbox-light'
	| 'kanagawa-wave'
	| 'kanagawa-dragon'
	| 'kanagawa-lotus'
	| 'nord'
	| 'nord-light'
	| 'everforest-dark'
	| 'everforest-light'
	| 'iceberg';

export interface ThemeMeta {
	id: ThemeId;
	name: string;
}

export const themes: ThemeMeta[] = [
	{ id: 'rose-pine', name: 'Rosé Pine' },
	{ id: 'rose-pine-moon', name: 'Rosé Pine Moon' },
	{ id: 'rose-pine-dawn', name: 'Rosé Pine Dawn' },
	{ id: 'gruvbox-dark', name: 'Gruvbox Dark' },
	{ id: 'gruvbox-light', name: 'Gruvbox Light' },
	{ id: 'kanagawa-wave', name: 'Kanagawa Wave' },
	{ id: 'kanagawa-dragon', name: 'Kanagawa Dragon' },
	{ id: 'kanagawa-lotus', name: 'Kanagawa Lotus' },
	{ id: 'nord', name: 'Nord' },
	{ id: 'nord-light', name: 'Nord Light' },
	{ id: 'everforest-dark', name: 'Everforest Dark' },
	{ id: 'everforest-light', name: 'Everforest Light' },
	{ id: 'iceberg', name: 'Iceberg' }
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
