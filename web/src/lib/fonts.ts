// Prose-font catalogue: the list of self-hosted font ids exposed to
// the settings picker, plus a small `applyFont` helper that flips the
// `data-font` attribute on `<html>` at runtime.
//
// `@font-face` declarations and `[data-font="<id>"]` selectors live in
// `src/app.css` — this file is only the runtime metadata the picker
// needs (id, display name, category). Keep the id set here in sync
// with the blocks in `app.css` and the `VALID_FONTS` list in
// `server/src/settings.rs` (the server-side test
// `font_slugs_exist_in_frontend` enforces the latter at compile time).
//
// Selection only applies to rendered prose (Markdown post bodies).
// UI chrome continues to use the default system stack from
// `--font-sans` so nav, buttons, and form widgets stay calm and
// consistent across font choices.
//
// Files: each family ships as a Latin+latin-ext variable WOFF2 under
// `static/fonts/<id>/<id>.woff2` (upright) and `<id>-italic.woff2`
// (italic). Subsets and conversion live in the build steps documented
// alongside the font directory.

export type FontId =
	| 'inter'
	| 'ibm-plex-sans'
	| 'source-sans-3'
	| 'literata'
	| 'source-serif-4'
	| 'vollkorn';

export type FontCategory = 'sans' | 'serif';

export interface FontMeta {
	id: FontId;
	name: string;
	category: FontCategory;
}

export const fonts: FontMeta[] = [
	{ id: 'inter', name: 'Inter', category: 'sans' },
	{ id: 'ibm-plex-sans', name: 'IBM Plex Sans', category: 'sans' },
	{ id: 'source-sans-3', name: 'Source Sans 3', category: 'sans' },
	{ id: 'literata', name: 'Literata', category: 'serif' },
	{ id: 'source-serif-4', name: 'Source Serif 4', category: 'serif' },
	{ id: 'vollkorn', name: 'Vollkorn', category: 'serif' }
];

export const DEFAULT_FONT: FontId = 'vollkorn';

/**
 * Apply a prose font in the browser by flipping the `data-font`
 * attribute on `<html>`. Each family is bound to a `--font-prose`
 * value via a `[data-font="<id>"]` block in `src/app.css`, so
 * switching fonts is a single attribute write — no CSSOM
 * `setProperty` calls and no `style="..."` attribute. This keeps us
 * clear of `style-src-attr` under the nonce-based CSP.
 *
 * Server-side, `src/hooks.server.ts` sets the initial `data-font`
 * attribute via `transformPageChunk` so SSR renders prose in the
 * user's chosen face on first byte (no FOUT beyond the WOFF2 fetch
 * itself).
 */
export function applyFont(id: FontId): void {
	if (typeof document === 'undefined') return;
	document.documentElement.setAttribute('data-font', id);
}
