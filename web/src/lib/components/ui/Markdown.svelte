<script lang="ts">
	import { renderMarkdown, type MarkdownProfile } from '$lib/markdown';

	interface Props {
		source: string;
		profile?: MarkdownProfile;
	}

	let { source, profile = 'full' }: Props = $props();

	let html = $derived(renderMarkdown(source, profile));
</script>

<div class="markdown font-prose text-prose" class:prominent={profile === 'full'}>
	{@html html}
</div>

<style>
	/* Body prose styling. Body font-size, line-height, and family are
	   applied via Tailwind utilities on the wrapper (`text-prose`,
	   `font-prose`); this rule sheet only covers child-element
	   styling that those utilities can't reach.

	   Heading sizes follow a 1.200 (minor third) modular scale
	   anchored at the body size from `text-prose` (1.0625rem). All
	   vertical rhythm is single-direction (margin-bottom only) so
	   successive blocks compose predictably and never collapse
	   against each other. First-child resets aren't needed because
	   nothing has margin-top. Heading line-height is tightened
	   (1.25) for display use. */

	/* Rendering hints scoped to prose containers only.
	   - `font-optical-sizing: auto` pins the `opsz` axis to the
	     rendered px size — Source Serif 4 and Literata ship `opsz`
	     masters tuned per size. Without this, some browsers default
	     to a display master that looks thin and aliased at body size.
	     Harmless no-op for fonts without an `opsz` axis (e.g. our
	     static-hinted Vollkorn cuts).
	   - `text-rendering: optimizeLegibility` enables kerning and
	     discretionary ligatures. The cost scales with glyph count, so
	     a thread with 200 replies pays it across every reply body. We
	     restrict it to `.prominent` — only `<Markdown profile="full">`
	     instances (OP body, activity-feed thread starts) — where the
	     reader's attention budget justifies the layout cost. Replies
	     keep the browser default, which already enables standard
	     kerning + common ligatures via CSS Fonts Module 3. */
	.markdown {
		font-optical-sizing: auto;
		/* Allow soft hyphens on narrow columns (mobile, deep nesting).
		   `<html lang="en">` is set in app.html so the browser knows
		   which dictionary to consult; without that this is a no-op. */
		hyphens: auto;
		/* Defensive against pathological UGC: a 200-character unbroken
		   token (long URL, hex blob, base64) would otherwise force the
		   column wider than its container and break the layout. We
		   pair `anywhere` with the default `word-break: normal` so
		   ordinary words still break at hyphenation points or whitespace
		   — `anywhere` only kicks in when there's no other option. The
		   explicit `word-break: normal` is belt-and-braces against any
		   ancestor rule that might have set `break-all`. */
		overflow-wrap: anywhere;
		word-break: normal;
	}

	.markdown.prominent {
		text-rendering: optimizeLegibility;
	}

	.markdown :global(p) {
		margin-bottom: 0.75em;
		/* Avoid one-word last lines (widows). Modern browsers; older
		   browsers ignore the value and fall back to `wrap`. */
		text-wrap: pretty;
	}

	.markdown :global(p:last-child) {
		margin-bottom: 0;
	}

	.markdown :global(h1),
	.markdown :global(h2),
	.markdown :global(h3),
	.markdown :global(h4),
	.markdown :global(h5),
	.markdown :global(h6) {
		font-weight: 600;
		line-height: 1.25;
		margin-bottom: 0.5em;
		color: var(--text-primary);
		/* Balance multi-line headings so the last line isn't a stub. */
		text-wrap: balance;
	}

	/* 1.200 scale, capped one step below the natural ladder: in-body
	   h1 renders at the natural h2 size, h2 at h3, and h3 falls to
	   body size with weight-only distinction. The cap keeps the
	   *page* the document — thread title (rendered outside Markdown)
	   stays the largest type, and a stray `# Heading` in a post never
	   overshoots the chrome. h4–h6 stay at body size for the same
	   reason. */
	.markdown :global(h1) {
		font-size: 1.44em;
	}

	.markdown :global(h2) {
		font-size: 1.2em;
	}

	.markdown :global(strong) {
		font-weight: 600;
	}

	.markdown :global(a) {
		color: var(--link);
		text-decoration: underline;
		/* `0.15em` scales with the surrounding font-size, so links inside
		   headings get a proportionally larger gap than links in body
		   prose. `1px` thickness reads as a hairline at body sizes, which
		   looks better than the browser default (typically ~auto / 2px)
		   without sacrificing affordance. */
		text-underline-offset: 0.15em;
		text-decoration-thickness: 1px;
	}

	.markdown :global(a:hover) {
		color: var(--link-hover);
	}

	.markdown :global(blockquote) {
		border-left: 3px solid var(--border);
		padding-left: 1em;
		margin-bottom: 0.75em;
		color: var(--text-secondary);
	}

	.markdown :global(code) {
		font-family: var(--font-mono);
		font-size: 0.875em;
		background: var(--bg-surface-raised);
		padding: 0.15em 0.35em;
		border-radius: 4px;
	}

	.markdown :global(pre) {
		background: var(--bg-surface-raised);
		border: 1px solid var(--border);
		border-radius: 6px;
		padding: 0.75em 1em;
		margin-bottom: 0.75em;
		overflow-x: auto;
		/* Render `\t` as 4 spaces. Without this, browsers default to 8,
		   which makes nested code (Python, Go) look pathological. */
		tab-size: 4;
	}

	.markdown :global(pre code) {
		background: none;
		padding: 0;
		border-radius: 0;
	}

	.markdown :global(ul),
	.markdown :global(ol) {
		margin-bottom: 0.5em;
		padding-left: 1.5em;
	}

	.markdown :global(ul) {
		list-style-type: disc;
	}

	.markdown :global(ol) {
		list-style-type: decimal;
	}

	.markdown :global(li) {
		margin-bottom: 0.25em;
	}

	.markdown :global(li > input[type='checkbox']) {
		margin-right: 0.4em;
		vertical-align: middle;
	}

	.markdown :global(hr) {
		border: none;
		border-top: 1px solid var(--border);
		margin-bottom: 1.25em;
	}

	.markdown :global(table) {
		border-collapse: collapse;
		width: 100%;
		margin-bottom: 0.75em;
	}

	.markdown :global(th),
	.markdown :global(td) {
		border: 1px solid var(--border);
		padding: 0.4em 0.75em;
		text-align: left;
	}

	.markdown :global(th) {
		background: var(--bg-surface-raised);
		font-weight: 600;
	}

	.markdown :global(del) {
		text-decoration: line-through;
		color: var(--text-muted);
	}
</style>
