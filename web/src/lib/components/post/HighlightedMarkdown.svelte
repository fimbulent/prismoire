<!--
	Markdown body with optional client-side query-token highlighting.

	Wraps the shared `Markdown` component, runs the highlight pass after
	the markdown HTML has been mounted. The shared `<mark>` styling is
	scoped to this wrapper via `:global(mark)` so the highlight colour
	stays consistent across all uses (search posts tab today; future
	per-post highlight surfaces).

	When `tokens` is empty (the common non-search case), the highlight
	effect is a no-op and there's no measurable cost over a bare
	`Markdown` render.
-->
<script lang="ts">
	import Markdown from '$lib/components/ui/Markdown.svelte';
	import type { MarkdownProfile } from '$lib/markdown';
	import { highlightTokensInElement } from '$lib/utils/highlight';

	interface Props {
		source: string;
		profile?: MarkdownProfile;
		/**
		 * Tokens to wrap in `<mark>` after the markdown renders. The
		 * caller is responsible for tokenising the query (typically
		 * via `searchTokens` from `$lib/utils/highlight`) so multiple
		 * sites use a single tokenisation rule.
		 */
		tokens?: string[];
	}

	let { source, profile = 'full', tokens = [] }: Props = $props();

	let host = $state<HTMLDivElement | null>(null);

	// `Markdown` rebuilds its inner HTML whenever `source` changes via
	// `{@html}`, which clears any prior `<mark>` wrappers automatically.
	// The effect re-runs on either dep changing — `tokens.join('\x00')`
	// turns the array into a stable key so token-set changes also
	// retrigger highlighting (rare in practice — a search query change
	// reloads the page — but kept correct for free).
	$effect(() => {
		const _src = source;
		const _key = tokens.join('\x00');
		if (!host) return;
		if (tokens.length === 0) return;
		highlightTokensInElement(host, tokens);
	});
</script>

<div bind:this={host} class="highlight-host">
	<Markdown {source} {profile} />
</div>

<style>
	/*
	 * Highlight styling for query tokens. The previous version set
	 * `background: var(--color-accent-muted)`, but `--accent-muted` is
	 * tuned per-palette as a *foreground* color (3:1 on bg-hover) — using
	 * it as a background under text-primary is the wrong contrast
	 * direction and reads as washed-out.
	 *
	 * Instead: a low-opacity accent tint (stays inside text-primary's
	 * audited contrast envelope because it composites onto the page bg)
	 * plus an inset ring at higher opacity so the highlight reads
	 * clearly as a delimited block even when the tint is faint. Both
	 * stops are derived via `color-mix` from the per-palette
	 * `--accent`, so the highlight remains theme-safe across all
	 * palettes without needing a dedicated `--mark-bg` token.
	 */
	.highlight-host :global(mark) {
		background-color: color-mix(in srgb, var(--accent) 22%, transparent);
		box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--accent) 55%, transparent);
		color: inherit;
		padding: 0 0.15em;
		border-radius: 3px;
	}
</style>
