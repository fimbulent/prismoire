<script lang="ts">
	import { renderMarkdown, type MarkdownProfile } from '$lib/markdown';

	interface Props {
		source: string;
		profile?: MarkdownProfile;
	}

	let { source, profile = 'full' }: Props = $props();

	let html = $derived(renderMarkdown(source, profile));
</script>

<div class="markdown">
	{@html html}
</div>

<style>
	.markdown {
		line-height: 1.75;
	}

	.markdown :global(p) {
		margin-bottom: 0.75em;
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
		margin-top: 1.25em;
		margin-bottom: 0.5em;
		color: var(--text-primary);
	}

	.markdown :global(h1) {
		font-size: 1.5em;
	}

	.markdown :global(h2) {
		font-size: 1.25em;
	}

	.markdown :global(h3) {
		font-size: 1.1em;
	}

	.markdown :global(h1:first-child),
	.markdown :global(h2:first-child),
	.markdown :global(h3:first-child),
	.markdown :global(h4:first-child),
	.markdown :global(h5:first-child),
	.markdown :global(h6:first-child) {
		margin-top: 0;
	}

	.markdown :global(strong) {
		font-weight: 600;
	}

	.markdown :global(a) {
		color: var(--link);
		text-decoration: underline;
		text-underline-offset: 2px;
	}

	.markdown :global(a:hover) {
		color: var(--link-hover);
	}

	.markdown :global(blockquote) {
		border-left: 3px solid var(--border);
		padding-left: 1em;
		margin: 0.75em 0;
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
		margin: 0.75em 0;
		overflow-x: auto;
	}

	.markdown :global(pre code) {
		background: none;
		padding: 0;
		border-radius: 0;
	}

	.markdown :global(ul),
	.markdown :global(ol) {
		margin: 0.5em 0;
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
		margin: 1.25em 0;
	}

	.markdown :global(table) {
		border-collapse: collapse;
		width: 100%;
		margin: 0.75em 0;
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
