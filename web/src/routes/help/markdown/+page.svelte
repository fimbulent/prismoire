<script lang="ts">
	import Markdown from '$lib/components/ui/Markdown.svelte';
</script>

<!--
	The example snippet renders side-by-side panels: a `<pre>` showing the raw
	Markdown source on the left, and a real `<Markdown>` render of the same
	source on the right. On mobile the two panels stack. Using `<Markdown>`
	for the "Result" side guarantees the demo matches what users actually
	see in posts — no re-implementing the renderer in HTML.
-->
{#snippet example(source: string)}
	<div class="grid md:grid-cols-2 bg-bg-surface border border-border rounded-md overflow-hidden my-4">
		<div class="bg-bg-surface-raised p-4 border-b md:border-b-0 md:border-r border-border">
			<div class="text-[0.7rem] uppercase font-bold tracking-wider text-text-muted mb-2 font-sans">
				You type
			</div>
			<pre class="font-prose text-prose text-text-primary whitespace-pre-wrap break-words m-0">{source}</pre>
		</div>
		<div class="p-4">
			<div class="text-[0.7rem] uppercase font-bold tracking-wider text-text-muted mb-2 font-sans">
				What appears
			</div>
			<Markdown {source} />
		</div>
	</div>
{/snippet}

<article>
	<h1 class="text-3xl font-bold leading-tight mb-4">Markdown</h1>

	<p class="text-text-secondary mb-3">
		Prismoire uses <strong>Markdown</strong> for formatting posts and replies. Markdown lets you
		add structure such as headings, lists, links, or emphasis by typing plain characters that get turned
		into formatted text when your post is rendered.
	</p>

	<p class="text-text-secondary mb-8">
		Each example below shows what you type on the left and what appears on the right.
	</p>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Bold and italic</h2>
		{@render example('**bold text** and *italic text*')}
		<p class="text-text-secondary">
			You can also use
			<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">__bold__</code>
			and
			<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">_italic_</code>
			if you prefer underscores.
		</p>
	</section>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Strikethrough</h2>
		{@render example('~~no longer accurate~~')}
	</section>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Links</h2>
		{@render example('[the project page](https://example.com)')}
	</section>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Mentions and rooms</h2>
		<p class="text-text-secondary mb-2">
			Type a username with an
			<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">@</code>
			prefix to link to that user's profile. Type a room with a
			<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">/r/</code>
			prefix to link to the room.
		</p>
		{@render example('hello @alice, see /r/general for context')}
	</section>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Headings</h2>
		<p class="text-text-secondary mb-2">
			Start a line with one or more
			<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">#</code>
			characters followed by a space. More
			<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">#</code>
			means a smaller heading.
		</p>
		{@render example(`# Top-level heading
## Sub-heading
### Smaller heading`)}
		<p class="text-text-muted text-sm">
			Headings work only in thread bodies; not replies.
		</p>
	</section>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Lists</h2>
		<p class="text-text-secondary mb-2">
			Unordered lists use
			<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">-</code>
			or
			<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">*</code>
			at the start of each line. Ordered lists use
			<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">1.</code>,
			<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">2.</code>,
			and so on.
		</p>
		{@render example(`- apples
- oranges
- bananas

1. wake up
2. drink coffee
3. start thinking`)}
	</section>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Blockquotes</h2>
		<p class="text-text-secondary mb-2">
			Start a line with
			<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">&gt;</code>
			to quote.
		</p>
		{@render example("> Reading is a means of thinking with another person's mind.")}
	</section>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Inline code</h2>
		<p class="text-text-secondary mb-2">Wrap text with single backticks to mark it as code.</p>
		{@render example('Use `map` and `filter` together.')}
	</section>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Code blocks</h2>
		<p class="text-text-secondary mb-2">
			Fence a block of code with three backticks on their own lines. Whitespace and indentation
			inside the block are preserved exactly.
		</p>
		{@render example(`\`\`\`
function greet(name) {
  return "hello, " + name;
}
\`\`\``)}
	</section>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Tables</h2>
		{@render example(`| Fruit  | Color  |
| ------ | ------ |
| apple  | red    |
| banana | yellow |`)}
	</section>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Horizontal rule</h2>
		<p class="text-text-secondary mb-2">Three or more dashes on their own line draw a divider.</p>
		{@render example('---')}
	</section>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Line breaks and paragraphs</h2>
		<p class="text-text-secondary">
			A single newline starts a new line. A blank line starts a new paragraph. You usually don't
			have to think about this — type the way you'd type an email.
		</p>
	</section>

	<section class="mb-8">
		<h2 class="text-xl font-semibold mb-2">Smart punctuation</h2>
		<p class="text-text-secondary mb-2">A few characters get tidied up automatically as you write:</p>
		{@render example(`"Hi," she said. "Pages 1--5 cover the basics --- skim them..."`)}
		<ul class="text-text-secondary list-disc pl-6 space-y-1 mt-3">
			<li>
				<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">--</code>
				becomes an en dash (–)
			</li>
			<li>
				<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">---</code>
				becomes an em dash (—)
			</li>
			<li>
				<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">...</code>
				becomes an ellipsis (…)
			</li>
			<li>Straight quotes become curly quotes</li>
		</ul>
	</section>

	<section class="bg-bg-surface border border-border rounded-md p-5 mb-6">
		<h2 class="text-xl font-semibold mb-2">What's not supported</h2>
		<p class="text-text-secondary mb-3">
			A few common Markdown features are intentionally left out so posts stay tidy:
		</p>
		<ul class="text-text-secondary list-disc pl-6 space-y-2">
			<li>
				<strong class="text-text-primary">Images.</strong> Image syntax is rendered as a plain link,
				not an embedded image.
			</li>
			<li>
				<strong class="text-text-primary">Raw HTML.</strong> HTML tags inside your post are stripped
				out.
			</li>
			<li>
				<strong class="text-text-primary">Task list checkboxes.</strong>
				<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">[ ]</code>
				and
				<code class="font-mono text-[0.875em] bg-bg-surface-raised text-text-primary px-1.5 py-0.5 rounded">[x]</code>
				markers in list items are removed.
			</li>
		</ul>
	</section>

	<section class="bg-bg-surface border border-border rounded-md p-5">
		<h2 class="text-xl font-semibold mb-2">Where each feature works</h2>
		<p class="text-text-secondary">
			<strong class="text-text-primary">Thread bodies</strong> support every feature on this page.
			<strong class="text-text-primary">Replies</strong> omit headings and horizontal rules so nested
			conversations stay compact.
			<strong class="text-text-primary">Bios</strong> on your profile are deliberately minimal — only
			paragraphs, bold, italic, strikethrough, inline code, and links.
		</p>
	</section>
</article>
