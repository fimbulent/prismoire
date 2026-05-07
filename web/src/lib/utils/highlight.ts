/**
 * Wrap each occurrence of any case-insensitive token in `<mark>` inside
 * the given root element, walking text nodes in place.
 *
 * Used by the `/search` posts tab: post bodies render as full Markdown
 * (so the user sees the post in its native formatting) and this helper
 * runs after the Markdown component has produced its DOM, splicing
 * `<mark>` elements around query matches in plain prose only. The
 * server can't pre-mark the body without colliding with Markdown
 * syntax (a `<mark>` injected mid-link or mid-code-fence would corrupt
 * the rendered output), so the highlight pass moves to the client.
 *
 * Skipped subtrees:
 * - `<pre>`, `<code>` — code is byte-precise and shouldn't have
 *   markup spliced in; visual emphasis on a code identifier reads as
 *   noise.
 * - `<a>` — preserves the integrity of existing link surfaces and
 *   keeps the underline/colour treatment from being overridden.
 * - `<script>`, `<style>` — defensive; our Markdown renderer never
 *   produces these, but we skip them so the helper remains safe to
 *   call on arbitrary HTML.
 * - `<mark>` — avoids nesting marks if the helper is ever called
 *   twice on the same DOM.
 *
 * Tokens are escaped before being compiled into a regex, so user
 * input cannot smuggle alternation, anchors, or backreferences.
 */
export function highlightTokensInElement(root: HTMLElement, tokens: string[]): void {
	const cleanTokens = tokens
		.map((t) => t.trim())
		.filter((t) => t.length > 0);
	if (cleanTokens.length === 0) return;

	// Single regex with all tokens — alternation, case-insensitive,
	// global. Sort longest-first so e.g. ["graph", "graphs"] matches
	// "graphs" as one token, not as "graph" + leftover "s".
	cleanTokens.sort((a, b) => b.length - a.length);
	const escaped = cleanTokens.map(escapeRegex).join('|');
	const re = new RegExp(`(${escaped})`, 'gi');

	const SKIP = new Set(['PRE', 'CODE', 'A', 'SCRIPT', 'STYLE', 'MARK']);
	const stack: Node[] = [root];
	while (stack.length > 0) {
		const node = stack.pop()!;
		// Snapshot children before mutating — `wrapMatchesInTextNode`
		// replaces the text node with a fragment, which would shift the
		// live NodeList mid-iteration.
		for (const child of Array.from(node.childNodes)) {
			if (child.nodeType === Node.ELEMENT_NODE) {
				const el = child as HTMLElement;
				if (SKIP.has(el.tagName)) continue;
				stack.push(el);
			} else if (child.nodeType === Node.TEXT_NODE) {
				wrapMatchesInTextNode(child as Text, re);
			}
		}
	}
}

function wrapMatchesInTextNode(textNode: Text, re: RegExp): void {
	const text = textNode.nodeValue ?? '';
	if (!text) return;
	re.lastIndex = 0;
	const frag = document.createDocumentFragment();
	let lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = re.exec(text)) !== null) {
		if (match.index > lastIndex) {
			frag.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
		}
		const mark = document.createElement('mark');
		mark.textContent = match[0];
		frag.appendChild(mark);
		lastIndex = re.lastIndex;
		// Defensive guard against zero-width matches (shouldn't happen
		// after the empty-token filter above, but a malformed token
		// could still produce one).
		if (match[0].length === 0) re.lastIndex++;
	}
	if (lastIndex === 0) return; // no matches — leave the original node alone
	if (lastIndex < text.length) {
		frag.appendChild(document.createTextNode(text.slice(lastIndex)));
	}
	textNode.parentNode?.replaceChild(frag, textNode);
}

/**
 * Split a free-form search query into the same tokens the server's
 * FTS layer would consider — alphanumerics plus apostrophes and
 * intra-word hyphens, lowercased. Mirrors `snippet_tokens` in
 * `server/src/search.rs` so the client highlights exactly the words
 * the server matched on.
 */
export function searchTokens(query: string): string[] {
	const out: string[] = [];
	for (const raw of query.split(/\s+/)) {
		const cleaned = Array.from(raw)
			.filter((c) => /[\p{L}\p{N}'-]/u.test(c))
			.join('')
			.toLowerCase();
		if (cleaned.length > 0) out.push(cleaned);
	}
	return out;
}

function escapeRegex(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
