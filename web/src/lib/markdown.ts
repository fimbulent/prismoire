import { Marked, type Tokens } from 'marked';
import { markedSmartypants } from 'marked-smartypants';
import sanitizeHtml from 'sanitize-html';

export type MarkdownProfile = 'full' | 'reply' | 'bio';

/**
 * Per-post attachment lookup the markdown renderer consults when it
 * sees an `![alt](filename)` image. The map key is the canonical
 * `filename` (post-`sanitize_attachment_filename`) the author signed
 * into the post's attachment array, NOT a URL — that's how the bind
 * path resolves refs (`docs/attachments.md` §3), and the server
 * already enforced that every entry here is an image MIME and unique.
 *
 * Pass the map for OP posts (which can carry attachments); replies and
 * bios should pass `undefined` since they can't carry attachments and
 * we don't want a stray `![](something.png)` in a reply body to
 * inadvertently render an `<img>` against another post's blob.
 */
export interface MarkdownAttachment {
	/** Lower-case hex SHA-256 — drops into `/api/attachments/{hash}`. */
	content_hash: string;
	/** Canonical MIME from the upload classifier. Renderer treats
	 * anything not starting with `image/` as a non-image ref (which
	 * the bind-time validator already blocks, but keep it defensive). */
	mime: string;
}

export type MarkdownAttachments = Record<string, MarkdownAttachment>;

/** Build a `MarkdownAttachments` map from the server's per-post attachment
 *  list, keyed by filename so the renderer can resolve `![](filename)` refs.
 *  Returns `undefined` (not an empty object) when the input is missing or
 *  empty, so callers can pass the result straight to `<Markdown attachments={…}>`
 *  and skip the renderer's attachment-extension build cost on the (common)
 *  no-attachment path. Shared across PostCard, ProfileActivityPost, and the
 *  admin reports view; keeps the filename → {hash, mime} projection in one
 *  place so a future schema change touches one helper, not three call sites.
 */
export function buildAttachmentMap(
	list: { content_hash: string; filename: string; mime: string }[] | undefined
): MarkdownAttachments | undefined {
	if (!list || list.length === 0) return undefined;
	const map: MarkdownAttachments = {};
	for (const att of list) {
		map[att.filename] = { content_hash: att.content_hash, mime: att.mime };
	}
	return map;
}

/** Minimal HTML attribute escape for values we interpolate into the
 *  raw markdown output before it goes through `sanitize-html`. The
 *  sanitizer would catch most of these, but escaping at emit time also
 *  prevents an embedded `"` from breaking out of the attribute value
 *  and producing structurally-invalid HTML that the sanitizer then has
 *  to rewrite. Five-char escape (`& < > " '`) is enough for attribute
 *  context. */
function escapeHtmlAttr(s: string): string {
	return s
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

function isSafeUrl(url: string): boolean {
	try {
		const parsed = new URL(url, 'https://placeholder.invalid');
		return parsed.protocol === 'https:' || parsed.protocol === 'http:';
	} catch {
		return false;
	}
}

/** True only for an *absolute* http(s) URL — no relative-resolution
 *  fallback. Used by the image renderer to split external image syntax
 *  (`![](https://example.com/foo.png)`, which we keep as a link) from
 *  attachment-style refs (`![](foo.png)`, which the caller must resolve
 *  via an `attachments` map). Without a base URL, a bare filename like
 *  `foo.png` throws in the `URL` constructor and falls into the
 *  `catch`, so it's correctly classified as not-external. */
function isAbsoluteHttpUrl(url: string): boolean {
	try {
		const parsed = new URL(url);
		return parsed.protocol === 'https:' || parsed.protocol === 'http:';
	} catch {
		return false;
	}
}

// Auto-link patterns for inline mentions of users (@name) and rooms (/r/slug).
// Charsets and length bounds mirror server validation exactly — divergence
// would produce auto-links that silently 404 on the profile/room page.
//   Usernames: 3–20 Unicode letters/digits/`_`/`-` (see
//   `server/src/display_name.rs`).
//   Room slugs: 3–30 ASCII `[a-z0-9_]` (see `server/src/room_name.rs`).
// The lookbehind ensures the sigil is at a word boundary so we do not match
// inside emails (`foo@bar.com`) or nested path segments (`foo/r/bar`).
const USERNAME_CLASS = String.raw`\p{L}\p{N}_\-`;
const MENTION_START_RE = new RegExp(`(?<![${USERNAME_CLASS}])@[${USERNAME_CLASS}]`, 'u');
// Mention tokens accept the bare and dotted forms (Phase 9.5):
//   `@alice`             — bare; the profile route disambiguates if needed.
//   `@alice.a1b2c3d4`    — long form; the 8-hex pubkey-prefix selects exactly
//                          one user and survives a future skeleton collision.
// The suffix is exactly 8 lowercase hex chars (canonical pubkey prefix); the
// trailing lookahead still excludes the username class so the link doesn't
// swallow a following letter/number.
const MENTION_TOKEN_RE = new RegExp(
	`^@([${USERNAME_CLASS}]{3,20})(\\.[0-9a-f]{8})?(?![${USERNAME_CLASS}])`,
	'u'
);
const ROOM_START_RE = /(?<![/\w])\/r\/[a-z0-9_]/;
const ROOM_TOKEN_RE = /^\/r\/([a-z0-9_]{3,30})(?![a-z0-9_])/;

interface MentionToken {
	type: 'mention';
	raw: string;
	username: string;
	/// Optional `.{8hex}` suffix (without the leading dot) when the
	/// long form was written explicitly. Empty for the bare form;
	/// the renderer routes to `/@{username}` and the profile page
	/// disambiguates.
	pubkeyPrefix?: string;
}

interface RoomRefToken {
	type: 'roomRef';
	raw: string;
	slug: string;
}

const SANITIZE_CONFIG: sanitizeHtml.IOptions = {
	allowedTags: [
		'p',
		'br',
		'strong',
		'em',
		'del',
		'code',
		'pre',
		'blockquote',
		'ul',
		'ol',
		'li',
		'a',
		'h1',
		'h2',
		'h3',
		'h4',
		'h5',
		'h6',
		'hr',
		'table',
		'thead',
		'tbody',
		'tr',
		'th',
		'td',
		// `<img>` is only emitted by the image renderer below when the
		// `![](filename)` ref resolves to one of *this post's* attachments
		// (image MIME, server-validated). The renderer hard-codes
		// `/api/attachments/{hash}` as the src, so the sanitizer doesn't
		// need to allow arbitrary external image hosts — the
		// `transformTags.img` pass below rewrites any img the markdown
		// somehow produces back to its alt text if the src isn't an
		// `/api/attachments/` URL.
		'img',
		'figure',
		'figcaption',
		// `<span>` is emitted by the image renderer for unresolved
		// attachment refs (`.image-omitted`) — see the comment in the
		// `image()` renderer. Class-only attribute; no `style` per the
		// project's CSP policy.
		'span'
	],
	allowedAttributes: {
		a: ['href', 'title', 'target', 'rel'],
		img: ['src', 'alt', 'loading', 'decoding', 'class'],
		figure: ['class'],
		figcaption: ['class'],
		span: ['class']
	},
	allowedSchemes: ['http', 'https'],
	// Belt-and-braces: even if a future renderer change emits an `<img>`
	// pointing at an external URL, this transform drops the tag back to
	// its alt text unless the src is the same-origin attachment route
	// the OP renderer hard-codes. Keeps `<img src="https://evil.com/x.png">`
	// from surviving a raw `<img>` smuggled through a code-block edge case.
	transformTags: {
		img(tagName: string, attribs: Record<string, string>) {
			const src = attribs.src ?? '';
			if (!src.startsWith('/api/attachments/')) {
				return { tagName: 'span', attribs: {}, text: attribs.alt ?? '' };
			}
			return { tagName, attribs };
		}
	},
	allowProtocolRelative: false,
	disallowedTagsMode: 'discard'
};

function createMarked(profile: MarkdownProfile, attachments?: MarkdownAttachments): Marked {
	const marked = new Marked({
		gfm: true,
		breaks: true
	});

	// Smart-punctuation pass: curly quotes, em/en dashes, ellipsis.
	// Operates on token text after tokenization, so it skips `<code>`
	// and `<pre>` content automatically. Cost is negligible (~tens of
	// microseconds per post).
	marked.use(markedSmartypants());

	if (profile === 'reply' || profile === 'bio') {
		marked.use({
			tokenizer: {
				heading(_src: string): Tokens.Heading | undefined {
					return undefined;
				},
				hr(_src: string): Tokens.Hr | undefined {
					return undefined;
				},
				lheading(_src: string): Tokens.Heading | undefined {
					return undefined;
				}
			}
		});
	}

	if (profile === 'bio') {
		marked.use({
			tokenizer: {
				blockquote(_src: string): Tokens.Blockquote | undefined {
					return undefined;
				},
				table(_src: string): Tokens.Table | undefined {
					return undefined;
				},
				fences(_src: string): Tokens.Code | undefined {
					return undefined;
				},
				list(_src: string): Tokens.List | undefined {
					return undefined;
				}
			}
		});
	}

	marked.use({
		extensions: [
			{
				name: 'mention',
				level: 'inline',
				start(src: string) {
					return src.match(MENTION_START_RE)?.index;
				},
				tokenizer(src: string): MentionToken | undefined {
					const m = MENTION_TOKEN_RE.exec(src);
					if (!m) return undefined;
					// `m[2]` is the matched `.{8hex}` suffix (with the leading
					// dot) when present; strip the dot for storage so the
					// renderer can compose the link without re-parsing.
					const pubkeyPrefix = m[2]?.slice(1);
					return { type: 'mention', raw: m[0], username: m[1], pubkeyPrefix };
				},
				renderer(token) {
					const m = token as MentionToken;
					// Long form when the author wrote it; bare form
					// otherwise. The profile page emits `<link
					// rel="canonical">` either way, so a bare mention that
					// later collides remains stable.
					const path = m.pubkeyPrefix
						? `${encodeURIComponent(m.username)}.${m.pubkeyPrefix}`
						: encodeURIComponent(m.username);
					const href = `/@${path}`;
					const text = m.pubkeyPrefix
						? `@${m.username}.${m.pubkeyPrefix}`
						: `@${m.username}`;
					return `<a href="${href}">${text}</a>`;
				}
			},
			{
				name: 'roomRef',
				level: 'inline',
				start(src: string) {
					return src.match(ROOM_START_RE)?.index;
				},
				tokenizer(src: string): RoomRefToken | undefined {
					const m = ROOM_TOKEN_RE.exec(src);
					if (!m) return undefined;
					return { type: 'roomRef', raw: m[0], slug: m[1] };
				},
				renderer(token) {
					const r = token as RoomRefToken;
					const href = `/r/${encodeURIComponent(r.slug)}`;
					return `<a href="${href}">/r/${r.slug}</a>`;
				}
			}
		],
		renderer: {
			link({ href, title, tokens }) {
				const text = this.parser.parseInline(tokens);
				if (!isSafeUrl(href)) return text;
				const titleAttr = title ? ` title="${title}"` : '';
				return `<a href="${href}"${titleAttr} rel="nofollow noopener noreferrer" target="_blank">${text}</a>`;
			},
			image({ href, title, text }) {
				// Attachment-resolved inline image (`docs/attachments.md` §3):
				// `![alt](filename)` where `filename` is one of this post's
				// attachments. The bind-time validator already enforced
				// image-MIME-only and at-most-once-per-revision, so we
				// just emit the `<img>` and trust the resolution. The
				// hash-keyed src goes through the trust-gated
				// `/api/attachments/{hash}` route so visibility is
				// enforced at serve time.
				const att = attachments?.[href];
				if (att && att.mime.startsWith('image/')) {
					const src = `/api/attachments/${encodeURIComponent(att.content_hash)}`;
					const alt = escapeHtmlAttr(text || title || att.content_hash);
					// Markdown's third image argument — `![alt](file "caption")` —
					// becomes a visible <figcaption> below the image, centered
					// via the `.markdown-figure` scope in `Markdown.svelte`.
					// When a caption is present we drop the redundant `title`
					// hover tooltip on the <img>: hovering would otherwise
					// double-show the same text that's already visible below.
					if (title) {
						const caption = escapeHtmlAttr(title);
						return `<figure class="markdown-figure"><img src="${src}" alt="${alt}" loading="lazy" decoding="async" class="attachment-inline" /><figcaption class="markdown-figcaption">${caption}</figcaption></figure>`;
					}
					return `<figure class="markdown-figure"><img src="${src}" alt="${alt}" loading="lazy" decoding="async" class="attachment-inline" /></figure>`;
				}

				// External-URL image syntax in user content stays as a
				// safe link rather than an `<img>` — we don't want post
				// bodies hot-loading arbitrary external image hosts
				// (privacy + mixed-content). Only true absolute http(s)
				// URLs go down this branch: a bare filename like
				// `game.png` would resolve relative to the current page
				// and produce a broken link (e.g. `/search/game.png`),
				// so we route those to the "omitted" branch below.
				if (isAbsoluteHttpUrl(href)) {
					const label = text || title || href;
					const titleAttr = title ? ` title="${title}"` : '';
					return `<a href="${href}"${titleAttr} rel="nofollow noopener noreferrer" target="_blank">${label}</a>`;
				}

				// Attachment-style ref the caller didn't resolve. Three
				// reasons this branch fires:
				// 1. Caller doesn't pass an `attachments` map (search
				//    results, profile bio, etc. — surfaces where inline
				//    images are intentionally suppressed).
				// 2. The ref is a typo / dangling (post body mentions
				//    `game.png` but no attachment with that filename is
				//    bound).
				// 3. The map is passed but the ref's resolved attachment
				//    is non-image MIME (the bind-time validator should
				//    block this, but defence in depth).
				// Either way, a broken `<img>` or a fake link would be
				// worse than a small "image omitted" hint: the reader
				// sees that media exists in the source post without
				// being misled into clicking through to a 404.
				const label = text || title || href;
				return `<span class="image-omitted">[image: ${escapeHtmlAttr(label)}]</span>`;
			},
			html() {
				return '';
			},
			checkbox() {
				return '';
			}
		}
	});

	return marked;
}

const fullMarked = createMarked('full');
const replyMarked = createMarked('reply');
const bioMarked = createMarked('bio');

const BIO_SANITIZE_CONFIG: sanitizeHtml.IOptions = {
	allowedTags: ['p', 'br', 'strong', 'em', 'del', 'code', 'a', 'span'],
	allowedAttributes: {
		a: ['href', 'title', 'target', 'rel'],
		span: ['class']
	},
	allowedSchemes: ['http', 'https'],
	allowProtocolRelative: false,
	disallowedTagsMode: 'discard'
};

/**
 * Walk the markdown AST for `source` and return the `href` of every
 * inline image token in document order. Used by `PostCard` to suppress
 * the download chip for attachments that the body already inlines as an
 * `<img>` — keeps the rendered post from showing the same image twice
 * (once inline, once as a chip below).
 *
 * Mirrors the server-side `extract_inline_image_refs` in
 * `server/src/attachments/bind.rs` (pulldown_cmark): tokens inside
 * fenced/inline code are skipped, so a literal `![not-real](foo.png)`
 * inside a code block does not cause us to suppress `foo.png`'s chip.
 * The token-walk approach (vs. a raw regex) gives us that exclusion
 * for free.
 */
export function extractImageRefs(source: string): string[] {
	const refs: string[] = [];
	const lexer = new Marked({ gfm: true, breaks: true });
	lexer.use({
		walkTokens(token) {
			if (token.type === 'image') {
				const href = (token as Tokens.Image).href;
				if (typeof href === 'string') refs.push(href);
			}
		}
	});
	// `parse` is the only entry point that fires `walkTokens` — calling
	// the lexer directly would return tokens but skip the walk callback.
	// We discard the rendered HTML; the side effect is what we want.
	lexer.parse(source);
	return refs;
}

export function renderMarkdown(
	source: string,
	profile: MarkdownProfile = 'full',
	attachments?: MarkdownAttachments
): string {
	// When the caller has attachments to resolve we build a fresh Marked
	// instance closed over the map. The three cached instances at module
	// scope cover the (very common) attachment-less paths (replies, bios,
	// preview-without-attachments) so the typical post render still skips
	// the extension setup cost. Per-render rebuild is fine for OP posts —
	// markdown rendering is ~tens of microseconds and posts are not
	// rendered in tight loops. Importantly, the rebuilt instance is local
	// to this call, so no module-level mutable state leaks under SSR.
	const marked =
		attachments && Object.keys(attachments).length > 0
			? createMarked(profile, attachments)
			: profile === 'full'
				? fullMarked
				: profile === 'bio'
					? bioMarked
					: replyMarked;
	const raw = marked.parse(source) as string;
	const config = profile === 'bio' ? BIO_SANITIZE_CONFIG : SANITIZE_CONFIG;
	return sanitizeHtml(raw, config);
}
