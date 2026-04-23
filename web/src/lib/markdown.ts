import { Marked, type Tokens } from 'marked';
import sanitizeHtml from 'sanitize-html';

export type MarkdownProfile = 'full' | 'reply' | 'bio';

function isSafeUrl(url: string): boolean {
	try {
		const parsed = new URL(url, 'https://placeholder.invalid');
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
const MENTION_TOKEN_RE = new RegExp(
	`^@([${USERNAME_CLASS}]{3,20})(?![${USERNAME_CLASS}])`,
	'u'
);
const ROOM_START_RE = /(?<![/\w])\/r\/[a-z0-9_]/;
const ROOM_TOKEN_RE = /^\/r\/([a-z0-9_]{3,30})(?![a-z0-9_])/;

interface MentionToken {
	type: 'mention';
	raw: string;
	username: string;
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
		'td'
	],
	allowedAttributes: {
		a: ['href', 'title', 'target', 'rel']
	},
	allowedSchemes: ['http', 'https'],
	allowProtocolRelative: false,
	disallowedTagsMode: 'discard'
};

function createMarked(profile: MarkdownProfile): Marked {
	const marked = new Marked({
		gfm: true,
		breaks: true
	});

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
					return { type: 'mention', raw: m[0], username: m[1] };
				},
				renderer(token) {
					const m = token as MentionToken;
					const href = `/@${encodeURIComponent(m.username)}`;
					return `<a href="${href}">@${m.username}</a>`;
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
				if (!isSafeUrl(href)) return text || title || '';
				const label = text || title || href;
				const titleAttr = title ? ` title="${title}"` : '';
				return `<a href="${href}"${titleAttr} rel="nofollow noopener noreferrer" target="_blank">${label}</a>`;
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
	allowedTags: ['p', 'br', 'strong', 'em', 'del', 'code', 'a'],
	allowedAttributes: {
		a: ['href', 'title', 'target', 'rel']
	},
	allowedSchemes: ['http', 'https'],
	allowProtocolRelative: false,
	disallowedTagsMode: 'discard'
};

export function renderMarkdown(source: string, profile: MarkdownProfile = 'full'): string {
	const marked = profile === 'full' ? fullMarked : profile === 'bio' ? bioMarked : replyMarked;
	const raw = marked.parse(source) as string;
	const config = profile === 'bio' ? BIO_SANITIZE_CONFIG : SANITIZE_CONFIG;
	return sanitizeHtml(raw, config);
}
