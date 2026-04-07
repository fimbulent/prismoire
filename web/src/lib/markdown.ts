import { Marked, type Tokens } from 'marked';
import DOMPurify from 'dompurify';

export type MarkdownProfile = 'full' | 'reply' | 'bio';

function isSafeUrl(url: string): boolean {
	try {
		const parsed = new URL(url, 'https://placeholder.invalid');
		return parsed.protocol === 'https:' || parsed.protocol === 'http:';
	} catch {
		return false;
	}
}

const SANITIZE_CONFIG = {
	ALLOWED_TAGS: [
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
	],
	ALLOWED_ATTR: ['href', 'title'],
	ALLOW_DATA_ATTR: false,
	ADD_ATTR: ['target'],
	FORBID_TAGS: ['img', 'iframe', 'style', 'script', 'object', 'embed', 'form']
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

const BIO_SANITIZE_CONFIG = {
	ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'del', 'code', 'a'],
	ALLOWED_ATTR: ['href', 'title'],
	ALLOW_DATA_ATTR: false,
	ADD_ATTR: ['target'],
	FORBID_TAGS: ['img', 'iframe', 'style', 'script', 'object', 'embed', 'form']
};

export function renderMarkdown(source: string, profile: MarkdownProfile = 'full'): string {
	const marked = profile === 'full' ? fullMarked : profile === 'bio' ? bioMarked : replyMarked;
	const raw = marked.parse(source) as string;
	const config = profile === 'bio' ? BIO_SANITIZE_CONFIG : SANITIZE_CONFIG;
	return DOMPurify.sanitize(raw, config);
}
