import { Marked, type Tokens } from 'marked';
import DOMPurify from 'dompurify';

export type MarkdownProfile = 'full' | 'reply';

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

	if (profile === 'reply') {
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

export function renderMarkdown(source: string, profile: MarkdownProfile = 'full'): string {
	const marked = profile === 'full' ? fullMarked : replyMarked;
	const raw = marked.parse(source) as string;
	return DOMPurify.sanitize(raw, SANITIZE_CONFIG);
}
