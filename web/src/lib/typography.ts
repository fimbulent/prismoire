// Smart-punctuation pass for short plain-text strings (thread titles,
// room names in chrome, anything we render outside the markdown
// pipeline). For markdown bodies, use `marked-smartypants` via
// `markdown.ts` instead — that handles `<code>` / `<pre>` skipping,
// which this function deliberately does not.
//
// Rules follow the Markdown convention used by `marked-smartypants`
// in default mode:
//   ---       em dash (U+2014)
//   --        en dash (U+2013)
//   ...       horizontal ellipsis (U+2026)
//   "foo"     curly double quotes — open/close paired by context
//   'foo'     curly single quotes — open/close paired by context
//   word's    typographic apostrophe (U+2019) inside contractions
//
// Known limitation: a leading `'` is always treated as an opening
// single quote, so elisions like `'twas` or `'90s` come out with the
// wrong glyph. Acceptable for thread titles where elisions are rare;
// the proper fix is a tokenizer-aware pass like the one in
// SmartyPants.pl, which is overkill here.

const ELLIPSIS = '\u2026';
const EM_DASH = '\u2014';
const EN_DASH = '\u2013';
const LSQUO = '\u2018';
const RSQUO = '\u2019';
const LDQUO = '\u201C';
const RDQUO = '\u201D';

export function smartypants(text: string): string {
	if (!text) return text;
	return text
		.replace(/---/g, EM_DASH)
		.replace(/--/g, EN_DASH)
		.replace(/\.\.\./g, ELLIPSIS)
		// Closing single after a word/digit/punct is an apostrophe or
		// a closing quote — both render as U+2019.
		.replace(/([\p{L}\p{N}.!?])'/gu, `$1${RSQUO}`)
		// Any remaining `'` is an opening single quote.
		.replace(/'/g, LSQUO)
		// Closing double after a word/digit/punct.
		.replace(/([\p{L}\p{N}.!?])"/gu, `$1${RDQUO}`)
		// Any remaining `"` is an opening double quote.
		.replace(/"/g, LDQUO);
}
