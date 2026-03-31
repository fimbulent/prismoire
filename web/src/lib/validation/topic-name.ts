const MIN_CHARS = 3;
const MAX_CHARS = 30;
const MAX_BYTES = 120;

const LETTER_RE = /^\p{L}$/u;

function isLetter(ch: string): boolean {
	return LETTER_RE.test(ch);
}

function isAsciiDigit(ch: string): boolean {
	return ch >= '0' && ch <= '9';
}

function isAllowedChar(ch: string): boolean {
	return isLetter(ch) || isAsciiDigit(ch) || ch === ' ' || ch === '-';
}

/**
 * Validate a topic name against the same rules enforced server-side.
 *
 * Returns `null` if the name is valid, or a human-readable error message.
 * Does not check for mixed scripts — that is enforced only on the server.
 */
export function validateTopicName(raw: string): string | null {
	const trimmed = raw.trim();
	if (trimmed.length === 0) return 'Topic name must not be empty';

	const normalized = trimmed.normalize('NFC');

	let hasAlpha = false;

	for (const ch of normalized) {
		if (isLetter(ch)) {
			hasAlpha = true;
		} else if (!isAllowedChar(ch)) {
			return 'Topic name may only contain letters, numbers, spaces, and hyphens';
		}
	}

	if (!hasAlpha) return 'Topic name must contain at least one letter';

	const charCount = [...normalized].length;
	if (charCount < MIN_CHARS) return 'Topic name must be at least 3 characters';
	if (charCount > MAX_CHARS) return 'Topic name must be at most 30 characters';
	if (new TextEncoder().encode(normalized).length > MAX_BYTES) return 'Topic name is too long';

	const first = [...normalized][0];
	const last = [...normalized].at(-1)!;
	if (first === ' ' || first === '-' || last === ' ' || last === '-') {
		return 'Topic name must not start or end with a space or hyphen';
	}

	if (/[ -]{2}/.test(normalized)) {
		return 'Topic name must not contain consecutive spaces or hyphens';
	}

	return null;
}
