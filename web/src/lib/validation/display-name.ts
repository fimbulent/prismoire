/** Minimum number of Unicode characters in a display name. */
const MIN_CHARS = 3;
/** Maximum number of Unicode characters in a display name. */
const MAX_CHARS = 20;
/** Maximum UTF-8 byte length of a display name. */
const MAX_BYTES = 64;

/// Matches Unicode letters (approximation via Unicode property escape).
const LETTER_RE = /^\p{L}$/u;

function isLetter(ch: string): boolean {
	return LETTER_RE.test(ch);
}

function isAsciiDigit(ch: string): boolean {
	return ch >= '0' && ch <= '9';
}

function isAllowedChar(ch: string): boolean {
	return isLetter(ch) || isAsciiDigit(ch) || ch === '_' || ch === '-';
}

/**
 * Validate a display name against the same rules enforced server-side.
 *
 * Returns `null` if the name is valid, or a human-readable error message.
 * Does not check for mixed scripts or confusable skeletons — those are
 * enforced only on the server.
 */
export function validateDisplayName(raw: string): string | null {
	const trimmed = raw.trim();
	if (trimmed.length === 0) return 'Display name must not be empty';

	const normalized = trimmed.normalize('NFC');

	let hasAlpha = false;

	for (const ch of normalized) {
		if (isLetter(ch)) {
			hasAlpha = true;
		} else if (!isAllowedChar(ch)) {
			return 'Display name may only contain letters, numbers, hyphens, and underscores';
		}
	}

	if (!hasAlpha) return 'Display name must contain at least one letter';

	const charCount = [...normalized].length;
	if (charCount < MIN_CHARS) return 'Display name must be at least 3 characters';
	if (charCount > MAX_CHARS) return 'Display name must be at most 20 characters';
	if (new TextEncoder().encode(normalized).length > MAX_BYTES) return 'Display name is too long';

	const first = normalized[0];
	const last = [...normalized].at(-1)!;
	if (first === '_' || first === '-' || last === '_' || last === '-') {
		return 'Display name must not start or end with a hyphen or underscore';
	}

	if (/[-_]{2}/.test(normalized)) {
		return 'Display name must not contain consecutive hyphens or underscores';
	}

	return null;
}
