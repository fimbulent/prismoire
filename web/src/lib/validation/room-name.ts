const MIN_CHARS = 3;
const MAX_CHARS = 30;

const RESERVED_SLUGS = ['top', 'all', 'favorites', 'new', 'public'];

/**
 * Validate a room slug against the same rules enforced server-side.
 *
 * Returns `null` if the slug is valid, or a human-readable error message.
 */
export function validateRoomSlug(raw: string): string | null {
	const slug = raw.trim().toLowerCase();
	if (slug.length === 0) return 'Room name must not be empty';

	for (const ch of slug) {
		if (
			!(ch >= 'a' && ch <= 'z') &&
			!(ch >= '0' && ch <= '9') &&
			ch !== '_'
		) {
			return 'Room name may only contain lowercase letters, numbers, and underscores';
		}
	}

	let hasAlpha = false;
	for (const ch of slug) {
		if (ch >= 'a' && ch <= 'z') {
			hasAlpha = true;
			break;
		}
	}
	if (!hasAlpha) return 'Room name must contain at least one letter';

	if (slug.length < MIN_CHARS) return `Room name must be at least ${MIN_CHARS} characters`;
	if (slug.length > MAX_CHARS) return `Room name must be at most ${MAX_CHARS} characters`;

	if (slug.startsWith('_') || slug.endsWith('_')) {
		return 'Room name must not start or end with an underscore';
	}

	if (slug.includes('__')) {
		return 'Room name must not contain consecutive underscores';
	}

	if (RESERVED_SLUGS.includes(slug)) {
		return `Room name "${slug}" is reserved`;
	}

	return null;
}
