import { ApiRequestError, type ErrorCode } from '$lib/api/auth';

/**
 * User-facing message catalog for every backend {@link ErrorCode}.
 *
 * Keys mirror the Rust `ErrorCode` enum in `server/src/error.rs` and
 * the `ErrorCode` TS union in `$lib/api/auth`. Adding a new variant
 * on the backend requires adding an entry here; TypeScript will flag
 * any missing keys because `ERROR_MESSAGES` is typed as a total
 * `Record<ErrorCode, string>`.
 *
 * Messages are intentionally terse and neutral — they should read
 * well inline in a form-field error, a toast, or a full page error.
 * Use plain present tense; avoid placeholder interpolation (dynamic
 * limits live in the legacy `message` field instead).
 */
const ERROR_MESSAGES: Record<ErrorCode, string> = {
	// Auth / session
	unauthenticated: 'You need to sign in to do that.',
	forbidden: "You don't have permission to do that.",
	invalid_challenge: 'Authentication challenge expired. Please try again.',
	passkey_ceremony_failed: 'Passkey authentication failed. Please try again.',
	user_not_found: 'User not found.',
	no_credentials: 'No passkeys are registered for this account.',
	invalid_display_name: 'Display name is invalid.',
	display_name_taken: 'That display name is already taken.',
	invalid_signature: 'Content signature is invalid.',
	not_own_profile: 'You can only edit your own profile.',

	// Invites
	invite_not_found: 'Invite not found.',
	invite_expired: 'This invite code has expired.',
	invite_invalid: 'Invalid invite code.',
	invite_exhausted: 'This invite code has been fully used.',
	invite_required: 'An invite code is required to sign up.',
	invite_max_uses_invalid: 'Max uses must be at least 1.',
	invite_expiry_invalid: 'Invite expiry is out of range.',

	// Setup
	setup_already_complete: 'Instance setup has already been completed.',
	setup_token_invalid: 'Invalid setup token.',
	setup_token_missing: 'No setup token is configured on the server.',

	// Rooms
	room_not_found: 'Room not found.',
	invalid_room_slug: 'Room slug is invalid.',
	announcements_admin_only: 'Only admins can post in announcements.',

	// Threads
	thread_not_found: 'Thread not found.',
	thread_locked: 'This thread is locked.',
	thread_already_locked: 'Thread is already locked.',
	thread_not_locked: 'Thread is not locked.',
	invalid_cursor: 'Invalid pagination cursor.',
	invalid_sort_mode: 'Invalid sort mode.',
	seen_ids_exceeded: 'Too many seen thread IDs in this request.',

	// Posts
	post_not_found: 'Post not found.',
	invalid_post_body: 'Post content is invalid.',
	invalid_thread_title: 'Thread title is invalid.',
	post_retracted: 'This post has been retracted and cannot be edited.',
	post_already_retracted: 'Post is already retracted.',
	not_post_author: 'You are not the author of this post.',
	parent_thread_mismatch: 'That parent post does not belong to this thread.',
	parent_retracted: 'Cannot reply to a retracted post.',

	// Trust
	self_trust_edge: 'You cannot set a trust edge on yourself.',
	no_trust_edge: 'No trust edge to remove.',
	invalid_trust_direction: 'Invalid trust direction.',

	// Misc user
	bio_too_long: 'Bio is too long.',

	// Admin
	admin_required: 'Admin access required.',
	reason_required: 'A reason is required for this action.',

	// Settings
	invalid_theme: 'Invalid theme.',

	// Catch-all
	bad_request: 'The request was invalid.',
	rate_limited: 'You are doing that too often. Please slow down.',
	internal: 'Something went wrong. Please try again.'
};

/**
 * Look up the user-facing string for a given error code. Returns the
 * generic `internal` message if the code is unknown — this lets the
 * frontend stay compatible with a server that ships a new code we
 * haven't mapped yet.
 */
export function messageForCode(code: ErrorCode): string {
	return ERROR_MESSAGES[code] ?? 'Something went wrong. Please try again.';
}

/**
 * Resolve an arbitrary caught value into a user-facing string.
 *
 * - {@link ApiRequestError}: prefers the mapped `code` message; falls
 *   back to the legacy server-provided `message` when the code is
 *   `internal` or unknown (so older backends still render something
 *   sensible).
 * - Other `Error` instances: returns `fallback`.
 * - Anything else: returns `fallback`.
 *
 * Pass a domain-specific `fallback` (e.g. `'Failed to create room'`)
 * so unexpected shapes still produce a useful message.
 */
export function errorMessage(e: unknown, fallback = 'Something went wrong'): string {
	if (e instanceof ApiRequestError) {
		// If the server sent a known code, trust the catalog.
		if (e.code && e.code !== 'internal' && e.code in ERROR_MESSAGES) {
			return ERROR_MESSAGES[e.code];
		}
		// Otherwise fall back to the legacy `message` string — this
		// keeps the UX working against a server that hasn't migrated
		// yet, and against validator-generated dynamic messages.
		if (e.message) return e.message;
		return fallback;
	}
	if (e instanceof Error && e.message) return e.message;
	return fallback;
}
