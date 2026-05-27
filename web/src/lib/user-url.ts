// Canonical URL construction for user-keyed routes.
//
// Profile URLs in Prismoire use the `@username.{8hex}` long form (see
// `docs/federation-impl-plan.md` Phase 9.5). The 8-hex suffix is the
// first eight lowercase-hex characters of the user's 32-byte Ed25519
// public key — it survives a future skeleton collision without
// silently changing meaning. The server's `@[username]/+page.server.ts`
// loader redirects bare `/@alice` to `/@alice.{8hex}` on first visit,
// but every link we control should already point at the long form so
// the redirect never has to fire.
//
// Use this helper *only* where the pubkey is actually known (any
// envelope on the wire that already carries `public_key_hex`, plus
// the session itself). For free-form `@mention` strings parsed out of
// markdown body text we have no pubkey and must fall through to the
// resolver — see `$lib/markdown.ts`.

/**
 * Build the canonical `/@username.{8hex}` profile path.
 *
 * Pass the full 32-byte pubkey in lowercase hex (`public_key_hex` as
 * it appears on every user-reference envelope from the API). The
 * function slices to the first 8 chars itself, so callers don't have
 * to remember the constant.
 *
 * The display name is URI-encoded so unicode / special characters
 * round-trip cleanly through the address bar.
 */
export function canonicalProfilePath(displayName: string, pubkeyHex: string): string {
	return `/@${encodeURIComponent(displayName)}.${pubkeyHex.slice(0, 8)}`;
}
