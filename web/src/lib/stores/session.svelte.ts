// SSR-safe session facade backed by the root `+layout.server.ts` load.
//
// There is intentionally NO module-level `$state` here: under
// adapter-node, module scope is shared across concurrent requests, and
// writing the logged-in user into it would leak one user's session into
// another user's render. Instead every getter reads from `page.data`,
// which SvelteKit scopes to the current request.
//
// For client-side auth ceremonies (login / signup / setup) the flow is
// now: call the API, then `invalidateAll()` so the root layout load
// re-runs and `page.data.session` reflects the new user. Route code no
// longer writes to a client store.

import { page } from '$app/state';
import { invalidateAll } from '$app/navigation';
import { logout as apiLogout, type SessionInfo } from '$lib/api/auth';

export const session = {
	get user(): SessionInfo | null {
		return page.data.session ?? null;
	},
	get isLoggedIn(): boolean {
		return page.data.session != null;
	},
	get isAdmin(): boolean {
		return page.data.session?.role === 'admin';
	},
	get isBanned(): boolean {
		return page.data.session?.status === 'banned';
	},
	get isSuspended(): boolean {
		return page.data.session?.status === 'suspended';
	},
	/**
	 * Banned or suspended — the UI must lock down to the restricted
	 * profile-only view. All non-allowed routes redirect to the user's
	 * own profile; most action buttons (posting, editing bio, trust
	 * changes) are hidden.
	 */
	get isRestricted(): boolean {
		const s = page.data.session?.status;
		return s === 'banned' || s === 'suspended';
	},
	/** ISO-8601 timestamp at which a suspension lifts, if applicable. */
	get suspendedUntil(): string | null {
		return page.data.session?.suspended_until ?? null;
	},
	get needsSetup(): boolean {
		return page.data.needsSetup === true;
	},

	/**
	 * Force the root layout load to re-run so `page.data.session`
	 * reflects the latest server state. Called after client-driven
	 * auth ceremonies (login, signup, setup).
	 */
	async refresh(): Promise<void> {
		await invalidateAll();
	},

	async logout(): Promise<void> {
		await apiLogout();
		await invalidateAll();
	}
};
