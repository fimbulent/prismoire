import {
	getSession,
	getSetupStatus,
	logout as apiLogout,
	type SessionInfo
} from '$lib/api/auth';
import { theme } from '$lib/stores/theme.svelte';
import type { ThemeId } from '$lib/themes';

let user = $state<SessionInfo | null>(null);
let loading = $state(true);
let needsSetup = $state(false);

export const session = {
	get user() {
		return user;
	},
	get loading() {
		return loading;
	},
	get isLoggedIn() {
		return user !== null;
	},
	get isAdmin() {
		return user?.role === 'admin';
	},
	get needsSetup() {
		return needsSetup;
	},

	async load() {
		loading = true;
		try {
			const status = await getSetupStatus();
			needsSetup = status.needs_setup;
			if (!needsSetup) {
				user = await getSession();
				if (user) {
					theme.init(user.theme as ThemeId);
				}
			}
		} catch {
			user = null;
		} finally {
			loading = false;
		}
	},

	set(info: SessionInfo) {
		user = info;
		needsSetup = false;
		loading = false;
		theme.init(info.theme as ThemeId);
	},

	async logout() {
		await apiLogout();
		user = null;
	}
};
