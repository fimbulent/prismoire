import { getSession, logout as apiLogout, type SessionInfo } from '$lib/api/auth';

let user = $state<SessionInfo | null>(null);
let loading = $state(true);

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

	async load() {
		loading = true;
		try {
			user = await getSession();
		} catch {
			user = null;
		} finally {
			loading = false;
		}
	},

	set(info: SessionInfo) {
		user = info;
		loading = false;
	},

	async logout() {
		await apiLogout();
		user = null;
	}
};
