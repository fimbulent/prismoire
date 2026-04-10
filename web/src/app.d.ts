// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces

import type { SessionInfo } from '$lib/api/auth';

declare global {
	namespace App {
		interface Error {
			message: string;
			errorId?: string;
		}
		// interface Locals {}
		/**
		 * Shape of the data returned by the root `+layout.server.ts`
		 * load (merged into every page's `data`). Keeping this typed
		 * means `$page.data.session` is no longer `any` at call sites
		 * like `src/lib/stores/session.svelte.ts`.
		 */
		interface PageData {
			session: SessionInfo | null;
			needsSetup: boolean;
		}
		interface PageState {
			viewRootStack?: string[];
		}
		// interface Platform {}
	}
}

export {};
