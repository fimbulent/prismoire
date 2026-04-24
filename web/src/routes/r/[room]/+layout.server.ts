// SSR the per-room tab bar so the row of room links paints on first byte
// (no client fetch, no flicker). The API caps at 7 entries; the client
// layout may drop overflow further via ResizeObserver. Anonymous users
// never see the tab bar, so skip the fetch entirely for them.

import type { LayoutServerLoad } from './$types';
import { tabBar, type TabBarEntry } from '$lib/api/rooms';

export const load: LayoutServerLoad = async ({ parent, fetch }) => {
	const { session } = await parent();
	if (!session) {
		return { tabBarRooms: [] as TabBarEntry[] };
	}
	try {
		const tabBarRooms = await tabBar({ fetch });
		return { tabBarRooms };
	} catch {
		// Tab bar is navigation chrome — never fail the whole route load if
		// it can't be fetched. Render without it and let the page itself
		// surface any real errors.
		return { tabBarRooms: [] as TabBarEntry[] };
	}
};
