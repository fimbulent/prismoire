// Room thread listing: requires an authenticated session. Sort mode is
// carried in the `?sort=` query param so it's shareable/bookmarkable and
// back-button friendly; the server load fetches the correct initial page
// for the requested sort. Load-more pagination stays client-driven.

import { redirect, error as kitError } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { getRoom, type Room } from '$lib/api/rooms';
import { listThreads, listAllThreads, type ThreadSort } from '$lib/api/threads';
import { ApiRequestError } from '$lib/api/auth';

const VALID_SORTS: ThreadSort[] = ['warm', 'new', 'active', 'trusted'];

function parseSort(raw: string | null): ThreadSort {
	return VALID_SORTS.includes(raw as ThreadSort) ? (raw as ThreadSort) : 'warm';
}

export const load: PageServerLoad = async ({ parent, fetch, params, url }) => {
	const { session, sessionError } = await parent();
	if (sessionError) {
		throw kitError(503, 'Session service temporarily unavailable');
	}
	if (!session) {
		throw redirect(307, '/login');
	}

	const slug = params.room;
	const sort = parseSort(url.searchParams.get('sort'));
	try {
		if (slug === 'all') {
			const res = await listAllThreads(undefined, sort, { fetch });
			return {
				room: null as Room | null,
				threads: res.threads,
				nextCursor: res.next_cursor,
				sort
			};
		}
		const [room, threadData] = await Promise.all([
			getRoom(slug, { fetch }),
			listThreads(slug, undefined, sort, { fetch })
		]);
		return {
			room,
			threads: threadData.threads,
			nextCursor: threadData.next_cursor,
			sort
		};
	} catch (e) {
		if (e instanceof ApiRequestError && e.status === 404) {
			throw kitError(404, 'Room not found');
		}
		throw kitError(500, 'Failed to load room');
	}
};
