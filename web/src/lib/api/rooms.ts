import { throwApiError, type FetchFn } from './auth';

/**
 * A room as returned by the paginated rooms list and detail endpoints.
 *
 * The viewer-specific fields — `recent_thread_count`, `sparkline`,
 * `last_visible_activity`, and `favorited` — reflect only threads the
 * viewer is permitted to see via the trust graph, so two different
 * users may see different values for the same room.
 */
export interface Room {
	id: string;
	slug: string;
	is_announcement: boolean;
	created_by: string;
	created_by_name: string;
	created_at: string;
	/**
	 * Viewer-visible threads with activity inside the dynamic window
	 * (`activity_window_days`). When the window is the full 7 days,
	 * render as "N threads this week"; otherwise "N threads last Nd".
	 */
	recent_thread_count: number;
	/**
	 * Per-day visible-thread activity counts. Length equals
	 * `activity_window_days` (1..=7); index 0 is the oldest bucket and
	 * the final index is today-so-far.
	 */
	sparkline: number[];
	/**
	 * Number of UTC day buckets represented in `sparkline`. Capped at 7;
	 * may be shorter when the server-side activity scan's LIMIT was
	 * reached before reaching 7 days back.
	 */
	activity_window_days: number;
	/** ISO timestamp of the most recent activity the viewer can see, if any. */
	last_visible_activity: string | null;
	/** Whether this room is in the viewer's favorites list. */
	favorited: boolean;
}

/** One page of rooms plus the cursor to fetch the next page (null when exhausted). */
export interface RoomListResponse {
	rooms: Room[];
	next_cursor: string | null;
}

interface FetchOpts {
	fetch?: FetchFn;
}

/**
 * Fetch the first page of rooms, sorted by viewer-visible activity.
 *
 * Returns the full response so callers can drive pagination via
 * {@link listRoomsMore} using `next_cursor`.
 */
export async function listRooms(opts: FetchOpts = {}): Promise<RoomListResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/rooms');
	if (!res.ok) await throwApiError(res);
	return res.json();
}

/**
 * Fetch the next page of rooms. `cursor` is the `next_cursor` value
 * returned by the previous page; the server returns an empty page and
 * `next_cursor: null` once the list is exhausted.
 */
export async function listRoomsMore(
	cursor: string,
	opts: FetchOpts = {}
): Promise<RoomListResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/rooms/more', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ cursor })
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}

export async function getRoom(idOrSlug: string, opts: FetchOpts = {}): Promise<Room> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/rooms/${encodeURIComponent(idOrSlug)}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

/**
 * One entry in the per-user tab bar. The server caps the list at
 * `TAB_BAR_SLOTS` (see server/src/rooms.rs); the frontend may drop
 * overflow further via ResizeObserver. The order is: favorites in
 * user-defined position order, then any non-favorited rooms needed to
 * fill the remaining slots, sorted by viewer-visible activity.
 */
export interface TabBarEntry {
	slug: string;
	is_announcement: boolean;
	favorited: boolean;
}

/**
 * Fetch the viewer's tab bar — favorites first (in user order), then
 * the most-active rooms backfilling the remaining slots, capped by
 * the server's `TAB_BAR_SLOTS`.
 */
export async function tabBar(opts: FetchOpts = {}): Promise<TabBarEntry[]> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/rooms/tab-bar');
	if (!res.ok) await throwApiError(res);
	const data: { rooms: TabBarEntry[] } = await res.json();
	return data.rooms;
}

/**
 * Lightweight room row returned by the autocomplete search endpoint.
 * Carries slug + viewer-visible recent thread count so the dropdown
 * can show "slug (N threads this week)" or "slug (N threads last Nd)"
 * without needing the heavier {@link Room} shape.
 */
export interface RoomChip {
	id: string;
	slug: string;
	is_announcement: boolean;
	/** Threads visible to the viewer within `activity_window_days`. */
	recent_thread_count: number;
	/** Width of the activity window this count represents (1..=7 days). */
	activity_window_days: number;
}

/**
 * Prefix-search active rooms for an autocomplete dropdown.
 *
 * An empty `query` returns the most-recently-active rooms so the
 * dropdown is non-empty as soon as the user focuses the field.
 */
export async function searchRooms(
	query: string,
	limit = 10,
	opts: FetchOpts = {}
): Promise<RoomChip[]> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams();
	if (query) params.set('q', query);
	params.set('limit', String(limit));
	const res = await f(`/api/rooms/search?${params.toString()}`);
	if (!res.ok) await throwApiError(res);
	const data: { rooms: RoomChip[] } = await res.json();
	return data.rooms;
}

/**
 * Fetch the viewer's favorite rooms in their stored position order,
 * each enriched with the full {@link Room} shape (sparkline, weekly
 * thread count, last visible activity). Drives the dedicated
 * favorites section at the top of `/rooms`.
 */
export async function listFavorites(opts: FetchOpts = {}): Promise<Room[]> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/me/favorites');
	if (!res.ok) await throwApiError(res);
	const data: { rooms: Room[] } = await res.json();
	return data.rooms;
}

/**
 * Add a room to the viewer's favorites. `idOrSlug` may be either the
 * room's UUID or its slug. Fails with `FavoriteCapExceeded` if the
 * user is already at the favorites cap.
 */
export async function favoriteRoom(idOrSlug: string, opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/rooms/${encodeURIComponent(idOrSlug)}/favorite`, {
		method: 'POST'
	});
	if (!res.ok) await throwApiError(res);
}

/** Remove a room from the viewer's favorites. Idempotent. */
export async function unfavoriteRoom(idOrSlug: string, opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/rooms/${encodeURIComponent(idOrSlug)}/favorite`, {
		method: 'DELETE'
	});
	if (!res.ok) await throwApiError(res);
}

/**
 * Replace the order of the viewer's favorites. `roomIds` must be the
 * same set as the viewer's current favorites (no additions or
 * removals) — the server returns `FavoriteSetMismatch` otherwise, at
 * which point the client should refetch and retry.
 */
export async function reorderFavorites(
	roomIds: string[],
	opts: FetchOpts = {}
): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/me/favorites', {
		method: 'PUT',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ room_ids: roomIds })
	});
	if (!res.ok) await throwApiError(res);
}
