import { throwApiError, type FetchFn } from './auth';
import type { Room } from './rooms';
import type { UserViewerInfo } from './users';

/**
 * One room in the autocomplete dropdown's "rooms" section.
 *
 * Mirrors `RoomChip` from the rooms-search endpoint — kept as a
 * separate type here so the search payload is a single self-contained
 * import, even though the shape happens to coincide today.
 */
export interface RoomHit {
	id: string;
	slug: string;
	is_announcement: boolean;
}

/** One user in the autocomplete dropdown's "users" section. */
export interface UserHit {
	id: string;
	display_name: string;
	/** Lowercase-hex pubkey of the user. */
	public_key_hex: string;
	viewer: UserViewerInfo;
}

/** One thread in the autocomplete dropdown's "threads" section. */
export interface ThreadHit {
	id: string;
	title: string;
	author_id: string;
	author_name: string;
	/** Lowercase-hex pubkey of the thread's OP author. */
	author_public_key_hex: string;
	room_id: string;
	room_slug: string;
	is_announcement: boolean;
	created_at: string;
	last_activity: string | null;
	viewer: UserViewerInfo;
}

/** Aggregated dropdown response: up to three hits per kind. */
export interface SearchDropdownResponse {
	rooms: RoomHit[];
	users: UserHit[];
	threads: ThreadHit[];
}

interface FetchOpts {
	fetch?: FetchFn;
}

/**
 * Fetch the sectioned autocomplete dropdown payload for the given
 * query. Posts are intentionally excluded — body search lives only on
 * the `/search` results page.
 *
 * The server treats an empty / whitespace-only query as a no-op and
 * returns three empty arrays.
 */
export async function searchDropdown(
	query: string,
	opts: FetchOpts = {}
): Promise<SearchDropdownResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const params = new URLSearchParams();
	if (query) params.set('q', query);
	const res = await f(`/api/search?${params.toString()}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

// ---------------------------------------------------------------------------
// Per-kind paginated endpoints (the `/search` results page).
// ---------------------------------------------------------------------------

interface PaginatedFetchOpts extends FetchOpts {
	cursor?: string | null;
}

/**
 * Build the query string for a paginated `/api/search/<kind>` call.
 * Empty / nullish cursors are omitted so the URL stays clean on the
 * first page.
 */
function paginatedParams(query: string, cursor: string | null | undefined): string {
	const params = new URLSearchParams();
	if (query) params.set('q', query);
	if (cursor) params.set('cursor', cursor);
	return params.toString();
}

/**
 * Maximum `seen_ids` size accepted by the four
 * `/api/search/<kind>/more` POST endpoints. Mirrors the server-side
 * cap (`FTS_OVERSAMPLE` = 200); sending more is rejected with a 400.
 * Callers should tail-slice their rendered-id array to this length.
 */
export const MAX_SEARCH_SEEN_IDS = 200;

/**
 * Shared body shape for the four `/api/search/<kind>/more` POST
 * endpoints. Mirrors the server's `MoreSearchRequest`.
 */
interface MoreSearchBody {
	q: string;
	cursor: string;
	seen_ids: string[];
}

async function postMore<T>(
	path: string,
	body: MoreSearchBody,
	opts: FetchOpts = {}
): Promise<T> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(path, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body)
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}

/**
 * Threads tab on the `/search` results page. The threads tab renders
 * titles only (matching the room-listing UX) — no body snippet — so
 * this shape carries no `snippet` field. Posts-tab search continues to
 * render full bodies with client-side highlighting.
 */
export interface ThreadSearchHit {
	id: string;
	title: string;
	author_id: string;
	author_name: string;
	/** Lowercase-hex pubkey of the thread's OP author. */
	author_public_key_hex: string;
	room_id: string;
	room_slug: string;
	created_at: string;
	locked: boolean;
	is_announcement: boolean;
	reply_count: number;
	last_activity: string | null;
	link_url: string | null;
	viewer: UserViewerInfo;
}

export interface ThreadSearchPageResponse {
	threads: ThreadSearchHit[];
	next_cursor: string | null;
}

export async function searchThreads(
	query: string,
	opts: PaginatedFetchOpts = {}
): Promise<ThreadSearchPageResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/search/threads?${paginatedParams(query, opts.cursor)}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

/**
 * Load page 2+ of thread search via POST. Sends the previously
 * rendered IDs (tail-sliced to `MAX_SEARCH_SEEN_IDS`) as `seen_ids`
 * so the server can drop cross-page duplicates introduced by FTS pool
 * drift between requests.
 */
export async function searchThreadsMore(
	query: string,
	cursor: string,
	seenIds: string[],
	opts: FetchOpts = {}
): Promise<ThreadSearchPageResponse> {
	return postMore<ThreadSearchPageResponse>(
		'/api/search/threads/more',
		{ q: query, cursor, seen_ids: seenIds },
		opts
	);
}

/** Posts tab on the `/search` results page. */
export interface PostSearchHit {
	id: string;
	thread_id: string;
	thread_title: string;
	room_id: string;
	room_slug: string;
	is_announcement: boolean;
	author_id: string;
	author_name: string;
	/** Lowercase-hex pubkey of the post author. */
	author_public_key_hex: string;
	created_at: string;
	/**
	 * Full post body (markdown). The frontend renders it via the
	 * shared Markdown component and highlights query tokens client-side
	 * by walking text nodes — server-side mark injection would
	 * collide with markdown syntax.
	 */
	body: string;
	/**
	 * True when this post is the thread's opening post (no parent).
	 * Lets the page render OPs with the `full` markdown profile
	 * (headings, hr) and replies with the trimmed `reply` profile,
	 * matching how each renders in its native context.
	 */
	is_op: boolean;
	viewer: UserViewerInfo;
}

export interface PostSearchPageResponse {
	posts: PostSearchHit[];
	next_cursor: string | null;
}

export async function searchPosts(
	query: string,
	opts: PaginatedFetchOpts = {}
): Promise<PostSearchPageResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/search/posts?${paginatedParams(query, opts.cursor)}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

/** See {@link searchThreadsMore}. */
export async function searchPostsMore(
	query: string,
	cursor: string,
	seenIds: string[],
	opts: FetchOpts = {}
): Promise<PostSearchPageResponse> {
	return postMore<PostSearchPageResponse>(
		'/api/search/posts/more',
		{ q: query, cursor, seen_ids: seenIds },
		opts
	);
}

/** Users tab on the `/search` results page. */
export interface UserSearchHit {
	id: string;
	display_name: string;
	/** Lowercase-hex pubkey of the user. */
	public_key_hex: string;
	viewer: UserViewerInfo;
}

export interface UserSearchPageResponse {
	users: UserSearchHit[];
	next_cursor: string | null;
}

export async function searchUsers(
	query: string,
	opts: PaginatedFetchOpts = {}
): Promise<UserSearchPageResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/search/users?${paginatedParams(query, opts.cursor)}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

/** See {@link searchThreadsMore}. */
export async function searchUsersMore(
	query: string,
	cursor: string,
	seenIds: string[],
	opts: FetchOpts = {}
): Promise<UserSearchPageResponse> {
	return postMore<UserSearchPageResponse>(
		'/api/search/users/more',
		{ q: query, cursor, seen_ids: seenIds },
		opts
	);
}

/**
 * Rooms tab on the `/search` results page.
 *
 * Mirrors the rich `Room` shape from `/api/rooms`, so the search page
 * can reuse `RoomCard` and surface sparkline + thread count + favorited
 * state per result.
 */
export type RoomSearchHit = Room;

export interface RoomSearchPageResponse {
	rooms: RoomSearchHit[];
	next_cursor: string | null;
}

export async function searchRooms(
	query: string,
	opts: PaginatedFetchOpts = {}
): Promise<RoomSearchPageResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f(`/api/search/rooms?${paginatedParams(query, opts.cursor)}`);
	if (!res.ok) await throwApiError(res);
	return res.json();
}

/** See {@link searchThreadsMore}. */
export async function searchRoomsMore(
	query: string,
	cursor: string,
	seenIds: string[],
	opts: FetchOpts = {}
): Promise<RoomSearchPageResponse> {
	return postMore<RoomSearchPageResponse>(
		'/api/search/rooms/more',
		{ q: query, cursor, seen_ids: seenIds },
		opts
	);
}
