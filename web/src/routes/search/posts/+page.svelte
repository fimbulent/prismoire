<script lang="ts">
	import { errorMessage } from '$lib/i18n/errors';
	import { searchPostsMore, MAX_SEARCH_SEEN_IDS, type PostSearchHit } from '$lib/api/search';
	import UserName from '$lib/components/trust/UserName.svelte';
	import Notice from '$lib/components/ui/Notice.svelte';
	import HighlightedMarkdown from '$lib/components/post/HighlightedMarkdown.svelte';
	import { relativeTime } from '$lib/format';
	import { smartypants } from '$lib/typography';
	import { searchTokens } from '$lib/utils/highlight';

	let { data } = $props<{
		data: { query: string; posts: PostSearchHit[]; nextCursor: string | null };
	}>();

	let appended = $state<PostSearchHit[]>([]);
	let appendedCursor = $state<string | null>(null);
	let hasLoadedMore = $state(false);
	let loadingMore = $state(false);
	let loadMoreError = $state<string | null>(null);

	$effect(() => {
		void data.query;
		void data.posts;
		appended = [];
		appendedCursor = null;
		hasLoadedMore = false;
		loadMoreError = null;
	});

	let nextCursor = $derived(hasLoadedMore ? appendedCursor : data.nextCursor);
	let posts = $derived([...data.posts, ...appended]);

	// Tokens for client-side highlight on the posts tab. Recomputed
	// only when the query string changes.
	let highlightTokens = $derived(searchTokens(data.query));

	// All rendered post IDs — sent as `seen_ids` (tail 200) on load-more
	// so the server can drop cross-page duplicates introduced by FTS
	// pool drift between requests.
	let renderedIds = $derived(posts.map((p) => p.id));

	async function loadMore() {
		if (!nextCursor || loadingMore) return;
		loadingMore = true;
		loadMoreError = null;
		try {
			const seenIds = renderedIds.slice(-MAX_SEARCH_SEEN_IDS);
			const res = await searchPostsMore(data.query, nextCursor, seenIds);
			// Client-side dedup safety net (see the threads tab for the
			// reasoning).
			const existing = new Set(renderedIds);
			const fresh = res.posts.filter((p) => !existing.has(p.id));
			appended = [...appended, ...fresh];
			appendedCursor = res.next_cursor;
			hasLoadedMore = true;
		} catch (e) {
			loadMoreError = errorMessage(e, 'Failed to load more results');
		} finally {
			loadingMore = false;
		}
	}
</script>

{#if !data.query}
	<Notice>Type a query in the search box above to begin.</Notice>
{:else if posts.length === 0}
	<p class="text-text-muted text-sm">No matching posts found.</p>
{:else}
	<!--
		Layout mirrors `ProfileActivityPost.svelte`'s two-column card:
		left rail carries the contextual framing (Started thread in / Replied
		in) + author + timestamp; right column carries the (optional) thread
		title link and the highlighted body. Two-column on md+, stacked on
		mobile. The two pages don't share a component yet — search results
		need an author UserName + trust badge that the activity feed
		intentionally omits — but keeping the visual idiom in lockstep means
		extracting a shared layout primitive later is straightforward if it
		earns its keep.
	-->
	<ul class="space-y-3">
		{#each posts as p (p.id)}
			<li class="bg-bg-surface border border-border rounded-md p-4 md:flex md:gap-6">
				<!--
					`[overflow-wrap:anywhere]` lets long unbreakable tokens (most
					commonly a username, since the username charset has no word
					boundaries to break at) wrap at character bounds when they
					would otherwise overflow the 10rem rail. It's inherited, so
					applying it once on the rail covers UserName + the framing
					copy + the thread title without sprinkling it into the
					component tree. The framing copy still prefers space breaks —
					`anywhere` is only a fallback when no other opportunity
					exists. `min-w-0` lets the rail's flex children shrink below
					their min-content so the wrap actually takes effect (default
					`min-width: auto` would otherwise pin children to their
					unbreakable token width and re-introduce the overflow).
				-->
				<div
					class="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-text-muted mb-2 md:mb-0 md:flex-col md:items-start md:gap-1 md:w-40 md:shrink-0 min-w-0 [&>*]:min-w-0 [overflow-wrap:anywhere]"
				>
					{#if p.is_op}
						<span>Started thread in</span>
						<a href="/r/{p.room_slug}" class="text-link hover:underline">{p.room_slug}</a>
					{:else}
						<span>Replied in</span>
						<a
							href="/r/{p.room_slug}/{p.thread_id}?post={p.id}"
							class="text-link hover:underline"
						>
							{smartypants(p.thread_title)}
						</a>
					{/if}
					<!--
						Mobile order: framing → room → timestamp (ml-auto'd right
						on the framing row) → flex break → UserName on its own row.
						On md+ the rail is `flex-col`, so we push the timestamp to
						the bottom via `md:order-last` to preserve the desktop
						stack (framing, room, UserName, timestamp). The break is
						`md:hidden` because flex-col already gives every child its
						own line.
					-->
					<span class="ml-auto md:ml-0 md:order-last">{relativeTime(p.created_at)}</span>
					<div class="basis-full h-0 md:hidden" aria-hidden="true"></div>
					<UserName name={p.author_name} viewer={p.viewer} compact muted />
				</div>
				<div class="md:max-w-measure md:flex-1 md:min-w-0">
					{#if p.is_op}
						<a
							href="/r/{p.room_slug}/{p.thread_id}"
							class="font-prose text-prose text-text-primary hover:underline font-medium leading-snug"
						>
							{smartypants(p.thread_title)}
						</a>
					{/if}
					<div class="text-prose leading-7 text-text-secondary mt-1">
						<!--
							OPs render with the `full` markdown profile (headings + hr
							allowed); replies render with `reply` (those block elements
							stripped). Mirrors how each post renders in its native
							thread context — see `ProfileActivityPost.svelte` for the
							matching split on the user-profile activity feed.
						-->
						<HighlightedMarkdown
							source={p.body}
							profile={p.is_op ? 'full' : 'reply'}
							tokens={highlightTokens}
						/>
					</div>
				</div>
			</li>
		{/each}
	</ul>
{/if}

{#if loadMoreError}
	<div class="mt-4">
		<Notice>{loadMoreError}</Notice>
	</div>
{/if}

{#if nextCursor && data.query}
	<div class="mt-6 flex justify-center">
		<button
			type="button"
			onclick={loadMore}
			disabled={loadingMore}
			class="px-4 py-2 bg-bg-surface border border-border rounded-md text-sm text-text-secondary hover:text-text-primary hover:border-accent-muted transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
		>
			{loadingMore ? 'Loading…' : 'Load more'}
		</button>
	</div>
{/if}
