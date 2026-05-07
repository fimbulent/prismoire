<!--
	`/search/*` shell. Renders the heading + tab strip; each per-kind
	sub-route (`/search/threads`, `/search/posts`, `/search/users`,
	`/search/rooms`) provides its own results list inside the `<slot/>`.

	The active tab is derived from the current pathname rather than a
	`?kind=` parameter — the sub-routes are first-class, so back/forward
	and prefetch behave as expected per `docs/search.md`.
-->
<script lang="ts">
	import { page } from '$app/state';

	type SearchKind = 'rooms' | 'users' | 'threads' | 'posts';

	const TABS: { kind: SearchKind; label: string; path: string }[] = [
		{ kind: 'threads', label: 'Threads', path: '/search/threads' },
		{ kind: 'posts', label: 'Posts', path: '/search/posts' },
		{ kind: 'rooms', label: 'Rooms', path: '/search/rooms' },
		{ kind: 'users', label: 'Users', path: '/search/users' }
	];

	let { data, children } = $props<{
		data: { query: string };
		children: import('svelte').Snippet;
	}>();

	let query = $derived(data.query);

	// Active tab from pathname. The redirect on `/search` goes to
	// `/search/threads`, so unknown paths fall through to "threads"
	// to keep the strip non-empty during navigation transitions.
	let activeKind = $derived.by<SearchKind>(() => {
		const path = page.url.pathname;
		const match = TABS.find((t) => path.startsWith(t.path));
		return match ? match.kind : 'threads';
	});

	function tabHref(path: string): string {
		const params = new URLSearchParams();
		if (query) params.set('q', query);
		const qs = params.toString();
		return `${path}${qs ? '?' + qs : ''}`;
	}

	let pageTitle = $derived(query ? `Search "${query}" — Prismoire` : 'Search — Prismoire');
</script>

<svelte:head>
	<title>{pageTitle}</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-4 py-6">
	<header class="mb-4">
		<h1 class="text-lg font-semibold text-text-primary">
			{#if query}
				Search results for <span class="text-accent">"{query}"</span>
			{:else}
				Search
			{/if}
		</h1>
	</header>

	<nav
		class="flex items-center gap-1 border-b border-border mb-4 text-sm"
		aria-label="Search categories"
	>
		{#each TABS as tab}
			{@const active = activeKind === tab.kind}
			<a
				href={tabHref(tab.path)}
				class="px-3 py-2 -mb-px border-b-2 transition-colors {active
					? 'border-accent text-text-primary font-semibold'
					: 'border-transparent text-text-secondary hover:text-text-primary'}"
				aria-current={active ? 'page' : undefined}
			>
				{tab.label}
			</a>
		{/each}
	</nav>

	{@render children()}
</div>
