<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { session } from '$lib/stores/session.svelte';
	import { theme } from '$lib/stores/theme.svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { applyTheme } from '$lib/themes';
	import { canonicalProfilePath } from '$lib/user-url';
	import Toasts from '$lib/components/ui/Toasts.svelte';
	import NavSearch from '$lib/components/ui/NavSearch.svelte';

	let { children } = $props();

	let dropdownOpen = $state(false);
	let dropdownEl = $state<HTMLElement | null>(null);
	// On mobile the nav doesn't fit logo + expanded search + dropdown,
	// so we hide the logo and let search take the full row while expanded.
	let searchExpanded = $state(false);

	// Keep the `<html data-theme>` attribute in sync with the current
	// theme when it changes (e.g. after `invalidateAll()` re-runs the
	// root layout load following login/setup). On initial hydration
	// this is a no-op because `hooks.server.ts` already substituted
	// the correct `data-theme` into `app.html` server-side. Settings-
	// page clicks call `theme.set()` which also calls `applyTheme`
	// directly for an instant optimistic swap.
	//
	// `applyTheme` is a single `setAttribute('data-theme', ...)` call,
	// which the browser does NOT treat as an inline `style` attribute,
	// so it is safe under our `style-src-attr: 'self'` CSP.
	$effect(() => {
		applyTheme(theme.current);
		// Clear any optimistic override once the session load has
		// reflected the server-side choice back to us.
		if (page.data.session?.theme === theme.current) {
			theme.clearOverride();
		}
	});

	$effect(() => {
		if (!dropdownOpen) return;
		function handleClickOutside(e: MouseEvent) {
			if (dropdownEl && !dropdownEl.contains(e.target as Node)) {
				dropdownOpen = false;
			}
		}
		function handleEscape(e: KeyboardEvent) {
			if (e.key === 'Escape') {
				dropdownOpen = false;
			}
		}
		document.addEventListener('click', handleClickOutside, true);
		document.addEventListener('keydown', handleEscape);
		return () => {
			document.removeEventListener('click', handleClickOutside, true);
			document.removeEventListener('keydown', handleEscape);
		};
	});

	async function handleLogout() {
		dropdownOpen = false;
		await session.logout();
		await goto('/login');
	}

	function navigateTo(path: string) {
		dropdownOpen = false;
		goto(path);
	}
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<div class="bg-bg text-text-primary min-h-screen flex flex-col">
<nav class="h-[var(--nav-height)] bg-bg-surface border-b border-border px-4 flex items-center gap-4">
	<!--
		On mobile, the logo collapses (shrinks + fades) when search expands
		so the search field can take the row. We use the CSS grid trick:
		the anchor is a single-column grid whose track animates from
		`1fr` (intrinsic content width, since the parent is content-sized)
		down to `0fr` — no hardcoded pixel width, so it works for any brand
		string a deployed instance might use. `overflow-hidden` +
		`whitespace-nowrap` + `min-w-0` on the inner span let the track
		actually shrink below content size and clip the text leftward as
		it does. Desktop (`sm:`) stays at `1fr` regardless of search state.
	-->
	<a
		href="/"
		aria-hidden={searchExpanded || undefined}
		tabindex={searchExpanded ? -1 : undefined}
		class="text-accent font-bold tracking-wide text-lg hover:opacity-90 grid overflow-hidden whitespace-nowrap transition-all duration-200 {searchExpanded
			? 'grid-cols-[0fr] opacity-0 pointer-events-none sm:grid-cols-[1fr] sm:opacity-100 sm:pointer-events-auto'
			: 'grid-cols-[1fr] opacity-100'}"
	>
		<span class="min-w-0">Prismoire</span>
	</a>

	<!--
		`ml-auto` anchors the right cluster to the right edge regardless of
		whether the logo is rendered. That way, hiding the logo on mobile
		(when search is expanded) doesn't reflow the right side — the
		search field can grow leftward into the freed space without any
		flex-grow snap, matching the desktop animation.
	-->
	<div class="ml-auto flex items-center gap-4 text-sm min-w-0">
		{#if session.isLoggedIn && !session.isRestricted}
			<NavSearch bind:expanded={searchExpanded} />
		{/if}
		{#if session.isLoggedIn}
			<div class="relative" bind:this={dropdownEl}>
				<button
					onclick={() => (dropdownOpen = !dropdownOpen)}
					aria-haspopup="true"
					aria-expanded={dropdownOpen}
					class="font-semibold text-text-primary bg-bg-surface-raised px-2 py-0.5 rounded border border-border cursor-pointer text-sm"
				>
					{session.user?.display_name}
				</button>
				{#if dropdownOpen}
					<div class="absolute right-0 top-full mt-1 w-44 bg-bg-surface border border-border rounded-md shadow-lg py-1 z-50">
						<button
							onclick={() => {
								const u = session.user;
								if (u) navigateTo(canonicalProfilePath(u.display_name, u.public_key_hex));
							}}
							class="w-full text-left px-3 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition-colors cursor-pointer"
						>
							Profile
						</button>
						{#if !session.isRestricted}
							<button
								onclick={() => navigateTo('/invites')}
								class="w-full text-left px-3 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition-colors cursor-pointer"
							>
								Invites
							</button>
							<button
								onclick={() => navigateTo('/add-contact')}
								class="w-full text-left px-3 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition-colors cursor-pointer"
							>
								Add contact
							</button>
						{/if}
						<button
							onclick={() => navigateTo('/settings')}
							class="w-full text-left px-3 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition-colors cursor-pointer"
						>
							Settings
						</button>
						{#if session.isAdmin}
							<button
								onclick={() => navigateTo('/admin')}
								class="w-full text-left px-3 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition-colors cursor-pointer"
							>
								Admin
							</button>
						{/if}
						<div class="border-t border-border-subtle my-1"></div>
						<button
							onclick={handleLogout}
							class="w-full text-left px-3 py-2 text-sm text-text-muted hover:bg-bg-hover hover:text-danger transition-colors cursor-pointer"
						>
							Sign out
						</button>
					</div>
				{/if}
			</div>
		{:else}
			<a href="/login" class="text-link hover:text-link-hover">Sign in</a>
		{/if}
	</div>
</nav>

<div class="w-full">
{@render children()}
</div>

<footer class="h-[var(--footer-height)] flex items-center justify-center gap-2 text-xs text-text-muted mt-auto">
	<a href="/help" class="hover:text-text-secondary transition-colors">Help</a>
	{#if session.isLoggedIn && !session.isRestricted}
		<span aria-hidden="true" class="select-none">·</span>
		<a href="/log" class="hover:text-text-secondary transition-colors">Admin log</a>
	{/if}
	{#if page.data.sourceRepoUrl}
		<span aria-hidden="true" class="select-none">·</span>
		<a
			href={page.data.sourceRepoUrl}
			rel="nofollow ugc noopener noreferrer"
			class="hover:text-text-secondary transition-colors"
		>
			Source code
		</a>
	{/if}
</footer>

<Toasts />
</div>
