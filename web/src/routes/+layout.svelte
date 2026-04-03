<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { session } from '$lib/stores/session.svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';

	let { children } = $props();

	let navHeight = $state(0);
	let dropdownOpen = $state(false);
	let dropdownEl = $state<HTMLElement | null>(null);

	$effect(() => {
		session.load();
	});

	$effect(() => {
		if (!session.loading && session.needsSetup && page.url.pathname !== '/setup') {
			goto('/setup');
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
		goto('/login');
	}

	function navigateTo(path: string) {
		dropdownOpen = false;
		goto(path);
	}
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<div class="bg-bg text-text-primary min-h-screen flex flex-col" style:--nav-height="{navHeight}px">
<nav bind:clientHeight={navHeight} class="bg-bg-surface border-b border-border px-4 py-3 flex items-center justify-between">
	<a href="/" class="text-accent font-bold tracking-wide text-lg hover:opacity-90">Prismoire</a>

	<div class="flex items-center gap-4 text-sm">
		{#if session.loading}
			<span class="text-text-muted">…</span>
		{:else if session.isLoggedIn}
			<div class="relative" bind:this={dropdownEl}>
				<button
					onclick={() => (dropdownOpen = !dropdownOpen)}
					aria-haspopup="true"
					aria-expanded={dropdownOpen}
					class="text-text-secondary hover:text-text-primary transition-colors cursor-pointer flex items-center gap-1"
				>
					{session.user?.display_name}
					<svg class="w-3.5 h-3.5 transition-transform" class:rotate-180={dropdownOpen} viewBox="0 0 20 20" fill="currentColor">
						<path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clip-rule="evenodd" />
					</svg>
				</button>
				{#if dropdownOpen}
					<div class="absolute right-0 top-full mt-1 w-44 bg-bg-surface border border-border rounded-md shadow-lg py-1 z-50">
						<button
							onclick={() => navigateTo('/invites')}
							class="w-full text-left px-3 py-2 text-sm text-text-secondary hover:bg-bg-hover hover:text-text-primary transition-colors cursor-pointer"
						>
							Invites
						</button>
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

{#if session.isLoggedIn}
	<footer class="text-center py-6 text-xs text-text-muted mt-auto">
		<a href="/log" class="hover:text-text-secondary transition-colors">Admin Log</a>
	</footer>
{/if}
</div>
