<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { session } from '$lib/stores/session.svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';

	let { children } = $props();

	let navHeight = $state(0);

	$effect(() => {
		session.load();
	});

	$effect(() => {
		if (!session.loading && session.needsSetup && page.url.pathname !== '/setup') {
			goto('/setup');
		}
	});

	async function handleLogout() {
		await session.logout();
		goto('/login');
	}
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<div class="bg-bg text-text-primary min-h-screen" style:--nav-height="{navHeight}px">
<nav bind:clientHeight={navHeight} class="bg-bg-surface border-b border-border px-4 py-3 flex items-center justify-between">
	<a href="/" class="text-accent font-bold tracking-wide text-lg hover:opacity-90">Prismoire</a>

	<div class="flex items-center gap-4 text-sm">
		{#if session.loading}
			<span class="text-text-muted">…</span>
		{:else if session.isLoggedIn}
			<span class="text-text-secondary">{session.user?.display_name}</span>
			<button
				onclick={handleLogout}
				class="text-text-muted hover:text-danger transition-colors cursor-pointer"
			>
				Sign out
			</button>
		{:else}
			<a href="/login" class="text-link hover:text-link-hover">Sign in</a>
			<a
				href="/signup"
				class="bg-accent text-bg font-semibold rounded-md px-3 py-1 hover:opacity-90"
			>
				Sign up
			</a>
		{/if}
	</div>
</nav>

{@render children()}
</div>
