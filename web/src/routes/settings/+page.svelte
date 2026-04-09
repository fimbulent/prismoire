<script lang="ts">
	import { goto } from '$app/navigation';
	import { updateSettings } from '$lib/api/settings';
	import { session } from '$lib/stores/session.svelte';
	import { theme } from '$lib/stores/theme.svelte';
	import { themes, type ThemeId } from '$lib/themes';

	let saving = $state(false);
	let savedId = $state<ThemeId | null>(null);

	$effect(() => {
		if (session.loading) return;
		if (!session.isLoggedIn) {
			goto('/login');
		}
	});

	async function selectTheme(id: ThemeId) {
		theme.set(id);
		saving = true;
		try {
			await updateSettings({ theme: id });
			savedId = id;
			setTimeout(() => {
				if (savedId === id) savedId = null;
			}, 1500);
		} catch {
			// Silently fail — the theme is already applied visually
		} finally {
			saving = false;
		}
	}
</script>

<svelte:head>
	<title>Settings \u2014 Prismoire</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-6 pt-6 pb-16">
	<h1 class="text-lg font-bold mb-6">Settings</h1>

	<section>
		<h2 class="text-sm font-semibold text-text-secondary mb-3">Theme</h2>
		<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
			{#each themes as t (t.id)}
				<button
					onclick={() => selectTheme(t.id)}
					class="relative rounded-lg border-2 p-3 text-left transition-colors cursor-pointer"
					class:border-accent={theme.current === t.id}
					class:border-border-subtle={theme.current !== t.id}
					class:hover:border-border={theme.current !== t.id}
				>
					<div
						class="rounded-md overflow-hidden mb-2 border border-black/10"
						style:background={t.vars['--bg']}
					>
						<div class="h-2" style:background={t.vars['--bg-surface']}></div>
						<div class="px-2 py-1.5 space-y-1">
							<div class="flex items-center gap-1.5">
								<div class="h-1.5 w-8 rounded-full" style:background={t.vars['--accent']}></div>
								<div class="h-1.5 w-12 rounded-full" style:background={t.vars['--text-primary']}></div>
							</div>
							<div class="h-1.5 w-16 rounded-full" style:background={t.vars['--text-secondary']}></div>
							<div class="flex items-center gap-1">
								<div class="h-1.5 w-3 rounded-full" style:background={t.vars['--trust-direct']}></div>
								<div class="h-1.5 w-3 rounded-full" style:background={t.vars['--trust-2hop']}></div>
								<div class="h-1.5 w-3 rounded-full" style:background={t.vars['--trust-3hop']}></div>
							</div>
						</div>
					</div>
					<div class="text-sm text-text-primary">
						{t.name}
						{#if theme.current === t.id && savedId === t.id}
							<span class="text-xs text-success ml-1">Saved</span>
						{/if}
					</div>
				</button>
			{/each}
		</div>
	</section>
</div>
