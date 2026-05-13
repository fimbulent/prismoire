<script lang="ts">
	import { page } from '$app/state';

	let { children } = $props();

	// Sections appear in nav order. `label` is the sidebar text;
	// `title` is the browser-tab title (avoids the awkward repetition
	// of "About Prismoire — Prismoire").
	const sections = [
		{ href: '/help/about', label: 'About Prismoire', title: 'About' },
		{ href: '/help/trust', label: 'Trust and distrust', title: 'Trust and Distrust' },
		{ href: '/help/markdown', label: 'Markdown', title: 'Markdown' }
	];

	const active = $derived(page.url.pathname);

	const activeTitle = $derived(
		sections.find((s) => active === s.href || active.startsWith(s.href + '/'))?.title ?? 'Help'
	);
</script>

<svelte:head>
	<title>{activeTitle} — Prismoire</title>
</svelte:head>

<div class="max-w-5xl mx-auto px-6 pt-6 pb-16">
	<div class="md:grid md:grid-cols-[14rem_1fr] md:gap-10">
		<nav
			aria-label="Help sections"
			class="bg-bg-surface border border-border rounded-md p-3 mb-6 md:mb-0 md:self-start"
		>
			<h2 class="text-xs font-bold uppercase tracking-wide text-text-muted px-2 mb-2">
				Help
			</h2>
			<ul class="space-y-0.5">
				{#each sections as section (section.href)}
					<li>
						<a
							href={section.href}
							aria-current={active === section.href ? 'page' : undefined}
							class={`block rounded px-2 py-1.5 text-sm no-underline transition-colors ${
								active === section.href
									? 'bg-bg-surface-raised text-accent font-semibold'
									: 'text-text-secondary hover:bg-bg-hover hover:text-text-primary'
							}`}
						>
							{section.label}
						</a>
					</li>
				{/each}
			</ul>
		</nav>
		<main class="font-prose text-prose">
			{@render children()}
		</main>
	</div>
</div>
