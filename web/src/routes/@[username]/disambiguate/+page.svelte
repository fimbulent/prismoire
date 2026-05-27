<!--
	Disambiguation page (Phase 9.5).

	Reached when multiple users share the typed bare name's
	confusable-folded skeleton — typically a local user and a federated
	stub, but more matches are possible. Each row is a card showing:

	  - The user's display name (the bare form, since all rows in the
	    list share the skeleton — the suffix is what differentiates them).
	  - The 8-hex pubkey-prefix as a chip, since that is the *only*
	    rendered differentiator between rows for the viewer.
	  - An instance hint when the user is homed elsewhere (truncated
	    home-instance pubkey). Suppressed for locally-homed users since
	    they're the implicit default.
	  - The wire-facing status as a badge for non-active rows so the
	    viewer recognises banned / suspended / deleted entries.

	Clicking a row navigates to the canonical long-form profile URL
	(`/@{name}.{pubkey-prefix}`). The loader on that page emits the
	`<link rel="canonical">`.
-->
<script lang="ts">
	import type { PageProps } from './$types';
	import { canonicalProfilePath } from '$lib/user-url';

	let { data }: PageProps = $props();

	/// Shortened instance fingerprint for the hint chip. We render 8
	/// hex chars (32 bits) — enough for the viewer to tell two
	/// instances apart at a glance without dominating the row.
	function instanceShort(hex: string): string {
		return hex.slice(0, 8);
	}
</script>

<svelte:head>
	<title>Choose user — {data.bareName} — Prismoire</title>
	<meta name="robots" content="noindex" />
</svelte:head>

<div class="max-w-2xl mx-auto px-6 py-8">
	<h1 class="text-2xl font-semibold text-text-primary mb-2">
		Multiple users named “{data.bareName}”
	</h1>
	<p class="text-sm text-text-secondary mb-6">
		Several accounts share this display name. Pick the one you meant — the
		address bar will switch to the long form so future links keep working.
	</p>

	<ul class="space-y-2">
		{#each data.matches as match (match.id)}
			<li>
				<a
					href={canonicalProfilePath(match.display_name, match.public_key_hex)}
					class="block bg-bg-surface border border-border rounded-md px-4 py-3 hover:border-accent-muted transition-colors"
				>
					<div class="flex items-center gap-3 flex-wrap">
						<span class="font-semibold text-text-primary">
							@{match.display_name}
						</span>
						<span
							class="font-mono text-xs px-2 py-0.5 rounded bg-bg-surface-raised border border-border text-text-secondary"
						>
							.{match.public_key_hex.slice(0, 8)}
						</span>
						{#if match.home_instance_hex}
							<span
								class="text-xs text-text-muted"
								title="Home instance pubkey: {match.home_instance_hex}"
							>
								home: {instanceShort(match.home_instance_hex)}
							</span>
						{:else}
							<span class="text-xs text-text-muted">home: local</span>
						{/if}
						{#if match.status !== 'active'}
							<span
								class="text-xs px-2 py-0.5 rounded border border-border-subtle text-text-muted uppercase tracking-wide"
							>
								{match.status}
							</span>
						{/if}
					</div>
				</a>
			</li>
		{/each}
	</ul>
</div>
