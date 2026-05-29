<script lang="ts">
	import { GRID, keyLabel } from '$lib/pubkey/keyLabel';

	let {
		pubkeyHex,
		size = 28,
		showName = true
	}: {
		/** Lowercase-hex instance signing key. */
		pubkeyHex: string;
		/** Glyph edge length in px. */
		size?: number;
		/** Whether to render the two-word name beside the glyph. */
		showName?: boolean;
	} = $props();

	const label = $derived(keyLabel(pubkeyHex));
	// CSS color string for SVG `fill` (a presentation attribute — CSP-safe,
	// unlike `style=` or Tailwind arbitrary colors; see web/CLAUDE.md).
	// OKLCH so a single fixed lightness/chroma reads evenly across every hue
	// (HSL lightness is not perceptual — yellow vs. blue would differ wildly).
	const fg = $derived(`oklch(0.62 0.15 ${label.hue})`);
</script>

<span class="inline-flex items-center gap-2" title={label.name}>
	<svg
		width={size}
		height={size}
		viewBox="0 0 {GRID} {GRID}"
		role="img"
		aria-label="Identicon for {label.name}"
		class="rounded shrink-0 bg-bg-surface"
	>
		{#each label.cells as on, i (i)}
			{#if on}
				<rect x={i % GRID} y={Math.floor(i / GRID)} width="1" height="1" fill={fg} />
			{/if}
		{/each}
	</svg>
	{#if showName}
		<span class="text-text-secondary font-medium">{label.name}</span>
	{/if}
</span>
