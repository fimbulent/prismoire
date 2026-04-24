<!--
	@component
	Activity sparkline. Shape and color palette mirror the design mockup
	in `mockups/topic-list-tailwind.html`:

	  * N 4px-wide bars separated by 2px gaps, where N = values.length
	    (typically 1..=7). A 7-bar sparkline is 42px wide; shorter windows
	    render narrower so the component hugs the number of buckets the
	    server actually returned.
	  * Bars are bottom-aligned with `rx="1"` rounded corners.
	  * Four-tier color palette (via CSS custom properties so theme
	    switching works automatically):
	      - `var(--border)`       — empty buckets (min 2px height)
	      - `var(--text-muted)`   — normal activity
	      - `var(--accent-muted)` — peak activity bar (ties: prefer later)
	      - `var(--accent)`       — today-so-far, when it is the peak

	SVG presentation attributes (`x`, `y`, `width`, `height`, `fill`) are
	used instead of inline `style=""`, so this renders cleanly under the
	project's `style-src-attr` CSP.
-->
<script lang="ts">
	interface Props {
		/** Per-bucket values, oldest first. Last entry is "today-so-far". */
		values: readonly number[];
		/** Optional accessible label for screen readers. */
		label?: string;
	}

	let { values, label }: Props = $props();

	// Geometry matches the mockup exactly at the 7-bar "full" width:
	// seven 4px bars + six 2px gaps = 40px, plus a trailing +2 of
	// padding lands on 42. For a variable bar count N we generalise as
	// N * BAR_W + (N - 1) * GAP + 2 so the rightmost bar keeps the same
	// 2px of breathing room as the 7-bar version.
	const HEIGHT = 14;
	const BAR_W = 4;
	const GAP = 2;
	const MIN_H = 2;
	const TRAILING_PAD = 2;

	const width = $derived(
		values.length === 0
			? BAR_W + TRAILING_PAD
			: values.length * BAR_W + (values.length - 1) * GAP + TRAILING_PAD
	);

	const maxValue = $derived(Math.max(0, ...values));

	// Index of the bar to highlight as the "peak" accent. Ties resolve
	// to the *later* bucket so today wins over an equal-height earlier
	// day. Returns -1 if every bucket is empty (nothing to highlight).
	const peakIdx = $derived.by(() => {
		if (maxValue <= 0) return -1;
		let idx = -1;
		for (let i = 0; i < values.length; i++) {
			if (values[i] >= maxValue) idx = i;
		}
		return idx;
	});

	const lastIdx = $derived(values.length - 1);

	function barHeight(v: number): number {
		if (v <= 0 || maxValue <= 0) return MIN_H;
		// Scale so the peak fills the full 14px column.
		return Math.max(MIN_H, Math.round((v / maxValue) * HEIGHT));
	}

	function barFill(v: number, i: number): string {
		if (v <= 0) return 'var(--border)';
		if (i === peakIdx && i === lastIdx) return 'var(--accent)';
		if (i === peakIdx) return 'var(--accent-muted)';
		return 'var(--text-muted)';
	}
</script>

<svg
	class="inline-block"
	{width}
	height={HEIGHT}
	viewBox="0 0 {width} {HEIGHT}"
	role={label ? 'img' : 'presentation'}
	aria-label={label}
>
	{#each values as v, i}
		{@const h = barHeight(v)}
		{@const x = i * (BAR_W + GAP)}
		{@const y = HEIGHT - h}
		<rect {x} {y} width={BAR_W} height={h} rx="1" fill={barFill(v, i)} />
	{/each}
</svg>
