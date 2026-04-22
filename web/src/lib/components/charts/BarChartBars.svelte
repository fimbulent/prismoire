<!--
	@component
	Renders the <rect> bars for the parent BarChart. Pulls scales and
	dimensions from the LayerCake context, so it only works as a child of
	`<LayerCake><Svg>...</Svg></LayerCake>`.

	Uses only SVG presentation attributes — no inline styles — so it
	complies with the project-wide `style-src-attr` CSP.
-->
<script lang="ts">
	import { getContext } from 'svelte';
	import type { Readable } from 'svelte/store';

	// LayerCake's context shape is dynamic; we narrow to the fields we use.
	type ScaleFn = ((v: number) => number) & { invert?: (v: number) => number };
	type LayerCakeCtx = {
		data: Readable<Array<{ i: number; value: number; label: string }>>;
		xScale: Readable<ScaleFn>;
		yScale: Readable<ScaleFn>;
		width: Readable<number>;
		height: Readable<number>;
	};

	const { data, xScale, yScale, width, height } = getContext<LayerCakeCtx>('LayerCake');

	// Bar width: 80% of the slot assigned to each bar, leaving 20% gap.
	const barWidth = $derived(($width / Math.max(1, $data.length)) * 0.8);
	const gap = $derived($width / Math.max(1, $data.length) - barWidth);
</script>

{#each $data as d (d.i)}
	{@const cx = $xScale(d.i + 0.5)}
	{@const y = $yScale(d.value)}
	{@const barH = Math.max(0, $height - y)}
	<rect
		x={cx - barWidth / 2}
		{y}
		width={barWidth}
		height={barH}
		rx="2"
		class={d.i === $data.length - 1 ? 'fill-accent' : 'fill-accent-muted'}
	>
		<title>{d.value}</title>
	</rect>
{/each}
