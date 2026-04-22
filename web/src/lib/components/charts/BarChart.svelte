<!--
	@component
	Minimal SVG bar chart built on LayerCake. Takes an array of
	`{ label, value }` rows and renders a single bar per row. The last bar
	is highlighted to indicate "current" (today / this week).

	Rendering notes:
	  * All bars use SVG presentation attributes (x/y/width/height/rx/fill),
	    not inline `style=""`, so this component is safe under the project's
	    `style-src-attr` CSP.
	  * LayerCake's own wrapper emits `style:position="relative"`, which is
	    a minor, app-global issue — cosmetic under CSP, the wrapper's own
	    stylesheet also applies `position: relative`.
-->
<script lang="ts">
	import { LayerCake, Svg } from 'layercake';
	import BarChartBars from './BarChartBars.svelte';

	interface Props {
		data: Array<{ label: string; value: number }>;
		/** Pixel height of the chart area (bars). Labels render below. */
		height?: number;
		/** Optional caption rendered below the chart, right-aligned. */
		caption?: string;
	}

	let { data, height = 96, caption }: Props = $props();

	const maxValue = $derived(Math.max(1, ...data.map((d) => d.value)));

	const labels = $derived(data.map((d) => d.label));
</script>

<div class="w-full">
	<div class="w-full" class:h-24={height === 96} class:h-32={height === 128}>
		<LayerCake
			data={data.map((d, i) => ({ ...d, i }))}
			x="i"
			y="value"
			xDomain={[0, data.length]}
			yDomain={[0, maxValue]}
			padding={{ top: 4, right: 0, bottom: 0, left: 0 }}
		>
			<Svg>
				<BarChartBars />
			</Svg>
		</LayerCake>
	</div>
	<div class="flex gap-1 mt-1">
		{#each labels as label, i}
			<div
				class="flex-1 text-center text-[0.6rem] {i === labels.length - 1
					? 'text-text-secondary font-semibold'
					: 'text-text-muted'}"
			>
				{label}
			</div>
		{/each}
	</div>
	{#if caption}
		<div class="text-[0.65rem] text-text-muted mt-1 text-right">{caption}</div>
	{/if}
</div>
