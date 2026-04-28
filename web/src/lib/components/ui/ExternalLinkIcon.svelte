<script lang="ts">
	let { class: className = 'inline align-[-0.05em]', size = 10 }: { class?: string; size?: number } =
		$props();
</script>

<svg
	width={size}
	height={size}
	viewBox="0 0 16 16"
	fill="none"
	stroke="currentColor"
	stroke-width="1.8"
	stroke-linecap="round"
	stroke-linejoin="round"
	class={className}
	aria-hidden="true"
>
	<path d="M6 3 H3 v10 h10 V10" />
	<polyline points="9 3 13 3 13 7" />
	<line x1="13" y1="3" x2="7" y2="9" />
</svg>
