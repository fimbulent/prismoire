<script lang="ts">
	interface Props {
		distance: number | null | undefined;
		compact?: boolean;
	}

	let { distance, compact = false }: Props = $props();

	type TrustLevel = 'direct' | '2hop' | '3hop' | 'untrusted';

	function level(): TrustLevel {
		if (distance == null) return 'untrusted';
		if (distance <= 1.0) return 'direct';
		if (distance <= 2.0) return '2hop';
		if (distance <= 3.0) return '3hop';
		return 'untrusted';
	}

	const filled: Record<TrustLevel, number> = {
		direct: 3,
		'2hop': 2,
		'3hop': 1,
		untrusted: 0
	};
</script>

<span
	class="trust-badge trust-badge-{level()} inline-flex items-center gap-0.5 text-xs leading-none rounded font-semibold {compact ? 'px-1 py-1' : 'px-1.5 py-1.5'}"
	title={distance != null ? `Trust distance: ${distance.toFixed(2)}` : 'Untrusted'}
>{#each [0, 1, 2] as i}<svg class={compact ? 'w-2 h-2' : 'w-2.5 h-2.5'} viewBox="0 0 8 8"><circle cx="4" cy="4" r="3.5" fill={i < filled[level()] ? 'currentColor' : 'none'} stroke="currentColor" stroke-width="1" /></svg>{/each}</span>

<style>
	.trust-badge-direct { color: var(--trust-direct); background: color-mix(in srgb, var(--trust-direct) 12%, transparent); }
	.trust-badge-2hop { color: var(--trust-2hop); background: color-mix(in srgb, var(--trust-2hop) 12%, transparent); }
	.trust-badge-3hop { color: var(--trust-3hop); background: color-mix(in srgb, var(--trust-3hop) 12%, transparent); }
	.trust-badge-untrusted { color: var(--trust-untrusted); background: color-mix(in srgb, var(--trust-untrusted) 10%, transparent); }
</style>
