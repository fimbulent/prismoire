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

	const dots: Record<TrustLevel, string> = {
		direct: '\u25CF\u25CF\u25CF',
		'2hop': '\u25CF\u25CF\u25CB',
		'3hop': '\u25CF\u25CB\u25CB',
		untrusted: '\u25CB\u25CB\u25CB'
	};
</script>

<span
	class="trust-badge trust-badge-{level()} inline-flex items-center text-xs leading-none rounded font-semibold -translate-y-px {compact ? 'px-1 py-0.5' : 'px-1.5 py-1 tracking-wide'}"
	title={distance != null ? `Trust distance: ${distance.toFixed(2)}` : 'Untrusted'}
>{dots[level()]}</span>

<style>
	.trust-badge-direct { color: var(--trust-direct); background: color-mix(in srgb, var(--trust-direct) 12%, transparent); }
	.trust-badge-2hop { color: var(--trust-2hop); background: color-mix(in srgb, var(--trust-2hop) 12%, transparent); }
	.trust-badge-3hop { color: var(--trust-3hop); background: color-mix(in srgb, var(--trust-3hop) 12%, transparent); }
	.trust-badge-untrusted { color: var(--trust-untrusted); background: color-mix(in srgb, var(--trust-untrusted) 10%, transparent); }
</style>
