<script lang="ts">
	import type { TrustInfo } from '$lib/api/users';

	interface Props {
		trust?: TrustInfo;
		compact?: boolean;
	}

	let { trust, compact = false }: Props = $props();

	let distance = $derived(trust?.distance ?? null);
	let distrusted = $derived(trust?.distrusted ?? false);

	type TrustLevel = 'direct' | '1_5hop' | '2hop' | '2_5hop' | '3hop' | 'untrusted';

	const snapPoints: [number, TrustLevel][] = [
		[1.0, 'direct'],
		[1.5, '1_5hop'],
		[2.0, '2hop'],
		[2.5, '2_5hop'],
		[3.0, '3hop'],
	];

	function level(): TrustLevel {
		if (distance == null) return 'untrusted';
		let closest: TrustLevel = 'untrusted';
		let minDiff = Infinity;
		for (const [point, lev] of snapPoints) {
			const diff = Math.abs(distance - point);
			if (diff < minDiff) {
				minDiff = diff;
				closest = lev;
			}
		}
		return closest;
	}

	type DotStyle = 'filled' | 'half' | 'empty';

	const dots: Record<TrustLevel, [DotStyle, DotStyle, DotStyle]> = {
		direct:    ['filled', 'filled', 'filled'],
		'1_5hop':  ['filled', 'filled', 'half'],
		'2hop':    ['filled', 'filled', 'empty'],
		'2_5hop':  ['filled', 'half', 'empty'],
		'3hop':    ['filled', 'empty', 'empty'],
		untrusted: ['empty', 'empty', 'empty'],
	};
</script>

{#if distrusted}<span
	class="trust-badge trust-badge-distrusted inline-flex items-center gap-0.5 text-xs leading-none rounded font-semibold {compact ? 'px-1 py-1' : 'px-1.5 py-1.5'}"
	title="Distrusted"
><svg class={compact ? 'w-2.5 h-2.5' : 'w-3 h-3'} viewBox="0 0 8 8" fill="none" stroke="currentColor" stroke-width="1"><circle cx="4" cy="4" r="3.25" /><line x1="1.5" y1="1.5" x2="6.5" y2="6.5" /></svg></span>
{:else}<span
	class="trust-badge trust-badge-{level()} inline-flex items-center gap-0.5 text-xs leading-none rounded font-semibold {compact ? 'px-1 py-1' : 'px-1.5 py-1.5'}"
	title={distance != null ? `Trust distance: ${distance.toFixed(2)}` : 'Untrusted'}
>{#each dots[level()] as dot}<svg class={compact ? 'w-2 h-2' : 'w-2.5 h-2.5'} viewBox="0 0 8 8">{#if dot === 'filled'}<circle cx="4" cy="4" r="3.5" fill="currentColor" stroke="currentColor" stroke-width="1" />{:else if dot === 'half'}<path d="M4 0.5 A3.5 3.5 0 0 0 4 7.5 Z" fill="currentColor" /><circle cx="4" cy="4" r="3.5" fill="none" stroke="currentColor" stroke-width="1" />{:else}<circle cx="4" cy="4" r="3.5" fill="none" stroke="currentColor" stroke-width="1" />{/if}</svg>{/each}</span>{/if}

<style>
	.trust-badge-direct { color: var(--trust-direct); background: color-mix(in srgb, var(--trust-direct) 12%, transparent); }
	.trust-badge-1_5hop { color: var(--trust-1_5hop); background: color-mix(in srgb, var(--trust-1_5hop) 12%, transparent); }
	.trust-badge-2hop { color: var(--trust-2hop); background: color-mix(in srgb, var(--trust-2hop) 12%, transparent); }
	.trust-badge-2_5hop { color: var(--trust-2_5hop); background: color-mix(in srgb, var(--trust-2_5hop) 12%, transparent); }
	.trust-badge-3hop { color: var(--trust-3hop); background: color-mix(in srgb, var(--trust-3hop) 12%, transparent); }
	.trust-badge-untrusted { color: var(--trust-untrusted); background: color-mix(in srgb, var(--trust-untrusted) 10%, transparent); }
	.trust-badge-distrusted { color: var(--danger); background: color-mix(in srgb, var(--danger) 12%, transparent); }
</style>
