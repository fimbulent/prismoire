<!--
	@component
	Host for transient toast notifications. Mount once in the root
	layout. Toasts are pushed via the imperative API in
	`./toast.svelte.ts` — `toast.error(msg)`, `toast.success(msg)`,
	`toast.info(msg)`.

	Two stacked ARIA live regions: errors are announced assertively
	(interrupts current screen-reader speech), success/info are
	announced politely (waits for a pause). The visual stack sits
	`fixed` in the bottom-right corner regardless of DOM order.

	Hover or focus pauses the auto-dismiss timer for that toast; on
	leave the timer restarts with a full duration window (see the
	`resume` note in `toast.svelte.ts`).
-->
<script lang="ts">
	import { fly } from 'svelte/transition';
	import { toasts, toast as toastApi, pause, resume, type Toast } from './toast.svelte';

	const errorToasts = $derived(toasts().filter((t) => t.kind === 'error'));
	const politeToasts = $derived(toasts().filter((t) => t.kind !== 'error'));

	// Side-stripe color per kind, layered over the standard surface
	// so toasts read as "tinted card" rather than "loud colored box".
	function kindAccentClass(kind: Toast['kind']): string {
		switch (kind) {
			case 'error':
				return 'border-l-4 border-l-danger';
			case 'success':
				return 'border-l-4 border-l-success';
			case 'info':
				return 'border-l-4 border-l-accent';
		}
	}
</script>

{#snippet toastRow(t: Toast)}
	<button
		type="button"
		onclick={() => toastApi.dismiss(t.id)}
		onmouseenter={() => pause(t.id)}
		onmouseleave={() => resume(t.id)}
		onfocusin={() => pause(t.id)}
		onfocusout={() => resume(t.id)}
		transition:fly={{ y: 16, duration: 200 }}
		class="pointer-events-auto block w-full text-left rounded-md border border-border bg-bg-surface text-text-primary text-sm px-4 py-3 shadow-md cursor-pointer hover:bg-bg-hover transition-colors {kindAccentClass(
			t.kind
		)}"
	>
		{t.message}
	</button>
{/snippet}

<div
	class="fixed z-50 bottom-4 right-4 left-4 sm:left-auto sm:max-w-sm flex flex-col gap-2 pointer-events-none"
	aria-label="Notifications"
>
	<!-- Errors: assertive — interrupts the current announcement. -->
	<div role="alert" aria-live="assertive" class="flex flex-col gap-2">
		{#each errorToasts as t (t.id)}
			{@render toastRow(t)}
		{/each}
	</div>
	<!-- Success / info: polite — announced at the next speech pause. -->
	<div role="status" aria-live="polite" class="flex flex-col gap-2">
		{#each politeToasts as t (t.id)}
			{@render toastRow(t)}
		{/each}
	</div>
</div>
