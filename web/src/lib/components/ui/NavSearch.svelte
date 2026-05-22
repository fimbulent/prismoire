<!--
	Magnifying-glass toggle that expands into the global search input.

	Wraps `SectionedAutocomplete` with the "icon collapses to nothing,
	tap to expand into a textbox" chrome from
	`mockups/thread-list-tailwind.html`. The wrapper owns the
	expanded / collapsed state and the width / opacity transition; the
	autocomplete itself stays a pure search component (input + dropdown)
	and exposes `focus()` + `clear()` so the wrapper can drive it
	imperatively without leaking state.

	## CSP

	The mockup uses inline `style.width / .padding / .opacity` writes
	to animate. Our CSP forbids `style-src-attr`, so we toggle Tailwind
	classes (`w-0` ↔ `w-48`, `opacity-0` ↔ `opacity-100`,
	`border-0` ↔ `border`, `px-0` ↔ `px-2`) on a `transition-all`
	wrapper instead. No inline `style` attribute or `element.style.*`
	writes anywhere.
-->
<script lang="ts">
	import SectionedAutocomplete from '$lib/components/ui/SectionedAutocomplete.svelte';

	// `expanded` is bindable so the surrounding nav can react — on mobile
	// it hides the Prismoire logo and lets the search field take the full
	// row width while expanded.
	let { expanded = $bindable(false) } = $props();
	let autocomplete = $state<{
		focus(): void;
		clear(): void;
		isEmpty(): boolean;
	} | null>(null);
	let wrapperEl = $state<HTMLDivElement | null>(null);

	function expand() {
		expanded = true;
		// Focus on the next microtask so the width transition has begun
		// before focus lands — focusing while the wrapper is still `w-0`
		// can scroll surrounding content into view unnecessarily.
		queueMicrotask(() => autocomplete?.focus());
	}

	function collapse() {
		expanded = false;
		autocomplete?.clear();
	}

	function toggle() {
		if (expanded) collapse();
		else expand();
	}

	// Escape collapses the input as a whole. The autocomplete's own
	// Escape handler closes the dropdown first; this listener only
	// catches presses that bubble out (dropdown was already closed).
	// Mounted via `$effect` so it's only registered while expanded —
	// avoids fighting Escape handlers elsewhere in the app.
	$effect(() => {
		if (!expanded || typeof document === 'undefined') return;
		function onKeydown(e: KeyboardEvent) {
			if (e.key === 'Escape' && !e.defaultPrevented) {
				collapse();
			}
		}
		document.addEventListener('keydown', onKeydown);
		return () => document.removeEventListener('keydown', onKeydown);
	});

	// Auto-collapse when focus leaves the wrapper *and* the input is
	// empty. We deliberately keep the field expanded if the user has
	// typed something — a brief stray click shouldn't wipe their query.
	// The autocomplete's row-click handler already preventDefaults the
	// pointerdown to keep focus on the input, so navigating to a result
	// doesn't trip this path either.
	function onFocusOut(e: FocusEvent) {
		const next = e.relatedTarget as Node | null;
		if (next && wrapperEl?.contains(next)) return; // focus moved within
		if (autocomplete?.isEmpty() ?? true) collapse();
	}
</script>

<div
	bind:this={wrapperEl}
	class="flex items-center gap-2 min-w-0"
	role="search"
	onfocusout={onFocusOut}
>
	<button
		type="button"
		onclick={toggle}
		aria-label={expanded ? 'Close search' : 'Open search'}
		aria-expanded={expanded}
		class="bg-transparent border-none text-text-secondary cursor-pointer p-1 rounded hover:bg-bg-hover hover:text-text-primary transition-colors"
	>
		<svg
			width="16"
			height="16"
			viewBox="0 0 16 16"
			fill="none"
			stroke="currentColor"
			stroke-width="1.5"
			stroke-linecap="round"
			aria-hidden="true"
		>
			<circle cx="7" cy="7" r="4.5" />
			<line x1="10.2" y1="10.2" x2="14" y2="14" />
		</svg>
	</button>

	<!--
		The autocomplete is rendered unconditionally so its dropdown +
		positioning state survive across the transition; the wrapper's
		width / opacity classes are what hide it when collapsed. Mounting
		on expand and unmounting on collapse would lose the (already
		debounced) request seq + committedQuery guards.
	-->
	<div
		class="overflow-visible transition-all duration-200 min-w-0 {expanded
			? 'w-[14rem] sm:w-48 opacity-100'
			: 'w-0 opacity-0 pointer-events-none'}"
		aria-hidden={!expanded}
	>
		<SectionedAutocomplete bind:this={autocomplete} onNavigate={collapse} />
	</div>
</div>
