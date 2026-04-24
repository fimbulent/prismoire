<!--
	@component
	A toggle button that stars/unstars a room as a favorite. Renders a
	filled or outlined star icon via SVG presentation attributes (no
	inline styles, CSP-safe). The parent is responsible for persisting
	the change via `favoriteRoom` / `unfavoriteRoom` — this component
	only emits a requested-state callback and renders the current state.
-->
<script lang="ts">
	interface Props {
		/** Current favorite state. */
		favorited: boolean;
		/** Fired with the desired new state when the user clicks. */
		onToggle: (next: boolean) => void;
		/** Disable the button (e.g. while a request is in flight, or at cap). */
		disabled?: boolean;
		/** Accessible label; defaults to generic "Favorite/Unfavorite". */
		label?: string;
	}

	let { favorited, onToggle, disabled = false, label }: Props = $props();

	const aria = $derived(label ?? (favorited ? 'Remove from favorites' : 'Add to favorites'));
</script>

<button
	type="button"
	onclick={(e) => {
		// Rooms list rows are often wrapped in <a>; prevent that link from
		// navigating when the user is clicking the star inside it.
		e.preventDefault();
		e.stopPropagation();
		if (!disabled) onToggle(!favorited);
	}}
	aria-label={aria}
	aria-pressed={favorited}
	{disabled}
	class="inline-flex items-center justify-center w-7 h-7 rounded-md cursor-pointer transition-colors duration-150
		{favorited
		? 'text-accent hover:bg-accent/10'
		: 'text-text-muted hover:text-text-secondary hover:bg-bg-hover'}
		disabled:opacity-50 disabled:cursor-not-allowed"
>
	<svg
		width="16"
		height="16"
		viewBox="0 0 24 24"
		fill={favorited ? 'currentColor' : 'none'}
		stroke="currentColor"
		stroke-width="2"
		stroke-linecap="round"
		stroke-linejoin="round"
		aria-hidden="true"
	>
		<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
	</svg>
</button>
