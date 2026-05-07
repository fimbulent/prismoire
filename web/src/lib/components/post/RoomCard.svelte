<!--
	A room as a card row in a vertical list.

	Used by:
	- `/rooms` — the main paginated rooms list with a dedicated
	  favorites rail; the parent owns optimistic state and passes
	  `onToggleFavorite` so the inline star drives both this card and
	  the rail in one round-trip.
	- `/search/rooms` — search results page reusing the same
	  visual treatment, with the same optimistic-favorite contract.

	The card shows the room slug + announcement badge, a viewer-scoped
	activity line ("N threads this week" or "last Nd"), the
	`last_visible_activity` relative timestamp when present, the
	7-day sparkline, and a favorite star aligned to the top right.
	The whole left column is a single anchor, so the click target
	covers everything except the favorite star.
-->
<script lang="ts">
	import Badge from '$lib/components/ui/Badge.svelte';
	import FavoriteStar from '$lib/components/ui/FavoriteStar.svelte';
	import Sparkline from '$lib/components/ui/Sparkline.svelte';
	import { relativeTime } from '$lib/format';
	import type { Room } from '$lib/api/rooms';

	interface Props {
		room: Room;
		/**
		 * Fired when the viewer clicks the inline favorite star. The
		 * parent is responsible for the optimistic flip + server call —
		 * this component is purely presentational so a single source of
		 * truth (the parent) drives the favorited flag and any companion
		 * UI (e.g. a favorites rail).
		 */
		onToggleFavorite: (room: Room, next: boolean) => void;
	}

	let { room, onToggleFavorite }: Props = $props();
</script>

<div
	class="bg-bg-surface border border-border rounded-md p-5 transition-[background,border-color] duration-150 hover:bg-bg-hover hover:border-accent-muted"
>
	<div class="flex items-start gap-3">
		<a
			href="/r/{encodeURIComponent(room.slug)}"
			class="flex-1 min-w-0 no-underline text-text-primary"
		>
			<div class="mb-1.5 flex items-center gap-2">
				<h3 class="text-base font-bold">{room.slug}</h3>
				{#if room.is_announcement}
					<Badge>Announcements</Badge>
				{/if}
			</div>
			<div class="flex items-center gap-4 text-xs text-text-muted">
				<span>
					{room.recent_thread_count}
					{room.recent_thread_count === 1 ? 'thread' : 'threads'}
					{room.activity_window_days >= 7
						? 'this week'
						: `last ${room.activity_window_days}d`}
				</span>
				{#if room.last_visible_activity}
					<span>
						Last active
						<span class="text-text-secondary">
							{relativeTime(room.last_visible_activity)}
						</span>
					</span>
				{/if}
				<Sparkline values={room.sparkline} label="Thread activity over 7 days" />
			</div>
		</a>
		<FavoriteStar
			favorited={room.favorited}
			onToggle={(next) => onToggleFavorite(room, next)}
		/>
	</div>
</div>
