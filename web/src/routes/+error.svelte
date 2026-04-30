<script lang="ts">
	// Root error boundary. SvelteKit renders this for any uncaught error
	// thrown from a `load` (via `kitError`) or any unexpected throw that
	// reaches `handleError` in `src/hooks.server.ts`. It renders inside
	// the root `+layout.svelte`, so the nav remains visible and the user
	// can navigate out without a full reload.
	//
	// `page.error` is typed as `App.Error` (`src/app.d.ts`): a generic
	// `message` plus an optional `errorId` (UUID generated server-side
	// for support correlation). For non-`kitError` 5xx, `handleError`
	// already replaces the raw message with a generic string, so we
	// never surface backend internals here.
	import { page } from '$app/state';
	import { goto } from '$app/navigation';

	const status = $derived(page.status);
	const errorId = $derived(page.error?.errorId);
	const message = $derived(page.error?.message ?? '');

	type Variant = {
		title: string;
		body: string;
		retry: boolean;
	};

	// Per-status copy. Keep messages friendly and non-blaming; never
	// leak backend implementation details. Anything not listed falls
	// through to `defaultVariant` (treated as a 5xx).
	const variants: Record<number, Variant> = {
		400: {
			title: 'Bad request',
			body: 'The request didn’t look right. Double-check the URL or try again.',
			retry: false
		},
		401: {
			title: 'Sign in required',
			body: 'This page is only visible once you’re signed in.',
			retry: false
		},
		403: {
			title: 'Out of reach',
			body: 'This part of the network isn’t visible to you.',
			retry: false
		},
		404: {
			title: 'Nothing here',
			body: 'This page may have moved, been removed, or never existed in your view of the network.',
			retry: false
		},
		429: {
			title: 'Slow down',
			body: 'You’re moving faster than the server can keep up with. Give it a moment.',
			retry: true
		},
		500: {
			title: 'Something broke',
			body: 'An unexpected error occurred on our end.',
			retry: true
		},
		503: {
			title: 'Temporarily unavailable',
			body: 'A backend service didn’t respond in time. Try again in a moment.',
			retry: true
		}
	};

	const defaultVariant: Variant = {
		title: 'Something went wrong',
		body: 'An unexpected error occurred.',
		retry: true
	};

	const variant = $derived(variants[status] ?? defaultVariant);
	const headTitle = $derived(`${status || 'Error'} ${variant.title} — Prismoire`);

	// Prefer the server-provided message when it's specific (not the
	// generic 5xx placeholder from `handleError` and not just a copy of
	// the canned variant body). Fall back to the friendlier variant
	// body otherwise. We never render both — that produced the awkward
	// "generic 404 explainer + specific 'Room not found'" stack.
	const bodyText = $derived(
		message.length > 0 && message !== 'Something went wrong' && message !== variant.body
			? message
			: variant.body
	);

	function goBack() {
		if (typeof history !== 'undefined' && history.length > 1) {
			history.back();
		} else {
			goto('/');
		}
	}

	function tryAgain() {
		if (typeof location !== 'undefined') {
			location.reload();
		}
	}
</script>

<svelte:head>
	<title>{headTitle}</title>
</svelte:head>

<div
	class="grid place-items-center px-4 py-12 min-h-[calc(100dvh-var(--nav-height)-var(--footer-height))] bg-gradient-to-b from-transparent via-bg-surface-dim/30 to-transparent"
>
	<div class="w-full max-w-md text-center">
		<!--
			Big status digits, color-ramped through the trust palette.
			`select-none` so the decorative number isn't accidentally
			swept up by a copy-all; the actionable errorId below stays
			selectable.
		-->
		{#if status}
			<div class="mb-8 leading-none select-none" aria-hidden="true">
				<span class="text-accent text-8xl sm:text-9xl font-extrabold tracking-tighter">
					{status}
				</span>
			</div>
		{/if}

		<h1 class="text-2xl font-bold text-text-primary tracking-wide mb-2">
			{variant.title}
		</h1>
		<p class="text-text-secondary text-sm mb-8">{bodyText}</p>

		<div class="flex flex-wrap gap-3 justify-center">
			<button
				type="button"
				onclick={goBack}
				class="bg-bg-surface-raised border border-border text-text-primary font-semibold rounded-md px-4 py-2 hover:bg-bg-hover transition-colors cursor-pointer"
			>
				Go back
			</button>
			<a
				href="/"
				class="bg-accent text-bg font-semibold rounded-md px-4 py-2 hover:opacity-90 transition-opacity"
			>
				Home
			</a>
			{#if variant.retry}
				<button
					type="button"
					onclick={tryAgain}
					class="bg-bg-surface-raised border border-border text-text-primary font-semibold rounded-md px-4 py-2 hover:bg-bg-hover transition-colors cursor-pointer"
				>
					Try again
				</button>
			{/if}
		</div>

		{#if errorId && status >= 500}
			<p class="mt-10 text-xs text-text-muted">
				Error ID:
				<span class="font-mono select-all text-text-secondary">{errorId}</span>
			</p>
		{/if}
	</div>
</div>