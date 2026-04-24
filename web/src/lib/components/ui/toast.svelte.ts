// SSR-safe transient-notification facade.
//
// Module-level `$state` under adapter-node is shared across concurrent
// requests, so writing request-scoped data into it would leak one
// user's notification into another user's render. Toasts are
// definitionally client-only — they're triggered from event handlers
// after hydration and never rendered on the server (the queue starts
// empty and stays empty during SSR). The `typeof window === 'undefined'`
// guard in `push()` makes the invariant defensive rather than
// aspirational: a stray server-side call (e.g. from a load function
// that accidentally imports this) is a silent no-op instead of a
// cross-request leak.

/** How long a toast remains visible before auto-dismiss. */
const DEFAULT_DURATION_MS = 5000;

/**
 * Max toasts visible at once. Older toasts drop off the top of the
 * stack when a new one arrives past the cap; the dropped toast's
 * pending auto-dismiss timer is cancelled so it cannot fire on an
 * already-evicted id.
 */
const MAX_VISIBLE = 3;

export type ToastKind = 'error' | 'success' | 'info';

export interface Toast {
	id: number;
	kind: ToastKind;
	message: string;
}

let items = $state<Toast[]>([]);
const timers = new Map<number, ReturnType<typeof setTimeout>>();
let nextId = 0;

function clearTimer(id: number): void {
	const t = timers.get(id);
	if (t !== undefined) {
		clearTimeout(t);
		timers.delete(id);
	}
}

function scheduleDismiss(id: number): void {
	timers.set(
		id,
		setTimeout(() => dismiss(id), DEFAULT_DURATION_MS)
	);
}

function push(kind: ToastKind, message: string): void {
	if (typeof window === 'undefined') return;
	const id = nextId++;
	const next = [...items, { id, kind, message }];
	while (next.length > MAX_VISIBLE) {
		const dropped = next.shift();
		if (dropped) clearTimer(dropped.id);
	}
	items = next;
	scheduleDismiss(id);
}

/** Remove a toast and cancel its auto-dismiss timer. Idempotent. */
export function dismiss(id: number): void {
	clearTimer(id);
	items = items.filter((t) => t.id !== id);
}

/**
 * Pause the auto-dismiss timer — e.g. while the user hovers or
 * focuses the host. `resume` restarts a fresh `DEFAULT_DURATION_MS`
 * window rather than continuing the remaining time; matches user
 * expectation that a hover "resets" the toast's lifetime.
 */
export function pause(id: number): void {
	clearTimer(id);
}

export function resume(id: number): void {
	if (timers.has(id)) return;
	if (!items.some((t) => t.id === id)) return;
	scheduleDismiss(id);
}

/**
 * Read-accessor for the reactive queue. Templates that call this
 * inside a `$derived` or `{#each}` track the underlying `$state`
 * through the getter, so mutations from `push`/`dismiss` re-render.
 */
export function toasts(): readonly Toast[] {
	return items;
}

/**
 * Imperative push API. Call from client event handlers:
 *
 *     toast.error('Failed to save favorite.');
 *     toast.success('Profile updated.');
 *
 * Takes a plain string rather than an `ApiRequestError` so it's
 * compatible with both raw server messages (today) and the
 * forthcoming code-to-message catalog (see `docs/fix-errors.md`).
 */
export const toast = {
	error: (message: string) => push('error', message),
	success: (message: string) => push('success', message),
	info: (message: string) => push('info', message),
	dismiss
};
