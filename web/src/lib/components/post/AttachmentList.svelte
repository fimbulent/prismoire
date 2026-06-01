<script lang="ts">
	/**
	 * Render attachment download chips for a post revision.
	 *
	 * Inline images are no longer rendered here — `![](filename)`
	 * references in the post body resolve into `<img>` tags at markdown
	 * render time (`docs/attachments.md` §3). The caller (`PostCard`)
	 * pre-filters out entries that the body inlines, so this component
	 * only sees attachments that genuinely belong below the body:
	 * non-image bindings (downloads) and image bindings the author did
	 * not `![](…)`-reference inline.
	 *
	 * Accepts both the live `AttachmentResponse` (latest-revision
	 * projection, always available) and the per-revision
	 * `RevisionAttachmentEntry` (decoded from signed payload, carries
	 * `available: boolean`). The two shapes share the fields this
	 * component consumes, so we declare a minimal item type. Entries
	 * with `available === false` render a "removed" placeholder chip —
	 * the binding is gone via §6.1 set-diff or the blob is missing, so
	 * the `/api/attachments/{hash}` URL would 404.
	 *
	 * A second, distinct unavailable case is federation fetch-on-demand
	 * (`docs/federation-protocol.md` §11.4): the binding is live and the
	 * metadata is signed, but the blob bytes are not (yet) resident
	 * because the post is remote and the origin fetch is pending or has
	 * hard-failed. The signed `available` flag can't capture this — it's
	 * a property of *this* instance's blob store, not the revision. So we
	 * probe each live chip's `/api/attachments/{hash}` with a client-side
	 * HEAD on mount; a `404` swaps the download link for an "unavailable"
	 * placeholder built from the same signed metadata (filename, MIME,
	 * size). The probe doubles as the §11.4 serve-trigger warm-up: a HEAD
	 * on a remote, not-yet-cached blob drives the inline origin fetch, so
	 * a chip that 404s on first paint may serve cleanly on a later visit.
	 *
	 * The probe is gated on `isRemote`: a locally-authored post's blobs
	 * are always resident (no fetch-on-demand), so probing them would be
	 * a wasted HEAD per chip on every render for the common all-local
	 * case. Only federated posts can carry a not-yet-resident blob.
	 */
	import { formatMime } from '$lib/api/attachments';

	interface AttachmentListItem {
		content_hash: string;
		filename: string;
		/** Canonical upload-classifier MIME — shown in the §11.4
		 * unavailable placeholder so the reader knows what the missing
		 * blob is. */
		mime: string;
		size: number;
		position: number;
		/** `false` only for old revisions whose attachment was later
		 * removed (or whose blob is missing). Undefined === available. */
		available?: boolean;
	}

	interface Props {
		attachments: AttachmentListItem[];
		/** Whether the owning post is federated. The §11.4 availability
		 * probe runs only when true — see the component docstring. */
		isRemote?: boolean;
	}

	let { attachments, isRemote = false }: Props = $props();

	/** Per-hash result of the §11.4 availability probe. Absence of a key
	 * means "not yet probed / in flight" — we render the optimistic
	 * download link until a `404` proves the blob unavailable, so a
	 * resident attachment never flickers through a placeholder. */
	let availability = $state<Record<string, 'available' | 'unavailable'>>({});

	/** Hashes a probe has already been dispatched for. Plain (non-`$state`)
	 * so reading/writing it inside the effect doesn't feed back into the
	 * effect's dependency set: the effect re-runs only when `attachments`
	 * changes, and this guard keeps a re-render (or revision switch that
	 * re-uses a hash) from re-probing a blob we've already checked. */
	const probed = new Set<string>();

	$effect(() => {
		// Local posts never have a non-resident blob, so skip the probe
		// entirely — chips render as plain download links.
		if (!isRemote) return;
		let cancelled = false;
		for (const att of attachments) {
			// `available === false` is the signed-metadata "removed" case;
			// it renders its own placeholder and never points at a live
			// URL, so there's nothing to probe.
			if (att.available === false || probed.has(att.content_hash)) continue;
			probed.add(att.content_hash);
			fetch(attachmentUrl(att.content_hash), { method: 'HEAD' })
				.then((res) => {
					if (cancelled) return;
					availability[att.content_hash] = res.status === 404 ? 'unavailable' : 'available';
				})
				.catch(() => {
					// Network blip / aborted navigation: stay optimistic and
					// keep the download link. A transient probe failure
					// shouldn't dead-end the user at a placeholder for a blob
					// that may well be servable.
				});
		}
		return () => {
			cancelled = true;
		};
	});

	/** Human-readable size: 24 KiB, 1.4 MiB. Keeps to two significant
	 * figures so an attachment chip stays compact. */
	function formatSize(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		const kib = bytes / 1024;
		if (kib < 1024) return `${kib < 10 ? kib.toFixed(1) : Math.round(kib)} KiB`;
		const mib = kib / 1024;
		return `${mib < 10 ? mib.toFixed(1) : Math.round(mib)} MiB`;
	}

	function attachmentUrl(hash: string): string {
		return `/api/attachments/${encodeURIComponent(hash)}`;
	}
</script>

{#if attachments.length > 0}
	<!-- `flex flex-wrap gap-2` gives both horizontal and vertical
	     spacing between chips. The previous `space-y-2` only added
	     top-margin, which left chips flush against each other when
	     multiple fit on a single line (since the `<a>` / `<div>`
	     placeholders are `inline-flex`). -->
	<div class="mt-3 flex flex-wrap gap-2">
		{#each attachments as att (att.content_hash + ':' + att.position)}
			{#if att.available === false}
				<!-- Binding dropped by a later revision's §6.1 set-diff
				     (or blob GC'd). Show a muted placeholder so the
				     reader knows this revision *had* an attachment here
				     without offering a 404-bound link. The filename is
				     still signed into the revision so it's safe to
				     display, but we deliberately don't link the hash. -->
				<div
					class="inline-flex items-center gap-2 max-w-full px-3 py-2 rounded-md border border-border border-dashed bg-bg-surface text-sm text-text-muted italic"
					aria-label="Attachment removed in a later revision"
				>
					<svg
						aria-hidden="true"
						width="16"
						height="16"
						viewBox="0 0 24 24"
						fill="none"
						stroke="currentColor"
						stroke-width="2"
						stroke-linecap="round"
						stroke-linejoin="round"
						class="shrink-0"
					>
						<line x1="18" y1="6" x2="6" y2="18" />
						<line x1="6" y1="6" x2="18" y2="18" />
					</svg>
					<span class="truncate">{att.filename}</span>
					<span class="whitespace-nowrap">· removed</span>
				</div>
			{:else if availability[att.content_hash] === 'unavailable'}
				<!-- Federation §11.4: the binding is live and signed, but
				     the blob bytes aren't resident on this instance (remote
				     post, origin fetch pending or hard-failed). Show a muted
				     placeholder built from the signed metadata so the reader
				     knows what's there without a 404-bound link. Distinct
				     from "removed" above: the attachment still exists at its
				     origin and may serve on a later visit once the §11.4
				     fetch-on-demand resolves. -->
				<div
					class="inline-flex items-center gap-2 max-w-full px-3 py-2 rounded-md border border-border border-dashed bg-bg-surface text-sm text-text-muted italic"
					aria-label="Attachment unavailable: {att.filename}, {formatMime(att.mime)}, {formatSize(
						att.size
					)}"
				>
					<svg
						aria-hidden="true"
						width="16"
						height="16"
						viewBox="0 0 24 24"
						fill="none"
						stroke="currentColor"
						stroke-width="2"
						stroke-linecap="round"
						stroke-linejoin="round"
						class="shrink-0"
					>
						<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
						<line x1="12" y1="3" x2="12" y2="15" />
						<polyline points="8 7 12 3 16 7" />
					</svg>
					<span class="truncate">{att.filename}</span>
					<span class="whitespace-nowrap">· {formatMime(att.mime)} · {formatSize(att.size)} · unavailable</span>
				</div>
			{:else}
				<a
					href={attachmentUrl(att.content_hash)}
					download={att.filename}
					class="inline-flex items-center gap-2 max-w-full px-3 py-2 rounded-md border border-border bg-bg-surface text-sm text-text-secondary hover:text-text-primary hover:bg-bg-hover"
				>
					<svg
						aria-hidden="true"
						width="16"
						height="16"
						viewBox="0 0 24 24"
						fill="none"
						stroke="currentColor"
						stroke-width="2"
						stroke-linecap="round"
						stroke-linejoin="round"
						class="shrink-0"
					>
						<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
						<polyline points="7 10 12 15 17 10" />
						<line x1="12" y1="15" x2="12" y2="3" />
					</svg>
					<span class="truncate">{att.filename}</span>
					<span class="text-text-muted whitespace-nowrap">· {formatSize(att.size)}</span>
				</a>
			{/if}
		{/each}
	</div>
{/if}
