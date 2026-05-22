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
	 */
	interface AttachmentListItem {
		content_hash: string;
		filename: string;
		size: number;
		position: number;
		/** `false` only for old revisions whose attachment was later
		 * removed (or whose blob is missing). Undefined === available. */
		available?: boolean;
	}

	interface Props {
		attachments: AttachmentListItem[];
	}

	let { attachments }: Props = $props();

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
