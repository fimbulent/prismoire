<script lang="ts">
	import {
		uploadAttachment,
		MAX_ATTACHMENT_SIZE,
		MAX_ATTACHMENTS_PER_OP,
		MAX_IMAGE_DIMENSION
	} from '$lib/api/attachments';
	import type { AttachmentBindRef } from '$lib/api/threads';
	import { errorMessage } from '$lib/i18n/errors';
	import { toast } from '$lib/components/ui/toast.svelte';
	import { slide } from 'svelte/transition';

	/**
	 * Local picker state per staged attachment. `bind` carries the
	 * canonical request shape the parent submits; the extra fields are
	 * purely for the picker UI (size badge, upload progress). Layout
	 * intent (inline vs download chip) is no longer a per-attachment
	 * toggle here — the post body's `![](filename)` references decide
	 * (`docs/attachments.md` §3), so the picker just stages bindings.
	 */
	interface PickerEntry {
		/** Stable client id (for keyed each + reorder); independent of the
		 * server-side content_hash so duplicates can be flagged before
		 * upload completes. */
		uid: string;
		bind: AttachmentBindRef;
		mime: string;
		size: number;
		/** Lifecycle: `uploading` while POST is in flight, `ready` once we
		 * have a content hash, `error` if the upload failed. */
		status: 'uploading' | 'ready' | 'error';
		errorMsg?: string;
	}

	/**
	 * Seed shape accepted by `Props.attachments`. The bind tuple
	 * (`content_hash`, `filename`) is what the parent will eventually
	 * submit to the server, but for an *edit*-form reopen the parent
	 * also knows the MIME and size from the post's read-side
	 * `AttachmentResponse`. Threading those through here lets the
	 * picker render the right type/size badge and — more importantly
	 * — show the drag-to-inline `⠿` handle for image entries on edit,
	 * so users can re-inline an existing image without removing and
	 * re-uploading it. Both extras are optional: the new-thread compose
	 * path has no prior MIME/size and falls back to placeholders, same
	 * as before.
	 */
	export interface PickerSeed {
		content_hash: string;
		filename: string;
		mime?: string;
		size?: number;
	}

	interface Props {
		/** Initial bindings to seed the picker with — read once at mount.
		 * After that the picker is authoritative and syncs through
		 * `onchange`. For edit forms, include `mime`/`size` so the type
		 * badge and the inline-drag handle render correctly without
		 * waiting for a reupload. */
		attachments: PickerSeed[];
		/** Notify the parent of structural changes (add/remove/reorder/
		 * filename edit). Emits the lean bind-tuple shape — the server
		 * never sees the seed's `mime`/`size` extras. */
		onchange: (attachments: AttachmentBindRef[]) => void;
		/** Optional hook fired once per successful image upload, after
		 *  the bind is `ready`. Receives the markdown snippet
		 *  (`![alt](filename)`) and the canonical filename so the parent
		 *  can append it to the post body. Images are inline-by-default;
		 *  the parent is expected to de-dup against existing body refs
		 *  (so re-opening an edit form doesn't double-insert a snippet
		 *  the body already contains). Non-image uploads do not fire
		 *  this — there's no markdown syntax that inlines a non-image
		 *  attachment. */
		oninsert?: (snippet: string, filename: string) => void;
		/** Disable interaction during form submission. */
		disabled?: boolean;
	}

	let { attachments, onchange, oninsert, disabled = false }: Props = $props();

	/**
	 * Picker's view of the entries — includes UI-only fields the parent
	 * doesn't care about. We seed from the parent `attachments` once on
	 * mount (edit form reopen); after that the picker is the source of
	 * truth and we sync down through `onchange`.
	 *
	 * Reactivity note: this is deliberately *not* derived from
	 * `attachments` — the parent only learns about new bindings after
	 * the upload finishes, so the picker has to manage its own staging
	 * UI for in-flight uploads.
	 */
	// svelte-ignore state_referenced_locally
	let entries = $state<PickerEntry[]>(
		attachments.map((b, i) => ({
			uid: `seed-${i}-${b.content_hash}`,
			bind: { content_hash: b.content_hash, filename: b.filename },
			// MIME/size come from the read-side `AttachmentResponse`
			// when the parent has them (edit form); the placeholder
			// applies only on compose paths that genuinely don't
			// know yet.
			mime: b.mime ?? 'application/octet-stream',
			size: b.size ?? 0,
			status: 'ready'
		}))
	);

	let formError = $state<string | null>(null);
	let dragOver = $state(false);

	let stagedCount = $derived(entries.length);
	let hasStaged = $derived(entries.some((e) => e.status === 'ready' || e.status === 'uploading'));
	let remaining = $derived(MAX_ATTACHMENTS_PER_OP - stagedCount);
	let hasReadyImage = $derived(
		entries.some((e) => e.status === 'ready' && e.mime.startsWith('image/'))
	);

	let fileInput: HTMLInputElement | undefined = $state();

	/** Generate a fresh uid that won't collide with seeded entries. */
	function makeUid(): string {
		return `u-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
	}

	/**
	 * Push the current entries' `bind` tuples up to the parent. Only
	 * entries that have a real content_hash (status = 'ready') are
	 * forwarded — the parent never sees half-uploaded bindings, which
	 * keeps the submit-disabled logic simple at the call site.
	 */
	function publish() {
		onchange(entries.filter((e) => e.status === 'ready').map((e) => e.bind));
	}

	/** Re-encode target for a given source MIME. Preserves the user's
	 *  format choice so PNGs stay PNG (transparency + no JPEG blur on
	 *  sharp edges), JPEGs stay JPEG (no generation loss from a lossy-
	 *  to-lossy transcode), and WebPs stay WebP. Anything outside the
	 *  ALLOWED_MIMES image set (HEIC, BMP, TIFF, GIF, …) falls back to
	 *  JPEG — those formats can't survive the server's allowlist
	 *  anyway, and `canvas.toBlob` is guaranteed to be able to produce
	 *  JPEG. PNG re-encode ignores the `quality` arg (lossless), so we
	 *  pass `undefined` to make that explicit. */
	function pickEncodeTarget(sourceMime: string): {
		mime: string;
		quality: number | undefined;
		ext: string;
	} {
		switch (sourceMime) {
			case 'image/png':
				return { mime: 'image/png', quality: undefined, ext: 'png' };
			case 'image/webp':
				return { mime: 'image/webp', quality: 0.85, ext: 'webp' };
			case 'image/jpeg':
			case 'image/jpg':
				return { mime: 'image/jpeg', quality: 0.85, ext: 'jpg' };
			default:
				return { mime: 'image/jpeg', quality: 0.85, ext: 'jpg' };
		}
	}

	/** Wrap `canvas.toBlob` as a promise so the encode chain can be
	 *  written as straight-line awaits. Returns `null` when the
	 *  browser can't encode in the requested format (rare for the
	 *  PNG/JPEG/WebP set we use, but the spec allows it). */
	function canvasToBlob(
		canvas: HTMLCanvasElement,
		mime: string,
		quality: number | undefined
	): Promise<Blob | null> {
		return new Promise((resolve) => canvas.toBlob(resolve, mime, quality));
	}

	/** Wrap a re-encoded Blob into a `File`, swapping the extension
	 *  only when the codec actually changed. Server re-classifies from
	 *  magic bytes regardless, but a matching extension keeps the
	 *  saved-from-link experience honest. */
	function buildFile(original: File, blob: Blob, mime: string, ext: string): File {
		if (mime === original.type) {
			return new File([blob], original.name, { type: mime });
		}
		const stripped = original.name.replace(/\.(png|jpe?g|webp|gif|heic|heif|bmp|tiff?)$/i, '');
		return new File([blob], `${stripped || 'image'}.${ext}`, { type: mime });
	}

	interface EncodeAttempt {
		mime: string;
		quality: number | undefined;
		ext: string;
	}

	interface ResizeResult {
		file: File;
		/** Set when the encoder fell back from the source format (e.g.
		 *  PNG → WebP) to fit the size cap. The caller surfaces this as
		 *  a toast so the silent codec switch isn't invisible — the
		 *  picker's chip will already show the new MIME/extension. */
		fallbackNote?: string;
		/** True when no attempt in the chain fit MAX_ATTACHMENT_SIZE.
		 *  Lets the caller produce a more specific error message than
		 *  the bare "too large" we'd show for non-image attachments. */
		exhaustedFallback?: boolean;
	}

	/**
	 * Downscale an image client-side to ≤MAX_IMAGE_DIMENSION on the
	 * longer edge and re-encode, walking an attempt chain until a
	 * candidate fits the server's MAX_ATTACHMENT_SIZE cap:
	 *
	 *   1. Source format (via `pickEncodeTarget`) — preserves PNG
	 *      transparency / JPEG quality whenever the encoded blob
	 *      already fits. Most uploads stop here.
	 *   2. WebP at q=0.85 — only invoked when the source was over
	 *      cap, which in practice means photographic content stored
	 *      as PNG. WebP is the only mainstream format combining
	 *      alpha + lossy, so a transparent PNG keeps its alpha (a
	 *      JPEG fallback would bake in a black/white background and
	 *      surprise the user days later).
	 *   3. WebP at q=0.70 — last-ditch retry for the very-photographic
	 *      cases. Below 0.70 the artifacting becomes obvious; we'd
	 *      rather reject and let the user crop than ship a muddy
	 *      result silently.
	 *
	 * The canvas round-trip itself strips EXIF / PNG tEXt and
	 * neutralizes decoder-exploit payloads on every upload (not just
	 * oversized ones) — those are privacy/security properties we want
	 * unconditionally.
	 *
	 * If `createImageBitmap` fails (corrupt input, codec unsupported
	 * by this browser — e.g. HEIC on non-Safari), the original File is
	 * returned and the server's allowlist / decode pass will reject
	 * it. The caller's catch block in `handleFiles` mirrors that
	 * fallback.
	 */
	async function resizeImage(file: File): Promise<ResizeResult> {
		const bitmap = await createImageBitmap(file).catch(() => null);
		if (!bitmap) return { file };
		const longest = Math.max(bitmap.width, bitmap.height);
		const scale = longest > MAX_IMAGE_DIMENSION ? MAX_IMAGE_DIMENSION / longest : 1;
		const targetW = Math.round(bitmap.width * scale);
		const targetH = Math.round(bitmap.height * scale);
		const canvas = document.createElement('canvas');
		canvas.width = targetW;
		canvas.height = targetH;
		const ctx = canvas.getContext('2d');
		if (!ctx) {
			bitmap.close();
			return { file };
		}
		ctx.drawImage(bitmap, 0, 0, targetW, targetH);
		bitmap.close();

		// Build the encode chain. When the source is already WebP we
		// skip the q=0.85 step (the source-format attempt already
		// uses 0.85) and go straight to q=0.70 for the retry.
		const primary = pickEncodeTarget(file.type);
		const chain: EncodeAttempt[] = [primary];
		if (primary.mime !== 'image/webp') {
			chain.push({ mime: 'image/webp', quality: 0.85, ext: 'webp' });
		}
		chain.push({ mime: 'image/webp', quality: 0.7, ext: 'webp' });

		let primarySize: number | null = null;
		let smallest: { blob: Blob; attempt: EncodeAttempt } | null = null;
		for (let i = 0; i < chain.length; i++) {
			const attempt = chain[i];
			const blob = await canvasToBlob(canvas, attempt.mime, attempt.quality);
			if (!blob) continue;
			if (i === 0) primarySize = blob.size;
			if (!smallest || blob.size < smallest.blob.size) {
				smallest = { blob, attempt };
			}
			if (blob.size <= MAX_ATTACHMENT_SIZE) {
				const formatChanged = attempt.mime !== file.type;
				const limit = Math.round(MAX_ATTACHMENT_SIZE / 1024);
				const note = formatChanged
					? primarySize !== null
						? `Re-encoded "${file.name}" as WebP to fit ${limit} KiB (source format was ${Math.round(primarySize / 1024)} KiB after resize).`
						: `Re-encoded "${file.name}" as WebP to fit ${limit} KiB.`
					: undefined;
				return {
					file: buildFile(file, blob, attempt.mime, attempt.ext),
					fallbackNote: note
				};
			}
		}

		// Every attempt blew the cap. Return the smallest blob we
		// produced so the caller's size-check still fires (rather
		// than the original unprocessed file, which would defeat the
		// EXIF-strip), and flag the chain as exhausted so the caller
		// can word the rejection accurately.
		if (smallest) {
			return {
				file: buildFile(file, smallest.blob, smallest.attempt.mime, smallest.attempt.ext),
				exhaustedFallback: true
			};
		}
		return { file, exhaustedFallback: true };
	}

	async function handleFiles(files: FileList | File[]) {
		formError = null;
		const list = Array.from(files);
		const available = MAX_ATTACHMENTS_PER_OP - stagedCount;
		if (list.length > available) {
			formError =
				available <= 0
					? `You can attach at most ${MAX_ATTACHMENTS_PER_OP} files.`
					: `Only ${available} more attachment${available === 1 ? '' : 's'} allowed.`;
			list.length = Math.max(available, 0);
		}
		for (const raw of list) {
			let file = raw;
			let exhaustedFallback = false;
			if (file.type.startsWith('image/')) {
				try {
					const result = await resizeImage(raw);
					file = result.file;
					exhaustedFallback = result.exhaustedFallback ?? false;
					if (result.fallbackNote) {
						// Toast (not formError) because this is informational,
						// not a rejection — the file is staged successfully,
						// the user just needs to know we changed the codec.
						toast.info(result.fallbackNote);
					}
				} catch {
					// Resize failed (corrupt image, unsupported codec) —
					// upload the original; server will reject if it can't
					// decode either.
					file = raw;
				}
			}
			if (file.size > MAX_ATTACHMENT_SIZE) {
				const limit = Math.round(MAX_ATTACHMENT_SIZE / 1024);
				formError = exhaustedFallback
					? `"${raw.name}" is still larger than ${limit} KiB even after WebP compression. Try a smaller image or crop it first.`
					: `"${raw.name}" is larger than ${limit} KiB.`;
				continue;
			}
			const uid = makeUid();
			const placeholder: PickerEntry = {
				uid,
				bind: {
					content_hash: '',
					filename: file.name
				},
				mime: file.type || 'application/octet-stream',
				size: file.size,
				status: 'uploading'
			};
			entries = [...entries, placeholder];
			try {
				const res = await uploadAttachment(file);
				entries = entries.map((e) =>
					e.uid === uid
						? {
								...e,
								mime: res.mime,
								size: res.size,
								status: 'ready',
								bind: {
									...e.bind,
									content_hash: res.content_hash
								}
							}
						: e
				);
				publish();
				// Inline-by-default for images: fire `oninsert` so the
				// parent can append `![alt](filename)` to the body. The
				// parent owns body state and dedup against existing
				// refs (so a re-opened edit form doesn't double up the
				// snippet for an image the body already inlines). Non-
				// image uploads stay silent — they're download chips
				// only and have no inline markdown form.
				if (oninsert && res.mime.startsWith('image/')) {
					const finalEntry = entries.find((e) => e.uid === uid);
					if (finalEntry) {
						oninsert(inlineSnippetFor(finalEntry), finalEntry.bind.filename);
					}
				}
			} catch (e) {
				const msg = errorMessage(e, 'Upload failed');
				entries = entries.map((entry) =>
					entry.uid === uid ? { ...entry, status: 'error', errorMsg: msg } : entry
				);
			}
		}
	}

	function onFileInputChange(e: Event) {
		const input = e.currentTarget as HTMLInputElement;
		if (input.files && input.files.length > 0) {
			handleFiles(input.files);
		}
		input.value = '';
	}

	function onDrop(e: DragEvent) {
		e.preventDefault();
		dragOver = false;
		if (disabled) return;
		const files = e.dataTransfer?.files;
		if (files && files.length > 0) handleFiles(files);
	}

	function onDragOver(e: DragEvent) {
		e.preventDefault();
		if (!disabled) dragOver = true;
	}

	function onDragLeave() {
		dragOver = false;
	}

	function removeEntry(uid: string) {
		entries = entries.filter((e) => e.uid !== uid);
		publish();
	}

	function updateFilename(uid: string, filename: string) {
		entries = entries.map((e) =>
			e.uid === uid ? { ...e, bind: { ...e.bind, filename } } : e
		);
		publish();
	}

	/** Move an entry one slot in the given direction. Kept for the
	 *  ArrowUp/ArrowDown keyboard fallback on the drag handle — pointer
	 *  drag covers the visual case but keyboard users still need a
	 *  reorder path now that the explicit ↑▼ buttons are gone. */
	function move(uid: string, direction: -1 | 1) {
		const idx = entries.findIndex((e) => e.uid === uid);
		if (idx < 0) return;
		const next = idx + direction;
		if (next < 0 || next >= entries.length) return;
		const copy = entries.slice();
		[copy[idx], copy[next]] = [copy[next], copy[idx]];
		entries = copy;
		publish();
	}

	/** Build the markdown snippet a drag-to-insert (or auto-insert)
	 *  produces. The alt text falls back to the filename stem so the
	 *  rendered `<img>` alt attribute is always meaningful (and so a
	 *  markdown reference is grep-able). Filenames with `)`/`(`/`\\`
	 *  in them break the link tail; we escape the same set
	 *  pulldown_cmark / marked treat as link delimiters so the
	 *  inserted text round-trips back to the original filename
	 *  through the parser. */
	function inlineSnippetFor(entry: PickerEntry): string {
		const alt = entry.bind.filename.replace(/\.[^.]+$/, '') || 'image';
		const safe = entry.bind.filename.replace(/([\\()])/g, '\\$1');
		return `![${alt}](${safe})`;
	}

	// Drag-and-drop reorder state. `draggedUid` is set during a handle
	// dragstart and survives through ondragend/ondrop; the closure
	// state is what reorder logic uses (not a custom dataTransfer
	// type), because a textarea drop target reads only the text/plain
	// payload, and we want the *same* dragstart to feed both consumers.
	//
	// The drop target decides which interpretation wins:
	//   • Drop on the body textarea → native text/plain handler pastes
	//     the markdown snippet at the cursor. The picker's reorder
	//     handlers never fire because the textarea isn't a child of
	//     the picker.
	//   • Drop on another entry's <li> → the picker's onListDrop fires,
	//     consumes the closure-state draggedUid, reorders, and never
	//     touches text/plain.
	// `dropIndicatorIdx` is the visual insertion point (0 = above the
	// first entry, N = below the Nth entry).
	let draggedUid = $state<string | null>(null);
	let dropIndicatorIdx = $state<number | null>(null);

	/** Start a drag from an entry's ⠿ handle. We populate the
	 *  text/plain payload only for ready image entries (the textarea
	 *  native drop path is meaningless for an in-flight upload or a
	 *  non-image attachment), but we always record the dragged uid so
	 *  reorder works for every entry. `effectAllowed = 'copyMove'`
	 *  signals both flavors so the cursor adapts depending on the drop
	 *  target. */
	function onHandleDragStart(e: DragEvent, entry: PickerEntry) {
		if (!e.dataTransfer || disabled) return;
		draggedUid = entry.uid;
		if (entry.status === 'ready' && entry.mime.startsWith('image/')) {
			e.dataTransfer.setData('text/plain', inlineSnippetFor(entry));
		}
		e.dataTransfer.effectAllowed = 'copyMove';
	}

	/** Cleanup when the drag ends (drop committed or escape-cancelled).
	 *  Always clears both state vars so a subsequent click on a handle
	 *  doesn't see a stale indicator. */
	function onHandleDragEnd() {
		draggedUid = null;
		dropIndicatorIdx = null;
	}

	/** Keyboard reorder fallback for the drag handle. Without this,
	 *  removing the ↑▼ buttons regresses keyboard accessibility — the
	 *  pointer-drag-only path leaves keyboard users with no way to
	 *  reorder. Alt-arrow is a common convention for "move this row"
	 *  in list editors (matches GitHub's notebook editor, VS Code's
	 *  command palette reorder, etc.). */
	function onHandleKeydown(e: KeyboardEvent, uid: string) {
		if (disabled) return;
		if (e.altKey && e.key === 'ArrowUp') {
			e.preventDefault();
			move(uid, -1);
		} else if (e.altKey && e.key === 'ArrowDown') {
			e.preventDefault();
			move(uid, 1);
		}
	}

	/** Compute the insertion index for a pointer over the `idx`-th
	 *  entry. Drops in the upper half slot the item above this entry
	 *  (index `idx`); drops in the lower half slot it below (index
	 *  `idx + 1`). Returning early when no drag is in flight prevents
	 *  the indicator from flashing during external file drags over the
	 *  list area. */
	function onListDragOver(e: DragEvent, idx: number) {
		if (draggedUid === null || !e.dataTransfer) return;
		e.preventDefault();
		e.dataTransfer.dropEffect = 'move';
		const li = e.currentTarget as HTMLElement;
		const rect = li.getBoundingClientRect();
		const before = e.clientY < rect.top + rect.height / 2;
		dropIndicatorIdx = before ? idx : idx + 1;
	}

	/** Commit a reorder. `targetIdx` is the insertion point computed
	 *  during the last `dragover`. We adjust by -1 when moving down
	 *  (the slice-out shifts subsequent indices left by one); dropping
	 *  on the source's own slot is a no-op rather than an array
	 *  thrash. */
	function onListDrop(e: DragEvent) {
		if (draggedUid === null || dropIndicatorIdx === null) {
			onHandleDragEnd();
			return;
		}
		e.preventDefault();
		const fromIdx = entries.findIndex((x) => x.uid === draggedUid);
		if (fromIdx < 0) {
			onHandleDragEnd();
			return;
		}
		let toIdx = dropIndicatorIdx;
		if (fromIdx < toIdx) toIdx -= 1;
		if (fromIdx !== toIdx) {
			const copy = entries.slice();
			const [moved] = copy.splice(fromIdx, 1);
			copy.splice(toIdx, 0, moved);
			entries = copy;
			publish();
		}
		onHandleDragEnd();
	}

	function formatSize(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		const kib = bytes / 1024;
		if (kib < 1024) return `${kib < 10 ? kib.toFixed(1) : Math.round(kib)} KiB`;
		return `${(kib / 1024).toFixed(1)} MiB`;
	}
</script>

<fieldset class="border-none p-0">
	<legend class="block text-sm font-medium text-text-secondary mb-1">
		Attachments
		<span class="text-text-muted font-normal">
			(optional, up to {MAX_ATTACHMENTS_PER_OP})
		</span>
	</legend>

	{#if remaining > 0}
		<div
			role="button"
			tabindex="0"
			aria-label="Drop files here or click to pick"
			onclick={() => !disabled && fileInput?.click()}
			onkeydown={(e) => {
				if ((e.key === 'Enter' || e.key === ' ') && !disabled) {
					e.preventDefault();
					fileInput?.click();
				}
			}}
			ondrop={onDrop}
			ondragover={onDragOver}
			ondragleave={onDragLeave}
			class="block w-full text-left rounded-md border border-dashed px-4 py-3 text-sm cursor-pointer transition-colors
				{dragOver
				? 'border-accent bg-bg-hover text-text-primary'
				: 'border-border bg-bg-surface text-text-muted hover:text-text-secondary hover:bg-bg-hover'}
				{disabled ? 'opacity-50 cursor-not-allowed' : ''}"
		>
			Drop files here or click to pick.
			<span class="text-text-muted">
				PNG, JPEG, WebP, PDF, or plain text. Max 500 KiB each, up to {MAX_ATTACHMENTS_PER_OP} files.
			</span>
		</div>
		<!-- No `accept=` attribute on purpose. The server's two-stage
		     classifier (`server/src/attachments/classify.rs`) accepts
		     any file whose bytes parse as valid UTF-8 as `text/plain`,
		     which intentionally covers every code file extension
		     (`.py`, `.rs`, `.toml`, `.sh`, ...). OS MIME mappings for
		     those extensions are inconsistent and often *not* `text/plain`
		     — so an `accept="text/plain"` filter would dim out exactly
		     the files the server is happy to accept. The picker also has
		     no security role here (the classifier rejects mismatches
		     post-upload, and users can rename files anyway), so the
		     simplest correct behaviour is to let the picker show
		     everything. -->
		<input
			bind:this={fileInput}
			type="file"
			multiple
			onchange={onFileInputChange}
			disabled={disabled}
			class="sr-only"
		/>
	{:else}
		<p class="text-xs text-text-muted">Maximum of {MAX_ATTACHMENTS_PER_OP} attachments reached.</p>
	{/if}

	{#if formError}
		<p transition:slide={{ duration: 150 }} class="text-danger text-xs mt-2">
			{formError}
		</p>
	{/if}

	{#if entries.length > 0}
		<!-- Reorder + inline-insert list. Each entry's <li> is both a
		     drag *source* (via the ⠿ handle) and a drag *target* (via
		     ondragover/ondrop on the row itself). The textarea in the
		     parent form is also a drag target via its native text/plain
		     handler — the same dragstart feeds both consumers, the drop
		     target chooses which payload to use. See script-level docs
		     on `draggedUid` for the full flow. -->
		<ul class="mt-3 space-y-2">
			{#each entries as entry, idx (entry.uid)}
				<li
					class="relative rounded-md border border-border bg-bg-surface p-3"
					transition:slide={{ duration: 150 }}
					ondragover={(e) => onListDragOver(e, idx)}
					ondrop={onListDrop}
					role="listitem"
				>
					<!-- Drop-position indicators. Rendered as absolutely-
					     positioned 2px accent lines tucked into the
					     `space-y-2` gutter so they don't shift surrounding
					     layout. `aria-hidden` because they're purely
					     visual; keyboard reorder gets the same outcome
					     via Alt-arrow on the handle. -->
					{#if dropIndicatorIdx === idx && draggedUid !== entry.uid}
						<div class="absolute -top-[5px] left-0 right-0 h-0.5 bg-accent rounded-full" aria-hidden="true"></div>
					{/if}
					{#if dropIndicatorIdx === idx + 1 && draggedUid !== entry.uid}
						<div class="absolute -bottom-[5px] left-0 right-0 h-0.5 bg-accent rounded-full" aria-hidden="true"></div>
					{/if}
					<div class="flex items-center gap-2">
						<!-- Unified drag handle. One ⠿ for both reorder
						     (any entry) and inline-insert (image entries
						     only — text/plain payload set conditionally
						     in onHandleDragStart). Spans, not buttons,
						     because Firefox creates a click-to-drag dead
						     zone when `draggable` lives on a <button>.
						     Alt-Arrow keys reorder for keyboard users
						     since the explicit ↑▼ buttons are gone. -->
						<span
							role="button"
							tabindex="0"
							draggable={!disabled}
							ondragstart={(e) => onHandleDragStart(e, entry)}
							ondragend={onHandleDragEnd}
							onkeydown={(e) => onHandleKeydown(e, entry.uid)}
							aria-label={entry.status === 'ready' && entry.mime.startsWith('image/')
								? 'Drag to reorder, or into the post body to inline'
								: 'Drag to reorder'}
							title={entry.status === 'ready' && entry.mime.startsWith('image/')
								? 'Drag to reorder · drag into the post body to display inline'
								: 'Drag to reorder'}
							class="shrink-0 select-none text-text-muted text-base leading-none cursor-grab active:cursor-grabbing hover:text-text-secondary focus:outline-none focus:text-accent {disabled ? 'opacity-30 cursor-not-allowed' : ''}"
						>⠿</span>
						<input
							type="text"
							value={entry.bind.filename}
							oninput={(e) => updateFilename(entry.uid, (e.currentTarget as HTMLInputElement).value)}
							disabled={disabled || entry.status !== 'ready'}
							aria-label="Attachment filename"
							class="flex-1 min-w-0 bg-bg border border-border rounded-md text-text-primary text-sm px-2 py-1 focus:outline-none focus:border-accent-muted"
						/>
						<button
							type="button"
							onclick={() => removeEntry(entry.uid)}
							disabled={disabled}
							aria-label="Remove attachment"
							class="shrink-0 bg-transparent border-none text-text-muted cursor-pointer text-xs font-sans hover:text-danger disabled:opacity-50"
						>Remove</button>
					</div>
					<!-- Meta line (MIME · size · status). Indented past
					     the handle width so it sits under the filename
					     input, keeping the row visually anchored on the
					     filename. -->
					<div class="flex items-center gap-3 mt-1.5 pl-6 text-xs text-text-muted">
						<span class="truncate">{entry.mime}</span>
						{#if entry.size > 0}
							<span>· {formatSize(entry.size)}</span>
						{/if}
						{#if entry.status === 'uploading'}
							<span class="text-accent">· uploading…</span>
						{:else if entry.status === 'error'}
							<span class="text-danger">· {entry.errorMsg ?? 'upload failed'}</span>
						{/if}
					</div>
				</li>
			{/each}
		</ul>
	{/if}
</fieldset>
