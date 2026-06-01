import { throwApiError, type FetchFn } from './auth';

/**
 * Successful response from `POST /api/attachments`
 * (`docs/attachments.md` §3 step 1). Echo `content_hash` back in the
 * subsequent thread/post request to bind the staged blob to a
 * revision. `mime` is the canonical MIME the server's classifier
 * settled on — may differ from the multipart-declared content type.
 */
export interface UploadResponse {
	content_hash: string;
	size: number;
	mime: string;
}

interface FetchOpts {
	fetch?: FetchFn;
}

/**
 * Upload a single file as a multipart blob. Server-side pipeline:
 * size cap, two-stage MIME classification, image re-encode, SHA-256
 * hashing, user-budget debit, staging-row insert. Returns the
 * canonical content hash to use in subsequent bind requests.
 *
 * Staging rows expire 24h after upload if never bound to a post
 * (`docs/attachments.md` §7).
 */
export async function uploadAttachment(file: File, opts: FetchOpts = {}): Promise<UploadResponse> {
	const f = opts.fetch ?? globalThis.fetch;
	const form = new FormData();
	form.append('file', file, file.name);
	const res = await f('/api/attachments', {
		method: 'POST',
		body: form
	});
	if (!res.ok) await throwApiError(res);
	return res.json();
}

/** Image MIMEs the backend accepts (see `signed::ALLOWED_MIMES`). */
export const IMAGE_MIMES = ['image/png', 'image/jpeg', 'image/webp'] as const;

/** Returns true if the MIME is an image MIME the server allows — i.e.
 *  one that may be referenced inline from the post body via
 *  `![](filename)` (`docs/attachments.md` §3). */
export function isImageMime(mime: string): boolean {
	return (IMAGE_MIMES as readonly string[]).includes(mime);
}

/** Short, human-facing label for a MIME — `image/png` → `PNG`,
 *  `application/pdf` → `PDF`. Used by the federation §11.4
 *  "attachment unavailable" placeholder, where the blob bytes aren't
 *  resident but the signed MIME still tells the reader what's missing.
 *  Falls back to the raw MIME for shapes without a recognisable
 *  subtype so we never render an empty token. */
export function formatMime(mime: string): string {
	const subtype = mime.split('/')[1];
	if (!subtype) return mime;
	// Drop structured-suffix noise (`svg+xml` → `svg`) and uppercase the
	// bare format token, which reads as a familiar file-type label.
	return subtype.split('+')[0].toUpperCase();
}

/** Per-blob storage cap (mirrors `signed::MAX_ATTACHMENT_SIZE`). */
export const MAX_ATTACHMENT_SIZE = 500 * 1024;

/** Maximum image dimension preserved client-side before upload — the
 *  server caps the same way during re-encode, so we may as well shrink
 *  client-side and save bandwidth. */
export const MAX_IMAGE_DIMENSION = 1600;

/** Per-OP attachment count cap (mirrors `signed::MAX_ATTACHMENTS_PER_OP`). */
export const MAX_ATTACHMENTS_PER_OP = 3;
