// GDPR privacy endpoints: data export and account self-deletion.
//
// Both endpoints accept banned and suspended users — right-to-access and
// right-to-erasure are not moderation-gated.

import { throwApiError, type FetchFn } from './auth';

interface FetchOpts {
	fetch?: FetchFn;
}

/**
 * Drive a browser download for a JSON or binary response.
 *
 * The endpoint sets a `Content-Disposition: attachment` header so browsers
 * offer "Save as" when navigated to directly. When called via `fetch`, we
 * materialize the body into a blob and click a hidden link to drive the
 * download — this keeps the session cookie attached (SvelteKit proxies the
 * call through Node to Axum) and avoids opening a new tab.
 */
async function downloadResponse(res: Response, fallbackFilename: string): Promise<void> {
	const blob = await res.blob();
	const disposition = res.headers.get('content-disposition') ?? '';
	const match = /filename="?([^";]+)"?/i.exec(disposition);
	const filename = match?.[1] ?? fallbackFilename;

	const url = URL.createObjectURL(blob);
	try {
		const a = document.createElement('a');
		a.href = url;
		a.download = filename;
		document.body.appendChild(a);
		a.click();
		a.remove();
	} finally {
		URL.revokeObjectURL(url);
	}
}

/**
 * Trigger a download of the user's full data export as a JSON file.
 *
 * The JSON carries profile, settings, signing keypair, credentials,
 * trust edges, threads/posts/reports, and (since export v2) the
 * per-revision attachment metadata + pending uploads + storage budget.
 * The actual attachment bytes live in the companion ZIP endpoint —
 * see {@link exportMyAttachments}.
 */
export async function exportMyData(opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/me/export');
	if (!res.ok) await throwApiError(res);
	await downloadResponse(res, 'prismoire-export.json');
}

/**
 * Trigger a download of the user's attachment bytes as a ZIP file.
 *
 * Companion to {@link exportMyData}: the JSON export carries the
 * per-binding metadata and points here via `attachments_blob_archive`.
 * The ZIP carries the actual blob bytes plus a `MANIFEST.json` that
 * maps each blob back to the bindings it satisfies. Users with zero
 * attachments still get a valid (mostly empty) ZIP.
 */
export async function exportMyAttachments(opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/me/export/attachments');
	if (!res.ok) await throwApiError(res);
	await downloadResponse(res, 'prismoire-attachments.zip');
}

/**
 * Delete the caller's account and all associated personal data.
 *
 * Server retracts every post, anonymises the user row, and drops
 * credentials + sessions. The response clears the session cookie, so the
 * caller must also refresh the session store afterwards.
 */
export async function deleteMyAccount(opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/me', { method: 'DELETE' });
	if (!res.ok) await throwApiError(res);
}
