// GDPR privacy endpoints: data export and account self-deletion.
//
// Both endpoints accept banned and suspended users — right-to-access and
// right-to-erasure are not moderation-gated.

import { throwApiError, type FetchFn } from './auth';

interface FetchOpts {
	fetch?: FetchFn;
}

/**
 * Trigger a download of the user's full data export as a JSON file.
 *
 * The endpoint sets a `Content-Disposition: attachment` header so browsers
 * offer "Save as" when navigated to directly. When called via `fetch`, we
 * materialize the body into a blob and click a hidden link to drive the
 * download — this keeps the session cookie attached (SvelteKit proxies the
 * call through Node to Axum) and avoids opening a new tab.
 */
export async function exportMyData(opts: FetchOpts = {}): Promise<void> {
	const f = opts.fetch ?? globalThis.fetch;
	const res = await f('/api/me/export');
	if (!res.ok) await throwApiError(res);

	const blob = await res.blob();
	const disposition = res.headers.get('content-disposition') ?? '';
	const match = /filename="?([^";]+)"?/i.exec(disposition);
	const filename = match?.[1] ?? 'prismoire-export.json';

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
