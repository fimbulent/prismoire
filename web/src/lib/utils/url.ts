/**
 * Display-only host for a link post — strips a leading "www." for compactness.
 * Falls back to the original URL string if parsing fails.
 */
export function linkHost(url: string): string {
	try {
		const host = new URL(url).hostname;
		return host.startsWith('www.') ? host.slice(4) : host;
	} catch {
		return url;
	}
}

/**
 * The portion of a URL after the host: pathname + search + hash.
 * Returns an empty string for bare hosts (e.g. "https://example.com/" → "").
 * Falls back to an empty string if parsing fails.
 */
export function linkRest(url: string): string {
	try {
		const u = new URL(url);
		const path = u.pathname === '/' ? '' : u.pathname;
		return `${path}${u.search}${u.hash}`;
	} catch {
		return '';
	}
}
