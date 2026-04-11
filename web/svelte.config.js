import adapter from '@sveltejs/adapter-node';
import { relative, sep } from 'node:path';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	compilerOptions: {
		runes: ({ filename }) => {
			const relativePath = relative(import.meta.dirname, filename);
			const pathSegments = relativePath.toLowerCase().split(sep);
			const isExternalLibrary = pathSegments.includes('node_modules');

			return isExternalLibrary ? undefined : true;
		}
	},
	kit: {
		// Node server adapter. The built app runs as a standalone Node
		// process: `node build/index.js`.
		adapter: adapter({
			out: 'build',
			precompress: false
		}),
		// Nonce-based CSP. SvelteKit injects a freshly generated nonce
		// into every inline <script> and <style> it emits for each SSR
		// response, and sets the corresponding Content-Security-Policy
		// header on the response. This lets us drop 'unsafe-inline'
		// entirely from the SSR HTML CSP — the Axum middleware's CSP
		// only covers /api/* responses (see
		// server/src/middleware/security_headers.rs).
		//
		// 'self' keeps same-origin script/style loading (the hashed
		// bundles under /_app/immutable/*). connect-src 'self' allows
		// client-side fetches back to /api/* via the reverse proxy.
		// img-src allows inline data: URIs for tiny UI icons. Everything
		// else stays default-src 'self' so new attack surfaces are
		// closed by default.
		//
		// `style-src-attr` is called out explicitly and scoped to a
		// single known hash plus `'unsafe-hashes'` (required for a hash
		// to apply to a `style` attribute rather than a `<style>`
		// element). The whitelisted hash covers SvelteKit's hardcoded
		// `#svelte-announcer` live-region element, which the client
		// router appends to `<body>` after the first client-side
		// navigation to announce `<title>` changes to screen readers.
		// Its inline `style="position: absolute; left: 0; top: 0;
		// clip: rect(0 0 0 0); clip-path: inset(50%); overflow: hidden;
		// white-space: nowrap; width: 1px; height: 1px"` cannot be
		// covered by a nonce (nonces do not apply to attribute styles),
		// so we pin its exact sha256 here. Element-level `<style>`
		// blocks stay strictly under nonce mode via `style-src`. If a
		// SvelteKit upgrade changes the announcer's inline style
		// string, this hash will need to be regenerated — a CSP report
		// to `/api/csp-report` will surface the new expected hash.
		csp: {
			mode: 'nonce',
			directives: {
				'default-src': ['self'],
				'script-src': ['self'],
				'style-src': ['self'],
				'style-src-attr': [
					"'unsafe-hashes'",
					"'sha256-S8qMpvofolR8Mpjy4kQvEm7m1q8clzU4dfDH0AmvZjo='"
				],
				'img-src': ['self', 'data:'],
				'font-src': ['self'],
				'connect-src': ['self'],
				'object-src': ['none'],
				'base-uri': ['self'],
				'form-action': ['self'],
				'frame-ancestors': ['none'],
				'report-uri': ['/api/csp-report']
			}
		}
	}
};

export default config;
