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
		csp: {
			mode: 'nonce',
			directives: {
				'default-src': ['self'],
				'script-src': ['self'],
				'style-src': ['self'],
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
