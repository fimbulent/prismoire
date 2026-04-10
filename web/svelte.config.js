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
		// process: `node build/index.js`. See docs/adapter-node.md for the
		// deployment topology (Caddy in front, Axum alongside for /api).
		adapter: adapter({
			out: 'build',
			precompress: false
		})
	}
};

export default config;
