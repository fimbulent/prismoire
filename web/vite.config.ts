import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const certFile = resolve(import.meta.dirname, 'certs/cert.pem');
const keyFile = resolve(import.meta.dirname, 'certs/key.pem');
const https =
	existsSync(certFile) && existsSync(keyFile)
		? { cert: readFileSync(certFile), key: readFileSync(keyFile) }
		: undefined;

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	// LayerCake ships raw .svelte source files (not pre-compiled). Without
	// this, adapter-node's SSR asks Node to import a .svelte file directly
	// and fails with ERR_UNKNOWN_FILE_EXTENSION on the first hard load of
	// any page that uses it. `noExternal` makes Vite bundle it through the
	// Svelte compiler instead.
	ssr: {
		noExternal: ['layercake']
	},
	server: {
		https,
		proxy: {
			'/api': 'http://localhost:3000',
			'/feed.xml': 'http://localhost:3000'
		}
	}
});