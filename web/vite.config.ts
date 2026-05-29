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

// Local multi-instance dev (`just dev N`): each instance's frontend runs
// on its own port and proxies `/api` to its own Axum. Both default to the
// single-instance values so a bare `just dev` is unaffected. `API_URL`
// matches the env var `src/hooks.server.ts` reads for server-side loads,
// so client and SSR fetches hit the same backend.
const apiTarget = process.env.API_URL ?? 'http://localhost:3000';
const webPort = process.env.WEB_PORT ? Number(process.env.WEB_PORT) : undefined;

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
		port: webPort,
		proxy: {
			'/api': apiTarget,
			'/feed.xml': apiTarget
		}
	}
});