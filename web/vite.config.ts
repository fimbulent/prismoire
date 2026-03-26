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
	server: {
		https,
		proxy: {
			'/api': 'http://localhost:3000',
			'/feed.xml': 'http://localhost:3000'
		}
	}
});