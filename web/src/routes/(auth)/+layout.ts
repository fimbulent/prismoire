// Auth pages (login, signup, setup) use the WebAuthn browser API
// (window.PublicKeyCredential, navigator.credentials.*) which is only
// available in the browser. Disable SSR for the whole group so the
// server never tries to render these pages.

export const ssr = false;
