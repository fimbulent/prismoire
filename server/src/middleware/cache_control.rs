//! `Cache-Control: no-store` for all API responses.
//!
//! Authenticated JSON must never be cached by the browser, a reverse
//! proxy, or a shared CDN. This middleware sets `Cache-Control: no-store`
//! as a blanket default on every response flowing through the `/api`
//! router.
//!
//! The header is inserted with `entry().or_insert(...)` semantics so an
//! individual handler can override it for a genuinely public, cacheable
//! resource (e.g. a future public rooms listing with short-lived public
//! caching). The default is the safe one: treat every API response as
//! sensitive until proven otherwise.
//!
//! Static asset caching (the SvelteKit `_app/immutable/*` bundles,
//! `index.html`, favicons) is the reverse proxy's job, not this
//! middleware's. Performance tuning for those assets lives in the Caddy
//! / reverse proxy configuration shipped with the NixOS module.

use axum::http::{HeaderValue, Request, header};
use axum::middleware::Next;
use axum::response::Response;

/// The single cache policy value applied to all API responses.
const NO_STORE: &str = "no-store";

/// Insert `Cache-Control: no-store` on every API response unless an
/// upstream handler already set a `Cache-Control` header.
pub async fn cache_control(request: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static(NO_STORE));
    response
}
