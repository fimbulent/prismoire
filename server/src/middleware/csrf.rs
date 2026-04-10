//! CSRF protection via Origin / Referer header checking.
//!
//! Prismoire uses `HttpOnly` + `SameSite=Strict` session cookies as the
//! primary CSRF defense — modern browsers will not attach the session cookie
//! to cross-site requests at all. This middleware adds a defense-in-depth
//! check on every state-changing request (non-safe HTTP methods): the
//! `Origin` header (with `Referer` as a fallback for clients that strip
//! `Origin`) must match the server's own origin, as declared by
//! `webauthn.rp_origin` in the config.
//!
//! Safe methods (`GET`, `HEAD`, `OPTIONS`) bypass the check — they are
//! considered side-effect-free by convention and are needed for normal
//! navigation that carries no Origin header.
//!
//! Requests that fail the check are rejected with `403 Forbidden` and a
//! JSON error body. This is intentionally opaque: a legitimate browser
//! client will never trip this path, and an attacker learns nothing useful
//! from the response shape.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Allowed origin for state-changing requests.
///
/// Derived from `webauthn.rp_origin` at startup and normalized to the
/// `scheme://host[:port]` form that browsers send in the `Origin` header
/// (no path, no query, no trailing slash).
#[derive(Clone)]
pub struct AllowedOrigin(pub Arc<String>);

impl AllowedOrigin {
    /// Normalize a configured origin URL to the form browsers send in the
    /// `Origin` header: `scheme://host[:port]`, with no path or trailing
    /// slash. Returns `None` if the URL is missing a host.
    pub fn from_url(url: &url::Url) -> Option<Self> {
        let scheme = url.scheme();
        let host = url.host_str()?;
        let normalized = match url.port() {
            Some(port) => format!("{scheme}://{host}:{port}"),
            None => format!("{scheme}://{host}"),
        };
        Some(Self(Arc::new(normalized)))
    }
}

/// Reject state-changing requests whose Origin / Referer does not match
/// the configured instance origin.
///
/// This runs as an Axum middleware layer via [`from_fn_with_state`]. It is
/// intended to sit outside the rate-limit layer and inside the outermost
/// routing so that all API routes — including auth and setup — are
/// protected.
///
/// [`from_fn_with_state`]: axum::middleware::from_fn_with_state
pub async fn csrf_origin_check(
    State(allowed): State<AllowedOrigin>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Safe methods are exempt.
    match *request.method() {
        Method::GET | Method::HEAD | Method::OPTIONS => return next.run(request).await,
        _ => {}
    }

    let headers = request.headers();

    // Prefer the Origin header. Browsers set it on all non-GET fetch
    // requests and cannot be spoofed by JS running on another origin.
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if origin == allowed.0.as_str() {
            return next.run(request).await;
        }
        return forbidden();
    }

    // Fall back to Referer for clients that strip Origin (older browsers,
    // some privacy extensions). Compare only the scheme + authority prefix.
    if let Some(referer) = headers.get(header::REFERER).and_then(|v| v.to_str().ok())
        && referer_matches(referer, allowed.0.as_str())
    {
        return next.run(request).await;
    }

    forbidden()
}

/// Return true if a `Referer` header value begins with the allowed origin
/// followed by `/` or end-of-string. This guards against prefix-match
/// spoofing (e.g. `https://evil.example.com.attacker.tld/`).
fn referer_matches(referer: &str, allowed: &str) -> bool {
    if !referer.starts_with(allowed) {
        return false;
    }
    let rest = &referer[allowed.len()..];
    rest.is_empty() || rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('#')
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "forbidden",
            "message": "cross-origin request rejected",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_origin_without_port() {
        let url = url::Url::parse("https://example.com/").unwrap();
        let origin = AllowedOrigin::from_url(&url).unwrap();
        assert_eq!(origin.0.as_str(), "https://example.com");
    }

    #[test]
    fn normalizes_origin_with_port() {
        let url = url::Url::parse("http://localhost:3000/").unwrap();
        let origin = AllowedOrigin::from_url(&url).unwrap();
        assert_eq!(origin.0.as_str(), "http://localhost:3000");
    }

    #[test]
    fn referer_matches_exact() {
        assert!(referer_matches(
            "https://example.com",
            "https://example.com"
        ));
    }

    #[test]
    fn referer_matches_with_path() {
        assert!(referer_matches(
            "https://example.com/foo/bar",
            "https://example.com"
        ));
    }

    #[test]
    fn referer_rejects_suffix_spoof() {
        assert!(!referer_matches(
            "https://example.com.attacker.tld/",
            "https://example.com"
        ));
    }

    #[test]
    fn referer_rejects_different_origin() {
        assert!(!referer_matches(
            "https://evil.example/",
            "https://example.com"
        ));
    }
}
