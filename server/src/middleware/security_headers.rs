//! Security response headers middleware.
//!
//! Sets a conservative set of defensive HTTP response headers on every
//! response. The headers are static — they do not depend on request state —
//! so a single `from_fn` middleware that inserts them after the inner
//! service runs is the simplest implementation.
//!
//! # Content Security Policy
//!
//! Since the adapter-node migration, Axum only serves `/api/*` (and
//! `/api/health`) — the SvelteKit Node process serves all HTML, and the
//! reverse proxy routes each origin to its owner. The CSP here therefore
//! only needs to cover API JSON responses. No HTML, no scripts, no
//! fonts, no images are served from this origin.
//!
//! The SSR HTML CSP is emitted by SvelteKit itself via `kit.csp` in
//! `web/svelte.config.js` — it uses a per-response nonce for inline
//! `<script>` / `<style>` tags and does not need `'unsafe-inline'`. Both
//! origins point `report-uri` at `/api/csp-report` so violations from
//! either surface land in the same `csp_reports` table.
//!
//! Notable choices:
//!
//! - `default-src 'none'`: an API that never emits HTML has nothing to
//!   load; deny everything by default.
//! - `connect-src 'self'`: preflight / XHR fetches targeting this origin.
//!   Not strictly required (browsers only enforce CSP on the response's
//!   own document, and an API response is rarely a document) but costs
//!   nothing and makes the policy self-describing.
//! - `frame-ancestors 'none'`: hard deny framing API responses
//!   (clickjacking defense for anything that might be rendered).
//! - `base-uri 'none'`, `form-action 'none'`, `object-src 'none'`: close
//!   off legacy attack vectors on the off chance a client ever renders
//!   an API response as HTML.
//! - `report-uri /api/csp-report`: Firefox reporting transport. Chromium
//!   uses the sibling `Reporting-Endpoints` header plus the `report-to`
//!   directive; both are emitted so both families of browsers funnel
//!   reports into the same endpoint.
//!
//! # HSTS
//!
//! `Strict-Transport-Security` is only sent when the configured origin is
//! `https://`. Sending it over plain HTTP is a no-op for browsers but
//! confusing for operators — omitting it makes the local-dev case
//! (`http://localhost:3000`) behave cleanly.

use axum::http::{HeaderName, HeaderValue, Request, header};
use axum::middleware::Next;
use axum::response::Response;

/// The CSP string applied to every API response.
///
/// `report-uri` is kept on the enforcing policy so regressions in
/// upstream handlers (a rogue `Content-Type: text/html` response, say)
/// become visible through the same endpoint SvelteKit's SSR CSP targets.
const CONTENT_SECURITY_POLICY: &str = "\
default-src 'none'; \
connect-src 'self'; \
frame-ancestors 'none'; \
base-uri 'none'; \
form-action 'none'; \
object-src 'none'; \
report-uri /api/csp-report; \
report-to csp-endpoint";

/// `Reporting-Endpoints` value: advertise the `csp-endpoint` name for
/// Chromium's `report-to` directive to reference. Firefox still uses the
/// legacy `report-uri` directive in the CSP string above.
const REPORTING_ENDPOINTS: &str = "csp-endpoint=\"/api/csp-report\"";

/// `Permissions-Policy` value: disable browser features Prismoire does not
/// use. `interest-cohort=()` blocks the legacy FLoC proposal;
/// `browsing-topics=()` blocks its successor, the Topics API.
const PERMISSIONS_POLICY: &str = "\
camera=(), microphone=(), geolocation=(), payment=(), usb=(), \
interest-cohort=(), browsing-topics=()";

/// HSTS header value: two years, include subdomains, preload-eligible.
const HSTS_VALUE: &str = "max-age=63072000; includeSubDomains; preload";

/// Whether the configured instance origin uses HTTPS, controlling whether
/// to emit HSTS. Determined at startup from `webauthn.rp_origin`.
#[derive(Clone, Copy)]
pub struct HttpsEnabled(pub bool);

/// Insert security headers on every response.
///
/// Uses `HeaderMap::entry().or_insert(...)` semantics so that upstream
/// handlers or other middleware can override a specific header if needed
/// (e.g. attachment downloads setting a stricter CSP). The only header we
/// force-overwrite is `X-Content-Type-Options`, which should never vary.
pub async fn security_headers(
    axum::extract::State(https): axum::extract::State<HttpsEnabled>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    insert_if_absent(
        headers,
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    insert_if_absent(
        headers,
        HeaderName::from_static("reporting-endpoints"),
        HeaderValue::from_static(REPORTING_ENDPOINTS),
    );
    insert_if_absent(
        headers,
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    insert_if_absent(
        headers,
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    insert_if_absent(
        headers,
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    insert_if_absent(
        headers,
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    insert_if_absent(
        headers,
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );

    // Always enforce MIME sniffing protection — no reason any handler
    // should ever override this.
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    if https.0 {
        insert_if_absent(
            headers,
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS_VALUE),
        );
    }

    response
}

fn insert_if_absent(headers: &mut axum::http::HeaderMap, name: HeaderName, value: HeaderValue) {
    headers.entry(name).or_insert(value);
}
