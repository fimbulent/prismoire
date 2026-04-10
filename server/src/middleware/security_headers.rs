//! Security response headers middleware.
//!
//! Sets a conservative set of defensive HTTP response headers on every
//! response. The headers are static — they do not depend on request state —
//! so a single `from_fn` middleware that inserts them after the inner
//! service runs is the simplest implementation.
//!
//! # Content Security Policy
//!
//! The CSP is tuned for a self-hosted, single-origin SvelteKit static
//! build served by Axum. Notable choices:
//!
//! - `script-src 'self' 'unsafe-inline'`: SvelteKit's `adapter-static`
//!   output includes a small inline bootstrap `<script>` that imports the
//!   hydration entry points. A nonce would require SSR; hashing would
//!   require regenerating the CSP every build. `'unsafe-inline'` is
//!   acceptable here because (a) user-authored content is Markdown,
//!   rendered through DOMPurify on the client, never as raw HTML that
//!   could inject `<script>` tags, and (b) the inline script is
//!   build-time output, not reflected user input.
//!
//!   TODO: when the frontend switches from `adapter-static` to
//!   `adapter-node` (see web/CLAUDE.md "Future: adapter-node"), replace
//!   `'unsafe-inline'` with a per-response nonce injected by SvelteKit's
//!   SSR into the bootstrap `<script>` and echoed in this CSP header.
//! - `connect-src 'self'`: JSON fetches from the SvelteKit app back to
//!   the Axum API on the same origin. WebAuthn ceremonies run entirely
//!   in the browser via the Credential Management API — they do not
//!   issue additional network requests that CSP would see.
//! - `frame-ancestors 'none'`: hard deny framing the site (clickjacking
//!   defense, strictly stronger than `X-Frame-Options: DENY`).
//! - `img-src 'self' data:`: allow inline data URIs for tiny UI icons.
//!   External image hotlinking is disallowed by spec (tracking pixel
//!   prevention).
//! - `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`: close
//!   off legacy attack vectors.
//!
//! # HSTS
//!
//! `Strict-Transport-Security` is only sent when the configured origin is
//! `https://`. Sending it over plain HTTP is a no-op for browsers but
//! confusing for operators — omitting it makes the local-dev case
//! (`http://localhost:3000`) behave cleanly.
//!
//! # CSP reporting
//!
//! No `report-uri` or `report-to` directive is set. Reporting is a rollout
//! tool, and the CSP is currently stable — there is no policy tightening
//! in flight that reports would inform. Collecting CSP violation noise
//! (which is dominated by browser extensions and translation tools) with
//! no one watching the reports has negative value.
//!
//! TODO: add CSP reporting as part of the `adapter-node` / nonce
//! migration described above. The recommended pattern, when that work
//! happens:
//!
//! 1. Add an Axum handler at `/api/csp-report` that accepts `POST`,
//!    parses the JSON body (`application/csp-report` or
//!    `application/reports+json`), filters reports whose `source-file`
//!    begins with `chrome-extension://`, `moz-extension://`,
//!    `safari-extension://`, `safari-web-extension://`, or similar
//!    extension schemes, and writes the remaining reports to a dedicated
//!    `csp_reports` table with an aggressive retention window (e.g. 14
//!    days, purged by a periodic job).
//! 2. Apply a tight per-IP rate limit to just that endpoint. CSP reports
//!    are browser-driven and a malicious page can trigger a flood of
//!    blocked-URI variations.
//! 3. Emit both `report-uri /api/csp-report` (for current Firefox) and
//!    `report-to csp-endpoint` plus a `Reporting-Endpoints:
//!    csp-endpoint="/api/csp-report"` response header (for Chromium).
//! 4. Ship a stricter `Content-Security-Policy-Report-Only` header
//!    alongside the enforcing CSP during the migration. The report-only
//!    policy represents the target state (no `'unsafe-inline'`,
//!    `strict-dynamic`, etc.); it is tightened iteratively based on
//!    reports until the enforcing CSP can be updated to match and the
//!    report-only header removed.
//! 5. Leave a minimal reporting directive on the enforcing CSP afterward
//!    so regressions become visible.
//!
//! Do not route reports to third-party services (Sentry, report-uri.com,
//! Datadog, etc.) — the spec is explicit about no third-party resources
//! and no analytics.

use axum::http::{HeaderName, HeaderValue, Request, header};
use axum::middleware::Next;
use axum::response::Response;

/// The CSP string applied to every response.
const CONTENT_SECURITY_POLICY: &str = "\
default-src 'self'; \
script-src 'self' 'unsafe-inline'; \
style-src 'self' 'unsafe-inline'; \
img-src 'self' data:; \
font-src 'self'; \
connect-src 'self'; \
object-src 'none'; \
base-uri 'self'; \
form-action 'self'; \
frame-ancestors 'none'";

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
