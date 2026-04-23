//! CSP violation report receiver.
//!
//! Accepts `POST /api/csp-report` from browsers when they block a
//! resource per the instance Content-Security-Policy. Two body formats
//! are supported, corresponding to the two reporting transports emitted
//! by [`crate::middleware::security_headers`] and `web/svelte.config.js`:
//!
//! 1. **Legacy `report-uri` format** (`application/csp-report`). Firefox
//!    and older Chromium. A single JSON object wrapping the report under
//!    a `"csp-report"` key.
//! 2. **Reporting API format** (`application/reports+json`). Modern
//!    Chromium via the `Reporting-Endpoints` header plus CSP
//!    `report-to` directive. A JSON array of report envelopes, each with
//!    a `"type"` of `"csp-violation"` and a `"body"` containing the
//!    report fields under slightly different (kebab-case → camelCase)
//!    names.
//!
//! The handler normalises both shapes into a single `CspReport` struct,
//! filters out reports originating from browser extensions (the dominant
//! source of noise), and inserts the remainder into the `csp_reports`
//! table. Any parse failure is swallowed silently — reports are
//! best-effort telemetry and never worth surfacing as 5xx to a browser.
//!
//! The endpoint itself:
//!
//! - Responds `204 No Content` unconditionally once the request has been
//!   read, so the browser never retries. Errors are logged server-side.
//! - Is mounted outside the authenticated routes but behind the standard
//!   IP rate limiter, **plus** its own tighter per-IP limiter defined in
//!   [`crate::rate_limit`]. A hostile page can trigger a flood of
//!   blocked-URI variations — this must not be able to fill the table
//!   or knock out the rest of the API.
//! - Bypasses CSRF: the browser submits these with no `Origin` header
//!   (it's a UA-initiated POST, not a fetch from page JS), so the
//!   standard origin check would reject them. CSRF on a write-only
//!   endpoint that only accepts opaque telemetry is pointless anyway.
//! - Drops any report whose `source-file`, `document-uri`, or
//!   `blocked-uri` begins with an extension scheme. Browser extensions
//!   injecting content into pages are the overwhelming majority of
//!   reports in practice, and filtering them at the edge keeps the
//!   table signal-to-noise usable.
//!
//! Retention: a background task in [`crate::csp_report::retention_loop`]
//! deletes rows older than 14 days once per hour. Kept short because
//! the value of a CSP report drops sharply after the first few hours.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::state::AppState;

/// Schemes used by browser extensions. Reports whose `source-file`,
/// `document-uri`, or `blocked-uri` begin with any of these are dropped
/// at the edge without hitting the database. These are the dominant
/// source of CSP report noise in practice — extensions injecting
/// content into pages that the site's CSP does not allow.
const EXTENSION_SCHEMES: &[&str] = &[
    "chrome-extension://",
    "moz-extension://",
    "safari-extension://",
    "safari-web-extension://",
    "webkit-masked-url://",
];

/// Normalised view of a CSP violation report, built from either the
/// legacy `application/csp-report` envelope or the modern Reporting API
/// `application/reports+json` envelope.
#[derive(Debug, Default, Clone)]
struct CspReport {
    document_uri: Option<String>,
    referrer: Option<String>,
    violated_directive: Option<String>,
    effective_directive: Option<String>,
    original_policy: Option<String>,
    blocked_uri: Option<String>,
    source_file: Option<String>,
    line_number: Option<i64>,
    column_number: Option<i64>,
    status_code: Option<i64>,
    script_sample: Option<String>,
}

impl CspReport {
    /// Return true if any of the URI fields begin with an extension scheme.
    fn is_extension_noise(&self) -> bool {
        let candidates = [
            self.document_uri.as_deref(),
            self.source_file.as_deref(),
            self.blocked_uri.as_deref(),
        ];
        candidates.into_iter().flatten().any(|uri| {
            EXTENSION_SCHEMES
                .iter()
                .any(|scheme| uri.starts_with(scheme))
        })
    }

    /// Cap each text field to [`MAX_FIELD_BYTES`].
    ///
    /// Browsers do not bound report field sizes — `original_policy`
    /// can be a multi-kilobyte string and `script_sample` is allowed
    /// to be 40 characters by spec but UAs vary. A hostile page could
    /// also stuff arbitrary content into the document URI. Capping at
    /// the edge keeps row sizes bounded so the table cannot be made
    /// to balloon under sustained noise.
    fn truncate_fields(&mut self) {
        for field in [
            &mut self.document_uri,
            &mut self.referrer,
            &mut self.violated_directive,
            &mut self.effective_directive,
            &mut self.original_policy,
            &mut self.blocked_uri,
            &mut self.source_file,
            &mut self.script_sample,
        ] {
            if let Some(s) = field.as_mut() {
                truncate_in_place(s, MAX_FIELD_BYTES);
            }
        }
    }
}

/// Maximum bytes retained for any single text field on a CSP report.
///
/// Picked at 1 KiB: comfortably above any well-formed URL or directive
/// while keeping a single row capped at ~16 KiB worst case across the
/// eight text columns.
const MAX_FIELD_BYTES: usize = 1024;

/// Truncate `s` in place to at most `max_bytes`, on a UTF-8 char
/// boundary so the resulting `String` stays valid.
fn truncate_in_place(s: &mut String, max_bytes: usize) {
    if s.len() <= max_bytes {
        return;
    }
    // Walk backwards from `max_bytes` to the nearest char boundary.
    // `is_char_boundary(0)` is always true, so this terminates.
    let mut cut = max_bytes;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
}

// ---------------------------------------------------------------------------
// Legacy `application/csp-report` envelope
// ---------------------------------------------------------------------------

/// Wrapper for the legacy `application/csp-report` body format, e.g.
/// `{"csp-report": { ... }}`.
#[derive(Debug, Deserialize)]
struct LegacyEnvelope {
    #[serde(rename = "csp-report")]
    csp_report: LegacyReport,
}

/// Fields of a legacy CSP report. All optional because the spec is
/// loose and UAs vary in what they emit.
#[derive(Debug, Deserialize)]
struct LegacyReport {
    #[serde(rename = "document-uri")]
    document_uri: Option<String>,
    referrer: Option<String>,
    #[serde(rename = "violated-directive")]
    violated_directive: Option<String>,
    #[serde(rename = "effective-directive")]
    effective_directive: Option<String>,
    #[serde(rename = "original-policy")]
    original_policy: Option<String>,
    #[serde(rename = "blocked-uri")]
    blocked_uri: Option<String>,
    #[serde(rename = "source-file")]
    source_file: Option<String>,
    #[serde(rename = "line-number")]
    line_number: Option<i64>,
    #[serde(rename = "column-number")]
    column_number: Option<i64>,
    #[serde(rename = "status-code")]
    status_code: Option<i64>,
    #[serde(rename = "script-sample")]
    script_sample: Option<String>,
}

impl From<LegacyReport> for CspReport {
    fn from(r: LegacyReport) -> Self {
        Self {
            document_uri: r.document_uri,
            referrer: r.referrer,
            violated_directive: r.violated_directive,
            effective_directive: r.effective_directive,
            original_policy: r.original_policy,
            blocked_uri: r.blocked_uri,
            source_file: r.source_file,
            line_number: r.line_number,
            column_number: r.column_number,
            status_code: r.status_code,
            script_sample: r.script_sample,
        }
    }
}

// ---------------------------------------------------------------------------
// Modern Reporting API `application/reports+json` envelope
// ---------------------------------------------------------------------------

/// A single envelope in the Reporting API body array. Only
/// `type = "csp-violation"` is meaningful here; anything else is ignored.
#[derive(Debug, Deserialize)]
struct ReportingEnvelope {
    #[serde(rename = "type")]
    report_type: Option<String>,
    body: Option<ReportingBody>,
}

/// The `body` of a Reporting API CSP violation report. Fields are
/// camelCase in this format, unlike the legacy kebab-case.
#[derive(Debug, Deserialize)]
struct ReportingBody {
    #[serde(rename = "documentURL")]
    document_url: Option<String>,
    referrer: Option<String>,
    #[serde(rename = "violatedDirective")]
    violated_directive: Option<String>,
    #[serde(rename = "effectiveDirective")]
    effective_directive: Option<String>,
    #[serde(rename = "originalPolicy")]
    original_policy: Option<String>,
    #[serde(rename = "blockedURL")]
    blocked_url: Option<String>,
    #[serde(rename = "sourceFile")]
    source_file: Option<String>,
    #[serde(rename = "lineNumber")]
    line_number: Option<i64>,
    #[serde(rename = "columnNumber")]
    column_number: Option<i64>,
    #[serde(rename = "statusCode")]
    status_code: Option<i64>,
    sample: Option<String>,
}

impl From<ReportingBody> for CspReport {
    fn from(b: ReportingBody) -> Self {
        Self {
            document_uri: b.document_url,
            referrer: b.referrer,
            violated_directive: b.violated_directive,
            effective_directive: b.effective_directive,
            original_policy: b.original_policy,
            blocked_uri: b.blocked_url,
            source_file: b.source_file,
            line_number: b.line_number,
            column_number: b.column_number,
            status_code: b.status_code,
            script_sample: b.sample,
        }
    }
}

/// Parse a request body into zero or more normalised `CspReport`s.
///
/// The two supported wire formats are distinguished by their outermost
/// JSON shape: the legacy envelope is an object (`{"csp-report": {...}}`)
/// while the Reporting API body is an array (`[{type, body}, ...]`).
/// We dispatch on the first non-whitespace byte rather than attempting
/// both shapes in sequence, because serde_json is lenient enough to
/// deserialise a JSON sequence into a struct with all-optional fields
/// (visiting elements in declaration order) and we would otherwise
/// silently lose Reporting API bodies to the legacy branch.
///
/// A body that parses as neither yields an empty vector, which the
/// caller treats as a no-op.
fn parse_reports(body: &[u8]) -> Vec<CspReport> {
    let first_non_ws = body.iter().find(|b| !b.is_ascii_whitespace());
    match first_non_ws {
        Some(b'{') => match serde_json::from_slice::<LegacyEnvelope>(body) {
            Ok(envelope) => vec![envelope.csp_report.into()],
            Err(_) => Vec::new(),
        },
        Some(b'[') => match serde_json::from_slice::<Vec<ReportingEnvelope>>(body) {
            Ok(envelopes) => envelopes
                .into_iter()
                .filter(|e| e.report_type.as_deref() == Some("csp-violation"))
                .filter_map(|e| e.body.map(CspReport::from))
                .collect(),
            Err(_) => Vec::new(),
        },
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Handler: POST /api/csp-report
// ---------------------------------------------------------------------------

/// Handle an incoming CSP violation report.
///
/// Always responds `204 No Content` so the browser treats the endpoint
/// as healthy and does not retry. Parse failures and database errors
/// are logged but never surfaced to the UA — reports are telemetry,
/// not a write path whose failure modes the user needs to see.
pub async fn receive_csp_report(State(state): State<Arc<AppState>>, body: Bytes) -> StatusCode {
    let reports = parse_reports(&body);
    for mut report in reports {
        if report.is_extension_noise() {
            continue;
        }
        report.truncate_fields();
        if let Err(e) = insert_report(&state.db, &report).await {
            eprintln!("failed to insert CSP report: {e}");
        }
    }
    StatusCode::NO_CONTENT
}

/// Insert a normalised CSP report into the `csp_reports` table.
async fn insert_report(pool: &SqlitePool, report: &CspReport) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO csp_reports (\
            document_uri, referrer, violated_directive, effective_directive, \
            original_policy, blocked_uri, source_file, line_number, \
            column_number, status_code, script_sample\
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        report.document_uri,
        report.referrer,
        report.violated_directive,
        report.effective_directive,
        report.original_policy,
        report.blocked_uri,
        report.source_file,
        report.line_number,
        report.column_number,
        report.status_code,
        report.script_sample,
    )
    .execute(pool)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Retention job
// ---------------------------------------------------------------------------

/// Maximum age of a CSP report before it is eligible for deletion.
///
/// 14 days is long enough to see a regression triggered by a Friday
/// deploy reported the following Monday, and short enough that the
/// table stays small even under sustained low-grade noise.
const RETENTION_DAYS: i64 = 14;

/// How often the retention job runs.
const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Background task: once per hour, delete any CSP report older than
/// [`RETENTION_DAYS`]. Runs for the lifetime of the process.
///
/// Errors are logged but never propagated — a transient DB failure
/// should not take the server down, and the next sweep will catch up.
pub async fn retention_loop(pool: SqlitePool) {
    let mut ticker = tokio::time::interval(RETENTION_SWEEP_INTERVAL);
    // Skip the first immediate tick; let the server finish starting up
    // before we touch the database with a maintenance query.
    ticker.tick().await;
    // SQLite's `datetime` modifier takes the lookback as a single
    // string token; we bind it instead of formatting it into the SQL
    // so the query stays parameterised end to end.
    let modifier = format!("-{RETENTION_DAYS} days");
    loop {
        ticker.tick().await;
        if let Err(e) = sqlx::query!(
            "DELETE FROM csp_reports WHERE received_at < datetime('now', ?)",
            modifier,
        )
        .execute(&pool)
        .await
        {
            eprintln!("csp_reports retention sweep failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_envelope() {
        let body = br#"{
            "csp-report": {
                "document-uri": "https://example.com/page",
                "violated-directive": "script-src 'self'",
                "blocked-uri": "https://evil.example/foo.js"
            }
        }"#;
        let reports = parse_reports(body);
        assert_eq!(reports.len(), 1);
        assert_eq!(
            reports[0].document_uri.as_deref(),
            Some("https://example.com/page")
        );
        assert_eq!(
            reports[0].blocked_uri.as_deref(),
            Some("https://evil.example/foo.js")
        );
    }

    #[test]
    fn parses_reporting_api_envelope() {
        let body = br#"[{
            "type": "csp-violation",
            "url": "https://example.com/page",
            "body": {
                "documentURL": "https://example.com/page",
                "violatedDirective": "script-src-elem",
                "blockedURL": "https://evil.example/foo.js",
                "lineNumber": 42,
                "sample": "alert(1)"
            }
        }]"#;
        let reports = parse_reports(body);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].line_number, Some(42));
        assert_eq!(reports[0].script_sample.as_deref(), Some("alert(1)"));
    }

    #[test]
    fn ignores_non_csp_reporting_api_types() {
        let body = br#"[{
            "type": "deprecation",
            "body": { "id": "foo" }
        }]"#;
        let reports = parse_reports(body);
        assert!(reports.is_empty());
    }

    #[test]
    fn extension_noise_detected() {
        let report = CspReport {
            source_file: Some("chrome-extension://abcdef/content.js".into()),
            ..Default::default()
        };
        assert!(report.is_extension_noise());
    }

    #[test]
    fn extension_noise_detected_on_blocked_uri() {
        let report = CspReport {
            blocked_uri: Some("moz-extension://abc/inject.js".into()),
            ..Default::default()
        };
        assert!(report.is_extension_noise());
    }

    #[test]
    fn legitimate_report_not_flagged_as_noise() {
        let report = CspReport {
            document_uri: Some("https://example.com/".into()),
            blocked_uri: Some("https://evil.example/inject.js".into()),
            ..Default::default()
        };
        assert!(!report.is_extension_noise());
    }

    #[test]
    fn unparseable_body_yields_empty() {
        assert!(parse_reports(b"garbage").is_empty());
        assert!(parse_reports(b"").is_empty());
    }

    #[test]
    fn truncate_in_place_short_string_unchanged() {
        let mut s = String::from("hello");
        truncate_in_place(&mut s, 1024);
        assert_eq!(s, "hello");
    }

    #[test]
    fn truncate_in_place_caps_long_ascii() {
        let mut s = "a".repeat(2048);
        truncate_in_place(&mut s, MAX_FIELD_BYTES);
        assert_eq!(s.len(), MAX_FIELD_BYTES);
    }

    #[test]
    fn truncate_in_place_respects_utf8_boundary() {
        // Each `é` is 2 bytes; cap at 5 bytes should land on a
        // boundary at 4 ("éé") rather than splitting the third char.
        let mut s = String::from("ééé");
        truncate_in_place(&mut s, 5);
        assert_eq!(s, "éé");
        assert_eq!(s.len(), 4);
    }

    #[test]
    fn truncate_fields_caps_oversized_report() {
        let mut report = CspReport {
            original_policy: Some("x".repeat(8192)),
            script_sample: Some("y".repeat(8192)),
            document_uri: Some("https://example.com/".into()),
            ..Default::default()
        };
        report.truncate_fields();
        assert_eq!(
            report.original_policy.as_deref().unwrap().len(),
            MAX_FIELD_BYTES
        );
        assert_eq!(
            report.script_sample.as_deref().unwrap().len(),
            MAX_FIELD_BYTES
        );
        // Short fields are left alone.
        assert_eq!(report.document_uri.as_deref(), Some("https://example.com/"));
    }
}
