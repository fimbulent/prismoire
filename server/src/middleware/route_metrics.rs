//! Per-route request / latency metrics middleware.
//!
//! Wraps every request flowing through the API router, keys on the
//! matched path template (`/api/threads/{id}`, not the URL), and
//! records count, success/failure counters, and latency into the
//! shared `Metrics` handle. Consumed by the admin dashboard via
//! `/api/admin/routes`.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::metrics::Metrics;

/// Sentinel path used when a request did not match any route — e.g.
/// a 404 from the outer router. Keeping it as a single fixed bucket
/// means unmatched URLs can't blow up the routes map.
const UNMATCHED_PATH: &str = "<unmatched>";

/// Record request count, outcome, and latency for the matched route.
pub async fn route_metrics(
    State(metrics): State<Arc<Metrics>>,
    request: Request,
    next: Next,
) -> Response {
    // `MatchedPath` is populated by the router when a request matches
    // a registered route. Capture it before calling `next`, while the
    // original request extensions are still intact.
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| UNMATCHED_PATH.to_string());
    let method = request.method().as_str().to_string();

    let started = Instant::now();
    let response = next.run(request).await;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;

    metrics.record_request(&method, &path, response.status().as_u16(), elapsed_ms);
    response
}
