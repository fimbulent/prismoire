//! Admin dashboard: per-route request statistics.
//!
//! Exposes a snapshot of the in-process route metrics (request count,
//! success/failure split, latency quantiles) collected by the
//! `route_metrics` middleware. Rows are sorted by 24h traffic
//! descending. The 24h columns are the primary view; cumulative
//! counters are included so operators can spot "was this route used
//! *ever*" without expanding the window.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Serialize;

use crate::admin::require_admin;
use crate::error::AppError;
use crate::session::AuthUser;
use crate::state::AppState;

/// Per-route traffic and latency snapshot.
///
/// Covers both a rolling 24-hour window and cumulative totals. Quantiles
/// are nearest-rank over a bounded recent-sample window and are `None`
/// until at least one successful latency observation has been recorded.
#[derive(Serialize)]
pub struct RouteStatsResponse {
    /// HTTP method (`"GET"`, `"POST"`, …).
    pub method: String,
    /// Matched path template, e.g. `/api/threads/{id}`.
    pub path: String,

    /// Total requests observed in the last 24 hours.
    pub total_24h: u64,
    /// 2xx responses in the last 24 hours.
    pub success_24h: u64,
    /// 4xx responses in the last 24 hours.
    pub client_error_24h: u64,
    /// 5xx responses in the last 24 hours.
    pub server_error_24h: u64,
    /// p50 response latency (ms) over the recent-sample window, or
    /// `None` if no samples have been recorded.
    pub latency_ms_p50_24h: Option<f64>,
    /// p95 response latency (ms); see `latency_ms_p50_24h`.
    pub latency_ms_p95_24h: Option<f64>,
    /// p99 response latency (ms); see `latency_ms_p50_24h`.
    pub latency_ms_p99_24h: Option<f64>,

    /// Cumulative requests since process start.
    pub total_all: u64,
    /// Cumulative 2xx responses since process start.
    pub success_all: u64,
    /// Cumulative 4xx responses since process start.
    pub client_error_all: u64,
    /// Cumulative 5xx responses since process start.
    pub server_error_all: u64,
}

/// Response wrapper for `GET /api/admin/routes`.
#[derive(Serialize)]
pub struct RouteListResponse {
    /// One entry per observed (method, path-template) pair, sorted by
    /// `total_24h` descending.
    pub routes: Vec<RouteStatsResponse>,
}

/// Return per-route request statistics, sorted by 24h count descending.
pub async fn list_routes(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let routes = state
        .metrics
        .route_snapshot()
        .into_iter()
        .map(|r| RouteStatsResponse {
            method: r.method,
            path: r.path,
            total_24h: r.total_24h,
            success_24h: r.success_24h,
            client_error_24h: r.client_error_24h,
            server_error_24h: r.server_error_24h,
            latency_ms_p50_24h: r.latency_ms_p50_24h,
            latency_ms_p95_24h: r.latency_ms_p95_24h,
            latency_ms_p99_24h: r.latency_ms_p99_24h,
            total_all: r.total_all,
            success_all: r.success_all,
            client_error_all: r.client_error_all,
            server_error_all: r.server_error_all,
        })
        .collect();

    Ok(Json(RouteListResponse { routes }))
}
