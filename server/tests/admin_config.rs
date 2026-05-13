#![cfg(feature = "test-auth")]
//! Handler tests for `PATCH /api/admin/config`.
//!
//! Covers the middleware-sensitive paths:
//!
//! - Admin auth: a non-admin is rejected with 403 before any DB work.
//! - Cross-field validation: `debounce > min_interval` is rejected
//!   even when each individual field is in range, and the request
//!   does not mutate the `instance_config` row (a partial-update
//!   regression would otherwise be invisible).
//! - Happy path: an in-range PATCH persists, the GET round-trips the
//!   new values, and an `edit_config` audit-log entry is written.

mod common;

use axum::http::{Method, StatusCode};
use common::{body_bytes, body_json, get_request, json_request, send, setup_admin, signup_as};

/// A non-admin (just-invited) user gets 403 on `PATCH /api/admin/config`.
///
/// The admin middleware lives in front of every handler under
/// `/api/admin/*`; if it ever silently no-ops, this test fails.
#[tokio::test]
async fn patch_admin_config_non_admin_forbidden() {
    let (app, _state) = common::test_app().await;
    let alice = setup_admin(&app, "alice").await;
    let bob = signup_as(&app, &alice, "bob").await;

    let req = json_request(
        Method::PATCH,
        "/api/admin/config",
        Some(&bob.cookie),
        &serde_json::json!({ "rebuild_debounce_ms": 2000 }),
    );
    let response = send(&app, req).await;
    let status = response.status();
    let bytes = body_bytes(response).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin PATCH should be 403; body={:?}",
        String::from_utf8_lossy(&bytes),
    );
}

/// Cross-field validation rejects `debounce > min_interval` even when
/// both individual values are in their per-field ranges.
///
/// Also asserts the row is *unchanged* afterwards — a regression that
/// applied one field before validating the cross-field invariant would
/// otherwise slip through.
#[tokio::test]
async fn patch_admin_config_cross_field_validation() {
    let (app, state) = common::test_app().await;
    let alice = setup_admin(&app, "alice").await;

    // Snapshot the current schedule so we can assert nothing changed.
    let before_req = get_request("/api/admin/config", Some(&alice.cookie));
    let before = body_json(send(&app, before_req).await).await;
    let before_debounce = before["rebuild_debounce_ms"].as_u64().expect("u64");
    let before_min = before["rebuild_min_interval_ms"].as_u64().expect("u64");

    // debounce = 40s, min_interval = 10s. Each is individually in range
    // (1s..=60s for debounce, 1s..=1h for min) but debounce > min, which
    // the validator catches.
    let req = json_request(
        Method::PATCH,
        "/api/admin/config",
        Some(&alice.cookie),
        &serde_json::json!({
            "rebuild_debounce_ms": 40_000,
            "rebuild_min_interval_ms": 10_000,
        }),
    );
    let response = send(&app, req).await;
    let status = response.status();
    let bytes = body_bytes(response).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "debounce > min should be 400; body={:?}",
        String::from_utf8_lossy(&bytes),
    );

    // Confirm the row is unchanged. If a future refactor accidentally
    // ran the UPDATE before the validator, debounce would now be 40_000.
    let after_req = get_request("/api/admin/config", Some(&alice.cookie));
    let after = body_json(send(&app, after_req).await).await;
    assert_eq!(after["rebuild_debounce_ms"].as_u64(), Some(before_debounce));
    assert_eq!(after["rebuild_min_interval_ms"].as_u64(), Some(before_min));

    // And no `edit_config` audit row should have been written.
    let log_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM admin_log WHERE action = 'edit_config'")
            .fetch_one(&state.db)
            .await
            .expect("count admin_log");
    assert_eq!(
        log_count, 0,
        "rejected PATCH must not write an audit-log entry",
    );
}

/// Happy path: a valid PATCH updates the row, the in-memory mirror,
/// and writes a single `edit_config` audit-log entry.
#[tokio::test]
async fn patch_admin_config_happy_path_persists_and_audits() {
    let (app, state) = common::test_app().await;
    let alice = setup_admin(&app, "alice").await;

    // Pick a new value distinct from the seeded default (5_000ms) so
    // the assertion can't pass by accident.
    let new_debounce = 7_500u64;

    let req = json_request(
        Method::PATCH,
        "/api/admin/config",
        Some(&alice.cookie),
        &serde_json::json!({ "rebuild_debounce_ms": new_debounce }),
    );
    let response = send(&app, req).await;
    let status = response.status();
    let bytes = body_bytes(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "valid PATCH should be 200; body={:?}",
        String::from_utf8_lossy(&bytes),
    );
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("response body is JSON");
    assert_eq!(body["rebuild_debounce_ms"].as_u64(), Some(new_debounce));

    // Round-trip via GET confirms persistence (and that the GET reads
    // from the in-memory mirror the PATCH just wrote).
    let get_req = get_request("/api/admin/config", Some(&alice.cookie));
    let got = body_json(send(&app, get_req).await).await;
    assert_eq!(got["rebuild_debounce_ms"].as_u64(), Some(new_debounce));

    // Exactly one audit row, attributed to alice, mentioning the
    // changed field. `build_change_summary` formats the reason as a
    // comma-joined `field=value` list.
    let row: (String, String) =
        sqlx::query_as("SELECT admin, reason FROM admin_log WHERE action = 'edit_config'")
            .fetch_one(&state.db)
            .await
            .expect("one edit_config row");
    assert_eq!(row.0, alice.user_id, "audit row attributed to alice");
    assert!(
        row.1.contains(&format!("debounce_ms={new_debounce}")),
        "audit reason should mention the changed field; got {:?}",
        row.1,
    );
}
