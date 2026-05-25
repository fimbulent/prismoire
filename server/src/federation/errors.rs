//! Shared CBOR error responses for `/federation/v1/*`.
//!
//! Per `docs/federation-protocol.md` §1.7 the federation surface is
//! CBOR-only — every response body, success or error, is CBOR. The
//! helpers here encode the `{ "error": <code> }` map called for by
//! §5/§6 error tables and stamp `Content-Type: application/cbor`.
//!
//! Both the per-route handlers (`peering.rs`, etc.) and the
//! envelope-verify middleware (`middleware.rs`) reach for these,
//! which is why they live in a small dedicated module rather than
//! being duplicated.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ciborium::value::Value;

use crate::federation::identity::CBOR_CONTENT_TYPE;

/// CBOR-encode `{ "error": <code> }` per §1.7.
fn cbor_error_body(code: &str) -> Vec<u8> {
    let value = Value::Map(vec![(
        Value::Text("error".into()),
        Value::Text(code.into()),
    )]);
    let mut buf = Vec::with_capacity(32);
    ciborium::ser::into_writer(&value, &mut buf).expect("ciborium ser is infallible");
    buf
}

/// Build a `status` response with a CBOR `{ "error": code }` body and
/// the `application/cbor` content type.
pub fn error_response(status: StatusCode, code: &str) -> Response {
    let mut r = (status, cbor_error_body(code)).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    r
}

/// `401 Unauthorized` — every envelope-verify failure mode collapses
/// to this on the wire per §6.5; the discriminated `VerifyError`
/// variant stays server-side for the §20 anomaly counter.
pub fn unauthorized() -> Response {
    error_response(StatusCode::UNAUTHORIZED, "unauthorized")
}

/// `403 Forbidden` — caller authenticated but is not authorized to
/// reach the route (e.g. §5.5 peer-of-peer with default peers-only
/// visibility when the requester is not an active peer).
pub fn forbidden(code: &str) -> Response {
    error_response(StatusCode::FORBIDDEN, code)
}

/// `400 Bad Request` — request body failed to decode or violates a
/// structural rule before any business logic runs.
pub fn bad_request(code: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, code)
}

/// `404 Not Found` — referenced row (e.g. an in-flight `request_id`)
/// doesn't exist in our local state.
pub fn not_found(code: &str) -> Response {
    error_response(StatusCode::NOT_FOUND, code)
}

/// `409 Conflict` — caller's request collides with an existing
/// peering invariant (e.g. domain already bound to a different
/// pubkey).
pub fn conflict(code: &str) -> Response {
    error_response(StatusCode::CONFLICT, code)
}

/// `415 Unsupported Media Type` — `Content-Type` is not
/// `application/cbor`; per §1.7 we reject rather than guess.
pub fn unsupported_media_type() -> Response {
    error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
}

/// `500 Internal Server Error` — local fault (DB, signer, etc.) that
/// is not the caller's responsibility. Operators see the detail in
/// `tracing` logs.
pub fn internal_error() -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal")
}
