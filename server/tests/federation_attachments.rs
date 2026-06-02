#![cfg(feature = "test-auth")]
//! Cross-instance attachment-blob integration tests (§11).
//!
//! Consolidates two formerly-separate phase files into the single
//! surface they both exercise — attachment blobs crossing the instance
//! boundary, from the origin's serve gate through the receiver's
//! fetch-on-demand pipeline:
//!
//! - **§11.5 origin serve gate.** `GET /federation/v1/attachments/{hash}`
//!   returns `200 OK` with the raw blob bytes and the stored
//!   `Content-Type` only when the hash maps to a locally-resident blob
//!   bound to the *current* revision of a locally-authored,
//!   non-retracted, non-deleted-author, locally-homed post. Every other
//!   case — malformed hex, unknown hash, `blob IS NULL`, resident bytes
//!   with no local binding (forwarding-cache rule), a retracted post, a
//!   binding on a prior revision, a tombstoned author, or a post stamped
//!   with a remote `home_instance` — collapses to the same `404`
//!   `attachment_not_found` per §11.4.
//! - **§11.3 / §11.4 receiver fetch-on-demand.** The synchronous serve
//!   trigger `try_fetch_for_serve` resolves the §11 origin from
//!   `posts.home_instance`, signs a §11.2 envelope GET, hash-verifies
//!   the response per §11.3, and stores the bytes — clearing any failure
//!   row on success. A hash mismatch records a terminal `mismatch`
//!   failure (bumping the §20 counter once) that short-circuits further
//!   fetches; an unavailable origin records a `transient` failure that
//!   honours the retry backoff; a hash with no remote binding resolves
//!   to no origin and writes no failure row.
//! - **§11.6 serve-side rate limiting.** The origin serve route 429s
//!   once the requesting peer exhausts its per-peer request budget or
//!   per-peer byte budget, keyed on the envelope sender's instance
//!   pubkey.
//!
//! Layer-0 invariants (the §11.5 SQL gate in isolation, the failure
//! table's conflict-upsert semantics, hash-verification helpers) live in
//! the in-module `#[cfg(test)]` blocks in `src/federation/attachments.rs`
//! and `src/federation/attachment_fetch.rs`.
//!
//! These scenarios drive the serve handler and the fetch trigger (the
//! functions under test) directly, so they do not use the
//! [`settle`](common::federation::settle) convergence driver — there is
//! no `frontier_fanout_loop` + poll race to replace here.
//!
//! Fixtures originate state through the real local APIs (upload +
//! create-thread on the origin instance, signed content pushes for the
//! receiver) rather than raw INSERTs, so the serve gate and fetch
//! pipeline run against exactly the row shapes production projects. The
//! few states with no real-API producer — an evicted blob (`blob NULL`
//! with the binding intact), a corrupt origin blob, a tombstoned author,
//! a post stamped with a remote `home_instance` — are reached by a single
//! targeted `UPDATE` on top of a real post, the same way `store_signed_
//! object` delivery is treated as legitimate injected test input
//! elsewhere in the suite.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use prismoire_server::AppState;
use prismoire_server::federation::attachment_fetch::try_fetch_for_serve;
use prismoire_server::federation::attachments::{
    ATTACHMENT_BYTES_PER_MIN_PER_PEER, ATTACHMENT_RPM_PER_PEER,
};
use prismoire_server::signed::AttachmentRef;
use prismoire_server::signing::{
    SigningOutput, sign_post_revision_with_key, sign_profile_revision_with_key,
    sign_thread_create_with_key,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};
use common::{Session, body_json, json_request, send, setup_admin};

// ---------------------------------------------------------------------------
// Shared hash / hex helpers — keep this crate self-contained without a
// `hex` dep.
// ---------------------------------------------------------------------------

/// Lowercase hex of a byte slice — the §3 URL form of a content hash.
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a 64-char lowercase hex string into raw 32-byte form.
fn hex32(s: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect();
    bytes.as_slice().try_into().expect("32 bytes")
}

/// SHA-256 of `bytes` — the content-address a real binding would carry.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Build a fixed-content 32-byte hash from a test-local seed byte. Used
/// only by the no-row cases (unknown hash) where the bytes are never
/// uploaded, so a real content hash would be ceremony.
fn seeded_hash(seed: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = seed;
    h[31] = seed.wrapping_add(0x5a);
    h
}

/// Pull the CBOR error code out of a non-200 attachment response body.
/// The handler emits `{ "error": <code> }` per §1.7.
fn parse_error_code(bytes: &[u8]) -> String {
    let v: Value = ciborium::de::from_reader(bytes).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("error body is not a map");
    };
    for (k, v) in m {
        if let (Value::Text(t), Value::Text(s)) = (&k, v)
            && t == "error"
        {
            return s;
        }
    }
    panic!("missing `error` field");
}

// ---------------------------------------------------------------------------
// Real-API origin fixtures
//
// Every §11.5 serve-gate scenario needs a *locally-authored* post on the
// serving instance that binds a *resident* attachment. We produce that the
// way production does: upload the bytes through `POST /api/attachments`,
// then bind them onto a thread OP via `POST /api/threads`. The resulting
// rows (resident blob, current-revision binding, `home_instance NULL`,
// live author) are exactly what the gate inspects.
// ---------------------------------------------------------------------------

/// Upload `bytes` as a single multipart "file" part and return the
/// server-computed content hash. The bytes must classify as one of the
/// allowed MIMEs; every fixture here uploads UTF-8 text, which is stored
/// verbatim so `content_hash == sha256(bytes)` and the served bytes equal
/// the input.
async fn upload_attachment(app: &Router, cookie: &str, bytes: &[u8]) -> [u8; 32] {
    let boundary = "X-PRISMOIRE-TEST-BOUNDARY";
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"upload.txt\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/attachments")
        .header(header::COOKIE, cookie)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("build upload request");
    let response = send(app, req).await;
    let status = response.status();
    let json = body_json(response).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "attachment upload should 201; got {status} body={json}",
    );
    hex32(json["content_hash"].as_str().expect("content_hash"))
}

/// Create a thread whose OP binds the named attachment, returning the OP
/// post id. The body carries no inline `![](...)` ref, so a text/plain
/// attachment binds without tripping the inline-image-only ref check.
async fn create_thread_with_attachment(
    app: &Router,
    cookie: &str,
    hash_hex: &str,
    filename: &str,
) -> String {
    let req = json_request(
        Method::POST,
        "/api/threads",
        Some(cookie),
        &serde_json::json!({
            "room": "general",
            "title": "attachment fixture thread",
            "body": "see attachment",
            "attachments": [ { "content_hash": hash_hex, "filename": filename } ],
        }),
    );
    let response = send(app, req).await;
    let status = response.status();
    let json = body_json(response).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "thread create should 201; got {status} body={json}",
    );
    json["post"]["id"].as_str().expect("op post id").to_string()
}

/// A locally-authored, locally-homed post that binds a resident
/// attachment on the serving instance — the §11.5 serve-gate happy state.
struct LocalOrigin {
    admin: Session,
    hash: [u8; 32],
    op_id: String,
}

/// Drive the real upload + create-thread path on `instance` so its §11.5
/// serve gate passes for the returned hash. `bytes` must be UTF-8 text.
async fn create_local_origin(
    harness: &MultiInstanceHarness,
    instance: &str,
    bytes: &[u8],
    filename: &str,
) -> LocalOrigin {
    let app = &harness.instance(instance).router;
    let admin = setup_admin(app, "origin-author").await;
    let hash = upload_attachment(app, &admin.cookie, bytes).await;
    let op_id =
        create_thread_with_attachment(app, &admin.cookie, &hex_lower(&hash), filename).await;
    LocalOrigin { admin, hash, op_id }
}

// ---------------------------------------------------------------------------
// Real-API receiver fixtures
//
// The receiver's fetch-pending state (a federated post homed at the
// origin, a current-revision binding, and a `blob = NULL` metadata row) is
// exactly what the §10.1 content-receive projection produces. We drive it
// with three signed pushes from the active-peer origin: a profile (stub
// hydration, home = sender), a thread-create (room + thread), and the OP
// post-rev carrying the attachment ref (posts + `project_post_attachments`).
// ---------------------------------------------------------------------------

/// Encode a §6.3 WireFormat `{ "p", "s" }`.
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

/// Pack WireFormat blobs under `{ "objects": [bstr, ...] }` per §10.1.
fn encode_content_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("objects".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + wires.iter().map(|w| w.len()).sum::<usize>());
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// Read the status tag of the first object in a §10.1 `{ "results": [...] }`
/// response.
fn first_result_status(body: &[u8]) -> String {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("results body is not a map");
    };
    let results = m
        .into_iter()
        .find_map(|(k, v)| match k {
            Value::Text(t) if t == "results" => Some(v),
            _ => None,
        })
        .expect("missing `results` field");
    let Value::Array(arr) = results else {
        panic!("`results` is not an array");
    };
    let Some(Value::Map(fields)) = arr.into_iter().next() else {
        panic!("no result entry");
    };
    for (k, v) in fields {
        if let (Value::Text(name), Value::Text(s)) = (&k, v)
            && name == "status"
        {
            return s;
        }
    }
    panic!("missing `status` field");
}

/// Push one signed object `from`→`to` over `/federation/v1/content` and
/// assert it lands `applied`.
async fn push_applied(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    signed: &SigningOutput,
) {
    let wire = encode_wire(&signed.payload, &signed.signature);
    let body = encode_content_body(&[wire]);
    let (status, resp) = send_envelope_signed(
        harness,
        from,
        to,
        Method::POST,
        "/federation/v1/content",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "push not 200 (body: {resp:?})");
    let tag = first_result_status(&resp);
    assert_eq!(tag, "applied", "push not applied (status: {tag})");
}

/// A text/plain attachment reference for a signed post-rev — mirrors what
/// the origin's upload stored (verbatim text, so `mime = text/plain`).
fn text_attachment_ref(hash: [u8; 32], size: u64, filename: &str) -> AttachmentRef {
    AttachmentRef {
        content_hash: hash,
        mime: "text/plain".to_string(),
        size,
        filename: filename.to_string(),
    }
}

/// Project the receiver's fetch-pending state on instance `to` by pushing
/// the real remote-author chain from active-peer `from`: profile →
/// thread-create → OP post-rev binding `attachment`. The post lands homed
/// at `from`, so the serve trigger resolves `from` as the §11 origin.
async fn push_pending_remote_post(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    author_key: &SigningKey,
    attachment: AttachmentRef,
) {
    let base_ms = 1_700_000_000_000u64;
    let thread_id = Uuid::new_v4();
    let post_id = Uuid::new_v4();

    let profile =
        sign_profile_revision_with_key(author_key, "remote-author", "", None, base_ms, None);
    push_applied(harness, from, to, &profile).await;

    let thread_create = sign_thread_create_with_key(
        author_key,
        &thread_id,
        "general",
        "placeholder",
        None,
        &post_id,
        base_ms,
    );
    push_applied(harness, from, to, &thread_create).await;

    let post_rev = sign_post_revision_with_key(
        author_key,
        &post_id,
        &thread_id,
        None,
        0,
        "remote body",
        base_ms,
        vec![attachment],
    );
    push_applied(harness, from, to, &post_rev).await;
}

/// Read back the stored blob bytes for `content_hash` (NULL → None).
async fn stored_blob(db: &SqlitePool, content_hash: &[u8; 32]) -> Option<Vec<u8>> {
    let hash_vec: Vec<u8> = content_hash.to_vec();
    sqlx::query!(
        "SELECT blob FROM attachment_blobs WHERE content_hash = ?",
        hash_vec,
    )
    .fetch_one(db)
    .await
    .expect("read blob")
    .blob
}

/// Read back the durable failure row for `content_hash` as
/// `(kind, last_attempt_at)`, or `None` if no row exists.
async fn failure_row(db: &SqlitePool, content_hash: &[u8; 32]) -> Option<(String, i64)> {
    let hash_vec: Vec<u8> = content_hash.to_vec();
    sqlx::query!(
        "SELECT kind, last_attempt_at FROM attachment_fetch_failures WHERE content_hash = ?",
        hash_vec,
    )
    .fetch_optional(db)
    .await
    .expect("read failure row")
    .map(|r| (r.kind, r.last_attempt_at))
}

/// Seed a 4-instance harness with active peering between "a" (the serving
/// instance) and "d" (the requesting peer).
async fn harness_with_peering() -> MultiInstanceHarness {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;
    harness
}

/// Establish mutual active peering so B's signed GET passes A's
/// `verify_known_peer`, and return `(receiver_state, origin_pubkey)`.
async fn peered_pair(harness: &MultiInstanceHarness) -> (Arc<AppState>, [u8; 32]) {
    establish_active_peering(harness, "b", "a").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    (b.state.clone(), *a.state.instance_key.public_bytes())
}

// ---------------------------------------------------------------------------
// §11.5 origin serve gate — GET /federation/v1/attachments/{hash}
// ---------------------------------------------------------------------------

/// Happy path: locally-authored, non-retracted post with a current-
/// revision binding whose blob bytes are resident on the serving instance
/// → 200 OK with the raw bytes and the stored Content-Type.
#[tokio::test]
async fn attachment_fetch_returns_200_with_bytes_for_local_origin() {
    let harness = harness_with_peering().await;
    let bytes = b"servable local-origin attachment bytes";
    let origin = create_local_origin(&harness, "a", bytes, "fixture.txt").await;

    let path = format!("/federation/v1/attachments/{}", hex_lower(&origin.hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "local-origin blob with a current binding must serve 200",
    );
    assert_eq!(resp.as_slice(), bytes, "raw blob bytes must round-trip");
}

/// Unknown hash — no `attachment_blobs` row for it at all → 404
/// `attachment_not_found`. §11.4 collapses unknown / evicted /
/// edit-removed into the same wire shape.
#[tokio::test]
async fn attachment_fetch_returns_404_for_unknown_hash() {
    let harness = harness_with_peering().await;

    let hash = seeded_hash(0xAA);
    let path = format!("/federation/v1/attachments/{}", hex_lower(&hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

/// Malformed hex (not 64 lowercase hex chars) — handler shortcuts to 404
/// without touching the DB. The §11.4 not-here collapse applies to bad
/// inputs too.
#[tokio::test]
async fn attachment_fetch_returns_404_for_malformed_hex() {
    let harness = harness_with_peering().await;

    let path = "/federation/v1/attachments/not-a-valid-hex-string";
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

/// §11.5 forwarding-cache rule: the blob bytes are resident (uploaded to
/// staging) but no `post_attachments` row binds the hash to a
/// locally-authored post. A bare upload that was never bound onto a thread
/// is exactly that state. Serving would violate the spec; the handler must
/// 404.
#[tokio::test]
async fn attachment_fetch_returns_404_when_resident_but_no_local_binding() {
    let harness = harness_with_peering().await;
    let app = &harness.instance("a").router;

    // Upload only — resident bytes, no binding to any local post.
    let uploader = setup_admin(app, "uploader").await;
    let bytes = b"orphan uploaded bytes with no post binding";
    let hash = upload_attachment(app, &uploader.cookie, bytes).await;

    let path = format!("/federation/v1/attachments/{}", hex_lower(&hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

/// §11.5 fetch-pending / evicted state: a binding row exists for the hash
/// but `attachment_blobs.blob IS NULL`. No real local API evicts a bound
/// blob while keeping the binding, so we reach the state with a single
/// targeted `UPDATE` on top of a real post — the NULL row is legitimate
/// cache-evicted input. 404 per §11.4.
#[tokio::test]
async fn attachment_fetch_returns_404_when_blob_bytes_null() {
    let harness = harness_with_peering().await;
    let bytes = b"bytes that will be evicted to NULL";
    let origin = create_local_origin(&harness, "a", bytes, "fixture.txt").await;

    // Minimal seed: drop the resident bytes, keep the binding + metadata.
    let hash_vec = origin.hash.to_vec();
    sqlx::query!(
        "UPDATE attachment_blobs SET blob = NULL WHERE content_hash = ?",
        hash_vec,
    )
    .execute(&harness.instance("a").state.db)
    .await
    .expect("evict blob bytes");

    let path = format!("/federation/v1/attachments/{}", hex_lower(&origin.hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

/// §11.5 retracted-post case: bytes resident, binding present, but the OP
/// was retracted via the real `DELETE /api/posts/{id}` handler. The serve
/// gate collapses this to 404 — the local backstop for a receive-side
/// delete-handler that has not yet run.
#[tokio::test]
async fn attachment_fetch_returns_404_when_post_retracted() {
    let harness = harness_with_peering().await;
    let app = &harness.instance("a").router;
    let bytes = b"bytes on a post that gets retracted";
    let origin = create_local_origin(&harness, "a", bytes, "doomed.txt").await;

    // Retract the OP through the real delete handler.
    let del = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/api/posts/{}", origin.op_id))
        .header(header::COOKIE, &origin.admin.cookie)
        .body(Body::empty())
        .expect("build retract request");
    let response = send(app, del).await;
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "retract should 204",
    );

    let path = format!("/federation/v1/attachments/{}", hex_lower(&origin.hash));
    let (status, _resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// §11.5 prior-revision case: the author edited the OP and dropped the
/// attachment via `PATCH /api/posts/{id}` with an empty `attachments`
/// array. The edit bumps `revision_count`, so the binding now sits on the
/// prior (removed) revision. The §11.5 check requires the binding to be on
/// the *current* revision. 404.
#[tokio::test]
async fn attachment_fetch_returns_404_when_binding_is_prior_revision() {
    let harness = harness_with_peering().await;
    let app = &harness.instance("a").router;
    let bytes = b"bytes removed during an edit";
    let origin = create_local_origin(&harness, "a", bytes, "removed.txt").await;

    // Edit the OP, dropping the attachment → new revision, stale binding.
    let edit = json_request(
        Method::PATCH,
        &format!("/api/posts/{}", origin.op_id),
        Some(&origin.admin.cookie),
        &serde_json::json!({
            "body": "edited body, attachment removed",
            "attachments": [],
        }),
    );
    let response = send(app, edit).await;
    assert_eq!(response.status(), StatusCode::OK, "OP edit should 200");

    let path = format!("/federation/v1/attachments/{}", hex_lower(&origin.hash));
    let (status, _resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Defence-in-depth: even with a current-revision binding in place, if the
/// post's author has been tombstoned (`users.deleted_at IS NOT NULL`) the
/// handler must 404 immediately. We tombstone via a targeted `UPDATE`
/// rather than `DELETE /api/me` precisely so the binding survives — that
/// pins the `users.deleted_at IS NULL` gate as the thing stopping the
/// serve, not a downstream refcount/binding reap.
#[tokio::test]
async fn attachment_fetch_returns_404_when_author_deleted() {
    let harness = harness_with_peering().await;
    let bytes = b"bytes whose author gets tombstoned";
    let origin = create_local_origin(&harness, "a", bytes, "fixture.txt").await;
    let db = harness.instance("a").state.db.clone();

    // Sanity: pre-deletion the serve succeeds.
    let path = format!("/federation/v1/attachments/{}", hex_lower(&origin.hash));
    let (status, _resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "pre-deletion control case must serve 200",
    );

    // Minimal seed: tombstone the author, leaving the bindings in place.
    sqlx::query!(
        "UPDATE users SET deleted_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?",
        origin.admin.user_id,
    )
    .execute(&db)
    .await
    .expect("tombstone author");

    let (status, _resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "post-deletion the `users.deleted_at IS NULL` gate must fire",
    );
}

/// §11.5 origin authority: a post stamped with a remote `home_instance`
/// (received via gossip-forwarding from the author's home instance) must
/// NOT serve its attachment from here even with resident bytes and a
/// current binding. The §11 origin authority lives at the recorded
/// `home_instance`, not at every peer that cached the bytes. No real local
/// API both binds a resident blob AND stamps a remote home, so we reach the
/// state with a single targeted `UPDATE` on top of a real post.
///
/// Pins the `p.home_instance IS NULL` clause of the `EXISTS` subquery
/// against regression.
#[tokio::test]
async fn attachment_fetch_returns_404_when_post_has_remote_home_instance() {
    let harness = harness_with_peering().await;
    let bytes = b"bytes on a post stamped with a remote home";
    let origin = create_local_origin(&harness, "a", bytes, "remote.txt").await;

    // Minimal seed: stamp a remote home pubkey on the locally-authored
    // post. Any non-NULL value flips the gate.
    let remote_home_pubkey = [0xABu8; 32];
    let home_slice: &[u8] = remote_home_pubkey.as_slice();
    sqlx::query!(
        "UPDATE posts SET home_instance = ? WHERE id = ?",
        home_slice,
        origin.op_id,
    )
    .execute(&harness.instance("a").state.db)
    .await
    .expect("stamp remote home_instance");

    let path = format!("/federation/v1/attachments/{}", hex_lower(&origin.hash));
    let (status, resp) = send_envelope_signed(&harness, "d", "a", Method::GET, &path, &[]).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "post with `home_instance` set must not serve — we are not §11 origin",
    );
    assert_eq!(parse_error_code(&resp), "attachment_not_found");
}

// ---------------------------------------------------------------------------
// §11.3 / §11.4 receiver fetch-on-demand — try_fetch_for_serve
//
// The synchronous serve trigger drives the failure-table state machine
// the local serve path (`/api/attachments/{hash}`) runs on a NULL blob.
// It wraps `fetch_attachment`, so the origin-resolution, hash-verify, and
// store steps of §11.3 are exercised end-to-end through this surface.
// ---------------------------------------------------------------------------

/// Happy path: B's trigger resolves A as origin, fetches, hash-verifies,
/// and stores the bytes — leaving no failure row.
#[tokio::test]
async fn serve_trigger_fetches_and_clears_failure_state() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, _a_pub) = peered_pair(&harness).await;

    let blob = b"servable federated bytes via real push".to_vec();
    let hash = sha256(&blob);

    // Origin A: real upload + create-thread so A's serve gate passes.
    let origin = create_local_origin(&harness, "a", &blob, "a.txt").await;
    assert_eq!(
        origin.hash, hash,
        "origin upload must content-address the bytes"
    );

    // Receiver B: real push of a remote post-rev binding the same hash,
    // homed at A.
    let author_key = SigningKey::generate(&mut OsRng);
    let aref = text_attachment_ref(hash, blob.len() as u64, "a.txt");
    push_pending_remote_post(&harness, "a", "b", &author_key, aref).await;

    assert!(
        try_fetch_for_serve(&b_state, hash).await,
        "trigger must report the bytes are now resident",
    );
    assert_eq!(
        stored_blob(&b_state.db, &hash).await.as_deref(),
        Some(blob.as_slice()),
        "trigger must leave the verified bytes in the receiver blob",
    );
    assert!(
        failure_row(&b_state.db, &hash).await.is_none(),
        "a successful fetch must leave no failure row",
    );
}

/// A hash mismatch (A serves corrupt bytes under the requested key) is
/// discarded, bumps the §20 mismatch counter exactly once, persists a
/// terminal `mismatch` failure row, and short-circuits a second trigger
/// without a re-fetch (proven by the counter staying at 1).
#[tokio::test]
async fn serve_trigger_records_mismatch_and_is_terminal() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, _a_pub) = peered_pair(&harness).await;

    // B requests the SHA-256 of the *declared* bytes; A is seeded with a
    // binding for that key, then its stored blob is corrupted so the
    // content-addressed serve returns bytes that don't hash to the key.
    let declared = b"what the reference claims".to_vec();
    let hash = sha256(&declared);
    let origin = create_local_origin(&harness, "a", &declared, "a.txt").await;
    assert_eq!(origin.hash, hash);

    let corrupt = b"totally different bytes".to_vec();
    assert_ne!(sha256(&corrupt), hash, "corrupt bytes must mismatch");
    let hash_vec = hash.to_vec();
    let corrupt_slice: &[u8] = &corrupt;
    sqlx::query!(
        "UPDATE attachment_blobs SET blob = ? WHERE content_hash = ?",
        corrupt_slice,
        hash_vec,
    )
    .execute(&harness.instance("a").state.db)
    .await
    .expect("corrupt origin blob");

    // Receiver B: real push binding the declared hash, homed at A.
    let author_key = SigningKey::generate(&mut OsRng);
    let aref = text_attachment_ref(hash, declared.len() as u64, "a.txt");
    push_pending_remote_post(&harness, "a", "b", &author_key, aref).await;

    assert!(
        !try_fetch_for_serve(&b_state, hash).await,
        "a mismatch must not produce servable bytes",
    );
    assert!(
        stored_blob(&b_state.db, &hash).await.is_none(),
        "mismatched bytes must not be stored — row stays fetch-pending",
    );
    let (kind, _) = failure_row(&b_state.db, &hash)
        .await
        .expect("mismatch must persist a failure row");
    assert_eq!(kind, "mismatch", "integrity failure must be terminal");
    assert_eq!(
        b_state
            .metrics
            .attachment_hash_mismatch
            .load(Ordering::Relaxed),
        1,
        "the first attempt bumps the §20 counter once",
    );

    // A second trigger must short-circuit on the terminal row WITHOUT a
    // transport attempt — proven by the mismatch counter staying at 1.
    assert!(!try_fetch_for_serve(&b_state, hash).await);
    assert_eq!(
        b_state
            .metrics
            .attachment_hash_mismatch
            .load(Ordering::Relaxed),
        1,
        "a terminal mismatch row must suppress further fetches",
    );
}

/// An unavailable origin (A holds no blob, so its content-addressed serve
/// 404s) records a `transient` failure that honours the retry backoff: an
/// immediate re-trigger does not re-attempt (proven by `last_attempt_at`
/// staying identical).
#[tokio::test]
async fn serve_trigger_records_transient_and_backs_off() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, _a_pub) = peered_pair(&harness).await;

    // B binds the hash (origin resolves to A) via a real push, but A was
    // never seeded with the blob, so A's content-addressed serve 404s →
    // §11.4 transient.
    let blob = b"bytes the origin does not hold".to_vec();
    let hash = sha256(&blob);
    let author_key = SigningKey::generate(&mut OsRng);
    let aref = text_attachment_ref(hash, blob.len() as u64, "a.txt");
    push_pending_remote_post(&harness, "a", "b", &author_key, aref).await;

    assert!(
        !try_fetch_for_serve(&b_state, hash).await,
        "an unavailable origin must not produce bytes",
    );
    let (kind, first_attempt) = failure_row(&b_state.db, &hash)
        .await
        .expect("a transient miss must persist a failure row");
    assert_eq!(kind, "transient");
    assert!(
        stored_blob(&b_state.db, &hash).await.is_none(),
        "transient miss leaves the row fetch-pending",
    );

    // An immediate re-trigger is inside ATTACHMENT_RETRY_BACKOFF, so it
    // must 404 WITHOUT re-attempting — proven by `last_attempt_at` staying
    // byte-for-byte identical (a re-attempt would refresh it).
    assert!(!try_fetch_for_serve(&b_state, hash).await);
    let (_, second_attempt) = failure_row(&b_state.db, &hash)
        .await
        .expect("failure row must persist across the backoff");
    assert_eq!(
        first_attempt, second_attempt,
        "within-backoff re-trigger must not refresh last_attempt_at",
    );
}

/// A hash with no remote binding resolves to no §11 origin: the trigger
/// reports false but writes no failure row (nothing to back off from, and
/// a binding may arrive later).
#[tokio::test]
async fn serve_trigger_no_origin_returns_false_without_row() {
    let harness = MultiInstanceHarness::new(2).await;
    let (b_state, _a_pub) = peered_pair(&harness).await;

    let unknown = sha256(b"never bound - serve trigger");

    assert!(!try_fetch_for_serve(&b_state, unknown).await);
    assert!(
        failure_row(&b_state.db, &unknown).await.is_none(),
        "a no-origin miss must not write a failure row",
    );
}

// ---------------------------------------------------------------------------
// §11.6 serve-side rate limiting on GET /federation/v1/attachments/{hash}
//
// The limiter keys on the envelope sender (the requesting peer's instance
// pubkey); we drive it into the rejecting state via its own public surface
// (cheap, in-memory) and assert the real handler returns 429 instead of
// serving the origin bytes it otherwise would.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn serve_route_429s_when_peer_exceeds_request_budget() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "b", "a").await;
    let a = harness.instance("a");
    let b_pub = *harness.instance("b").state.instance_key.public_bytes();

    let blob = b"servable bytes behind the rpm gate";
    let origin = create_local_origin(&harness, "a", blob, "a.txt").await;
    let path = format!("/federation/v1/attachments/{}", hex_lower(&origin.hash));

    // Control: under budget, A is the origin and holds the bytes → 200.
    let (status, body) = send_envelope_signed(&harness, "b", "a", Method::GET, &path, b"").await;
    assert_eq!(status, StatusCode::OK, "origin must serve under budget");
    assert_eq!(body, blob, "served bytes must be the origin blob");

    // Saturate B's per-peer request window on A, then the same request that
    // just succeeded must shed.
    for _ in 0..ATTACHMENT_RPM_PER_PEER {
        a.state.attachment_serve_rate_limiter.try_admit(b_pub);
    }
    let (status, _) = send_envelope_signed(&harness, "b", "a", Method::GET, &path, b"").await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "request over the per-peer RPM budget must 429",
    );
}

#[tokio::test]
async fn serve_route_429s_when_peer_exceeds_byte_budget() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "b", "a").await;
    let a = harness.instance("a");
    let b_pub = *harness.instance("b").state.instance_key.public_bytes();

    let blob = b"servable bytes behind the byte gate";
    let origin = create_local_origin(&harness, "a", blob, "a.txt").await;
    let path = format!("/federation/v1/attachments/{}", hex_lower(&origin.hash));

    // Burn B's whole per-minute byte budget on A in one charge; the
    // request-count budget is untouched, so the 429 is attributable to the
    // byte budget alone.
    a.state
        .attachment_serve_rate_limiter
        .charge_bytes(b_pub, ATTACHMENT_BYTES_PER_MIN_PER_PEER);

    let (status, _) = send_envelope_signed(&harness, "b", "a", Method::GET, &path, b"").await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "request over the per-peer byte budget must 429",
    );
}
