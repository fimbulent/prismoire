//! `GET /federation/v1/edges/backfill` — chain-continuity recovery
//! (`docs/federation-protocol.md` §9.3 + Phase 5).
//!
//! The narrow chain-walk for a single `(source, target)` trust-edge
//! pair. It is the §7.6 correctness backstop for any edge the
//! forwarder failed to deliver: a sender whose chain has grown out of
//! sync with this instance asks here for the canonical bytes,
//! oldest-first, paginated by an opaque cursor.
//!
//! Distinct from the broader `POST /backfill/by-hash` and
//! `GET /backfill/by-author` / `edges-by-key` routes in §10.5 — those
//! cover *bulk* recovery and land in Phase 8. This route ships now
//! because it shares the Phase-5 partition-heal Layer-1 scenario with
//! the §9.1 push handler in `edges.rs`.
//!
//! ## Behaviour
//!
//! 1. Query params: `source=<hex>&target=<hex>&since=<base64url>&limit=<n>`.
//!    Hex keys are 64-char (32-byte) Ed25519 pubkeys; `since` is
//!    opaque (server-private structure — see [`Cursor`]); `limit`
//!    caps at [`MAX_EDGE_BACKFILL_PAGE`].
//! 2. Resolve `source` and `target` to local `users.id` via
//!    `users.public_key`. Phase 5 only persists a `trust_edges` row
//!    when both endpoints are local users (see `edges.rs`); if either
//!    key is unknown to this instance we have no chain to serve and
//!    return `400 unknown_chain` per the spec.
//! 3. Chain-walk `trust_edges` joined with `signed_objects` on
//!    `canonical_hash`, ordered oldest-first with `canonical_hash`
//!    as the deterministic tiebreaker. Apply the cursor's
//!    `(created_at, canonical_hash)` "strictly after" predicate when
//!    present. Fetch `limit + 1` rows so the next-cursor decision is
//!    a single LIMIT instead of a separate count.
//! 4. Encode each row as §6.3 WireFormat (`{ p, s }`), pack the array
//!    under `{ objects, [next_cursor], complete }`, stamp
//!    `Content-Type: application/cbor`.
//!
//! ## Erased rows (Phase 5 carve-out)
//!
//! `signed_objects` rows with `payload IS NULL` (erased per §3.1)
//! still exist for chain continuity. §10.5.6 prescribes a `410 Gone`
//! response carrying the erasure authority for those, but the full
//! 410-Gone protocol — including the `authority` WireFormat — is a
//! Phase 8 concern. For Phase 5 we *skip* erased rows in the result
//! set: the cursor still advances past them via the next page's
//! `(created_at, canonical_hash) > (last)` predicate, so a chain with
//! holes still paginates correctly. The sender either has the gap
//! filled via a future re-walk after we add 410-Gone, or via the
//! §10.5.1 by-hash route once that lands.

use std::sync::Arc;

use axum::extract::{Extension, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::Value;

use crate::AppState;
use crate::federation::envelope::encode_signed_object;
use crate::federation::errors::{bad_request, internal_error};
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::signed::FedEnvelope;

/// §9.6 `MAX_EDGE_BACKFILL_PAGE`: receiver-enforced cap on `limit`
/// (default 100). Requests with `limit > MAX_EDGE_BACKFILL_PAGE` or
/// `limit == 0` collapse to `400 limit_out_of_range`.
pub const MAX_EDGE_BACKFILL_PAGE: u32 = 100;

/// Width of the ISO-8601 `%Y-%m-%dT%H:%M:%SZ` strings that
/// `set_trust_edge` / `apply_with_local_projection` mint into
/// `trust_edges.created_at`. Fixed-width packing lets the cursor stay
/// inside the §10.5.2 64-byte budget without a length prefix.
const ISO_TIMESTAMP_LEN: usize = 20;

/// Raw cursor layout: `[ ISO timestamp (20B) | canonical_hash (32B) ]`.
/// 52 bytes, base64url-encoded to 70 ASCII chars for the `since` URL
/// parameter; the response carries the raw 52 bytes as a `bstr`.
const CURSOR_LEN: usize = ISO_TIMESTAMP_LEN + 32;

// ---------------------------------------------------------------------------
// Query string
// ---------------------------------------------------------------------------

/// Query-string fields for `GET /federation/v1/edges/backfill`.
///
/// All fields are `Option`-typed so a missing field surfaces as a
/// per-field `400` (`malformed` / `invalid_key`) at the handler
/// rather than a serde-rejection HTML page from Axum.
#[derive(serde::Deserialize)]
pub struct EdgesBackfillQuery {
    /// Hex-encoded 32-byte Ed25519 pubkey of the chain's source
    /// (= `from_key` on each signed `trust-edge`). Required.
    pub source: Option<String>,
    /// Hex-encoded 32-byte Ed25519 pubkey of the chain's target.
    /// Required.
    pub target: Option<String>,
    /// Opaque base64url cursor from a prior response. Absent or
    /// empty means "from the chain root."
    pub since: Option<String>,
    /// Max objects to return; capped at [`MAX_EDGE_BACKFILL_PAGE`].
    /// Absent → page-default (`MAX_EDGE_BACKFILL_PAGE`).
    pub limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// Cursor encoding (server-private; opaque to clients)
// ---------------------------------------------------------------------------

/// Decoded `(created_at, canonical_hash)` cursor.
///
/// Stored as a fixed-width binary blob to stay under the §10.5.2
/// 64-byte cursor budget without a length-prefix dance. The
/// canonical-hash tiebreaker means two rows with identical
/// `created_at` (legal — `trust_edges.created_at` is per-second) still
/// produce a strict total order on the chain walk.
struct Cursor {
    /// Verbatim `trust_edges.created_at` (ISO 8601, `Z` suffix).
    /// Must be exactly [`ISO_TIMESTAMP_LEN`] bytes to encode.
    created_at: String,
    /// Last-emitted row's canonical hash (the strict-after tiebreak).
    canonical_hash: [u8; 32],
}

/// Decode a base64url `since` parameter into a [`Cursor`]. Returns
/// `None` for any structural deviation (base64 garbage, wrong length,
/// non-ASCII timestamp) — the caller surfaces that as
/// `400 invalid_cursor`, the spec's "client adopts response and retries
/// without since" signal.
fn decode_cursor(since: &str) -> Option<Cursor> {
    let bytes = URL_SAFE_NO_PAD.decode(since.as_bytes()).ok()?;
    if bytes.len() != CURSOR_LEN {
        return None;
    }
    let ts_bytes = &bytes[..ISO_TIMESTAMP_LEN];
    // The ISO string is pure ASCII — reject any byte sequence that
    // round-trips through UTF-8 to a non-ASCII or differently-shaped
    // value, since the SQL comparison is text-string and a non-ISO
    // value would never match anything but still bloats logs.
    if !ts_bytes.iter().all(u8::is_ascii) {
        return None;
    }
    let created_at = std::str::from_utf8(ts_bytes).ok()?.to_string();
    let mut canonical_hash = [0u8; 32];
    canonical_hash.copy_from_slice(&bytes[ISO_TIMESTAMP_LEN..]);
    Some(Cursor {
        created_at,
        canonical_hash,
    })
}

/// Encode a row's `(created_at, canonical_hash)` into the raw
/// 52-byte cursor blob. Returns `None` if `created_at` is not exactly
/// [`ISO_TIMESTAMP_LEN`] bytes (it always is for rows minted by
/// `apply_with_local_projection` / `set_trust_edge`, but defensive
/// against any future migration that loosens the format).
fn encode_cursor(created_at: &str, canonical_hash: &[u8; 32]) -> Option<Vec<u8>> {
    if created_at.len() != ISO_TIMESTAMP_LEN || !created_at.is_ascii() {
        return None;
    }
    let mut out = Vec::with_capacity(CURSOR_LEN);
    out.extend_from_slice(created_at.as_bytes());
    out.extend_from_slice(canonical_hash);
    Some(out)
}

// ---------------------------------------------------------------------------
// Hex-pubkey decode
// ---------------------------------------------------------------------------

/// Decode a hex-encoded 32-byte Ed25519 pubkey. Returns `None` for
/// any non-32-byte result (wrong length, non-hex characters); the
/// caller surfaces that as `400 invalid_key`.
fn decode_hex_pubkey(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Response encoding
// ---------------------------------------------------------------------------

/// One chain-walk row in encode-ready form: the verbatim signed-payload
/// bytes and signature plus the `(created_at, canonical_hash)` pair
/// the next-cursor calculation needs.
struct ChainRow {
    payload: Vec<u8>,
    signature: Vec<u8>,
    created_at: String,
    canonical_hash: [u8; 32],
}

/// Encode `{ "objects": [WireFormat...], ["next_cursor": bstr,]
/// "complete": bool }` per §9.3 / §10.5.2.
fn encode_backfill_body(
    objects: &[ChainRow],
    next_cursor: Option<Vec<u8>>,
    complete: bool,
) -> Vec<u8> {
    let arr: Vec<Value> = objects
        .iter()
        .map(|row| Value::Bytes(encode_signed_object(&row.payload, &row.signature)))
        .collect();

    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(3);
    entries.push((Value::Text("objects".into()), Value::Array(arr)));
    if let Some(c) = next_cursor {
        entries.push((Value::Text("next_cursor".into()), Value::Bytes(c)));
    }
    entries.push((Value::Text("complete".into()), Value::Bool(complete)));
    let body = Value::Map(entries);
    let mut buf = Vec::with_capacity(
        64 + objects
            .iter()
            .map(|r| r.payload.len() + r.signature.len() + 32)
            .sum::<usize>(),
    );
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    buf
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /federation/v1/edges/backfill` (§9.3).
///
/// The `FedEnvelope` extractor pins the middleware contract at the
/// handler signature — `verify_known_peer` only forwards requests from
/// active peers, so by the time we reach here the caller has already
/// proved possession of an `active` peer signing key. The envelope's
/// fields themselves are unused: §9.3 keys backfill on the requested
/// chain pair, not on the requester.
pub async fn handle_edges_backfill(
    State(state): State<Arc<AppState>>,
    Extension(_envelope): Extension<FedEnvelope>,
    Query(params): Query<EdgesBackfillQuery>,
) -> Response {
    // Required query params. Empty strings are treated as missing —
    // `?source=&target=` is a degenerate URL no peer should send, but
    // collapsing to `malformed` is more useful than parsing it as
    // "empty key" and then failing `invalid_key` further along.
    let source_hex = match params.source.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return bad_request("malformed"),
    };
    let target_hex = match params.target.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return bad_request("malformed"),
    };

    let source_bytes = match decode_hex_pubkey(source_hex) {
        Some(b) => b,
        None => return bad_request("invalid_key"),
    };
    let target_bytes = match decode_hex_pubkey(target_hex) {
        Some(b) => b,
        None => return bad_request("invalid_key"),
    };

    // Spec: `limit` capped at MAX_EDGE_BACKFILL_PAGE; we also reject
    // 0 as out-of-range (a zero-row page is what `complete: true` is
    // for, so accepting `limit=0` would invite confused clients).
    let limit = match params.limit {
        None => MAX_EDGE_BACKFILL_PAGE,
        Some(n) if (1..=MAX_EDGE_BACKFILL_PAGE).contains(&n) => n,
        _ => return bad_request("limit_out_of_range"),
    };

    let cursor = match params.since.as_deref() {
        None | Some("") => None,
        Some(s) => match decode_cursor(s) {
            Some(c) => Some(c),
            None => return bad_request("invalid_cursor"),
        },
    };

    // Resolve the chain endpoints to local user ids. Phase 5 only
    // produces `trust_edges` rows for local pairs, so a chain whose
    // endpoints we have never seen is "have nothing" — return
    // `unknown_chain` rather than misleadingly empty pages.
    let source_slice: &[u8] = source_bytes.as_slice();
    let target_slice: &[u8] = target_bytes.as_slice();
    let source_id_opt =
        match sqlx::query_scalar!("SELECT id FROM users WHERE public_key = ?", source_slice,)
            .fetch_optional(&state.db)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "db error resolving source user in edges backfill");
                return internal_error();
            }
        };
    let target_id_opt =
        match sqlx::query_scalar!("SELECT id FROM users WHERE public_key = ?", target_slice,)
            .fetch_optional(&state.db)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "db error resolving target user in edges backfill");
                return internal_error();
            }
        };
    let (source_id, target_id) = match (source_id_opt, target_id_opt) {
        (Some(s), Some(t)) => (s, t),
        _ => return bad_request("unknown_chain"),
    };

    // Page-fetch: ask for `limit + 1` rows so we can decide whether
    // there is a next page (and set `complete` / `next_cursor`)
    // without a second query. The cursor predicate is the
    // textbook (created_at, canonical_hash) > (cursor) keyset
    // pagination — ISO timestamps sort lexicographically iff they
    // are the same fixed width, which they are by `set_trust_edge` /
    // `apply_with_local_projection` construction.
    let fetch_n = (limit as i64) + 1;
    let cursor_iso: Option<String> = cursor.as_ref().map(|c| c.created_at.clone());
    let cursor_hash: Option<Vec<u8>> = cursor.as_ref().map(|c| c.canonical_hash.to_vec());

    let rows = match sqlx::query!(
        "SELECT te.canonical_hash AS \"canonical_hash!: Vec<u8>\", \
                te.created_at AS \"created_at!: String\", \
                so.payload AS \"payload?: Vec<u8>\", \
                so.signature AS \"signature!: Vec<u8>\" \
         FROM trust_edges te \
         JOIN signed_objects so ON so.canonical_hash = te.canonical_hash \
         WHERE te.source_user = ? AND te.target_user = ? \
           AND te.canonical_hash IS NOT NULL \
           AND so.payload IS NOT NULL \
           AND ( \
                ? IS NULL \
                OR te.created_at > ? \
                OR (te.created_at = ? AND te.canonical_hash > ?) \
           ) \
         ORDER BY te.created_at ASC, te.canonical_hash ASC \
         LIMIT ?",
        source_id,
        target_id,
        cursor_iso,
        cursor_iso,
        cursor_iso,
        cursor_hash,
        fetch_n,
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "db error walking trust-edge chain in backfill");
            return internal_error();
        }
    };

    // If the requester had no cursor and the chain holds no
    // non-erased rows at all, the spec asks for `unknown_chain`
    // ("server has no edges for this pair"). With a cursor we are
    // mid-walk: an empty result there means "we are past the end,"
    // i.e. `complete: true` with an empty objects array.
    if cursor.is_none() && rows.is_empty() {
        // We resolved both endpoints but the join produced no chain.
        // That is the spec's "server has no edges for this pair"
        // condition — distinct from `invalid_cursor`, distinct from
        // mid-walk "you have everything."
        let has_any_unjoined = match sqlx::query_scalar!(
            "SELECT 1 AS \"present!: i64\" FROM trust_edges \
             WHERE source_user = ? AND target_user = ? LIMIT 1",
            source_id,
            target_id,
        )
        .fetch_optional(&state.db)
        .await
        {
            Ok(r) => r.is_some(),
            Err(e) => {
                tracing::error!(error = %e, "db error checking unknown_chain");
                return internal_error();
            }
        };
        if !has_any_unjoined {
            return bad_request("unknown_chain");
        }
        // The chain exists but every row is currently unrepresentable
        // (e.g. all payloads erased). Return an empty `complete: true`
        // page; the per-hash backfill route (Phase 8) will surface
        // the 410 Gone details once it lands.
        return ok_response(encode_backfill_body(&[], None, true));
    }

    // Honest "we asked for limit+1 to detect more pages" pagination.
    let has_more = (rows.len() as i64) > limit as i64;
    let mut page_rows: Vec<ChainRow> = Vec::with_capacity(limit as usize);
    for row in rows.into_iter().take(limit as usize) {
        // payload is `Option<Vec<u8>>` because of the schema type, but
        // the WHERE clause filtered IS NOT NULL — so a None here is a
        // real race (a concurrent erasure landed between query and
        // map) and we skip silently rather than crash.
        let Some(payload) = row.payload else {
            continue;
        };
        // canonical_hash is a 32-byte BLOB by schema CHECK. A length
        // mismatch is a corrupted DB row, not a recoverable condition:
        // silently skipping would advance the cursor past the row that
        // *did* fit and re-encounter the corrupt row on every page,
        // starving the requesting peer. Fail loud so an operator
        // notices the invariant violation.
        let canonical_hash: [u8; 32] = match row.canonical_hash.as_slice().try_into() {
            Ok(h) => h,
            Err(_) => {
                tracing::error!(
                    "edges backfill: trust-edge row has non-32-byte canonical_hash; \
                     refusing to advance cursor past corrupt row"
                );
                return internal_error();
            }
        };
        page_rows.push(ChainRow {
            payload,
            signature: row.signature,
            created_at: row.created_at,
            canonical_hash,
        });
    }

    let next_cursor = if has_more && let Some(last) = page_rows.last() {
        encode_cursor(&last.created_at, &last.canonical_hash)
    } else {
        None
    };
    let complete = !has_more;

    // §10.5.2: `complete: false` requires `next_cursor`. We built an
    // over-the-cap page (`has_more`) but `encode_cursor` failed on
    // the last row — that should be unreachable for rows minted by
    // this server (every `created_at` is the canonical 20-char
    // `YYYY-MM-DDTHH:MM:SSZ` form `chrono`'s `%Y-%m-%dT%H:%M:%SZ`
    // produces, which `decode_cursor` accepts). Returning
    // `complete: true` here would silently truncate the chain and
    // make the requesting peer think it had walked to the head —
    // exactly the data-loss footgun §9.3 chain-continuity is meant
    // to prevent. Fail loud instead so an operator notices the
    // invariant violation.
    if !complete && next_cursor.is_none() {
        tracing::error!(
            "edges backfill: tail row carries non-standard ISO timestamp; \
             cannot mint a next_cursor without violating §10.5.2 invariant"
        );
        return internal_error();
    }

    ok_response(encode_backfill_body(&page_rows, next_cursor, complete))
}

/// Build the `200 OK` `application/cbor` response for an encoded body.
fn ok_response(body: Vec<u8>) -> Response {
    let mut r = (StatusCode::OK, body).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    r
}

// ===========================================================================
// `GET /federation/v1/moves/backfill` — §12.3 chain-continuity recovery
// ===========================================================================
//
// Mirrors the `/edges/backfill` chain-walk pattern above, with three
// differences worth flagging:
//
//   * Keyed on a single `key=<hex>` (the moving identity K) instead of
//     a `(source, target)` pair. K is the natural index of
//     `user_moves`, populated by `apply_one_move` for both `applied`
//     and `superseded` moves (§12.5 chain evidence).
//
//   * `created_at` is a Unix-millisecond INTEGER, not an ISO string —
//     the cursor packs it as 8 bytes big-endian + 32 bytes
//     `canonical_hash` = 40 bytes (well under the §10.5.2 64-byte
//     cap), and the SQL keyset-pagination predicate operates on
//     INTEGER comparisons rather than text.
//
//   * Backfill is broadly serviceable per §12.5 ("any peer that ever
//     held a move remains a viable backfill source") — there is no
//     local-only carve-out like `/edges/backfill`'s "both endpoints
//     resolved to local users" gate. The chain is served from
//     whatever `user_moves` rows we hold for K, full stop. An empty
//     result with no cursor is `unknown_chain`; mid-walk with no rows
//     is `complete: true`.
//
// Erased rows: §12.5 declares moves "retained indefinitely" so the
// `payload IS NULL` carve-out from `/edges/backfill` cannot fire here
// in any legitimate flow. The query still filters `payload IS NOT
// NULL` defensively so a corrupted local row does not crash the
// handler.

/// §12.6 `MAX_MOVE_BACKFILL_PAGE`: receiver-enforced cap on `limit`
/// (default 100). Same shape as `MAX_EDGE_BACKFILL_PAGE`; per §12.5
/// move chains for any one K are short, so single-page responses are
/// the common case.
pub const MAX_MOVE_BACKFILL_PAGE: u32 = 100;

/// Raw move-cursor layout: `[ created_at i64 BE (8B) | canonical_hash (32B) ]`.
/// 40 bytes total, base64url-encoded to 54 ASCII chars for the `since`
/// URL parameter; the response carries the raw 40 bytes as a `bstr`.
const MOVE_CURSOR_LEN: usize = 8 + 32;

/// Query-string fields for `GET /federation/v1/moves/backfill`.
#[derive(serde::Deserialize)]
pub struct MovesBackfillQuery {
    /// Hex-encoded 32-byte Ed25519 pubkey of the moving identity K.
    /// Required.
    pub key: Option<String>,
    /// Opaque base64url cursor from a prior response. Absent or empty
    /// means "from the chain root."
    pub since: Option<String>,
    /// Max objects to return; capped at [`MAX_MOVE_BACKFILL_PAGE`].
    pub limit: Option<u32>,
}

/// Decoded `(created_at_ms, canonical_hash)` move cursor.
struct MoveCursor {
    created_at_ms: i64,
    canonical_hash: [u8; 32],
}

fn decode_move_cursor(since: &str) -> Option<MoveCursor> {
    let bytes = URL_SAFE_NO_PAD.decode(since.as_bytes()).ok()?;
    if bytes.len() != MOVE_CURSOR_LEN {
        return None;
    }
    let mut ts_be = [0u8; 8];
    ts_be.copy_from_slice(&bytes[..8]);
    let created_at_ms = i64::from_be_bytes(ts_be);
    let mut canonical_hash = [0u8; 32];
    canonical_hash.copy_from_slice(&bytes[8..]);
    Some(MoveCursor {
        created_at_ms,
        canonical_hash,
    })
}

fn encode_move_cursor(created_at_ms: i64, canonical_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MOVE_CURSOR_LEN);
    out.extend_from_slice(&created_at_ms.to_be_bytes());
    out.extend_from_slice(canonical_hash);
    out
}

/// One move chain-walk row in encode-ready form. Distinct from
/// `ChainRow` (which carries an ISO string `created_at` for
/// `trust_edges`) so the two pagination flows do not have to share a
/// timestamp type.
struct MoveChainRow {
    payload: Vec<u8>,
    signature: Vec<u8>,
    created_at_ms: i64,
    canonical_hash: [u8; 32],
}

fn encode_moves_backfill_body(
    objects: &[MoveChainRow],
    next_cursor: Option<Vec<u8>>,
    complete: bool,
) -> Vec<u8> {
    let arr: Vec<Value> = objects
        .iter()
        .map(|row| Value::Bytes(encode_signed_object(&row.payload, &row.signature)))
        .collect();

    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(3);
    entries.push((Value::Text("objects".into()), Value::Array(arr)));
    if let Some(c) = next_cursor {
        entries.push((Value::Text("next_cursor".into()), Value::Bytes(c)));
    }
    entries.push((Value::Text("complete".into()), Value::Bool(complete)));
    let body = Value::Map(entries);
    let mut buf = Vec::with_capacity(
        64 + objects
            .iter()
            .map(|r| r.payload.len() + r.signature.len() + 32)
            .sum::<usize>(),
    );
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    buf
}

/// `GET /federation/v1/moves/backfill` (§12.3).
pub async fn handle_moves_backfill(
    State(state): State<Arc<AppState>>,
    Extension(_envelope): Extension<FedEnvelope>,
    Query(params): Query<MovesBackfillQuery>,
) -> Response {
    let key_hex = match params.key.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return bad_request("malformed"),
    };
    let key_bytes = match decode_hex_pubkey(key_hex) {
        Some(b) => b,
        None => return bad_request("invalid_key"),
    };

    let limit = match params.limit {
        None => MAX_MOVE_BACKFILL_PAGE,
        Some(n) if (1..=MAX_MOVE_BACKFILL_PAGE).contains(&n) => n,
        _ => return bad_request("limit_out_of_range"),
    };

    let cursor = match params.since.as_deref() {
        None | Some("") => None,
        Some(s) => match decode_move_cursor(s) {
            Some(c) => Some(c),
            None => return bad_request("invalid_cursor"),
        },
    };

    // Page-fetch: `limit + 1` rows to detect a next page without a
    // second query. Keyset pagination on
    // `(user_moves.created_at, user_moves.canonical_hash)` —
    // INTEGER + BLOB compares are native SQLite operations and the
    // `idx_user_moves_chain_walk` index covers the ORDER BY.
    let fetch_n = (limit as i64) + 1;
    let key_slice: &[u8] = key_bytes.as_slice();
    let cursor_ts: Option<i64> = cursor.as_ref().map(|c| c.created_at_ms);
    let cursor_hash: Option<Vec<u8>> = cursor.as_ref().map(|c| c.canonical_hash.to_vec());

    let rows = match sqlx::query!(
        "SELECT um.canonical_hash AS \"canonical_hash!: Vec<u8>\", \
                um.created_at AS \"created_at!: i64\", \
                so.payload AS \"payload?: Vec<u8>\", \
                so.signature AS \"signature!: Vec<u8>\" \
         FROM user_moves um \
         JOIN signed_objects so ON so.canonical_hash = um.canonical_hash \
         WHERE um.user_key = ? \
           AND so.payload IS NOT NULL \
           AND ( \
                ? IS NULL \
                OR um.created_at > ? \
                OR (um.created_at = ? AND um.canonical_hash > ?) \
           ) \
         ORDER BY um.created_at ASC, um.canonical_hash ASC \
         LIMIT ?",
        key_slice,
        cursor_ts,
        cursor_ts,
        cursor_ts,
        cursor_hash,
        fetch_n,
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "db error walking move chain in backfill");
            return internal_error();
        }
    };

    // Without a cursor an empty result is the spec's `unknown_chain`
    // condition (this peer has never held a move for K — §12.5
    // retention is indefinite, so "no rows" really means "never seen").
    // Mid-walk an empty result is the natural "you have everything"
    // terminator and returns `complete: true` with no objects.
    if cursor.is_none() && rows.is_empty() {
        return bad_request("unknown_chain");
    }

    let has_more = (rows.len() as i64) > limit as i64;
    let mut page_rows: Vec<MoveChainRow> = Vec::with_capacity(limit as usize);
    for row in rows.into_iter().take(limit as usize) {
        // payload is `Option<Vec<u8>>` because of the schema type but
        // the WHERE clause filtered IS NOT NULL — a None here is a
        // race with a concurrent erasure path that does not exist in
        // any §12 code path; skip silently.
        let Some(payload) = row.payload else {
            continue;
        };
        // §12 moves are 32-byte canonical_hash by schema CHECK. A
        // length mismatch is a corrupted row; silently skipping would
        // strand the requesting peer on every page (cursor never
        // advances past the bad row). Fail loud.
        let canonical_hash: [u8; 32] = match row.canonical_hash.as_slice().try_into() {
            Ok(h) => h,
            Err(_) => {
                tracing::error!(
                    "moves backfill: user_moves row has non-32-byte canonical_hash; \
                     refusing to advance cursor past corrupt row"
                );
                return internal_error();
            }
        };
        page_rows.push(MoveChainRow {
            payload,
            signature: row.signature,
            created_at_ms: row.created_at,
            canonical_hash,
        });
    }

    let next_cursor = if has_more && let Some(last) = page_rows.last() {
        Some(encode_move_cursor(last.created_at_ms, &last.canonical_hash))
    } else {
        None
    };
    let complete = !has_more;

    ok_response(encode_moves_backfill_body(
        &page_rows,
        next_cursor,
        complete,
    ))
}

// ---------------------------------------------------------------------------
// Layer-0 unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip() {
        let ts = "2026-05-25T12:34:56Z";
        let hash = [0xABu8; 32];
        let encoded = encode_cursor(ts, &hash).expect("encode");
        assert_eq!(encoded.len(), CURSOR_LEN);
        let b64 = URL_SAFE_NO_PAD.encode(&encoded);
        let decoded = decode_cursor(&b64).expect("decode");
        assert_eq!(decoded.created_at, ts);
        assert_eq!(decoded.canonical_hash, hash);
    }

    #[test]
    fn cursor_rejects_wrong_length() {
        // 51-byte payload (one short).
        let raw = vec![0u8; CURSOR_LEN - 1];
        let b64 = URL_SAFE_NO_PAD.encode(&raw);
        assert!(decode_cursor(&b64).is_none());

        // 53-byte payload (one long).
        let raw = vec![0u8; CURSOR_LEN + 1];
        let b64 = URL_SAFE_NO_PAD.encode(&raw);
        assert!(decode_cursor(&b64).is_none());
    }

    #[test]
    fn cursor_rejects_garbage_base64() {
        // `!` is not in the base64url alphabet.
        assert!(decode_cursor("!!!not-base64!!!").is_none());
    }

    #[test]
    fn cursor_rejects_non_ascii_timestamp_bytes() {
        let mut raw = vec![0xC3u8; ISO_TIMESTAMP_LEN]; // 0xC3 starts a non-ASCII UTF-8 byte
        raw.extend_from_slice(&[0u8; 32]);
        let b64 = URL_SAFE_NO_PAD.encode(&raw);
        assert!(decode_cursor(&b64).is_none());
    }

    #[test]
    fn cursor_encode_rejects_non_iso_timestamp() {
        // 19-char timestamp (missing the `Z`).
        assert!(encode_cursor("2026-05-25T12:34:56", &[0u8; 32]).is_none());
        // 21-char timestamp.
        assert!(encode_cursor("2026-05-25T12:34:56Zz", &[0u8; 32]).is_none());
    }

    #[test]
    fn hex_pubkey_decode_accepts_lower_and_upper() {
        let lower = "deadbeef".repeat(8);
        let upper = "DEADBEEF".repeat(8);
        assert_eq!(decode_hex_pubkey(&lower), decode_hex_pubkey(&upper));
        assert!(decode_hex_pubkey(&lower).is_some());
    }

    #[test]
    fn hex_pubkey_rejects_wrong_length() {
        assert!(decode_hex_pubkey("deadbeef").is_none()); // 8 chars
        assert!(decode_hex_pubkey(&"de".repeat(33)).is_none()); // 66 chars
    }

    #[test]
    fn hex_pubkey_rejects_non_hex() {
        let bad = format!("{}gh", "de".repeat(31));
        assert!(decode_hex_pubkey(&bad).is_none());
    }

    #[test]
    fn encode_body_omits_next_cursor_on_complete() {
        let body = encode_backfill_body(&[], None, true);
        let v: Value = ciborium::de::from_reader(body.as_slice()).unwrap();
        let Value::Map(m) = v else {
            panic!("not a map");
        };
        let keys: Vec<String> = m
            .iter()
            .filter_map(|(k, _)| {
                if let Value::Text(t) = k {
                    Some(t.clone())
                } else {
                    None
                }
            })
            .collect();
        assert!(keys.contains(&"objects".into()));
        assert!(keys.contains(&"complete".into()));
        assert!(!keys.contains(&"next_cursor".into()));
    }

    #[test]
    fn move_cursor_round_trip() {
        let ts: i64 = 1_700_000_000_123;
        let hash = [0xCDu8; 32];
        let encoded = encode_move_cursor(ts, &hash);
        assert_eq!(encoded.len(), MOVE_CURSOR_LEN);
        let b64 = URL_SAFE_NO_PAD.encode(&encoded);
        let decoded = decode_move_cursor(&b64).expect("decode");
        assert_eq!(decoded.created_at_ms, ts);
        assert_eq!(decoded.canonical_hash, hash);
    }

    #[test]
    fn move_cursor_rejects_wrong_length() {
        let raw = vec![0u8; MOVE_CURSOR_LEN - 1];
        let b64 = URL_SAFE_NO_PAD.encode(&raw);
        assert!(decode_move_cursor(&b64).is_none());

        let raw = vec![0u8; MOVE_CURSOR_LEN + 1];
        let b64 = URL_SAFE_NO_PAD.encode(&raw);
        assert!(decode_move_cursor(&b64).is_none());
    }

    #[test]
    fn move_cursor_fits_in_protocol_budget() {
        // §10.5.2 caps cursor at 64 bytes.
        const { assert!(MOVE_CURSOR_LEN <= 64) };
    }

    #[test]
    fn encode_body_includes_next_cursor_when_incomplete() {
        let cursor_bytes = vec![0xAAu8; CURSOR_LEN];
        let body = encode_backfill_body(&[], Some(cursor_bytes.clone()), false);
        let v: Value = ciborium::de::from_reader(body.as_slice()).unwrap();
        let Value::Map(m) = v else {
            panic!("not a map");
        };
        let got_cursor = m.iter().find_map(|(k, v)| match (k, v) {
            (Value::Text(t), Value::Bytes(b)) if t == "next_cursor" => Some(b.clone()),
            _ => None,
        });
        assert_eq!(got_cursor, Some(cursor_bytes));
    }
}
