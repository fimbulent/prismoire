//! Autonomous outbound `GET /federation/v1/edges/backfill` issuer
//! (§9.3 chain-continuity recovery), the active half of the Phase 9.8
//! deferred-orphan buffer.
//!
//! ## Where this fits in
//!
//! `edges.rs::apply_one_edge` enqueues an orphan into
//! `pending_trust_edges` and — *only* on the first orphan for a given
//! `(source_pubkey, prior_edge_hash)` gap — sets a flag that fires
//! [`request_edge_predecessor`] on a `tokio::spawn` after the receive
//! transaction commits. The dedup is keyed on the pending row's
//! primary key, so siblings / re-pushes for the same gap collapse to
//! one outbound request — exactly the §9.6 `MAX_BACKFILL_RATE` budget
//! the spec calls for.
//!
//! ## Behaviour
//!
//! 1. Resolve the source pubkey's currently-authoritative home via
//!    `user_homes`-backed [`crate::federation::remote_users::resolve_current_home`];
//!    a chain-grounded home is preferred over the envelope sender so
//!    a relayed orphan triggers a backfill aimed at the actual origin
//!    rather than the (possibly distant) forwarder. Falls back to
//!    `users.home_instance` for the stub if `user_homes` has no row
//!    yet (very common — moves are rare and the stub already carries
//!    the registration home from §16.1).
//! 2. Compute a `since` cursor from the local chain tip if any rows
//!    for the `(source, target)` pair have already projected — that
//!    way we ask only for the bytes between our tip and the orphan,
//!    not the whole chain. If no chain rows exist yet we ask from the
//!    root (omit `since`).
//! 3. Sign and dispatch one `GET /federation/v1/edges/backfill` via
//!    the configured [`FederationTransport`]. The receiver's per-peer
//!    rate limit caps cascades, so a "issue one request, decode, feed
//!    back into apply_one_edge" loop would be both unnecessary and a
//!    politeness violation. Phase 9.8 takes the simpler best-effort
//!    posture instead: one page, log on partial result, and rely on
//!    the next push from the sender (or the next §9.6 sweep cycle) to
//!    retrigger if the chain is still incomplete after this drain.
//! 4. Decode the `{ objects: [WireFormat...], next_cursor?, complete }`
//!    response body. Feed each WireFormat through
//!    [`crate::federation::edges::apply_one_edge`] in array order
//!    (oldest-first per §10.5.2). The receive path itself drains the
//!    pending buffer via `drain_pending_orphans_after` on each
//!    `Projected` outcome, so the orphan that triggered this request
//!    promotes naturally as soon as its predecessor lands.
//!
//! ## Failure handling
//!
//! Every transport / wire-format / status failure surfaces as
//! [`BackfillError`] and gets logged at `warn!` by the spawn block in
//! `edges.rs`. The buffered orphan stays in `pending_trust_edges`
//! either way: a transient failure here is recoverable on the next
//! push or §9.3 retry from the sender's side. The TTL sweep
//! (`evict_expired_pending_trust_edges`) is the ultimate backstop —
//! anything still pending after `DEFERRED_ORPHAN_TTL` (1h) gets
//! evicted and becomes the sender's problem.

use std::sync::Arc;

use axum::body::Bytes;
use ciborium::value::Value;
use http::{Method, Request, StatusCode, header};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::AppState;
use crate::federation::envelope::{AUTH_HEADER, sign_outbound};
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::transport::{PeerId, TransportError};
use crate::users::hex_lower;

/// Cap on concurrent autonomous §9.3 backfill requests this instance
/// has in flight. Keeps a stream of fresh orphans (e.g. a peer
/// re-pushing a long chain from the tail) from spawning hundreds of
/// outbound `GET /edges/backfill` tasks. The buffered orphan stays in
/// `pending_trust_edges` when we decline to fire, so the next live
/// push or §9.6 sweep tick is the recovery path.
const OUTBOUND_BACKFILL_CONCURRENCY: usize = 8;

/// Per-instance gate for outbound §9.3 backfill spawns. Held on
/// [`AppState`] rather than a module `static` so the cap is per-instance —
/// identical to a process-global in production (one instance per process)
/// while keeping the multiple in-process `AppState`s of the federation test
/// harness from sharing one budget. See [`OutboundBackfillPermits::try_acquire`]
/// for the acquire-or-skip contract.
pub struct OutboundBackfillPermits(Arc<Semaphore>);

impl Default for OutboundBackfillPermits {
    fn default() -> Self {
        Self(Arc::new(Semaphore::new(OUTBOUND_BACKFILL_CONCURRENCY)))
    }
}

impl OutboundBackfillPermits {
    /// Try to claim a permit for an outbound §9.3 backfill spawn. Returns
    /// `None` when the cap is currently saturated — caller logs and skips
    /// the spawn; the buffered orphan retries on the next push or §9.6
    /// sweep. The permit must be held for the lifetime of the spawned
    /// task so the count decreases when the request finishes.
    pub(crate) fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        match self.0.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(TryAcquireError::NoPermits) => None,
            Err(TryAcquireError::Closed) => None,
        }
    }
}

/// Failure modes surfaced by [`request_edge_predecessor`]. Coarse on
/// purpose: the caller logs and moves on; the buffered orphan is the
/// retry state.
#[derive(Debug)]
pub enum BackfillError {
    /// Reading `users.home_instance` / `user_homes` failed at the DB
    /// layer. Distinct from "no home on file" (handled inline as a
    /// no-op below).
    Db(sqlx::Error),
    /// Source key has no resolvable home: not in `user_homes` and the
    /// `users` stub carries `home_instance IS NULL`. We have no peer
    /// to ask. Buffered orphan stays put; expect re-push or TTL
    /// eviction.
    NoHome,
    /// Outbound transport refused the dispatch (unknown peer, blocked
    /// target, dispatch error). Verbatim [`TransportError`] for log
    /// fidelity.
    Transport(TransportError),
    /// Peer returned a non-2xx status. Carries the status; body
    /// content is intentionally not surfaced (the response is
    /// CBOR-framed and useful only inside the success path).
    UnexpectedStatus(StatusCode),
    /// Response body failed CBOR decode, or carried a
    /// structurally-invalid `{ objects, next_cursor?, complete }`
    /// shape.
    BadResponseBody,
}

impl std::fmt::Display for BackfillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackfillError::Db(e) => write!(f, "db error: {e}"),
            BackfillError::NoHome => write!(f, "no resolvable home for source key"),
            BackfillError::Transport(e) => write!(f, "transport: {e}"),
            BackfillError::UnexpectedStatus(s) => write!(f, "unexpected status: {s}"),
            BackfillError::BadResponseBody => write!(f, "malformed backfill response"),
        }
    }
}

impl std::error::Error for BackfillError {}

impl From<sqlx::Error> for BackfillError {
    fn from(value: sqlx::Error) -> Self {
        BackfillError::Db(value)
    }
}

/// Issue one §9.3 `GET /edges/backfill` against `source`'s current
/// home asking for the chain segment after our local tip for the
/// `(source, target)` pair. Re-feeds returned WireFormats through the
/// §9.1 receive path — `apply_one_edge` drains the pending buffer on
/// each successful projection, so an orphan whose predecessor lands
/// in this response promotes during the same call.
pub async fn request_edge_predecessor(
    state: Arc<AppState>,
    source: [u8; 32],
    target: [u8; 32],
    prior: [u8; 32],
) -> Result<(), BackfillError> {
    // Step 1: resolve source's home. Prefer `user_homes` (chain-
    // grounded — covers moves), fall back to `users.home_instance`
    // for the stub (the §16.1 registration home stamped at hydrate
    // time).
    let home = match resolve_source_home(&state.db, &source).await? {
        Some(h) => h,
        None => {
            tracing::debug!(
                source = %hex_lower(&source),
                "no home on file for orphan source; skipping autonomous backfill",
            );
            return Err(BackfillError::NoHome);
        }
    };

    // Step 2: ask from the chain root. We deliberately do NOT pass a
    // `since` cursor here, even when the local pair has projected
    // rows. The receiver's `since` semantics is "edges *after* this
    // cursor by `(created_at, canonical_hash)`", but our gap is in
    // the *past*: we received E5..EN but are missing E2. If we asked
    // "since the tip of E5..EN", the response would be empty — the
    // peer has nothing newer than our tip, only older. We don't have
    // `prior`'s timestamp to mint a cursor for it (only its hash),
    // so the safest correct choice is to ask from the root and rely
    // on the per-edge dedup in `apply_one_edge_inner` (`Duplicate`
    // for bytes already in `signed_objects`) to collapse the rows we
    // already have. Bandwidth cost is the chain length; correctness
    // is restored — the missing predecessor is in the response.
    let source_hex = hex_lower(&source);
    let target_hex = hex_lower(&target);
    let path = format!("/federation/v1/edges/backfill?source={source_hex}&target={target_hex}");

    // §6.5 step 9 signs over the path without the query string, but
    // the receiver's `Query` extractor needs the query on the URI.
    // Mirror the harness `send_envelope_signed_split` discipline:
    // sign over the bare path, dispatch against the full URI.
    let signed_path = match path.split_once('?') {
        Some((p, _)) => p,
        None => path.as_str(),
    };

    let header_value = sign_outbound(&state.instance_key, home, &Method::GET, signed_path, b"");
    let request = Request::builder()
        .method(Method::GET)
        .uri(&path)
        .header(AUTH_HEADER, header_value)
        .header(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
        .body(Bytes::new())
        .expect("request builder");

    let response = state
        .federation_transport
        .request(&PeerId::from_bytes(home), request)
        .await
        .map_err(BackfillError::Transport)?;
    let status = response.status();
    if !status.is_success() {
        return Err(BackfillError::UnexpectedStatus(status));
    }

    // Step 4: decode and re-feed.
    let body = response.into_body();
    let (objects, next_cursor, complete) =
        decode_backfill_body(&body).ok_or(BackfillError::BadResponseBody)?;

    if !objects.is_empty() {
        tracing::debug!(
            source = %hex_lower(&source),
            target = %hex_lower(&target),
            prior = %hex_lower(&prior),
            count = objects.len(),
            complete,
            "feeding §9.3 backfill response into §9.1 receive path",
        );
    }

    for wire_bytes in &objects {
        // Re-feed through the same per-edge state machine the live
        // push uses. `arrived_from = home` is the right §7.5 hint —
        // we just talked to that peer, no point forwarding back to
        // them. The receive-path projection of the predecessor calls
        // `drain_pending_orphans_after`, which promotes the orphan
        // we originally enqueued.
        //
        // Suppress recursive backfill on the re-feed path: if a
        // re-fed edge itself Defers (orphan of orphan), we DON'T
        // chain another `request_edge_predecessor` from here. Phase
        // 9.8 takes the best-effort posture (`§9.6 MAX_BACKFILL_RATE`)
        // — the next live push of the deeper edge, or the §9.6 sweep
        // tick, will retrigger.
        if let Err(e) = super::edges::apply_one_edge_inner(&state, wire_bytes, home).await {
            tracing::warn!(
                source = %hex_lower(&source),
                target = %hex_lower(&target),
                error = %e,
                "db error feeding backfill response into apply_one_edge; aborting drain",
            );
            return Err(BackfillError::Db(e));
        }
    }

    // Wake the trust-graph rebuild loop if this drain fed any edges. This
    // worker runs spawned-and-detached, long after `handle_edges_push`
    // fired its one-per-batch notify, so the predecessor edges promoted
    // here (via `drain_pending_orphans_after` inside `apply_one_edge_inner`)
    // land with no outstanding wake. `rebuild_loop` has no free-running
    // timer, so without this the backfilled chain stays invisible to
    // readers until unrelated mutation traffic wakes the loop.
    if !objects.is_empty() {
        state.trust_graph_notify.notify_one();
    }

    // §10.5.2 `complete: false` means the receiver paginated the
    // response. Phase 9.8 stops at the first page deliberately —
    // chasing the next page from here would put us in an unbounded
    // recursive role the §9.6 spec budget didn't allocate. If the
    // chain still has gaps after this drain, the orphan stays in
    // `pending_trust_edges` and the next live push (or §9.6 sweep
    // tick) retriggers a fresh full-chain request.
    if !complete && next_cursor.is_some() {
        tracing::debug!(
            source = %hex_lower(&source),
            target = %hex_lower(&target),
            "§9.3 backfill returned incomplete chain; stopping at first page",
        );
    }

    Ok(())
}

/// Resolve `source_key` to its currently-authoritative home, or
/// `None` if no home is known.
///
/// Consults `user_homes` first (the §12.4 latest-wins move
/// projection); falls back to `users.home_instance` for the stub
/// when no move chain exists. NULL `home_instance` is a *local*
/// user — an orphan whose source is local is local corruption (a
/// local-authored edge wouldn't have arrived over the federation
/// receive path), so we return `None` and let the caller log it.
async fn resolve_source_home(
    db: &sqlx::SqlitePool,
    source_key: &[u8; 32],
) -> Result<Option<[u8; 32]>, sqlx::Error> {
    let key_slice: &[u8] = source_key.as_slice();

    if let Some(row) = sqlx::query!(
        "SELECT current_home_key AS \"current_home_key!: Vec<u8>\" \
           FROM user_homes WHERE user_key = ?",
        key_slice,
    )
    .fetch_optional(db)
    .await?
    {
        if row.current_home_key.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&row.current_home_key);
            return Ok(Some(out));
        }
        tracing::error!(
            source = %hex_lower(source_key),
            "user_homes.current_home_key has unexpected length",
        );
    }

    let stub = sqlx::query!(
        "SELECT home_instance AS \"home_instance?: Vec<u8>\" \
           FROM users WHERE public_key = ?",
        key_slice,
    )
    .fetch_optional(db)
    .await?;

    let Some(row) = stub else {
        return Ok(None);
    };
    let Some(home_bytes) = row.home_instance else {
        return Ok(None);
    };
    if home_bytes.len() != 32 {
        tracing::error!(
            source = %hex_lower(source_key),
            "users.home_instance has unexpected length",
        );
        return Ok(None);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&home_bytes);
    Ok(Some(out))
}

/// Decode the `{ "objects": [bstr...], "next_cursor"?: bstr,
/// "complete": bool }` shape that `handle_edges_backfill` returns.
/// Returns `None` on any structural deviation — the caller logs and
/// leaves the orphan in the pending buffer for the next retry.
///
/// `pub(crate)` so the §13.3 step-4 prior-home data-recovery flow in
/// [`crate::federation::prior_home_recovery`] can reuse it for the
/// §14.5 / §14.6 page responses, which carry the same §10.5.2
/// envelope as `/edges/backfill`.
#[allow(clippy::type_complexity)]
pub(crate) fn decode_backfill_body(body: &[u8]) -> Option<(Vec<Vec<u8>>, Option<Vec<u8>>, bool)> {
    let value: Value = ciborium::de::from_reader(body).ok()?;
    let Value::Map(entries) = value else {
        return None;
    };
    let mut objects: Option<Vec<Vec<u8>>> = None;
    let mut next_cursor: Option<Vec<u8>> = None;
    let mut complete: Option<bool> = None;
    for (k, v) in entries {
        let Value::Text(key) = k else { continue };
        match key.as_str() {
            "objects" => {
                let Value::Array(arr) = v else {
                    return None;
                };
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    let Value::Bytes(b) = item else {
                        return None;
                    };
                    out.push(b);
                }
                objects = Some(out);
            }
            "next_cursor" => {
                let Value::Bytes(b) = v else {
                    return None;
                };
                next_cursor = Some(b);
            }
            "complete" => {
                let Value::Bool(b) = v else {
                    return None;
                };
                complete = Some(b);
            }
            _ => {}
        }
    }
    Some((objects?, next_cursor, complete?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_backfill_body_round_trip() {
        let body = Value::Map(vec![
            (
                Value::Text("objects".into()),
                Value::Array(vec![Value::Bytes(vec![1, 2, 3]), Value::Bytes(vec![4, 5])]),
            ),
            (Value::Text("complete".into()), Value::Bool(true)),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let (objects, next_cursor, complete) = decode_backfill_body(&buf).expect("decode");
        assert_eq!(objects, vec![vec![1, 2, 3], vec![4, 5]]);
        assert!(next_cursor.is_none());
        assert!(complete);
    }

    #[test]
    fn decode_backfill_body_rejects_non_bstr_object() {
        let body = Value::Map(vec![
            (
                Value::Text("objects".into()),
                Value::Array(vec![Value::Text("not a bstr".into())]),
            ),
            (Value::Text("complete".into()), Value::Bool(true)),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        assert!(decode_backfill_body(&buf).is_none());
    }

    #[test]
    fn decode_backfill_body_carries_next_cursor() {
        let body = Value::Map(vec![
            (Value::Text("objects".into()), Value::Array(vec![])),
            (
                Value::Text("next_cursor".into()),
                Value::Bytes(vec![9, 9, 9]),
            ),
            (Value::Text("complete".into()), Value::Bool(false)),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&body, &mut buf).unwrap();
        let (_, next_cursor, complete) = decode_backfill_body(&buf).expect("decode");
        assert_eq!(next_cursor, Some(vec![9, 9, 9]));
        assert!(!complete);
    }
}
