//! §13.3 step-4 data-recovery flow (`docs/federation-protocol.md`
//! §14.5 / §14.6 + §14.7 fallback).
//!
//! After cross-instance registration on D for key K commits, the
//! destination tries to backfill K's prior signed activity:
//!
//! 1. **Primary path** — when [`discover_prior_home`] surfaced a
//!    confirmed peer A, page through `/federation/v1/prior-home/
//!    content-by-key` (§14.5) and `/federation/v1/prior-home/
//!    inbound-edges-by-key` (§14.6) against A. Each page rides the
//!    §14.1 challenge/response surface — a single challenge is
//!    cached across pages within `PRIOR_HOME_CHALLENGE_TTL`, but
//!    every page carries a freshly-signed §5.7 response per the
//!    §14.5 / §14.6 spec ("response per page").
//! 2. **Fallback path** — when the primary either wasn't attempted
//!    (no confirmed peer) or didn't reach `complete: true` on both
//!    surfaces, sweep D's own active peers via the §10.5.1
//!    `/backfill/by-author` (K-authored content) and `/backfill/
//!    edges-by-key?direction=both` (any edge touching K) routes.
//!    These rides the standard peer-to-peer envelope; no §14.1
//!    challenge is required because the receiving peer is already
//!    in D's `peers` table as `status = 'active'`.
//!
//! [`discover_prior_home`]: super::registration::discover_prior_home
//!
//! ## Best-effort posture (§14.7)
//!
//! Neither path is a gate on registration. `drive_recovery` is
//! invoked via `tokio::spawn` after the registration transaction
//! commits — failure here surfaces only in tracing telemetry
//! (`recovery: best_effort_incomplete`) and the local user's
//! `signed_objects` set is **purely additive**. Whatever we already
//! held for K (e.g. from prior gossip) stays.
//!
//! ## Page caps
//!
//! Each surface is bounded by [`MAX_RECOVERY_PAGES`] (sequential
//! pagination, default 64). A peer feeding us a buggy `next_cursor`
//! cannot loop the recovery worker forever. Per-page `limit` is
//! omitted on the wire so each peer's `MAX_BACKFILL_PAGE` default
//! applies (currently 100 per Phase 8).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, Request, StatusCode, header};

use crate::AppState;
use crate::federation::content::{ContentResult, ContentStatus, apply_one_object};
use crate::federation::edge_backfill::decode_backfill_body;
use crate::federation::edges::apply_one_edge_inner;
use crate::federation::envelope::{AUTH_HEADER, decode_signed_object, sign_outbound};
use crate::federation::identity::CBOR_CONTENT_TYPE;
use crate::federation::prior_home_client::{
    CHALLENGE_PATH, ProbeError, encode_challenge_request, mint_response, parse_challenge_response,
    signed_post,
};
use crate::federation::transport::{PeerId, TransportError};
use crate::signed::SignedPayload;
use crate::users::hex_lower;

/// Hard ceiling on pages fetched per surface before bailing. Bounds
/// runaway from a peer minting an infinite cursor stream. 64 pages
/// × `MAX_BACKFILL_PAGE` (100) is enough headroom for any realistic
/// account history while keeping wall-clock cost bounded.
const MAX_RECOVERY_PAGES: usize = 64;

/// Hard ceiling on peers swept by the §10.5.1 fallback layer per
/// recovery run. Symmetric with `PRIOR_HOME_PROBE_FANOUT_MAX` (16) so
/// the two layers' outbound amplification stays in the same order of
/// magnitude — a single registration can fan out to at most 16 peers
/// in discovery and 16 in fallback. Peer rows are visited in
/// recently-active order (same `ORDER BY` as the discovery fan-out),
/// so the bound clips the long tail of stale-but-active peers, not
/// the live core.
const MAX_FALLBACK_PEERS: usize = 16;

/// §10.5.5 `BACKFILL_CONCURRENT_PER_PEER`. Max concurrent outbound
/// §10.5.1 backfill pagination streams to a *single* destination peer.
/// [`proactive_backfill_batch`] runs up to
/// [`PROACTIVE_BACKFILL_BATCH_CONCURRENCY`] authors at once; if several of
/// them home on the same peer, an uncapped fanout opens that many
/// simultaneous `/backfill/by-author` streams to it and trips the peer's
/// own `BACKFILL_RPM_PER_PEER` / `BACKFILL_BYTES_PER_MIN_PER_PEER` budget —
/// which 429s us off the *only* peer that hosts the author. Gating per
/// destination peer keeps a single peer's inbound view of us within the
/// same per-peer budget it would apply, so backfill makes forward progress
/// instead of self-throttling.
const BACKFILL_CONCURRENT_PER_PEER: usize = 4;

/// Total number of `429 Too Many Requests` responses
/// [`paginate_peer_backfill`] will absorb (honoring `Retry-After`) before
/// abandoning a peer. Cumulative across the whole pagination, not
/// per-page: a peer that 429s every page would otherwise pin the worker
/// for `MAX_RECOVERY_PAGES * MAX_RETRY_AFTER_SECS`. Bounding the *total*
/// caps the added wall-clock at `THROTTLE_MAX_RETRIES * MAX_RETRY_AFTER_SECS`
/// (~5 min) per surface; a backfill too large to finish within that budget
/// simply resumes on the next §7.6 retrigger (best-effort, off the
/// critical path).
const THROTTLE_MAX_RETRIES: u32 = 5;

/// Clamp ceiling for a peer-supplied `Retry-After` (seconds). Our own
/// limiters always emit `60`; this clamp bounds a peer that returns an
/// absurd value so it can't park the worker arbitrarily long. A missing
/// or unparseable header defaults to this same value.
const MAX_RETRY_AFTER_SECS: u64 = 60;

/// Per-destination-peer concurrency gate for §10.5.1 backfill pagination,
/// keyed by peer pubkey, each a [`BACKFILL_CONCURRENT_PER_PEER`]-permit
/// semaphore. Process-wide so every backfill call site (the frontier batch
/// and the §13.3 registration fallback) shares one budget per peer. The
/// map grows bounded-by-peer-count (operator-gated); entries are never
/// reclaimed, which is fine at peer-set scale.
static PER_PEER_BACKFILL_SEMAPHORES: LazyLock<
    Mutex<HashMap<[u8; 32], Arc<tokio::sync::Semaphore>>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Fetch (or lazily create) the [`BACKFILL_CONCURRENT_PER_PEER`]-permit
/// semaphore gating outbound backfill pagination to `peer`.
fn per_peer_backfill_semaphore(peer: [u8; 32]) -> Arc<tokio::sync::Semaphore> {
    PER_PEER_BACKFILL_SEMAPHORES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(peer)
        .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(BACKFILL_CONCURRENT_PER_PEER)))
        .clone()
}

/// Parse a `Retry-After` header as delta-seconds. Returns `None` for an
/// absent, non-ASCII, or non-integer value (incl. the rarely-used
/// HTTP-date form, which our peers never emit) so the caller can fall back
/// to a default. Not clamped here — the caller clamps to
/// [`MAX_RETRY_AFTER_SECS`].
fn retry_after_secs(response: &http::Response<Bytes>) -> Option<u64> {
    response
        .headers()
        .get(header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Max concurrent by-author backfills driven by
/// [`proactive_backfill_batch`]. Matches `OUTBOUND_BACKFILL_CONCURRENCY`
/// (8) in `edge_backfill.rs`, so the frontier Trigger-3 batch and the
/// §11.9.5 reverse-bootstrap edge path stay in the same order-of-magnitude
/// outbound budget instead of the unbounded per-author `tokio::spawn`
/// fanout this batch replaced (one task per newly-frontier'd author, each
/// able to sweep up to `MAX_FALLBACK_PEERS`).
const PROACTIVE_BACKFILL_BATCH_CONCURRENCY: usize = 8;

/// §10.5.5 single-peer-per-author rule, enforced process-wide: at most one
/// outstanding by-author proactive backfill per `author_key` across *all*
/// call sites. Both the frontier Trigger-3 batch and the §11.9.5
/// reverse-bootstrap edge path funnel through [`proactive_author_backfill`],
/// so without a shared claim a trust edge arriving for K at the same moment
/// K enters the content frontier would fire two concurrent by-author sweeps
/// for the same key, doubling outbound load and racing the same stub
/// hydration. Keyed by author pubkey; entries are held only for the
/// lifetime of an in-flight backfill via [`AuthorInFlightGuard`].
static IN_FLIGHT_AUTHORS: LazyLock<Mutex<HashSet<[u8; 32]>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// RAII claim on an `author_key` in [`IN_FLIGHT_AUTHORS`]. Construction via
/// [`AuthorInFlightGuard::try_claim`] returns `None` when the key is already
/// claimed (the §10.5.5 skip case); the claim is released on `Drop`, so an
/// early return — or a panic — in the backfill body cannot leak a permanent
/// claim that would wedge the author out of all future backfills.
struct AuthorInFlightGuard([u8; 32]);

impl AuthorInFlightGuard {
    /// Claim `author_key`, or `None` if a backfill for it is already in
    /// flight anywhere in the process.
    fn try_claim(author_key: [u8; 32]) -> Option<Self> {
        let mut set = IN_FLIGHT_AUTHORS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        set.insert(author_key).then_some(Self(author_key))
    }
}

impl Drop for AuthorInFlightGuard {
    fn drop(&mut self) {
        IN_FLIGHT_AUTHORS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.0);
    }
}

/// `POST /federation/v1/prior-home/content-by-key` (§14.5).
const CONTENT_BY_KEY_PATH: &str = "/federation/v1/prior-home/content-by-key";

/// `POST /federation/v1/prior-home/inbound-edges-by-key` (§14.6).
const INBOUND_EDGES_BY_KEY_PATH: &str = "/federation/v1/prior-home/inbound-edges-by-key";

/// Per-surface telemetry counters. Folded into the final
/// `recovery: best_effort_incomplete | ok` log line so an operator
/// triaging a registration can see which surface contributed what.
#[derive(Debug, Default, Clone, Copy)]
struct SurfaceStats {
    /// Pages successfully fetched (200 OK + decodable body).
    pages_fetched: usize,
    /// Objects ingested through the appropriate §10.1 / §9.1 path
    /// (counted as bytes presented to the per-row state machine —
    /// duplicates / deferred / rejected all still count, since the
    /// recovery flow's success metric is "we got the bytes here",
    /// not "the bytes projected cleanly").
    objects_seen: usize,
    /// `true` iff the surface reached `complete: true` within the
    /// page cap.
    complete: bool,
}

/// Aggregate of primary + fallback. Returned by [`drive_recovery`]
/// so an integration test or telemetry hook can introspect what
/// happened without scraping logs.
#[derive(Debug, Default, Clone, Copy)]
pub struct RecoveryStats {
    /// `true` iff a primary-path attempt was made at all (i.e.
    /// `confirmed_peer` was `Some`).
    pub primary_attempted: bool,
    /// `true` iff the primary path reached `complete: true` on both
    /// §14.5 *and* §14.6.
    pub primary_complete: bool,
    /// `true` iff the fallback path ran (always runs unless the
    /// primary path completed both surfaces).
    pub fallback_attempted: bool,
    /// `true` iff every fallback peer attempted reached
    /// `complete: true` on both §10.5.1 routes — a strong floor
    /// guaranteeing we exhausted what the peer network exposes.
    /// Note that this is `false` when D has zero active peers (we
    /// couldn't actually sweep anything, so reporting "complete" would
    /// be misleading to operators triaging an incomplete recovery).
    /// Pair this flag with the peer-count log field to distinguish
    /// "swept N peers, all hit `complete: true`" from "swept zero
    /// peers because D has no active peering".
    pub fallback_complete: bool,
    /// Total signed objects fed back into receive paths across both
    /// surfaces and both layers. Diagnostic only — duplicates and
    /// rejects count.
    pub objects_seen: usize,
}

impl RecoveryStats {
    /// Per §14.7 the recovery is "best-effort": partial success is
    /// success. We log `best_effort_incomplete` iff neither the
    /// primary nor the fallback fully completed on the surfaces
    /// they attempted.
    fn is_incomplete(&self) -> bool {
        let primary_ok = self.primary_attempted && self.primary_complete;
        let fallback_ok = self.fallback_attempted && self.fallback_complete;
        !(primary_ok || fallback_ok)
    }
}

/// Failure modes for one §14.5 / §14.6 page fetch. Coarse on
/// purpose: a single page failure aborts pagination on *that*
/// surface but leaves the other surface and the fallback layer
/// free to run. Logged at `debug`/`info` so a normally-offline A
/// doesn't spam `warn`.
#[derive(Debug)]
enum PageError {
    Transport(TransportError),
    Status(StatusCode),
    Decode(&'static str),
}

impl std::fmt::Display for PageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Status(s) => write!(f, "status: {s}"),
            Self::Decode(w) => write!(f, "decode: {w}"),
        }
    }
}

/// `ProbeError` collapses cleanly to the same coarse buckets we
/// use for §14.5 / §14.6 pagination, so a §14.1 challenge mint
/// that fails surfaces as the same `PageError`.
impl From<ProbeError> for PageError {
    fn from(e: ProbeError) -> Self {
        match e {
            ProbeError::Transport(t) => Self::Transport(t),
            ProbeError::Status(s) => Self::Status(s),
            ProbeError::Decode(w) => Self::Decode(w),
        }
    }
}

/// Encode a §14.5 / §14.6 page request body:
/// `{ challenge, response, since?, limit? }`. `limit` is always
/// omitted here — we let the receiver apply its default page size.
fn encode_bulk_fetch_body(
    challenge_wire: &[u8],
    response_wire: &[u8],
    since: Option<&[u8]>,
) -> Vec<u8> {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(3);
    entries.push((
        Value::Text("challenge".into()),
        Value::Bytes(challenge_wire.to_vec()),
    ));
    entries.push((
        Value::Text("response".into()),
        Value::Bytes(response_wire.to_vec()),
    ));
    if let Some(s) = since {
        entries.push((Value::Text("since".into()), Value::Bytes(s.to_vec())));
    }
    let body = Value::Map(entries);
    let mut buf = Vec::with_capacity(challenge_wire.len() + response_wire.len() + 32);
    ciborium::ser::into_writer(&body, &mut buf).expect("ciborium ser is infallible");
    buf
}

/// Drive the §14.1 step-1 mint against `peer` for `subject_key` and
/// return `(challenge_wire, challenge_payload)`. The payload is the
/// inner WireFormat (peeled), which is what `mint_response` needs to
/// SHA-256 into `challenge_hash`. We cache both so subsequent pages
/// reuse the same `challenge` field on the wire (per §14.5 prose:
/// "MAY be reused across pages within `PRIOR_HOME_CHALLENGE_TTL`").
async fn mint_challenge(
    state: &Arc<AppState>,
    peer: &PeerId,
    subject_key: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), PageError> {
    let (status, body) = signed_post(
        state,
        peer,
        CHALLENGE_PATH,
        encode_challenge_request(subject_key),
    )
    .await?;
    if !status.is_success() {
        return Err(PageError::Status(status));
    }
    let challenge_wire = parse_challenge_response(&body)
        .ok_or(PageError::Decode("challenge response missing `challenge`"))?;
    let (challenge_payload, _) = decode_signed_object(&challenge_wire)
        .ok_or(PageError::Decode("challenge wire is not a SignedObject"))?;
    Ok((challenge_wire, challenge_payload))
}

/// Page-fetch one bulk surface (§14.5 or §14.6) until `complete: true`
/// or the page cap is hit. Each call to `ingest` is the per-row hook —
/// it gets the raw WireFormat bytes for one object and applies them
/// to whichever receive path (§10.1 for content, §9.1 for edges) the
/// surface owns.
async fn paginate_bulk_surface<F, Fut>(
    state: &Arc<AppState>,
    peer: &PeerId,
    path: &'static str,
    subject_key: &[u8; 32],
    signing_key: &SigningKey,
    mut ingest: F,
) -> Result<SurfaceStats, PageError>
where
    F: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (challenge_wire, challenge_payload) = mint_challenge(state, peer, subject_key).await?;

    let mut stats = SurfaceStats::default();
    let mut cursor: Option<Vec<u8>> = None;
    for _ in 0..MAX_RECOVERY_PAGES {
        // Fresh §5.7 response per page so `created_at` stays inside
        // MAX_FEDERATION_CLOCK_SKEW — see §14.5 prose.
        let response_wire = mint_response(signing_key, subject_key, &challenge_payload);
        let body = encode_bulk_fetch_body(&challenge_wire, &response_wire, cursor.as_deref());

        let (status, raw) = signed_post(state, peer, path, body).await?;
        if !status.is_success() {
            return Err(PageError::Status(status));
        }
        stats.pages_fetched += 1;

        let (objects, next_cursor, complete) =
            decode_backfill_body(&raw).ok_or(PageError::Decode("malformed §10.5.2 envelope"))?;

        for wire in objects {
            stats.objects_seen += 1;
            ingest(wire).await;
        }

        if complete {
            stats.complete = true;
            return Ok(stats);
        }
        // `complete: false` without a cursor would be a server-side
        // §10.5.2 contract violation — bail rather than loop.
        let Some(next) = next_cursor else {
            return Err(PageError::Decode(
                "page reported !complete but omitted next_cursor",
            ));
        };
        cursor = Some(next);
    }
    // Hit the page cap. Treat as "this surface didn't finish" but
    // keep the partial fetch — the recovery contract is additive.
    Ok(stats)
}

/// Primary-path recovery: §14.5 + §14.6 against the confirmed prior
/// home. Each surface's pagination is independent — a §14.5 failure
/// doesn't abort §14.6. Returns the per-surface stats so the caller
/// can decide whether to run the fallback layer.
async fn recover_via_prior_home(
    state: &Arc<AppState>,
    subject_key: &[u8; 32],
    signing_key: &SigningKey,
    peer_key: [u8; 32],
    peer_domain: &str,
) -> (SurfaceStats, SurfaceStats) {
    let peer_id = PeerId::from_bytes(peer_key);

    // Hit content-by-key first. The content receive path doesn't
    // depend on edges, and content is typically the larger volume
    // — failing fast here gives a cleaner "first attempt result"
    // signal for the operator.
    let content_stats = match paginate_bulk_surface(
        state,
        &peer_id,
        CONTENT_BY_KEY_PATH,
        subject_key,
        signing_key,
        |wire| {
            let state = state.clone();
            async move {
                ingest_content_object(&state, &wire, peer_key).await;
            }
        },
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(
                peer = %peer_domain,
                subject = %hex_lower(subject_key),
                error = %e,
                "§13.3 step-4 primary path: §14.5 content-by-key failed",
            );
            SurfaceStats::default()
        }
    };

    // §14.6 inbound edges. Same posture — independent fail bucket.
    let edges_stats = match paginate_bulk_surface(
        state,
        &peer_id,
        INBOUND_EDGES_BY_KEY_PATH,
        subject_key,
        signing_key,
        |wire| {
            let state = state.clone();
            async move {
                ingest_edge_object(&state, &wire, peer_key).await;
            }
        },
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(
                peer = %peer_domain,
                subject = %hex_lower(subject_key),
                error = %e,
                "§13.3 step-4 primary path: §14.6 inbound-edges-by-key failed",
            );
            SurfaceStats::default()
        }
    };

    (content_stats, edges_stats)
}

/// Feed one §14.5 / §10.5.1 content row through the appropriate
/// receive path. §14.5 returns mixed classes: post-revs, retracts,
/// profiles, AND K-authored outbound trust-edges. The first three
/// belong on `apply_one_object`; trust-edges belong on
/// `apply_one_edge_inner` (which is what §9.1 push uses). Peek the
/// inner class up front so each row goes to its rightful receive
/// path — otherwise outbound edges round-trip as `WrongClass` and
/// silently vanish from D's projection.
///
/// Logs at `debug` for the diagnostic statuses (`Deferred`,
/// `Rejected`) so an operator can correlate counts after a recovery
/// run; `Applied` and `Duplicate` are the expected cases and stay
/// silent.
async fn ingest_content_object(state: &Arc<AppState>, wire: &[u8], arrived_from: [u8; 32]) {
    // Peel the WireFormat once to inspect the inner class. A malformed
    // page row falls through to `apply_one_object`, which will
    // surface the schema rejection in the normal logging channel.
    if let Some((payload_bytes, _)) = decode_signed_object(wire)
        && let Ok(SignedPayload::TrustEdge(_)) = SignedPayload::parse(&payload_bytes)
    {
        ingest_edge_object(state, wire, arrived_from).await;
        return;
    }
    match apply_one_object(state, wire, arrived_from).await {
        Ok(ContentResult { status, .. }) => match status {
            ContentStatus::Rejected(reason) => {
                tracing::debug!(
                    arrived_from = %hex_lower(&arrived_from),
                    reason = ?reason,
                    "recovery: content object rejected during ingest",
                );
            }
            ContentStatus::Deferred => {
                tracing::debug!(
                    arrived_from = %hex_lower(&arrived_from),
                    "recovery: content object deferred during ingest",
                );
            }
            ContentStatus::Applied | ContentStatus::Duplicate => {}
        },
        Err(e) => {
            tracing::warn!(
                arrived_from = %hex_lower(&arrived_from),
                error = %e,
                "recovery: db error applying content object",
            );
        }
    }
}

/// Spawn the §11.9.5 `UnknownSource` recovery for an edge surfaced
/// during a recovery sweep. Deliberately a *synchronous* `fn`, not an
/// `async fn`: it sits on the recursion cycle `proactive_author_backfill`
/// → inbound-edge pull → `ingest_edge_object` → here →
/// `proactive_author_backfill`, and routing the spawn through a plain
/// function (whose body holds no awaited future) is what lets Rust's
/// auto-`Send` solver resolve that cycle. The spawned task is boxed as a
/// `dyn Future + Send` for the same reason.
fn spawn_unknown_source_backfill(
    state: Arc<AppState>,
    source: [u8; 32],
    arrived_from: [u8; 32],
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
        Box::pin(async move {
            let _permit = permit;
            proactive_author_backfill(&state, source, Some(arrived_from)).await;
        });
    tokio::spawn(fut);
}

/// Feed one §14.6 / §10.5.1 edge row through `apply_one_edge_inner`,
/// then act on its recovery signal:
///
/// - §9.3 `Predecessor` is deliberately dropped. We are already inside
///   a recovery sweep; chaining a fresh chain-backfill from here would
///   just multiply the budget the §9.6 cap allocated for normal
///   traffic, and the next live push or sweep tick re-triggers it.
/// - §11.9.5 `UnknownSource` is honored. On a relay spoke the inbound-
///   edge pull (§10.5.4 step 6) is the *only* path that ever surfaces a
///   third-party `S → T` edge whose target is a frontier author, and
///   the reverse-BFS that would otherwise hydrate `S` dead-ends because
///   the spoke can't resolve `S`'s home (its author lives on a peer the
///   spoke isn't federated with). Pulling `S`'s profile directly from
///   the edge-deliverer — `arrived_from`, which holds it — is what
///   breaks that deadlock so `sweep_pending_projections` can finally
///   project the edge. Bounded by the same outbound-permit budget as
///   the live-push path; the single-flight guard inside
///   [`proactive_author_backfill`] keeps the fan-out across the
///   expansion frontier from looping.
async fn ingest_edge_object(state: &Arc<AppState>, wire: &[u8], arrived_from: [u8; 32]) {
    match apply_one_edge_inner(state, wire, arrived_from).await {
        Ok((_, recovery)) => {
            if let Some(crate::federation::edges::EdgeRecovery::UnknownSource {
                source,
                arrived_from,
            }) = recovery
                && let Some(permit) =
                    crate::federation::edge_backfill::try_acquire_outbound_permit()
            {
                spawn_unknown_source_backfill(state.clone(), source, arrived_from, permit);
            }
        }
        Err(e) => {
            tracing::warn!(
                arrived_from = %hex_lower(&arrived_from),
                error = %e,
                "recovery: db error applying edge object",
            );
        }
    }
}

/// Issue one peer-authed §10.5.1 GET (`/backfill/by-author` or
/// `/backfill/edges-by-key`), paginate to `complete: true` or the
/// page cap, and ingest each row through `ingest`.
///
/// `path_with_query` is the URI path complete with `?key=...` etc.
/// Cursor is appended as `&since=<base64url>` once we have one.
async fn paginate_peer_backfill<F, Fut>(
    state: &Arc<AppState>,
    peer: &PeerId,
    base_path_query: &str,
    mut ingest: F,
) -> Result<SurfaceStats, PageError>
where
    F: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    // §10.5.5 per-destination-peer concurrency cap. Acquire-and-wait (not
    // skip): the caller has already committed to this peer for this author,
    // and the upstream single-flight guard means only one task per author
    // queues here, so blocking briefly behind other streams to the same
    // peer is preferable to abandoning the backfill. Held for the whole
    // pagination; released on any return path below.
    let peer_sem = per_peer_backfill_semaphore(*peer.as_bytes());
    let _peer_permit = peer_sem
        .acquire()
        .await
        .expect("per-peer backfill semaphore is never closed");

    let mut stats = SurfaceStats::default();
    let mut cursor: Option<String> = None;
    // Cumulative across all pages of this surface — see `THROTTLE_MAX_RETRIES`.
    let mut throttle_retries = 0u32;
    let mut pages_fetched = 0usize;
    while pages_fetched < MAX_RECOVERY_PAGES {
        // Compose the full URI. Cursor is base64url-encoded raw bytes
        // on the wire — `decode_backfill_body` returned the raw
        // version; we re-encode here to match the §10.5.1 GET
        // `?since=` shape.
        let path: String = match &cursor {
            None => base_path_query.to_string(),
            Some(c) => format!("{base_path_query}&since={c}"),
        };
        let signed_path = match path.split_once('?') {
            Some((p, _)) => p,
            None => path.as_str(),
        };
        let header_value = sign_outbound(
            &state.instance_key,
            *peer.as_bytes(),
            &Method::GET,
            signed_path,
            b"",
        );
        let request = Request::builder()
            .method(Method::GET)
            .uri(&path)
            .header(AUTH_HEADER, header_value)
            .header(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)
            .body(Bytes::new())
            .map_err(|_| PageError::Decode("request build failed"))?;

        let response = state
            .federation_transport
            .request(peer, request)
            .await
            .map_err(PageError::Transport)?;
        let status = response.status();
        // §10.5.5 backpressure: the peer is rate-limiting us. Honor
        // `Retry-After` and retry the *same* page rather than abandoning the
        // peer — for a by-author backfill this may be the only peer that
        // hosts the author, so bailing to the next candidate would just fail
        // the whole backfill against a peer that has nothing. Bounded by
        // `THROTTLE_MAX_RETRIES` total so a peer that 429s forever can't pin
        // the worker; the retry does not consume a page from the cap.
        if status == StatusCode::TOO_MANY_REQUESTS {
            if throttle_retries >= THROTTLE_MAX_RETRIES {
                return Err(PageError::Status(status));
            }
            throttle_retries += 1;
            let wait = retry_after_secs(&response)
                .unwrap_or(MAX_RETRY_AFTER_SECS)
                .clamp(1, MAX_RETRY_AFTER_SECS);
            tracing::debug!(
                peer = %peer,
                wait_secs = wait,
                attempt = throttle_retries,
                "peer-backfill 429; honoring Retry-After and retrying same page",
            );
            tokio::time::sleep(Duration::from_secs(wait)).await;
            continue;
        }
        if !status.is_success() {
            return Err(PageError::Status(status));
        }
        pages_fetched += 1;
        stats.pages_fetched += 1;

        let body = response.into_body();
        let (objects, next_cursor, complete) =
            decode_backfill_body(&body).ok_or(PageError::Decode("malformed §10.5.2 envelope"))?;

        for wire in objects {
            stats.objects_seen += 1;
            ingest(wire).await;
        }

        if complete {
            stats.complete = true;
            return Ok(stats);
        }
        let Some(next) = next_cursor else {
            return Err(PageError::Decode(
                "peer-backfill page reported !complete but omitted next_cursor",
            ));
        };
        cursor = Some(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            next,
        ));
    }
    Ok(stats)
}

/// Fallback recovery against D's own active peers using the §10.5.1
/// peer-authed routes. For each peer that successfully completes a
/// surface, we accumulate the byte counts; for any peer that fails
/// or doesn't complete, we move on (the contract is best-effort).
async fn recover_via_peer_network(
    state: &Arc<AppState>,
    subject_key: &[u8; 32],
) -> (SurfaceStats, SurfaceStats, usize) {
    let mut candidates: Vec<([u8; 32], String)> = match list_active_peers(state).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                subject = %hex_lower(subject_key),
                error = %e,
                "§13.3 step-4 fallback: db error listing active peers",
            );
            return (SurfaceStats::default(), SurfaceStats::default(), 0);
        }
    };
    if candidates.is_empty() {
        return (SurfaceStats::default(), SurfaceStats::default(), 0);
    }
    // Clip the long tail. `list_active_peers` already sorts by
    // recently-active first, so the truncated head is the
    // most-likely-to-respond subset — same selection bias as the
    // §13.3 discovery fan-out.
    candidates.truncate(MAX_FALLBACK_PEERS);

    let key_hex = hex_lower(subject_key);
    let content_path = format!("/federation/v1/backfill/by-author?key={key_hex}");
    let edges_path = format!("/federation/v1/backfill/edges-by-key?key={key_hex}&direction=both");

    let n_peers = candidates.len();
    let mut content_acc = SurfaceStats::default();
    let mut edges_acc = SurfaceStats::default();
    // The fallback is "complete" iff every peer we asked completed
    // both surfaces — a strict floor.
    let mut fallback_all_complete = true;

    for (peer_key, peer_domain) in candidates {
        let peer_id = PeerId::from_bytes(peer_key);

        let by_author = paginate_peer_backfill(state, &peer_id, &content_path, |wire| {
            let state = state.clone();
            async move {
                ingest_content_object(&state, &wire, peer_key).await;
            }
        })
        .await;
        match by_author {
            Ok(s) => {
                content_acc.pages_fetched += s.pages_fetched;
                content_acc.objects_seen += s.objects_seen;
                if !s.complete {
                    fallback_all_complete = false;
                }
            }
            Err(e) => {
                tracing::debug!(
                    peer = %peer_domain,
                    subject = %key_hex,
                    error = %e,
                    "§13.3 step-4 fallback: §10.5.1 by-author failed",
                );
                fallback_all_complete = false;
            }
        }

        let edges_by_key = paginate_peer_backfill(state, &peer_id, &edges_path, |wire| {
            let state = state.clone();
            async move {
                ingest_edge_object(&state, &wire, peer_key).await;
            }
        })
        .await;
        match edges_by_key {
            Ok(s) => {
                edges_acc.pages_fetched += s.pages_fetched;
                edges_acc.objects_seen += s.objects_seen;
                if !s.complete {
                    fallback_all_complete = false;
                }
            }
            Err(e) => {
                tracing::debug!(
                    peer = %peer_domain,
                    subject = %key_hex,
                    error = %e,
                    "§13.3 step-4 fallback: §10.5.1 edges-by-key failed",
                );
                fallback_all_complete = false;
            }
        }
    }

    content_acc.complete = fallback_all_complete;
    edges_acc.complete = fallback_all_complete;
    (content_acc, edges_acc, n_peers)
}

/// Pull the `status='active'` peer set, recently-handshaken first.
/// Same ordering as the §13.3 fan-out so the fallback sweep prefers
/// the most-likely-to-respond peers.
pub(crate) async fn list_active_peers(
    state: &Arc<AppState>,
) -> Result<Vec<([u8; 32], String)>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT instance_pubkey AS \"instance_pubkey!: Vec<u8>\", \
                instance_domain AS \"instance_domain!: String\" \
         FROM peers \
         WHERE status = 'active' \
         ORDER BY COALESCE(last_handshake, first_seen) DESC",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            <[u8; 32]>::try_from(r.instance_pubkey.as_slice())
                .ok()
                .map(|k| (k, r.instance_domain))
        })
        .collect())
}

/// Best-effort `instance_domain` lookup for a peer pubkey, used only to
/// label log lines when the delivering peer isn't in the active-peer
/// set returned by [`list_active_peers`]. `None` if no row matches.
async fn peer_domain(state: &Arc<AppState>, pubkey: &[u8; 32]) -> Option<String> {
    let key_slice: &[u8] = pubkey.as_slice();
    sqlx::query!(
        "SELECT instance_domain AS \"instance_domain!: String\" \
         FROM peers WHERE instance_pubkey = ?",
        key_slice,
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .map(|r| r.instance_domain)
}

/// §7.6 / §10.5 proactive by-author pull-backfill for a single author
/// `author_key` that newly entered our local content frontier.
///
/// Tries active peers (recently-handshaken first, clipped to
/// `MAX_FALLBACK_PEERS`) until one completes the `/backfill/by-author`
/// content surface, seeding the author's *existing* content. Frontier
/// push only carries content authored *after* a peer learns our
/// interest, so without this backfill a freshly-trusted author's
/// history would never arrive. Best-effort and meant to be
/// `tokio::spawn`ed off the trust-graph rebuild critical path: every
/// failure is logged at debug and swallowed.
///
/// §10.5.4 step 6: concurrent with the by-author content, the author's
/// *inbound* edges (`edges-by-key?...&direction=target` — who trusts K)
/// are pulled from the same peer that served the content. This is the
/// direction that advances our reverse frontier (§8.1): expanding past K
/// means discovering who trusts K. Without it, a third-party truster
/// `S → K` that arrived at the author's home *before* we frontiered K is
/// never relayed to us (§7.6 replay carries only the relaying instance's
/// *local-origin* edges), so K's `trusted_by` would silently omit `S` —
/// the cross-instance asymmetry this pull closes. K's *outbound* edges
/// (`direction=source`) are forward-trust, not needed for our visibility
/// computation, so they are not fetched. A pulled inbound edge whose
/// truster we haven't hydrated lands in `frontier_edges` (not yet
/// `trust_edges`) via [`apply_one_edge_inner`]'s §8.1 discovery path, so
/// the next reverse-BFS can reach and materialize that truster.
///
/// `prefer_peer`, when set, is the peer that delivered the edge whose
/// `EndpointMissing` projection triggered this run (§11.9.5). For a
/// trust-coded `S → local` edge pushed straight from `S`'s home, that
/// peer *is* the author's home, so it is queried first and exempted
/// from the [`MAX_FALLBACK_PEERS`] cap — best case the source's stub
/// hydrates in one round-trip; worst case (the deliverer was a relay
/// that doesn't host the author) we fall through to the recency-ranked
/// sweep. Without this hint the cap could clip the one peer that hosts
/// the author out of a large active-peer set, and even within the cap
/// we would query peers one-by-one until we stumbled onto the home.
pub(crate) async fn proactive_author_backfill(
    state: &Arc<AppState>,
    author_key: [u8; 32],
    prefer_peer: Option<[u8; 32]>,
) {
    // §10.5.5: at most one outstanding by-author request per author across
    // the whole process. Claim the key for the duration of this run; if a
    // backfill for it is already in flight (from the other call site or a
    // prior still-running batch entry), skip cheaply rather than racing a
    // duplicate sweep. The guard releases the claim on drop (incl. early
    // returns below and panics).
    let _in_flight = match AuthorInFlightGuard::try_claim(author_key) {
        Some(guard) => guard,
        None => {
            tracing::debug!(
                author = %hex_lower(&author_key),
                "proactive by-author backfill: already in flight, skipping (§10.5.5)",
            );
            return;
        }
    };

    let mut candidates = match list_active_peers(state).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                author = %hex_lower(&author_key),
                error = %e,
                "proactive by-author backfill: db error listing active peers",
            );
            return;
        }
    };

    // Promote the delivering peer to the front *before* the cap, so a
    // large active-peer set can't truncate away the one peer most likely
    // to host the author. If it isn't already in the active set (e.g.
    // not `status = 'active'`), prepend it with a best-effort domain for
    // logging — `paginate_peer_backfill` keys off the pubkey alone.
    if let Some(prefer) = prefer_peer {
        match candidates.iter().position(|(k, _)| *k == prefer) {
            Some(pos) => {
                let hit = candidates.remove(pos);
                candidates.insert(0, hit);
            }
            None => {
                let domain = peer_domain(state, &prefer)
                    .await
                    .unwrap_or_else(|| hex_lower(&prefer));
                candidates.insert(0, (prefer, domain));
            }
        }
    }

    if candidates.is_empty() {
        return;
    }
    candidates.truncate(MAX_FALLBACK_PEERS);

    let key_hex = hex_lower(&author_key);
    let content_path = format!("/federation/v1/backfill/by-author?key={key_hex}");
    // §10.5.4 step 6 — the author's inbound trusters (edges that point AT
    // K). `direction=target` is the reverse-frontier-advancing axis (§8.1);
    // we never pull `direction=source` here (forward-trust, irrelevant to
    // our visibility computation).
    let inbound_edges_path =
        format!("/federation/v1/backfill/edges-by-key?key={key_hex}&direction=target");

    for (peer_key, peer_domain) in candidates {
        let peer_id = PeerId::from_bytes(peer_key);
        let res = paginate_peer_backfill(state, &peer_id, &content_path, |wire| {
            let state = state.clone();
            async move {
                ingest_content_object(&state, &wire, peer_key).await;
            }
        })
        .await;
        match res {
            // Success requires the peer to have actually served the
            // author. `by-author` returns `complete: true` with ZERO
            // objects for a key the peer has never seen (the remote-author
            // carve-out in `backfill.rs`), so `complete` alone is not
            // enough — a peer that doesn't host this author would
            // otherwise satisfy the loop and we'd never ask the peer that
            // does, leaving the source's stub unhydrated and its edge
            // unprojected. §10.5.6 is explicit: `200`+empty+`complete:true`
            // means "peer has nothing matching → try next candidate peer",
            // NOT done. A peer that genuinely hosts the author serves at
            // least its genesis profile-rev (§11.9.5), so `objects_seen > 0`
            // is the real "found it here" signal. Do not relax this back to
            // `complete` alone.
            Ok(stats) if stats.complete && stats.objects_seen > 0 => {
                tracing::debug!(
                    author = %key_hex,
                    peer = %peer_domain,
                    objects = stats.objects_seen,
                    "proactive by-author backfill complete",
                );
                // §10.5.4 step 6: this peer demonstrably hosts the author
                // (it just served K's content), so it holds the
                // authoritative inbound-edge set too. Pull who-trusts-K
                // from the *same* peer before returning. Best-effort: a
                // failure here doesn't undo the content already applied,
                // and the §7.7 pull backstop re-attempts on the next read.
                if let Err(e) =
                    paginate_peer_backfill(state, &peer_id, &inbound_edges_path, |wire| {
                        let state = state.clone();
                        async move {
                            ingest_edge_object(&state, &wire, peer_key).await;
                        }
                    })
                    .await
                {
                    tracing::debug!(
                        author = %key_hex,
                        peer = %peer_domain,
                        error = %e,
                        "proactive inbound-edges backfill: peer surface failed",
                    );
                }
                // Wake the trust-graph rebuild loop. This run just landed
                // recovery work through `apply_one_edge_inner` /
                // `sweep_pending_projections` — the inbound-edge pull above
                // (`ingest_edge_object`) and the profile hydration in the
                // content phase, which projects any pending `S → K` orphan
                // into `trust_edges`. Unlike the §9.1 live push, neither path
                // notifies internally, and `rebuild_loop` has no free-running
                // timer (it only wakes on this `Notify`), so without this the
                // recovered edges sit in the DB and never surface to readers
                // until unrelated mutation traffic happens to wake the loop.
                // `notify_one` coalesces and the loop debounces, so a spurious
                // wake when nothing new landed is cheap.
                state.trust_graph_notify.notify_one();
                return;
            }
            Ok(_) => {
                // Either incomplete (hit page cap / a !complete page) or
                // complete-but-empty (this peer doesn't host the author).
                // Both mean "this peer can't finish the job" — move on to
                // the next candidate.
            }
            Err(e) => {
                tracing::debug!(
                    author = %key_hex,
                    peer = %peer_domain,
                    error = %e,
                    "proactive by-author backfill: peer surface failed",
                );
            }
        }
    }
}

/// Bounded-concurrency drain of [`proactive_author_backfill`] across a
/// batch of newly-frontier'd authors (frontier Trigger-3, §7.6).
///
/// Replaces a per-author `tokio::spawn` fanout: the old loop launched one
/// detached task per author with no ceiling, so a single trust-graph
/// rebuild that admitted N new remote authors could fire N ×
/// `MAX_FALLBACK_PEERS` outbound by-author sweeps at once, bypassing the
/// outbound budget the sibling §11.9.5 edge path respects. This drives the
/// whole batch through a [`tokio::task::JoinSet`] holding at most
/// [`PROACTIVE_BACKFILL_BATCH_CONCURRENCY`] in flight: prime that many,
/// then admit one more each time a slot frees, until the batch is drained.
/// The burst is bounded while every author still gets serviced.
///
/// Per-author single-flight (§10.5.5) lives inside
/// [`proactive_author_backfill`], so any author already being backfilled
/// from another call site is skipped cheaply here rather than de-duped at
/// this layer. Meant to be `tokio::spawn`ed once, off the rebuild critical
/// path; each task is best-effort and self-logging.
pub(crate) async fn proactive_backfill_batch(state: Arc<AppState>, authors: Vec<[u8; 32]>) {
    let mut pending = authors.into_iter();
    let mut workers: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    let spawn_next = |workers: &mut tokio::task::JoinSet<()>,
                      pending: &mut std::vec::IntoIter<[u8; 32]>| {
        if let Some(author) = pending.next() {
            let state = Arc::clone(&state);
            workers.spawn(async move {
                proactive_author_backfill(&state, author, None).await;
            });
        }
    };

    for _ in 0..PROACTIVE_BACKFILL_BATCH_CONCURRENCY {
        spawn_next(&mut workers, &mut pending);
    }

    while workers.join_next().await.is_some() {
        spawn_next(&mut workers, &mut pending);
    }
}

/// Orchestrate the §13.3 step-4 recovery flow end-to-end. Tries the
/// §14.5 / §14.6 primary path against `confirmed_peer` if present;
/// always also runs the §10.5.1 fallback unless the primary path
/// completed both surfaces. Returns aggregate stats for telemetry /
/// integration-test introspection.
///
/// Designed to be run via `tokio::spawn` from the registration
/// `complete` handler — never blocks the user-facing response.
///
/// Argument ownership is by-value because the typical call site
/// hands these in from a spawn block that has its own lifetime
/// independent of the originating request.
pub async fn drive_recovery(
    state: Arc<AppState>,
    subject_key: [u8; 32],
    signing_key: SigningKey,
    confirmed_peer: Option<([u8; 32], String)>,
) -> RecoveryStats {
    let mut stats = RecoveryStats::default();

    if let Some((peer_key, peer_domain)) = confirmed_peer {
        stats.primary_attempted = true;
        let (content_stats, edges_stats) =
            recover_via_prior_home(&state, &subject_key, &signing_key, peer_key, &peer_domain)
                .await;
        stats.objects_seen += content_stats.objects_seen + edges_stats.objects_seen;
        stats.primary_complete = content_stats.complete && edges_stats.complete;

        tracing::info!(
            subject = %hex_lower(&subject_key),
            peer = %peer_domain,
            content_pages = content_stats.pages_fetched,
            content_objects = content_stats.objects_seen,
            content_complete = content_stats.complete,
            edges_pages = edges_stats.pages_fetched,
            edges_objects = edges_stats.objects_seen,
            edges_complete = edges_stats.complete,
            "§13.3 step-4 primary path finished",
        );
    }

    // Run fallback unless the primary path already cleared both
    // surfaces — in that case the peer network can't add anything
    // (every object K signed lives canonically on K's prior home,
    // and we just fetched all of it).
    if !stats.primary_complete {
        stats.fallback_attempted = true;
        let (content_stats, edges_stats, n_peers) =
            recover_via_peer_network(&state, &subject_key).await;
        stats.objects_seen += content_stats.objects_seen + edges_stats.objects_seen;
        stats.fallback_complete = content_stats.complete && edges_stats.complete;
        tracing::info!(
            subject = %hex_lower(&subject_key),
            peers = n_peers,
            content_pages = content_stats.pages_fetched,
            content_objects = content_stats.objects_seen,
            edges_pages = edges_stats.pages_fetched,
            edges_objects = edges_stats.objects_seen,
            complete = stats.fallback_complete,
            "§13.3 step-4 fallback path finished",
        );
    }

    if stats.is_incomplete() {
        tracing::info!(
            subject = %hex_lower(&subject_key),
            primary_attempted = stats.primary_attempted,
            primary_complete = stats.primary_complete,
            fallback_attempted = stats.fallback_attempted,
            fallback_complete = stats.fallback_complete,
            objects_seen = stats.objects_seen,
            recovery = "best_effort_incomplete",
            "§13.3 step-4 recovery finished with partial coverage",
        );
    } else {
        tracing::info!(
            subject = %hex_lower(&subject_key),
            objects_seen = stats.objects_seen,
            recovery = "ok",
            "§13.3 step-4 recovery finished",
        );
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_bulk_fetch_body_omits_since_when_none() {
        let body = encode_bulk_fetch_body(b"chal", b"resp", None);
        let v: Value = ciborium::de::from_reader(body.as_slice()).unwrap();
        let Value::Map(m) = v else {
            panic!("not a map")
        };
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].0, Value::Text("challenge".into()));
        assert_eq!(m[1].0, Value::Text("response".into()));
    }

    #[test]
    fn encode_bulk_fetch_body_carries_since_when_some() {
        let body = encode_bulk_fetch_body(b"chal", b"resp", Some(b"cursor"));
        let v: Value = ciborium::de::from_reader(body.as_slice()).unwrap();
        let Value::Map(m) = v else {
            panic!("not a map")
        };
        assert_eq!(m.len(), 3);
        assert_eq!(m[2].0, Value::Text("since".into()));
        assert_eq!(m[2].1, Value::Bytes(b"cursor".to_vec()));
    }

    fn response_with_retry_after(value: &str) -> http::Response<Bytes> {
        http::Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header(header::RETRY_AFTER, value)
            .body(Bytes::new())
            .unwrap()
    }

    #[test]
    fn retry_after_secs_parses_delta_seconds() {
        assert_eq!(retry_after_secs(&response_with_retry_after("60")), Some(60));
        // Leading/trailing whitespace is tolerated.
        assert_eq!(retry_after_secs(&response_with_retry_after(" 5 ")), Some(5));
    }

    #[test]
    fn retry_after_secs_rejects_non_integer_and_absent() {
        // HTTP-date form (which our peers never emit) is not parsed.
        assert_eq!(
            retry_after_secs(&response_with_retry_after("Wed, 21 Oct 2026 07:28:00 GMT")),
            None,
        );
        assert_eq!(retry_after_secs(&response_with_retry_after("soon")), None);
        let no_header = http::Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .body(Bytes::new())
            .unwrap();
        assert_eq!(retry_after_secs(&no_header), None);
    }

    #[test]
    fn stats_is_incomplete_unless_some_layer_succeeded() {
        let mut s = RecoveryStats::default();
        assert!(s.is_incomplete()); // nothing attempted

        s.primary_attempted = true;
        assert!(s.is_incomplete());

        s.primary_complete = true;
        assert!(!s.is_incomplete());

        s.primary_complete = false;
        s.fallback_attempted = true;
        s.fallback_complete = true;
        assert!(!s.is_incomplete());
    }
}
