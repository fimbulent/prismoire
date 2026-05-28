use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use prismoire_config::{AttachmentCacheConfig, AttachmentsConfig};
use sqlx::SqlitePool;
use tokio::sync::Notify;
use webauthn_rs::Webauthn;

use crate::error::{AppError, ErrorCode};
use crate::federation::backfill_rate_limit::BackfillRateLimiter;
use crate::federation::content_rate_limit::ContentRateLimiter;
use crate::federation::envelope::NonceLru;
use crate::federation::forwarder::ForwardingLru;
use crate::federation::frontier::LocalFrontier;
use crate::federation::instance_key::InstanceKey;
use crate::federation::outbound_queue::OutboundQueues;
use crate::federation::prior_home_challenge_rate_limit::PriorHomeChallengeRateLimiter;
use crate::federation::prior_home_rate_limit::PriorHomeRateLimiter;
use crate::federation::push_rate_limit::PushRateLimiter;
use crate::federation::transport::FederationTransport;
use crate::instance_config::AttachmentBudget;
use crate::metrics::Metrics;
use crate::trust::{PendingDeltas, RebuildSchedule, TrustGraph};

/// Shared application state available to all request handlers.
pub struct AppState {
    pub db: SqlitePool,
    pub webauthn: Arc<Webauthn>,
    /// Whether the instance still needs initial admin setup.
    /// Starts `true` if no admin account exists at boot; flipped to `false`
    /// once the `/api/setup/complete` flow succeeds. Checked by the
    /// setup-mode middleware to gate non-setup routes.
    pub needs_setup: AtomicBool,
    /// One-time setup token read from the `server.setup_token_file` config path at startup.
    /// `None` after setup completes (or if the instance already has an admin).
    pub setup_token: Option<String>,
    /// Notified when trust edges are mutated (trust, distrust, invite signup).
    /// The background rebuild loop waits on this to trigger debounced rebuilds.
    pub trust_graph_notify: Arc<Notify>,
    /// In-memory trust graph (dual CSR) for on-demand BFS queries.
    /// Rebuilt by the background task when mutations are detected. Readers
    /// clone the inner `Arc<TrustGraph>` for zero-contention concurrent access.
    pub trust_graph: Arc<std::sync::RwLock<Arc<TrustGraph>>>,
    /// Process-wide metrics (BFS cache rates, graph build timings, last
    /// rebuild timestamp). Recorded at instrumentation points and read
    /// by the admin overview endpoint.
    pub metrics: Arc<Metrics>,
    /// Per-viewer pending trust-edge mutations not yet absorbed by a
    /// rebuild. Mutation handlers record into this immediately after
    /// their DB write commits; forward-BFS handlers read from it to
    /// overlay the viewer's own outgoing edges on top of the cached
    /// graph so trust badges respond instantly to button clicks
    /// instead of waiting for the next debounced rebuild.
    pub pending_deltas: Arc<PendingDeltas>,
    /// Live mirror of the rebuild-schedule columns from `instance_config`.
    /// Shared with the trust-graph rebuild loop, which snapshots it once
    /// per scheduling window (and re-reads `bfs_cache_bytes` at rebuild
    /// time). Admin edits via `/api/admin/config` overwrite the value
    /// here and persist to the DB row in the same handler.
    pub rebuild_schedule: Arc<std::sync::RwLock<RebuildSchedule>>,
    /// Live mirror of the `source_repo_url` column from `instance_config`.
    /// Read by `/api/setup/status` so the SvelteKit root layout can
    /// render the AGPL source link in the footer without a DB roundtrip
    /// per request. `None` only before the initial setup flow completes.
    pub source_repo_url: Arc<std::sync::RwLock<Option<String>>>,
    /// Live mirror of the attachment-budget columns from
    /// `instance_config` (docs/attachments.md §10.3). Read by the
    /// upload handler at debit time so admin edits via
    /// `/api/admin/config` take effect on the next upload without a
    /// server restart.
    pub attachment_budget: Arc<std::sync::RwLock<AttachmentBudget>>,
    /// Server-static attachment-processing knobs from TOML
    /// (`docs/attachments.md` §10.2): decode/output pixel caps, staging
    /// TTL, sweep cadence, request-body overhead. Loaded once at
    /// startup; restart-required to change.
    pub attachments_config: AttachmentsConfig,
    /// §11.5 receiver-local attachment-cache budget from TOML
    /// (`[federation.attachment_cache]`). Bounds the total bytes
    /// retained for federation-fetched blobs. Sender-local — peers
    /// never observe this value. Loaded once at startup; restart-
    /// required to change. The eviction sweep that actually enforces
    /// this budget lands in a later phase; the field is plumbed here
    /// so the budget can be set in operator config today.
    pub federation_attachment_cache: AttachmentCacheConfig,
    /// Bare canonical domain this instance presents on the wire
    /// (`docs/federation-protocol.md` §5.2 `instance_domain`). Read
    /// from `webauthn.rp_id` at boot; restart-required to change.
    /// Surfaced in the `/federation/v1/identity` response and in the
    /// outbound peer-request body.
    pub instance_domain: String,
    /// Per-instance Ed25519 signing key (§6.2). Single active key
    /// per instance in V1. Used to sign every outbound federation
    /// envelope and to derive this instance's public identity on
    /// the wire. Loaded or freshly generated at startup by
    /// [`crate::federation::instance_key::load_or_generate`].
    pub instance_key: Arc<InstanceKey>,
    /// Process-wide replay-protection LRU for inbound envelope
    /// verification (§6.5 step 12, §6.7). Shared across all
    /// `/federation/v1/*` handlers because the nonce uniqueness
    /// requirement is *per-instance*, not per-route.
    pub federation_nonce_lru: Arc<NonceLru>,
    /// Outbound transport used to dispatch federation requests to
    /// peers. Production binds this to a `reqwest`-backed impl;
    /// integration tests bind it to an in-process router registry
    /// so multi-instance scenarios run without sockets.
    pub federation_transport: Arc<dyn FederationTransport>,
    /// In-memory snapshot of this instance's own frontier — the
    /// 3-hop / 2-hop forward closures over local users that we
    /// advertise to peers per `docs/federation-protocol.md` §7.4 + §8.
    /// Refreshed by [`crate::federation::frontier::refresh_local_frontier`]
    /// before each outbound announce and read by the §8.5 GET route.
    /// Readers clone the inner `Arc<LocalFrontier>` for zero-contention
    /// concurrent access.
    pub local_frontier: Arc<std::sync::RwLock<Arc<LocalFrontier>>>,
    /// §7.5 dedup-LRU + peer-index registry shared across the
    /// originator path (`crate::users::set_trust_edge` /
    /// `delete_trust_edge`) and the relay path
    /// (`crate::federation::edges::handle_edges_push`). One process-
    /// wide instance, keyed on `canonical_hash`, valued on a bitset
    /// of peer indices we have already forwarded the object to.
    pub forwarding_lru: Arc<ForwardingLru>,
    /// §7.3 per-peer outbound FIFO queues + drain workers
    /// (Phase 6.4). The forwarder pushes wire-ready singleton blobs in
    /// via `enqueue(...)`; each peer's drain worker coalesces up to
    /// `MAX_CONTENT_BATCH_OUTBOUND = 64` items into a single signed
    /// HTTP push, with exponential backoff on transient failure.
    pub outbound_queues: Arc<OutboundQueues>,
    /// §10.6 fold-in (Phase 7): per-source-instance rolling-hour
    /// object counter for `POST /federation/v1/content`. Closes the
    /// abuse surface flagged in Phase 6 — a single peer can no
    /// longer sustain `MAX_CONTENT_BATCH = 64` objects per request
    /// indefinitely. In-memory only; resets on restart.
    pub content_rate_limiter: Arc<ContentRateLimiter>,
    /// Same shape as [`AppState::content_rate_limiter`], but
    /// parameterised with [`crate::federation::moves::MAX_MOVE_OBJECTS_PER_HOUR`]
    /// — a much tighter ceiling than `/content` because §12 moves
    /// are rare-per-user and indefinitely retained, and because the
    /// unconditional-flood / `REDUNDANCY_K_MOVE = 5` amplification
    /// makes abuse on this route disproportionately expensive
    /// downstream.
    pub move_rate_limiter: Arc<ContentRateLimiter>,
    /// §10.5.5 receiver-side per-peer per-minute request + byte
    /// budgets gating the three Phase-8 pull-backfill routes
    /// (`/backfill/by-hash`, `/backfill/by-author`,
    /// `/backfill/edges-by-key`). Overflow returns `429` with
    /// `Retry-After: 60`. In-memory only; resets on restart.
    pub backfill_rate_limiter: Arc<BackfillRateLimiter>,
    /// §14.3 receiver-side per-subject-key per-day budget gating the
    /// three §14 prior-home routes (`/prior-home/probe`,
    /// `/prior-home/content-by-key`, `/prior-home/inbound-edges-by-key`).
    /// Shared counter across all three because the threat model is
    /// captured-key enumeration — splitting the budget would let an
    /// attacker alternate endpoints to near-double per-key request
    /// volume. Overflow returns `429` with `Retry-After: 86400`. In-
    /// memory only; resets on restart.
    pub prior_home_rate_limiter: Arc<PriorHomeRateLimiter>,
    /// §14.3 receiver-side per-minute issuance budgets gating
    /// `POST /federation/v1/prior-home/challenge`: 60/min per source
    /// IP (cheap pre-verification rejection) and 10/min per subject
    /// key K (post-curve-validation cap on signing). Distinct from
    /// [`AppState::prior_home_rate_limiter`], which is the daily
    /// budget at the redeem-time serve endpoints. Overflow returns
    /// `429` with `Retry-After: 60`. In-memory only; resets on restart.
    pub prior_home_challenge_rate_limiter: Arc<PriorHomeChallengeRateLimiter>,
    /// §16.5 per-peer per-minute request budget gating
    /// `POST /federation/v1/user-status` (`USER_STATUS_RPM_PER_PEER`).
    /// Overflow returns `429` with `Retry-After: 60`. In-memory only;
    /// resets on restart.
    pub user_status_rate_limiter: Arc<PushRateLimiter>,
    /// §17.5 per-peer per-minute request budget gating
    /// `POST /federation/v1/thread-status` (`THREAD_STATUS_RPM_PER_PEER`).
    /// Overflow returns `429` with `Retry-After: 60`. In-memory only;
    /// resets on restart.
    pub thread_status_rate_limiter: Arc<PushRateLimiter>,
    /// §18.5 per-peer per-minute request budget gating
    /// `POST /federation/v1/reports` (`REPORTS_RPM_PER_PEER`). Tighter
    /// ceiling than the status routes because the sender can vary
    /// `post_id` to flood the moderation queue. Overflow returns `429`
    /// with `Retry-After: 60`. In-memory only; resets on restart.
    pub reports_rate_limiter: Arc<PushRateLimiter>,
}

impl AppState {
    /// Acquire a read handle to the trust graph.
    ///
    /// Returns a cloned `Arc` so the lock is released immediately. Logs and
    /// returns a 500 error if the lock is poisoned.
    pub fn get_trust_graph(&self) -> Result<Arc<TrustGraph>, AppError> {
        self.trust_graph
            .read()
            .map(|guard| Arc::clone(&guard))
            .map_err(|_| {
                tracing::error!("trust graph lock poisoned");
                self.metrics.record_trust_graph_lock_poisoned();
                AppError::code(ErrorCode::Internal)
            })
    }
}
