use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use prismoire_config::AttachmentsConfig;
use sqlx::SqlitePool;
use tokio::sync::Notify;
use webauthn_rs::Webauthn;

use crate::error::{AppError, ErrorCode};
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
