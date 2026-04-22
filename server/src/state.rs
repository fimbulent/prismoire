use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use sqlx::SqlitePool;
use tokio::sync::Notify;
use webauthn_rs::Webauthn;

use crate::error::{AppError, ErrorCode};
use crate::metrics::Metrics;
use crate::trust::TrustGraph;

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
                eprintln!("trust graph lock poisoned");
                AppError::code(ErrorCode::Internal)
            })
    }
}
