use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use sqlx::SqlitePool;
use webauthn_rs::Webauthn;

use crate::error::AppError;
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
    /// One-time setup token read from `PRISMOIRE_SETUP_TOKEN_FILE` at startup.
    /// `None` after setup completes (or if the instance already has an admin).
    pub setup_token: Option<String>,
    /// Set to `true` when trust edges are mutated (trust, block, invite signup).
    /// The background trust recomputation task checks and clears this flag
    /// each tick.
    pub trust_graph_dirty: AtomicBool,
    /// In-memory trust graph (dual CSR) for on-demand BFS queries.
    /// Rebuilt periodically when `trust_graph_dirty` is set. Readers clone
    /// the inner `Arc<TrustGraph>` for zero-contention concurrent access.
    pub trust_graph: std::sync::RwLock<Arc<TrustGraph>>,
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
                AppError::Internal("internal server error".into())
            })
    }
}
