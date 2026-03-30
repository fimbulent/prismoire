use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use sqlx::SqlitePool;
use webauthn_rs::Webauthn;

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
}
