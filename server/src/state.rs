use std::sync::Arc;

use sqlx::SqlitePool;
use webauthn_rs::Webauthn;

/// Shared application state available to all request handlers.
pub struct AppState {
    pub db: SqlitePool,
    pub webauthn: Arc<Webauthn>,
}
