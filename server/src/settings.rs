use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::session::AuthUser;
use crate::state::AppState;

const VALID_THEMES: &[&str] = &[
    "rose-pine",
    "nord",
    "everforest",
    "midnight-blue",
    "warm-ember",
    "stone",
    "moss",
    "coral",
    "blueprint",
];

pub const DEFAULT_THEME: &str = "rose-pine";

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SettingsResponse {
    pub theme: String,
}

#[derive(Deserialize)]
pub struct UpdateSettingsRequest {
    pub theme: Option<String>,
}

// ---------------------------------------------------------------------------
// GET /api/settings
// ---------------------------------------------------------------------------

/// Return the current user's settings.
pub async fn get_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let theme = get_user_theme(&state.db, &user.user_id).await?;
    Ok(Json(SettingsResponse { theme }))
}

// ---------------------------------------------------------------------------
// PATCH /api/settings
// ---------------------------------------------------------------------------

/// Update the current user's settings.
pub async fn update_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(ref theme) = req.theme {
        if !VALID_THEMES.contains(&theme.as_str()) {
            return Err(AppError::BadRequest("invalid theme".into()));
        }

        sqlx::query(
            "INSERT INTO user_settings (user_id, theme) VALUES (?, ?) \
             ON CONFLICT(user_id) DO UPDATE SET theme = excluded.theme",
        )
        .bind(&user.user_id)
        .bind(theme)
        .execute(&state.db)
        .await?;
    }

    let theme = get_user_theme(&state.db, &user.user_id).await?;
    Ok(Json(SettingsResponse { theme }))
}

/// Load the user's theme, falling back to the default.
pub async fn get_user_theme(db: &sqlx::SqlitePool, user_id: &str) -> Result<String, AppError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT theme FROM user_settings WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(row
        .map(|(t,)| t)
        .unwrap_or_else(|| DEFAULT_THEME.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_slugs_exist_in_frontend() {
        let ts = include_str!("../../web/src/lib/themes.ts");
        for slug in VALID_THEMES {
            assert!(
                ts.contains(&format!("id: '{slug}'")),
                "theme slug '{slug}' not found in web/src/lib/themes.ts"
            );
        }
    }
}
