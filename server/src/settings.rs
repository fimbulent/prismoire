use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, ErrorCode};
use crate::session::RestrictedAuthUser;
use crate::state::AppState;

const VALID_THEMES: &[&str] = &[
    "rose-pine",
    "rose-pine-moon",
    "rose-pine-dawn",
    "gruvbox-dark",
    "gruvbox-light",
    "kanagawa-wave",
    "kanagawa-dragon",
    "kanagawa-lotus",
    "nord",
    "nord-light",
    "everforest-dark",
    "everforest-light",
    "iceberg",
];

pub const DEFAULT_THEME: &str = "rose-pine";

/// Allow-list of prose-font slugs. Mirrors the catalogue in
/// `web/src/lib/fonts.ts` and the `@font-face` declarations in
/// `web/src/app.css`. Adding a font is a three-place change: the
/// .woff2 files in `web/static/fonts/<slug>/`, an entry here, and an
/// entry in the frontend catalogue (verified at compile time by the
/// `font_slugs_exist_in_frontend` test below).
const VALID_FONTS: &[&str] = &["ibm-plex-sans", "literata", "vollkorn"];

pub const DEFAULT_FONT: &str = "literata";

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SettingsResponse {
    pub theme: String,
    pub font: String,
}

#[derive(Deserialize)]
pub struct UpdateSettingsRequest {
    pub theme: Option<String>,
    pub font: Option<String>,
}

// ---------------------------------------------------------------------------
// GET /api/settings
// ---------------------------------------------------------------------------

/// Return the current user's settings.
pub async fn get_settings(
    State(state): State<Arc<AppState>>,
    user: RestrictedAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let (theme, font) = get_user_settings(&state.db, &user.user_id).await?;
    Ok(Json(SettingsResponse { theme, font }))
}

// ---------------------------------------------------------------------------
// PATCH /api/settings
// ---------------------------------------------------------------------------

/// Update the current user's settings.
pub async fn update_settings(
    State(state): State<Arc<AppState>>,
    user: RestrictedAuthUser,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(ref theme) = req.theme {
        if !VALID_THEMES.contains(&theme.as_str()) {
            return Err(AppError::code(ErrorCode::InvalidTheme));
        }

        sqlx::query!(
            "INSERT INTO user_settings (user_id, theme) VALUES (?, ?) \
             ON CONFLICT(user_id) DO UPDATE SET theme = excluded.theme",
            user.user_id,
            theme,
        )
        .execute(&state.db)
        .await?;
    }

    if let Some(ref font) = req.font {
        if !VALID_FONTS.contains(&font.as_str()) {
            return Err(AppError::code(ErrorCode::InvalidFont));
        }

        sqlx::query!(
            "INSERT INTO user_settings (user_id, font) VALUES (?, ?) \
             ON CONFLICT(user_id) DO UPDATE SET font = excluded.font",
            user.user_id,
            font,
        )
        .execute(&state.db)
        .await?;
    }

    let (theme, font) = get_user_settings(&state.db, &user.user_id).await?;
    Ok(Json(SettingsResponse { theme, font }))
}

/// Load the user's full settings tuple `(theme, font)`, applying the
/// per-column defaults when the row is missing. Combined into one
/// helper so the GET / PATCH handlers and the session resolver each
/// run a single round-trip instead of one query per column.
pub async fn get_user_settings(
    db: &sqlx::SqlitePool,
    user_id: &str,
) -> Result<(String, String), AppError> {
    let row = sqlx::query!(
        "SELECT theme, font FROM user_settings WHERE user_id = ?",
        user_id,
    )
    .fetch_optional(db)
    .await?;
    Ok(match row {
        Some(r) => (r.theme, r.font),
        None => (DEFAULT_THEME.to_string(), DEFAULT_FONT.to_string()),
    })
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

    #[test]
    fn font_slugs_exist_in_frontend() {
        let ts = include_str!("../../web/src/lib/fonts.ts");
        for slug in VALID_FONTS {
            assert!(
                ts.contains(&format!("id: '{slug}'")),
                "font slug '{slug}' not found in web/src/lib/fonts.ts"
            );
        }
    }
}
