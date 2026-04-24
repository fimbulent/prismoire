//! Per-user favorited rooms.
//!
//! The `room_favorites` table stores each user's pinned rooms in a dense
//! 0-based `position` ordering. Favorites drive two surfaces: the tab-bar
//! (see `rooms::tab_bar`) and a dedicated section at the top of `/rooms`.
//!
//! Cap: 50 favorites per user. Any higher would stop fitting reasonably on
//! the tab bar overflow logic and is more than any user is going to
//! actually pin. The cap is enforced in the favorite handler.
//!
//! Reorder semantics: the `PUT /api/me/favorites` endpoint validates that
//! the submitted `room_ids` set is exactly the user's current favorite set
//! (same membership, regardless of order). If another tab added or removed
//! a favorite between the client's view and the submission, the endpoint
//! returns [`ErrorCode::FavoriteSetMismatch`] (409) so the client can
//! refetch and retry. This avoids silently dropping or reviving favorites
//! across concurrent tabs.
//!
//! Positions are rewritten from 0..N-1 in a single transaction on every
//! mutation (add / remove / reorder). Per-user favorite counts stay small,
//! so there is no point in fractional indexing.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::error::{AppError, ErrorCode};
use crate::rooms::{RoomResponse, build_favorites_response};
use crate::session::AuthUser;
use crate::state::AppState;
use crate::trust::load_distrust_set;

/// Maximum number of rooms a single user may favorite. Enforced in
/// `favorite_room`; the reorder endpoint accepts any set that equals the
/// current favorites so it does not need to re-check the cap.
pub const FAVORITES_CAP: i64 = 50;

// ---------------------------------------------------------------------------
// GET /api/me/favorites
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
pub struct FavoritesListResponse {
    pub rooms: Vec<RoomResponse>,
}

/// GET /api/me/favorites — list the user's favorite rooms in position order.
///
/// Returns the full viewer-enriched `RoomResponse` (sparkline, weekly
/// thread count, last visible activity) for each favorite so the
/// dedicated section at the top of `/rooms` can render without a
/// second round-trip. Rooms in the list have `favorited: true` by
/// construction.
pub async fn list_favorites(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let reader_uuid = user.uuid();
    let graph = state.get_trust_graph()?;
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;

    let rooms =
        build_favorites_response(&state.db, &user.user_id, &reverse_map, &distrust_set).await?;
    Ok(Json(FavoritesListResponse { rooms }))
}

// ---------------------------------------------------------------------------
// POST /api/rooms/:id/favorite
// ---------------------------------------------------------------------------

/// POST /api/rooms/:id/favorite — add a room to the user's favorites.
///
/// No-ops (204) if the room is already favorited. Enforces [`FAVORITES_CAP`]
/// before inserting. The new favorite is appended to the end of the user's
/// list (position = current count).
pub async fn favorite_room(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id_or_slug): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let room_id = resolve_room_id(&state.db, &id_or_slug).await?;

    // BEGIN IMMEDIATE serializes concurrent favorite/unfavorite calls
    // for the same user so the cap check and position assignment see a
    // consistent snapshot (two concurrent DEFERRED transactions could
    // both read count=N and both INSERT at position=N).
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    // Already favorited? Nothing to do.
    let existing = sqlx::query!(
        r#"SELECT room_id FROM room_favorites WHERE user_id = ? AND room_id = ?"#,
        user.user_id,
        room_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    if existing.is_some() {
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT);
    }

    // Enforce the cap before inserting.
    let count = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM room_favorites WHERE user_id = ?"#,
        user.user_id,
    )
    .fetch_one(&mut *tx)
    .await?
    .n;

    if count >= FAVORITES_CAP {
        return Err(AppError::code(ErrorCode::FavoriteCapExceeded));
    }

    sqlx::query!(
        "INSERT INTO room_favorites (user_id, room_id, position) VALUES (?, ?, ?)",
        user.user_id,
        room_id,
        count,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /api/rooms/:id/favorite
// ---------------------------------------------------------------------------

/// DELETE /api/rooms/:id/favorite — remove a room from favorites.
///
/// No-ops (204) if the room was not favorited. After removal, remaining
/// favorites are renumbered 0..N-1 to keep `position` dense. All mutations
/// happen in a single transaction.
pub async fn unfavorite_room(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id_or_slug): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let room_id = resolve_room_id(&state.db, &id_or_slug).await?;

    // BEGIN IMMEDIATE — see note on `favorite_room` and `reorder_favorites`.
    // Without it, a concurrent write could slip between the DELETE and the
    // position renumber and leave the list with duplicate positions.
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    let result = sqlx::query!(
        "DELETE FROM room_favorites WHERE user_id = ? AND room_id = ?",
        user.user_id,
        room_id,
    )
    .execute(&mut *tx)
    .await?;

    if result.rows_affected() > 0 {
        renumber_positions(&mut tx, &user.user_id).await?;
    }

    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// PUT /api/me/favorites
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ReorderFavoritesRequest {
    pub room_ids: Vec<String>,
}

/// PUT /api/me/favorites — replace the ordering of favorites.
///
/// Body: `{ "room_ids": ["<id>", ...] }` — the full ordered list of the
/// user's current favorite rooms. The submitted set must equal the user's
/// current favorite set exactly (same membership). If the client's view is
/// stale (e.g. a concurrent tab added or removed a favorite), the request
/// fails with [`ErrorCode::FavoriteSetMismatch`] (409) so the client can
/// refetch and retry with the correct set.
///
/// On success, positions are rewritten to match the request order.
pub async fn reorder_favorites(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<ReorderFavoritesRequest>,
) -> Result<impl IntoResponse, AppError> {
    // BEGIN IMMEDIATE grabs SQLite's RESERVED lock up front instead of
    // the default DEFERRED (which only takes SHARED until the first
    // write). Without this, another tab inserting or removing a favorite
    // between our SELECT and our UPDATEs can slip through the set-equality
    // check and corrupt the position ordering. IMMEDIATE makes concurrent
    // writers wait on `busy_timeout` so the read and the rewrites see a
    // single consistent snapshot.
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    // Fetch the user's current favorite room ids. Compared as a set
    // against the submitted room_ids to detect concurrent modifications.
    let current: Vec<String> = sqlx::query!(
        "SELECT room_id FROM room_favorites WHERE user_id = ?",
        user.user_id,
    )
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .map(|r| r.room_id)
    .collect();

    // Set equality: same length + same membership. We also reject
    // duplicates in the submitted list (via `sort + dedup` length check)
    // so a caller can't sneak a second copy of the same room into the
    // ordering and confuse the client.
    let mut sorted_current = current.clone();
    sorted_current.sort();

    let mut sorted_submitted = req.room_ids.clone();
    sorted_submitted.sort();
    sorted_submitted.dedup();

    if sorted_submitted.len() != req.room_ids.len() || sorted_submitted != sorted_current {
        return Err(AppError::code(ErrorCode::FavoriteSetMismatch));
    }

    // Rewrite positions in the submitted order. The PK is
    // `(user_id, room_id)` and there is no unique constraint on
    // `position`, so a straight per-row UPDATE can't collide.
    for (idx, room_id) in req.room_ids.iter().enumerate() {
        let pos = idx as i64;
        sqlx::query!(
            "UPDATE room_favorites SET position = ? WHERE user_id = ? AND room_id = ?",
            pos,
            user.user_id,
            room_id,
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Resolve a path parameter that may be either a room id or slug to
/// the canonical room id. Soft-deleted and merged rooms are treated as
/// non-existent. Returns [`ErrorCode::RoomNotFound`] if nothing matches.
async fn resolve_room_id(db: &sqlx::SqlitePool, id_or_slug: &str) -> Result<String, AppError> {
    sqlx::query!(
        "SELECT id FROM rooms \
         WHERE (id = ? OR slug = ?) AND merged_into IS NULL AND deleted_at IS NULL",
        id_or_slug,
        id_or_slug,
    )
    .fetch_optional(db)
    .await?
    .map(|r| r.id)
    .ok_or_else(|| AppError::code(ErrorCode::RoomNotFound))
}

/// Renumber a user's remaining favorites to 0..N-1 after a delete.
///
/// Reads the current rows ordered by existing position, then rewrites
/// each row to its new ordinal. Straight per-row UPDATEs are safe
/// because the PK is `(user_id, room_id)` and no unique index exists
/// on `position`.
async fn renumber_positions(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: &str,
) -> Result<(), sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT room_id FROM room_favorites WHERE user_id = ? ORDER BY position ASC",
        user_id,
    )
    .fetch_all(&mut **tx)
    .await?;

    for (idx, row) in rows.iter().enumerate() {
        let pos = idx as i64;
        sqlx::query!(
            "UPDATE room_favorites SET position = ? WHERE user_id = ? AND room_id = ?",
            pos,
            user_id,
            row.room_id,
        )
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}
