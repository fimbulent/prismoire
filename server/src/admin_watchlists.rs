//! Admin dashboard: moderation watchlists.
//!
//! Surfaces users that an operator may want to look at:
//! - Most Distrusted Users
//! - Highest Distrust:Trust Ratio
//! - Ban-Adjacent Trusters
//!
//! Already-banned users are excluded from every list — the watchlists
//! exist to help an admin find *candidates* for review, not to
//! re-litigate decisions that have already been made. Suspended users
//! are kept because suspension is a short-term signal that operators
//! may want to escalate to a ban. Self-deleted users
//! (`deleted_at IS NOT NULL`) are also excluded: the anonymised row
//! has no actionable identity left, so surfacing it to a moderator
//! serves no purpose.
//!
//! Each list is computed live per request against SQLite. The queries
//! are aggregations over `trust_edges` / `ban_trust_snapshots` and the
//! row cap is small (`LIMIT 20`), so "live" is fine at the scale we
//! run at today.
//!
//! TODO(caching): if any of these start showing up as slow on real
//! instances, wrap the aggregation results in an `Arc<RwLock<…>>` on
//! AppState with a short-lived (e.g. 60s) refresh, matching the
//! pattern used by the in-memory trust graph. The shape of the
//! response is intentionally stable across requests so a cache layer
//! can be dropped in without changing the handler or the frontend.
//!
//! Thresholds (minimum inbound distrusts, minimum total edges for the
//! ratio list, etc.) are defined as constants here and surfaced in
//! the JSON under `thresholds` so the frontend can quote them back to
//! the operator without duplicating the numbers.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Serialize;

use crate::admin::require_admin;
use crate::error::AppError;
use crate::session::AuthUser;
use crate::state::AppState;

/// Hard cap on rows returned per watchlist. The UI does not paginate;
/// operators drill into a user's profile page for more detail.
const LIMIT_PER_LIST: i64 = 20;

/// Hide users with only a single inbound distrust — at that level the
/// signal is too easily a personal feud rather than community-level
/// distrust.
const MIN_INBOUND_DISTRUSTS: i64 = 2;

/// For the distrust/trust ratio list, require at least this many
/// inbound trust+distrust edges total. Ratios over tiny samples
/// (1 distrust, 0 trusts → ∞) are noise.
const MIN_INBOUND_EDGES_FOR_RATIO: i64 = 5;

/// For the ban-adjacent list, require a user to have issued at least
/// this many outbound trusts total, so we aren't ranking users who
/// trusted one person who later got banned.
const MIN_TRUSTS_ISSUED_FOR_BAN_ADJACENT: i64 = 3;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Subset of user fields that every watchlist row carries — enough
/// for the UI to render a link, a status pill, and (where relevant)
/// ordering context.
#[derive(Serialize)]
pub struct UserChip {
    pub id: String,
    pub display_name: String,
    /// `"active"`, `"suspended"`, or `"banned"`.
    pub status: String,
}

#[derive(Serialize)]
pub struct DistrustedUserRow {
    pub user: UserChip,
    pub inbound_distrusts: i64,
    pub inbound_trusts: i64,
    /// `None` when `inbound_trusts == 0` — rendered as "∞" on the
    /// frontend.
    pub ratio: Option<f64>,
}

#[derive(Serialize)]
pub struct RatioRow {
    pub user: UserChip,
    pub inbound_distrusts: i64,
    pub inbound_trusts: i64,
    pub ratio: Option<f64>,
    pub post_count: i64,
    /// ISO-8601 UTC timestamp of account creation.
    pub joined_at: String,
}

#[derive(Serialize)]
pub struct BanAdjacentRow {
    pub user: UserChip,
    /// Distinct banned/suspended targets this user trusted at the
    /// moment the ban or suspend fired, counted from
    /// `ban_trust_snapshots`.
    pub banned_trusts: i64,
    /// Current outbound trust edges (`trust_edges.trust_type='trust'`).
    pub total_trusts: i64,
    /// `banned_trusts / total_trusts` in `[0, 1]`, or `None` when the
    /// user has zero current outbound trusts.
    pub hit_rate: Option<f64>,
}

#[derive(Serialize)]
pub struct Thresholds {
    pub min_inbound_distrusts: i64,
    pub min_inbound_edges_for_ratio: i64,
    pub min_trusts_issued_for_ban_adjacent: i64,
    pub limit_per_list: i64,
}

#[derive(Serialize)]
pub struct WatchlistsResponse {
    pub thresholds: Thresholds,
    pub most_distrusted: Vec<DistrustedUserRow>,
    pub distrust_trust_ratio: Vec<RatioRow>,
    pub ban_adjacent_trusters: Vec<BanAdjacentRow>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Build every watchlist in one request.
///
/// Each list is an independent aggregation; we run them sequentially
/// against the SQLite pool rather than fanning them out — SQLite
/// serializes writers anyway, and concurrent reads from the same pool
/// don't buy much at these row counts.
pub async fn get_watchlists(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    require_admin(&user)?;

    let most_distrusted = load_most_distrusted(&state.db).await?;
    let distrust_trust_ratio = load_distrust_trust_ratio(&state.db).await?;
    let ban_adjacent_trusters = load_ban_adjacent_trusters(&state.db).await?;

    Ok(Json(WatchlistsResponse {
        thresholds: Thresholds {
            min_inbound_distrusts: MIN_INBOUND_DISTRUSTS,
            min_inbound_edges_for_ratio: MIN_INBOUND_EDGES_FOR_RATIO,
            min_trusts_issued_for_ban_adjacent: MIN_TRUSTS_ISSUED_FOR_BAN_ADJACENT,
            limit_per_list: LIMIT_PER_LIST,
        },
        most_distrusted,
        distrust_trust_ratio,
        ban_adjacent_trusters,
    }))
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// Compute distrust:trust ratio, preserving `None` for divide-by-zero.
/// Kept as a helper so the two lists that use it stay consistent.
fn compute_ratio(distrusts: i64, trusts: i64) -> Option<f64> {
    if trusts == 0 {
        None
    } else {
        Some(distrusts as f64 / trusts as f64)
    }
}

async fn load_most_distrusted(db: &sqlx::SqlitePool) -> Result<Vec<DistrustedUserRow>, AppError> {
    // For each user that has received ≥ MIN_INBOUND_DISTRUSTS distrusts,
    // also count their inbound trusts. Left-joining the trust subquery
    // keeps users whose trust count is zero; COALESCE turns the NULL
    // into a 0 so the serialized row is clean.
    let rows = sqlx::query!(
        r#"
        SELECT
            u.id,
            u.display_name,
            u.status,
            d.distrusts AS "inbound_distrusts!: i64",
            COALESCE(t.trusts, 0) AS "inbound_trusts!: i64"
        FROM (
            SELECT target_user, COUNT(*) AS distrusts
            FROM trust_edges
            WHERE trust_type = 'distrust'
            GROUP BY target_user
            HAVING COUNT(*) >= ?1
        ) d
        JOIN users u ON u.id = d.target_user
        LEFT JOIN (
            SELECT target_user, COUNT(*) AS trusts
            FROM trust_edges
            WHERE trust_type = 'trust'
            GROUP BY target_user
        ) t ON t.target_user = d.target_user
        WHERE u.status != 'banned' AND u.deleted_at IS NULL
        ORDER BY d.distrusts DESC, u.display_name ASC
        LIMIT ?2
        "#,
        MIN_INBOUND_DISTRUSTS,
        LIMIT_PER_LIST,
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| DistrustedUserRow {
            user: UserChip {
                id: r.id,
                display_name: r.display_name,
                status: r.status,
            },
            inbound_distrusts: r.inbound_distrusts,
            inbound_trusts: r.inbound_trusts,
            ratio: compute_ratio(r.inbound_distrusts, r.inbound_trusts),
        })
        .collect())
}

async fn load_distrust_trust_ratio(db: &sqlx::SqlitePool) -> Result<Vec<RatioRow>, AppError> {
    // Ranks by ratio with a floor on total inbound volume so a single
    // distrust with zero trusts doesn't climb to the top. Ratio is
    // computed in SQL as a nullable CAST so ORDER BY puts the
    // divide-by-zero (infinite) rows first — that matches the
    // "∞ above any finite ratio" mockup ordering.
    //
    // Post count uses a correlated subquery that only counts
    // non-retracted posts, matching what we show on profile pages.
    let rows = sqlx::query!(
        r#"
        WITH inbound AS (
            SELECT
                target_user,
                SUM(CASE WHEN trust_type = 'distrust' THEN 1 ELSE 0 END) AS distrusts,
                SUM(CASE WHEN trust_type = 'trust' THEN 1 ELSE 0 END) AS trusts
            FROM trust_edges
            GROUP BY target_user
        )
        SELECT
            u.id,
            u.display_name,
            u.status,
            u.created_at,
            i.distrusts AS "inbound_distrusts!: i64",
            i.trusts AS "inbound_trusts!: i64",
            (SELECT COUNT(*) FROM posts p WHERE p.author = u.id AND p.retracted_at IS NULL) AS "post_count!: i64"
        FROM inbound i
        JOIN users u ON u.id = i.target_user
        WHERE (i.distrusts + i.trusts) >= ?1
          AND i.distrusts > 0
          AND u.status != 'banned'
          AND u.deleted_at IS NULL
        ORDER BY
            CASE WHEN i.trusts = 0 THEN 1 ELSE 0 END DESC,
            CAST(i.distrusts AS REAL) / NULLIF(i.trusts, 0) DESC,
            i.distrusts DESC
        LIMIT ?2
        "#,
        MIN_INBOUND_EDGES_FOR_RATIO,
        LIMIT_PER_LIST,
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| RatioRow {
            user: UserChip {
                id: r.id,
                display_name: r.display_name,
                status: r.status,
            },
            inbound_distrusts: r.inbound_distrusts,
            inbound_trusts: r.inbound_trusts,
            ratio: compute_ratio(r.inbound_distrusts, r.inbound_trusts),
            post_count: r.post_count,
            joined_at: r.created_at,
        })
        .collect())
}

async fn load_ban_adjacent_trusters(
    db: &sqlx::SqlitePool,
) -> Result<Vec<BanAdjacentRow>, AppError> {
    // `ban_trust_snapshots` logs every inbound-trust edge at the
    // moment a user was banned or suspended. Grouping by
    // `trusting_user` and counting distinct `target_user` values tells
    // us how many banned/suspended users this truster had endorsed.
    //
    // The denominator is the user's *current* outbound trusts — same
    // table (trust_edges) as everywhere else — so "hit rate" answers
    // "how much of this person's current endorsement has historically
    // pointed at abusers".
    //
    // MIN_TRUSTS_ISSUED_FOR_BAN_ADJACENT on total_trusts keeps the
    // list away from users who trusted one person who later got
    // banned — technically a 100% hit rate, but not meaningful.
    let rows = sqlx::query!(
        r#"
        WITH bans AS (
            SELECT trusting_user, COUNT(DISTINCT target_user) AS banned_trusts
            FROM ban_trust_snapshots
            GROUP BY trusting_user
        ),
        totals AS (
            SELECT source_user, COUNT(*) AS total_trusts
            FROM trust_edges
            WHERE trust_type = 'trust'
            GROUP BY source_user
        )
        SELECT
            u.id,
            u.display_name,
            u.status,
            b.banned_trusts AS "banned_trusts!: i64",
            COALESCE(t.total_trusts, 0) AS "total_trusts!: i64"
        FROM bans b
        JOIN users u ON u.id = b.trusting_user
        LEFT JOIN totals t ON t.source_user = b.trusting_user
        WHERE COALESCE(t.total_trusts, 0) >= ?1
          AND u.status != 'banned'
          AND u.deleted_at IS NULL
        ORDER BY
            CAST(b.banned_trusts AS REAL) / NULLIF(COALESCE(t.total_trusts, 0), 0) DESC,
            b.banned_trusts DESC,
            u.display_name ASC
        LIMIT ?2
        "#,
        MIN_TRUSTS_ISSUED_FOR_BAN_ADJACENT,
        LIMIT_PER_LIST,
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| BanAdjacentRow {
            user: UserChip {
                id: r.id,
                display_name: r.display_name,
                status: r.status,
            },
            banned_trusts: r.banned_trusts,
            total_trusts: r.total_trusts,
            hit_rate: if r.total_trusts == 0 {
                None
            } else {
                Some(r.banned_trusts as f64 / r.total_trusts as f64)
            },
        })
        .collect())
}
