use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::session::AuthUser;
use crate::state::AppState;
use crate::trust::{MINIMUM_TRUST_THRESHOLD, TrustInfo, TrustPath, load_distrust_set};

const MAX_BIO_LEN: usize = 500;
const ACTIVITY_PAGE_SIZE: i64 = 10;
const TRUST_LIST_PREVIEW: i64 = 5;
const TRUST_LIST_FETCH: i64 = 50;
const TRUST_LIST_MAX: i64 = 500;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct UserProfileResponse {
    pub display_name: String,
    pub created_at: String,
    pub signup_method: String,
    pub bio: Option<String>,
    pub role: String,
    pub is_self: bool,
    pub trust_stance: String,
    pub trust: TrustInfo,
    pub trust_score: Option<f64>,
}

#[derive(Serialize)]
pub struct TrustPathResponse {
    #[serde(rename = "type")]
    pub path_type: String,
    pub via: Option<TrustUserRef>,
    pub via2: Option<TrustUserRef>,
}

#[derive(Serialize)]
pub struct TrustUserRef {
    pub display_name: String,
    pub trust: TrustInfo,
}

#[derive(Serialize)]
pub struct ScoreReduction {
    pub display_name: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct TrustDetailResponse {
    pub trusts_given: i64,
    pub trusts_received: i64,
    pub distrusts_issued: i64,
    pub reads: u32,
    pub readers: u32,
    pub trust_score: Option<f64>,
    pub trust: TrustInfo,
    pub paths: Vec<TrustPathResponse>,
    pub score_reductions: Vec<ScoreReduction>,
    pub trusts: Vec<TrustEdgeUser>,
    pub trusts_total: i64,
    pub trusted_by: Vec<TrustEdgeUser>,
    pub trusted_by_total: i64,
}

#[derive(Serialize)]
pub struct TrustEdgeUser {
    pub display_name: String,
    pub trust: TrustInfo,
}

#[derive(Serialize)]
pub struct TrustEdgesResponse {
    pub users: Vec<TrustEdgeUser>,
    pub total: i64,
    pub capped: bool,
}

#[derive(Serialize)]
pub struct ActivityItem {
    #[serde(rename = "type")]
    pub activity_type: String,
    pub post_id: String,
    pub thread_id: String,
    pub thread_title: String,
    pub room_name: String,
    pub room_slug: String,
    pub body: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ActivityResponse {
    pub items: Vec<ActivityItem>,
    pub next_cursor: Option<String>,
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ActivityQuery {
    pub filter: Option<String>,
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct TrustEdgesQuery {
    pub direction: String,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpdateBioRequest {
    pub bio: Option<String>,
}

#[derive(Deserialize)]
pub struct SetTrustEdgeRequest {
    #[serde(rename = "type")]
    pub edge_type: TrustEdgeType,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum TrustEdgeType {
    Trust,
    Distrust,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Look up a user ID by display name, returning 404 if not found.
async fn resolve_user(
    db: &sqlx::SqlitePool,
    username: &str,
) -> Result<(String, String, String, String, Option<String>, String), AppError> {
    // Returns: (id, display_name, created_at, signup_method, bio, role)
    let row = sqlx::query_as::<_, (String, String, String, String, Option<String>, String)>(
        "SELECT id, display_name, created_at, signup_method, bio, role \
         FROM users WHERE display_name = ? AND status = 'active'",
    )
    .bind(username)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| AppError::NotFound("user not found".into()))?;
    Ok(row)
}

/// Look up the viewer's trust stance toward `target_user`.
/// Returns "trust", "distrust", or "neutral".
async fn get_trust_stance(
    db: &sqlx::SqlitePool,
    source_user: &str,
    target_user: &str,
) -> Result<String, AppError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT trust_type FROM trust_edges WHERE source_user = ? AND target_user = ?",
    )
    .bind(source_user)
    .bind(target_user)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(t,)| t).unwrap_or_else(|| "neutral".into()))
}

/// Build a UUID→display_name map for a set of UUIDs.
async fn resolve_display_names(
    db: &sqlx::SqlitePool,
    uuids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, String>, AppError> {
    let mut map = std::collections::HashMap::new();
    for uuid in uuids {
        let id_str = uuid.to_string();
        if let Some((name,)) =
            sqlx::query_as::<_, (String,)>("SELECT display_name FROM users WHERE id = ?")
                .bind(&id_str)
                .fetch_optional(db)
                .await?
        {
            map.insert(*uuid, name);
        }
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// GET /api/users/:username — Core profile
// ---------------------------------------------------------------------------

/// Returns basic user profile info, viewer relationship, and trust score.
pub async fn get_profile(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let (target_id, display_name, created_at, signup_method, bio, role) =
        resolve_user(&state.db, &username).await?;

    let is_self = user.user_id == target_id;
    let trust_stance = if is_self {
        "neutral".to_string()
    } else {
        get_trust_stance(&state.db, &user.user_id, &target_id).await?
    };
    let you_distrust = trust_stance == "distrust";

    let graph = state.get_trust_graph()?;
    let viewer_uuid =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::Internal("invalid user id".into()))?;
    let target_uuid =
        Uuid::parse_str(&target_id).map_err(|_| AppError::Internal("invalid user id".into()))?;

    let (trust_score, trust) = if is_self {
        (None, TrustInfo::self_trust())
    } else {
        match graph.trust_between(viewer_uuid, target_uuid) {
            Some((score, distance)) => (
                Some(score),
                TrustInfo {
                    distance,
                    distrusted: you_distrust,
                },
            ),
            None => (
                None,
                TrustInfo {
                    distance: None,
                    distrusted: you_distrust,
                },
            ),
        }
    };

    Ok(Json(UserProfileResponse {
        display_name,
        created_at,
        signup_method,
        bio,
        role,
        is_self,
        trust_stance,
        trust,
        trust_score,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/users/:username/trust — Trust details
// ---------------------------------------------------------------------------

/// Returns trust stats, paths, score reductions, and trust edge lists.
pub async fn get_trust_detail(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let (target_id, _display_name, ..) = resolve_user(&state.db, &username).await?;

    let is_self = user.user_id == target_id;

    // Trust stats
    let (trusts_given,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM trust_edges WHERE source_user = ? AND trust_type = 'trust'",
    )
    .bind(&target_id)
    .fetch_one(&state.db)
    .await?;

    let (trusts_received,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM trust_edges WHERE target_user = ? AND trust_type = 'trust'",
    )
    .bind(&target_id)
    .fetch_one(&state.db)
    .await?;

    let (distrusts_issued,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM trust_edges WHERE source_user = ? AND trust_type = 'distrust'",
    )
    .bind(&target_id)
    .fetch_one(&state.db)
    .await?;

    let graph = state.get_trust_graph()?;
    let viewer_uuid =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::Internal("invalid user id".into()))?;
    let target_uuid =
        Uuid::parse_str(&target_id).map_err(|_| AppError::Internal("invalid user id".into()))?;

    // Single forward BFS from viewer — used for trust_between, distance_map, and path enrichment.
    let viewer_scores = graph.forward_scores(viewer_uuid);

    let mut distance_map: HashMap<String, f64> = viewer_scores
        .into_iter()
        .map(|s| (s.target_user.to_string(), s.distance))
        .collect();
    // The viewer isn't included in their own distance map; pin them at 0 so
    // they sort first rather than falling through to f64::MAX (untrusted).
    distance_map.insert(user.user_id.clone(), 0.0);

    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;
    let you_distrust = !is_self && distrust_set.contains(&target_id);

    // When the viewer has distrusted the target, trust is fixed at 0 — skip
    // paths and score reductions since they have no effect.
    let (trust_score, trust, paths, score_reductions) = if is_self || you_distrust {
        let trust = if is_self {
            TrustInfo::self_trust()
        } else {
            TrustInfo {
                distance: None,
                distrusted: true,
            }
        };
        (None, trust, Vec::new(), Vec::new())
    } else {
        let (score, distance) = graph
            .trust_between(viewer_uuid, target_uuid)
            .map(|(s, d)| (Some(s), d))
            .unwrap_or((None, None));

        let raw_paths = graph.paths_to(viewer_uuid, target_uuid);

        let intermediary_uuids: Vec<Uuid> = raw_paths
            .iter()
            .flat_map(|p| match p {
                TrustPath::Direct => vec![],
                TrustPath::TwoHop { via } => vec![*via],
                TrustPath::ThreeHop { via1, via2 } => vec![*via1, *via2],
            })
            .collect();

        let name_map = resolve_display_names(&state.db, &intermediary_uuids).await?;

        let built_paths: Vec<TrustPathResponse> = raw_paths
            .into_iter()
            .map(|p| match p {
                TrustPath::Direct => TrustPathResponse {
                    path_type: "direct".into(),
                    via: None,
                    via2: None,
                },
                TrustPath::TwoHop { via } => {
                    let id = via.to_string();
                    TrustPathResponse {
                        path_type: "2hop".into(),
                        via: Some(TrustUserRef {
                            display_name: name_map
                                .get(&via)
                                .cloned()
                                .unwrap_or_else(|| "unknown".into()),
                            trust: TrustInfo::build(&id, &distance_map, &distrust_set),
                        }),
                        via2: None,
                    }
                }
                TrustPath::ThreeHop { via1, via2 } => {
                    let id1 = via1.to_string();
                    let id2 = via2.to_string();
                    TrustPathResponse {
                        path_type: "3hop".into(),
                        via: Some(TrustUserRef {
                            display_name: name_map
                                .get(&via1)
                                .cloned()
                                .unwrap_or_else(|| "unknown".into()),
                            trust: TrustInfo::build(&id1, &distance_map, &distrust_set),
                        }),
                        via2: Some(TrustUserRef {
                            display_name: name_map
                                .get(&via2)
                                .cloned()
                                .unwrap_or_else(|| "unknown".into()),
                            trust: TrustInfo::build(&id2, &distance_map, &distrust_set),
                        }),
                    }
                }
            })
            .collect();

        let reductions = sqlx::query_as::<_, (String,)>(
            "SELECT u.display_name FROM trust_edges te \
             JOIN users u ON u.id = te.target_user \
             WHERE te.source_user = ? AND te.trust_type = 'trust' \
             AND te.target_user IN (SELECT target_user FROM trust_edges WHERE source_user = ? AND trust_type = 'distrust')",
        )
        .bind(&target_id)
        .bind(&user.user_id)
        .fetch_all(&state.db)
        .await?
        .into_iter()
        .map(|(name,)| ScoreReduction {
            display_name: name,
            reason: "distrusted by you".into(),
        })
        .collect();

        (
            score,
            TrustInfo {
                distance,
                distrusted: false,
            },
            built_paths,
            reductions,
        )
    };

    // Trust edge lists: who this user trusts / trusted by
    // Fetch all edges, sort by viewer's trust distance (closest first), then alphabetically.
    let sort_trust_edges = |mut edges: Vec<TrustEdgeUser>| -> Vec<TrustEdgeUser> {
        edges.sort_by(|a, b| {
            let da = a.trust.distance.unwrap_or(f64::MAX);
            let db = b.trust.distance.unwrap_or(f64::MAX);
            da.partial_cmp(&db)
                .unwrap()
                .then_with(|| a.display_name.cmp(&b.display_name))
        });
        edges
    };

    let trusts_batch = sqlx::query_as::<_, (String, String)>(
        "SELECT u.display_name, u.id FROM trust_edges te \
         JOIN users u ON u.id = te.target_user \
         WHERE te.source_user = ? AND te.trust_type = 'trust' \
         ORDER BY te.created_at DESC LIMIT ?",
    )
    .bind(&target_id)
    .bind(TRUST_LIST_FETCH)
    .fetch_all(&state.db)
    .await?;

    let (trusts_total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM trust_edges WHERE source_user = ? AND trust_type = 'trust'",
    )
    .bind(&target_id)
    .fetch_one(&state.db)
    .await?;

    let trusts: Vec<TrustEdgeUser> = sort_trust_edges(
        trusts_batch
            .into_iter()
            .map(|(name, uid)| TrustEdgeUser {
                trust: TrustInfo::build(&uid, &distance_map, &distrust_set),
                display_name: name,
            })
            .collect(),
    )
    .into_iter()
    .take(TRUST_LIST_PREVIEW as usize)
    .collect();

    let trusted_by_batch = sqlx::query_as::<_, (String, String)>(
        "SELECT u.display_name, u.id FROM trust_edges te \
         JOIN users u ON u.id = te.source_user \
         WHERE te.target_user = ? AND te.trust_type = 'trust' \
         ORDER BY te.created_at DESC LIMIT ?",
    )
    .bind(&target_id)
    .bind(TRUST_LIST_FETCH)
    .fetch_all(&state.db)
    .await?;

    let (trusted_by_total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM trust_edges WHERE target_user = ? AND trust_type = 'trust'",
    )
    .bind(&target_id)
    .fetch_one(&state.db)
    .await?;

    let trusted_by: Vec<TrustEdgeUser> = sort_trust_edges(
        trusted_by_batch
            .into_iter()
            .map(|(name, uid)| TrustEdgeUser {
                trust: TrustInfo::build(&uid, &distance_map, &distrust_set),
                display_name: name,
            })
            .collect(),
    )
    .into_iter()
    .take(TRUST_LIST_PREVIEW as usize)
    .collect();

    let reads = graph.reads_count(target_uuid, MINIMUM_TRUST_THRESHOLD);
    let readers = graph.readers_count(target_uuid, MINIMUM_TRUST_THRESHOLD);

    Ok(Json(TrustDetailResponse {
        trusts_given,
        trusts_received,
        distrusts_issued,
        reads,
        readers,
        trust_score,
        trust,
        paths,
        score_reductions,
        trusts,
        trusts_total,
        trusted_by,
        trusted_by_total,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/users/:username/activity — Paginated activity
// ---------------------------------------------------------------------------

/// Returns paginated recent activity (threads started and replies).
//
// TODO: pagination cursor is `p.created_at` with strict `<` comparison,
// which is broken when multiple posts share the same timestamp: ties
// aren't deterministically ordered so rows can be dropped entirely, and
// if a single timestamp has more than ACTIVITY_PAGE_SIZE rows the cursor
// fails to advance and the client loops on the same page. Switch to a
// compound cursor of `(created_at, post_id)` using a tuple comparison
// (`WHERE (p.created_at, p.id) < (?, ?) ORDER BY p.created_at DESC, p.id
// DESC`) so the next-page filter excludes exactly the rows already seen.
pub async fn get_activity(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(username): Path<String>,
    Query(query): Query<ActivityQuery>,
) -> Result<impl IntoResponse, AppError> {
    let (target_id, ..) = resolve_user(&state.db, &username).await?;

    let filter = query.filter.as_deref().unwrap_or("all");
    let cursor = query.cursor.as_deref().unwrap_or("");

    let type_filter = match filter {
        "threads" => "AND p.parent IS NULL",
        "comments" => "AND p.parent IS NOT NULL",
        _ => "",
    };

    let cursor_filter = if cursor.is_empty() {
        ""
    } else {
        "AND p.created_at < ?"
    };

    let sql = format!(
        "SELECT \
           CASE WHEN p.parent IS NULL THEN 'thread_started' ELSE 'replied' END AS activity_type, \
           p.id AS post_id, \
           t.id AS thread_id, \
           t.title AS thread_title, \
           r.name AS room_name, \
           r.slug AS room_slug, \
           pr.body AS body, \
           p.created_at \
         FROM posts p \
         JOIN threads t ON t.id = p.thread \
         JOIN rooms r ON r.id = t.room \
         JOIN post_revisions pr ON pr.post_id = p.id AND pr.revision = p.revision_count - 1 \
         WHERE p.author = ? AND p.retracted_at IS NULL \
           {type_filter} {cursor_filter} \
         ORDER BY p.created_at DESC \
         LIMIT ?",
    );

    let mut query = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        ),
    >(&sql)
    .bind(&target_id);
    if !cursor.is_empty() {
        query = query.bind(cursor);
    }
    let rows = query
        .bind(ACTIVITY_PAGE_SIZE + 1)
        .fetch_all(&state.db)
        .await?;

    let has_more = rows.len() as i64 > ACTIVITY_PAGE_SIZE;
    let items: Vec<ActivityItem> = rows
        .into_iter()
        .take(ACTIVITY_PAGE_SIZE as usize)
        .map(
            |(
                activity_type,
                post_id,
                thread_id,
                thread_title,
                room_name,
                room_slug,
                body,
                created_at,
            )| {
                ActivityItem {
                    activity_type,
                    post_id,
                    thread_id,
                    thread_title,
                    room_name,
                    room_slug,
                    body,
                    created_at: created_at.clone(),
                }
            },
        )
        .collect();

    let next_cursor = if has_more {
        items.last().map(|item| item.created_at.clone())
    } else {
        None
    };

    Ok(Json(ActivityResponse { items, next_cursor }))
}

// ---------------------------------------------------------------------------
// GET /api/users/:username/trust/edges — Full trust edge list
// ---------------------------------------------------------------------------

/// Returns the full list of trust edges for a user (capped at 500),
/// sorted by viewer's trust distance (closest first), then alphabetically.
pub async fn get_trust_edges(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(username): Path<String>,
    Query(query): Query<TrustEdgesQuery>,
) -> Result<impl IntoResponse, AppError> {
    let (target_id, ..) = resolve_user(&state.db, &username).await?;

    let graph = state.get_trust_graph()?;
    let viewer_uuid =
        Uuid::parse_str(&user.user_id).map_err(|_| AppError::Internal("invalid user id".into()))?;
    let cached_dm = graph.distance_map(viewer_uuid);
    // The viewer isn't included in their own distance map; pin them at 0 so
    // they sort first rather than falling through to f64::MAX (untrusted).
    // TODO: Avoid cloning the entire cached map just to insert one entry.
    //  Check for the viewer's own ID inline at lookup sites instead.
    let mut distance_map = HashMap::clone(&cached_dm);
    distance_map.insert(user.user_id.clone(), 0.0);

    let (rows, total) = match query.direction.as_str() {
        "trusts" => {
            let rows = sqlx::query_as::<_, (String, String)>(
                "SELECT u.display_name, u.id FROM trust_edges te \
                 JOIN users u ON u.id = te.target_user \
                 WHERE te.source_user = ? AND te.trust_type = 'trust'",
            )
            .bind(&target_id)
            .fetch_all(&state.db)
            .await?;
            let total = rows.len() as i64;
            (rows, total)
        }
        "trusted_by" => {
            let rows = sqlx::query_as::<_, (String, String)>(
                "SELECT u.display_name, u.id FROM trust_edges te \
                 JOIN users u ON u.id = te.source_user \
                 WHERE te.target_user = ? AND te.trust_type = 'trust'",
            )
            .bind(&target_id)
            .fetch_all(&state.db)
            .await?;
            let total = rows.len() as i64;
            (rows, total)
        }
        _ => {
            return Err(AppError::BadRequest(
                "direction must be 'trusts' or 'trusted_by'".into(),
            ));
        }
    };

    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;

    let mut users: Vec<TrustEdgeUser> = rows
        .into_iter()
        .map(|(name, uid)| {
            let trust = TrustInfo::build(&uid, &distance_map, &distrust_set);
            TrustEdgeUser {
                display_name: name,
                trust,
            }
        })
        .collect();

    users.sort_by(|a, b| {
        let da = a.trust.distance.unwrap_or(f64::MAX);
        let db = b.trust.distance.unwrap_or(f64::MAX);
        da.partial_cmp(&db)
            .unwrap()
            .then_with(|| a.display_name.cmp(&b.display_name))
    });

    let capped = total > TRUST_LIST_MAX;
    users.truncate(TRUST_LIST_MAX as usize);

    Ok(Json(TrustEdgesResponse {
        users,
        total,
        capped,
    }))
}

// ---------------------------------------------------------------------------
// PATCH /api/users/:username — Update bio
// ---------------------------------------------------------------------------

/// Update the authenticated user's bio. Only allowed on own profile.
pub async fn update_bio(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(username): Path<String>,
    Json(req): Json<UpdateBioRequest>,
) -> Result<impl IntoResponse, AppError> {
    if user.display_name != username {
        return Err(AppError::Unauthorized(
            "can only edit your own profile".into(),
        ));
    }

    let bio = req.bio.as_deref().map(str::trim);
    if let Some(b) = bio
        && b.len() > MAX_BIO_LEN
    {
        return Err(AppError::BadRequest(format!(
            "bio must be at most {MAX_BIO_LEN} characters"
        )));
    }

    let bio_value = bio.filter(|b| !b.is_empty());

    sqlx::query("UPDATE users SET bio = ? WHERE id = ?")
        .bind(bio_value)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// PUT /api/users/:username/trust-edge — Set trust or distrust
// ---------------------------------------------------------------------------

/// Set a trust or distrust edge. Replaces any existing edge atomically.
pub async fn set_trust_edge(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(username): Path<String>,
    Json(req): Json<SetTrustEdgeRequest>,
) -> Result<impl IntoResponse, AppError> {
    let (target_id, ..) = resolve_user(&state.db, &username).await?;

    if user.user_id == target_id {
        return Err(AppError::BadRequest(
            "cannot set trust edge on yourself".into(),
        ));
    }

    let trust_type = match req.edge_type {
        TrustEdgeType::Trust => "trust",
        TrustEdgeType::Distrust => "distrust",
    };

    let mut tx = state.db.begin().await?;

    sqlx::query("DELETE FROM trust_edges WHERE source_user = ? AND target_user = ?")
        .bind(&user.user_id)
        .bind(&target_id)
        .execute(&mut *tx)
        .await?;

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO trust_edges (id, source_user, target_user, trust_type) VALUES (?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&target_id)
    .bind(trust_type)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    state.trust_graph_notify.notify_one();

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /api/users/:username/trust-edge — Remove trust edge (go neutral)
// ---------------------------------------------------------------------------

/// Remove any trust/distrust edge from the viewer to this user.
pub async fn delete_trust_edge(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let (target_id, ..) = resolve_user(&state.db, &username).await?;

    let result = sqlx::query("DELETE FROM trust_edges WHERE source_user = ? AND target_user = ?")
        .bind(&user.user_id)
        .bind(&target_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("no trust edge to remove".into()));
    }

    state.trust_graph_notify.notify_one();

    Ok(StatusCode::NO_CONTENT)
}
