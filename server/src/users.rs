use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::display_name::display_name_skeleton;
use crate::error::{AppError, ErrorCode};
use crate::session::{AuthUser, RestrictedAuthUser};
use crate::state::AppState;
use crate::trust::{MINIMUM_TRUST_THRESHOLD, TrustInfo, TrustPath, UserStatus, load_distrust_set};

/// Hard upper bound on how many users a single search request can return.
/// Acts as both the default and the clamp for caller-supplied `limit`.
const USER_SEARCH_MAX: i64 = 20;

/// Restricted (banned/suspended) users may only interact with their own
/// profile. Endpoints that accept a `:username` path parameter call this
/// before the main query to reject cross-user access with 403.
///
/// The comparison is on `display_name` because that is the identifier in
/// the URL path. Display names are unique (enforced by both a UNIQUE
/// constraint and the `display_name_skeleton` index) and not renameable,
/// so an exact-string match is a sufficient identity check. If display-
/// name renaming is ever introduced, switch to a user-id comparison
/// (resolve the URL username to an id and compare against `user.user_id`).
fn enforce_self_only_for_restricted(
    user: &RestrictedAuthUser,
    username: &str,
) -> Result<(), AppError> {
    if !user.status.is_active() && user.display_name != username {
        return Err(AppError::code(ErrorCode::Forbidden));
    }
    Ok(())
}

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
    pub id: String,
    pub display_name: String,
    pub created_at: String,
    pub signup_method: String,
    pub bio: Option<String>,
    pub role: String,
    pub is_self: bool,
    pub can_invite: bool,
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
    pub room_slug: String,
    pub body: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ActivityResponse {
    pub items: Vec<ActivityItem>,
    pub next_cursor: Option<String>,
    /// True when the viewer is an admin and the non-admin codepath would have
    /// returned fewer rows (i.e. the admin's own trust graph doesn't grant
    /// them full visibility of this profile). Drives the "you're viewing as
    /// an admin" notice on the frontend. Never set for self-views or when
    /// the admin has regular reverse-trust access.
    pub admin_override: bool,
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

/// Look up a user by display name, returning 404 if not found.
///
/// Returns `(id, display_name, created_at, signup_method, bio, role, status)`.
/// Does not filter by status — callers decide how to handle banned/suspended users.
async fn resolve_user(
    db: &sqlx::SqlitePool,
    username: &str,
) -> Result<
    (
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        UserStatus,
        bool,
    ),
    AppError,
> {
    let row = sqlx::query!(
        r#"SELECT id, display_name, created_at, signup_method, bio, role, status,
                  can_invite AS "can_invite!: bool", deleted_at
             FROM users WHERE display_name = ?"#,
        username,
    )
    .fetch_optional(db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::UserNotFound))?;
    let raw_status = UserStatus::try_from(row.status.as_str()).map_err(|e| {
        eprintln!("{e}");
        AppError::code(ErrorCode::Internal)
    })?;
    let status = UserStatus::effective(raw_status, row.deleted_at.as_deref());
    Ok((
        row.id,
        row.display_name,
        row.created_at,
        row.signup_method,
        row.bio,
        row.role,
        status,
        row.can_invite,
    ))
}

/// Look up the viewer's trust stance toward `target_user`.
/// Returns "trust", "distrust", or "neutral".
async fn get_trust_stance(
    db: &sqlx::SqlitePool,
    source_user: &str,
    target_user: &str,
) -> Result<String, AppError> {
    let row = sqlx::query!(
        "SELECT trust_type FROM trust_edges WHERE source_user = ? AND target_user = ?",
        source_user,
        target_user,
    )
    .fetch_optional(db)
    .await?;
    Ok(row
        .map(|r| r.trust_type)
        .unwrap_or_else(|| "neutral".into()))
}

/// Build a UUID→(display_name, effective_status) map for a set of UUIDs.
///
/// Effective status is the wire-facing projection: a user whose
/// `deleted_at` is set surfaces as `UserStatus::Deleted` regardless of
/// what `users.status` says. See [`UserStatus::effective`].
async fn resolve_display_names(
    db: &sqlx::SqlitePool,
    uuids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, (String, UserStatus)>, AppError> {
    let mut map = std::collections::HashMap::new();
    for uuid in uuids {
        let id_str = uuid.to_string();
        if let Some(row) = sqlx::query!(
            "SELECT display_name, status, deleted_at FROM users WHERE id = ?",
            id_str,
        )
        .fetch_optional(db)
        .await?
        {
            let raw = UserStatus::try_from(row.status.as_str()).unwrap_or(UserStatus::Active);
            let status = UserStatus::effective(raw, row.deleted_at.as_deref());
            map.insert(*uuid, (row.display_name, status));
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
    user: RestrictedAuthUser,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    enforce_self_only_for_restricted(&user, &username)?;

    let (target_id, display_name, created_at, signup_method, bio, role, target_status, can_invite) =
        resolve_user(&state.db, &username).await?;

    let is_self = user.user_id == target_id;
    let trust_stance = if is_self {
        "neutral".to_string()
    } else {
        get_trust_stance(&state.db, &user.user_id, &target_id).await?
    };
    let you_distrust = trust_stance == "distrust";

    let graph = state.get_trust_graph()?;
    let viewer_uuid = user.uuid();
    let target_uuid = Uuid::parse_str(&target_id).map_err(|_| {
        eprintln!("invalid target user id: {target_id}");
        AppError::code(ErrorCode::Internal)
    })?;

    let (trust_score, trust) = if is_self {
        (None, TrustInfo::self_trust())
    } else {
        match graph.trust_between(viewer_uuid, target_uuid) {
            Some((score, distance)) => (
                Some(score),
                TrustInfo {
                    distance,
                    distrusted: you_distrust,
                    status: target_status,
                },
            ),
            None => (
                None,
                TrustInfo {
                    distance: None,
                    distrusted: you_distrust,
                    status: target_status,
                },
            ),
        }
    };

    Ok(Json(UserProfileResponse {
        id: target_id,
        display_name,
        created_at,
        signup_method,
        bio,
        role,
        is_self,
        can_invite,
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
    user: RestrictedAuthUser,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    enforce_self_only_for_restricted(&user, &username)?;

    let (target_id, _display_name, _, _, _, _, target_status, _) =
        resolve_user(&state.db, &username).await?;

    let is_self = user.user_id == target_id;

    // Trust stats
    let trusts_given = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM trust_edges WHERE source_user = ? AND trust_type = 'trust'"#,
        target_id,
    )
    .fetch_one(&state.db)
    .await?
    .n;

    let trusts_received = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM trust_edges WHERE target_user = ? AND trust_type = 'trust'"#,
        target_id,
    )
    .fetch_one(&state.db)
    .await?
    .n;

    let distrusts_issued = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM trust_edges WHERE source_user = ? AND trust_type = 'distrust'"#,
        target_id,
    )
    .fetch_one(&state.db)
    .await?
    .n;

    let graph = state.get_trust_graph()?;
    let viewer_uuid = user.uuid();
    let target_uuid = Uuid::parse_str(&target_id).map_err(|_| {
        eprintln!("invalid target user id: {target_id}");
        AppError::code(ErrorCode::Internal)
    })?;

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
                status: target_status,
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
                    let (vname, vstatus) = name_map
                        .get(&via)
                        .cloned()
                        .unwrap_or_else(|| ("unknown".into(), UserStatus::Active));
                    TrustPathResponse {
                        path_type: "2hop".into(),
                        via: Some(TrustUserRef {
                            display_name: vname,
                            trust: TrustInfo::build(&id, &distance_map, &distrust_set, vstatus),
                        }),
                        via2: None,
                    }
                }
                TrustPath::ThreeHop { via1, via2 } => {
                    let id1 = via1.to_string();
                    let id2 = via2.to_string();
                    let (v1name, v1status) = name_map
                        .get(&via1)
                        .cloned()
                        .unwrap_or_else(|| ("unknown".into(), UserStatus::Active));
                    let (v2name, v2status) = name_map
                        .get(&via2)
                        .cloned()
                        .unwrap_or_else(|| ("unknown".into(), UserStatus::Active));
                    TrustPathResponse {
                        path_type: "3hop".into(),
                        via: Some(TrustUserRef {
                            display_name: v1name,
                            trust: TrustInfo::build(&id1, &distance_map, &distrust_set, v1status),
                        }),
                        via2: Some(TrustUserRef {
                            display_name: v2name,
                            trust: TrustInfo::build(&id2, &distance_map, &distrust_set, v2status),
                        }),
                    }
                }
            })
            .collect();

        let reductions = sqlx::query!(
            "SELECT u.display_name FROM trust_edges te \
             JOIN users u ON u.id = te.target_user \
             WHERE te.source_user = ? AND te.trust_type = 'trust' \
             AND te.target_user IN (SELECT target_user FROM trust_edges WHERE source_user = ? AND trust_type = 'distrust')",
            target_id,
            user.user_id,
        )
        .fetch_all(&state.db)
        .await?
        .into_iter()
        .map(|r| ScoreReduction {
            display_name: r.display_name,
            reason: "distrusted by you".into(),
        })
        .collect();

        (
            score,
            TrustInfo {
                distance,
                distrusted: false,
                status: target_status,
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

    let trusts_batch = sqlx::query!(
        "SELECT u.display_name, u.id, u.status, u.deleted_at FROM trust_edges te \
         JOIN users u ON u.id = te.target_user \
         WHERE te.source_user = ? AND te.trust_type = 'trust' \
         ORDER BY te.created_at DESC LIMIT ?",
        target_id,
        TRUST_LIST_FETCH,
    )
    .fetch_all(&state.db)
    .await?;

    let trusts_total = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM trust_edges WHERE source_user = ? AND trust_type = 'trust'"#,
        target_id,
    )
    .fetch_one(&state.db)
    .await?
    .n;

    let trusts: Vec<TrustEdgeUser> = sort_trust_edges(
        trusts_batch
            .into_iter()
            .map(|r| {
                let raw = UserStatus::try_from(r.status.as_str()).unwrap_or(UserStatus::Active);
                TrustEdgeUser {
                    trust: TrustInfo::build(
                        &r.id,
                        &distance_map,
                        &distrust_set,
                        UserStatus::effective(raw, r.deleted_at.as_deref()),
                    ),
                    display_name: r.display_name,
                }
            })
            .collect(),
    )
    .into_iter()
    .take(TRUST_LIST_PREVIEW as usize)
    .collect();

    let trusted_by_batch = sqlx::query!(
        "SELECT u.display_name, u.id, u.status, u.deleted_at FROM trust_edges te \
         JOIN users u ON u.id = te.source_user \
         WHERE te.target_user = ? AND te.trust_type = 'trust' \
         ORDER BY te.created_at DESC LIMIT ?",
        target_id,
        TRUST_LIST_FETCH,
    )
    .fetch_all(&state.db)
    .await?;

    let trusted_by_total = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM trust_edges WHERE target_user = ? AND trust_type = 'trust'"#,
        target_id,
    )
    .fetch_one(&state.db)
    .await?
    .n;

    let trusted_by: Vec<TrustEdgeUser> = sort_trust_edges(
        trusted_by_batch
            .into_iter()
            .map(|r| {
                let raw = UserStatus::try_from(r.status.as_str()).unwrap_or(UserStatus::Active);
                TrustEdgeUser {
                    trust: TrustInfo::build(
                        &r.id,
                        &distance_map,
                        &distrust_set,
                        UserStatus::effective(raw, r.deleted_at.as_deref()),
                    ),
                    display_name: r.display_name,
                }
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
    user: RestrictedAuthUser,
    Path(username): Path<String>,
    Query(query): Query<ActivityQuery>,
) -> Result<impl IntoResponse, AppError> {
    enforce_self_only_for_restricted(&user, &username)?;

    let (target_id, ..) = resolve_user(&state.db, &username).await?;

    // Trust-gated visibility: the activity feed exposes post bodies, so it must
    // respect the author-trust-in-reader rule. Because every row shares the
    // same author, the per-post check collapses to one question asked once:
    //
    //   - Self-view → show everything.
    //   - Reverse trust from the target meets threshold → show everything.
    //   - Admin whose own trust graph wouldn't grant access → show everything
    //     via the admin carve-out, and flag `admin_override` so the frontend
    //     can surface a notice that the viewer is seeing content a normal
    //     user wouldn't. Admins need the bypass for investigating users whose
    //     trust network excludes them (e.g. an isolated sybil clique).
    //   - Otherwise → fall back to the reply-visibility grant: only show
    //     replies whose direct parent was authored by the viewer. The grant
    //     is a per-content exception to the author-trust rule (spec §
    //     "Reply visibility grant"), so the viewer can see replies to their
    //     own posts even from a low-trust author.
    let is_self = user.user_id == target_id;

    // Distrust short-circuit: if the viewer distrusts the target, the target's
    // content (and any subtrees rooted there) is pruned from the viewer's
    // world per spec §"Distrust action UX". The profile endpoint already
    // surfaces `trust_stance = "distrust"` so the frontend can show the
    // "You have distrusted this user" banner; here we just return an empty
    // activity feed so no items leak through.
    if !is_self {
        let stance = get_trust_stance(&state.db, &user.user_id, &target_id).await?;
        if stance == "distrust" {
            return Ok(Json(ActivityResponse {
                items: Vec::new(),
                next_cursor: None,
                admin_override: false,
            }));
        }
    }

    let reverse_trust_ok = if is_self {
        true
    } else {
        let viewer_uuid = user.uuid();
        let graph = state.get_trust_graph()?;
        let reverse_map = graph.reverse_score_map(viewer_uuid);
        reverse_map
            .get(&target_id)
            .is_some_and(|s| *s >= MINIMUM_TRUST_THRESHOLD)
    };
    let admin_override = !reverse_trust_ok && !is_self && user.is_admin();
    let full_visibility = reverse_trust_ok || admin_override;

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

    // Reply-grant fallback: inner-join the parent post and constrain it to
    // the viewer. The inner join drops thread-start rows (parent IS NULL)
    // automatically, which matches the grant's scope — top-level threads
    // don't have a parent author to ground the exception on.
    let (grant_join, grant_filter) = if full_visibility {
        ("", "")
    } else {
        (
            "JOIN posts parent_post ON parent_post.id = p.parent",
            "AND parent_post.author = ?",
        )
    };

    let sql = format!(
        "SELECT \
           CASE WHEN p.parent IS NULL THEN 'thread_started' ELSE 'replied' END AS activity_type, \
           p.id AS post_id, \
           t.id AS thread_id, \
           t.title AS thread_title, \
           r.slug AS room_slug, \
           pr.body AS body, \
           p.created_at \
         FROM posts p \
         JOIN threads t ON t.id = p.thread \
         JOIN rooms r ON r.id = t.room \
         JOIN post_revisions pr ON pr.post_id = p.id AND pr.revision = p.revision_count - 1 \
         {grant_join} \
         WHERE p.author = ? AND p.retracted_at IS NULL \
           {type_filter} {cursor_filter} {grant_filter} \
         ORDER BY p.created_at DESC \
         LIMIT ?",
    );

    // Runtime-checked rather than `sqlx::query_as!`: the SQL is assembled
    // from `format!` across filter / cursor / grant_join variants (12
    // combinations), and the macro requires a static SQL literal. A
    // `QueryBuilder` refactor would tighten the parameter-binding safety
    // here but still wouldn't unlock compile-time schema checking.
    let mut query =
        sqlx::query_as::<_, (String, String, String, String, String, String, String)>(&sql)
            .bind(&target_id);
    if !cursor.is_empty() {
        query = query.bind(cursor);
    }
    if !full_visibility {
        query = query.bind(&user.user_id);
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
            |(activity_type, post_id, thread_id, thread_title, room_slug, body, created_at)| {
                ActivityItem {
                    activity_type,
                    post_id,
                    thread_id,
                    thread_title,
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

    Ok(Json(ActivityResponse {
        items,
        next_cursor,
        admin_override,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/users/:username/trust/edges — Full trust edge list
// ---------------------------------------------------------------------------

/// Returns the full list of trust edges for a user (capped at 500),
/// sorted by viewer's trust distance (closest first), then alphabetically.
pub async fn get_trust_edges(
    State(state): State<Arc<AppState>>,
    user: RestrictedAuthUser,
    Path(username): Path<String>,
    Query(query): Query<TrustEdgesQuery>,
) -> Result<impl IntoResponse, AppError> {
    enforce_self_only_for_restricted(&user, &username)?;

    let (target_id, ..) = resolve_user(&state.db, &username).await?;

    let graph = state.get_trust_graph()?;
    let viewer_uuid = user.uuid();
    let cached_dm = graph.distance_map(viewer_uuid);
    // The viewer isn't included in their own distance map; pin them at 0 so
    // they sort first rather than falling through to f64::MAX (untrusted).
    // TODO: Avoid cloning the entire cached map just to insert one entry.
    //  Check for the viewer's own ID inline at lookup sites instead.
    let mut distance_map = HashMap::clone(&cached_dm);
    distance_map.insert(user.user_id.clone(), 0.0);

    struct EdgeRow {
        display_name: String,
        id: String,
        status: String,
        deleted_at: Option<String>,
    }

    let rows: Vec<EdgeRow> = match query.direction.as_str() {
        "trusts" => sqlx::query!(
            "SELECT u.display_name, u.id, u.status, u.deleted_at FROM trust_edges te \
             JOIN users u ON u.id = te.target_user \
             WHERE te.source_user = ? AND te.trust_type = 'trust'",
            target_id,
        )
        .fetch_all(&state.db)
        .await?
        .into_iter()
        .map(|r| EdgeRow {
            display_name: r.display_name,
            id: r.id,
            status: r.status,
            deleted_at: r.deleted_at,
        })
        .collect(),
        "trusted_by" => sqlx::query!(
            "SELECT u.display_name, u.id, u.status, u.deleted_at FROM trust_edges te \
             JOIN users u ON u.id = te.source_user \
             WHERE te.target_user = ? AND te.trust_type = 'trust'",
            target_id,
        )
        .fetch_all(&state.db)
        .await?
        .into_iter()
        .map(|r| EdgeRow {
            display_name: r.display_name,
            id: r.id,
            status: r.status,
            deleted_at: r.deleted_at,
        })
        .collect(),
        _ => {
            return Err(AppError::code(ErrorCode::InvalidTrustDirection));
        }
    };
    let total = rows.len() as i64;

    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;

    let mut users: Vec<TrustEdgeUser> = rows
        .into_iter()
        .map(|r| {
            let raw = UserStatus::try_from(r.status.as_str()).unwrap_or(UserStatus::Active);
            let status = UserStatus::effective(raw, r.deleted_at.as_deref());
            let trust = TrustInfo::build(&r.id, &distance_map, &distrust_set, status);
            TrustEdgeUser {
                display_name: r.display_name,
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
        return Err(AppError::code(ErrorCode::NotOwnProfile));
    }

    let bio = req.bio.as_deref().map(str::trim);
    if let Some(b) = bio
        && b.len() > MAX_BIO_LEN
    {
        return Err(AppError::with_message(
            ErrorCode::BioTooLong,
            format!("bio must be at most {MAX_BIO_LEN} characters"),
        ));
    }

    let bio_value = bio.filter(|b| !b.is_empty());

    sqlx::query!(
        "UPDATE users SET bio = ? WHERE id = ?",
        bio_value,
        user.user_id,
    )
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
        return Err(AppError::code(ErrorCode::SelfTrustEdge));
    }

    let trust_type = match req.edge_type {
        TrustEdgeType::Trust => "trust",
        TrustEdgeType::Distrust => "distrust",
    };

    let mut tx = state.db.begin().await?;

    sqlx::query!(
        "DELETE FROM trust_edges WHERE source_user = ? AND target_user = ?",
        user.user_id,
        target_id,
    )
    .execute(&mut *tx)
    .await?;

    let id = Uuid::new_v4().to_string();
    sqlx::query!(
        "INSERT INTO trust_edges (id, source_user, target_user, trust_type) VALUES (?, ?, ?, ?)",
        id,
        user.user_id,
        target_id,
        trust_type,
    )
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

    let result = sqlx::query!(
        "DELETE FROM trust_edges WHERE source_user = ? AND target_user = ?",
        user.user_id,
        target_id,
    )
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::code(ErrorCode::NoTrustEdge));
    }

    state.trust_graph_notify.notify_one();

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /api/users/search — Display-name autocomplete
// ---------------------------------------------------------------------------

/// Lightweight user chip returned by the search endpoint. Carries just
/// enough to render an autocomplete dropdown row and drive the "selected
/// user" preview card — callers who need the full profile should fetch
/// `GET /api/users/:username` after the user picks a row.
#[derive(Serialize)]
pub struct UserChip {
    pub id: String,
    pub display_name: String,
    pub status: String,
    pub role: String,
}

#[derive(Serialize)]
pub struct UserSearchResponse {
    pub users: Vec<UserChip>,
}

#[derive(Deserialize)]
pub struct UserSearchQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// GET /api/users/search?q=&limit= — prefix-match search over active users.
///
/// **Admin-only.** The response carries moderation status and role,
/// and a prefix walk would trivially enumerate the user base — both
/// of which are information the broader authenticated user population
/// has no business seeing. Gate here until a non-admin caller
/// justifies widening the surface (and at that point the response
/// shape needs to be trimmed too).
///
/// Matches against `display_name_skeleton`, the confusable-safe
/// canonical form stored alongside each display name, so searches are
/// resilient to case differences and visually-similar characters.
/// Returns at most `USER_SEARCH_MAX` rows, ordered by exact match
/// first, then shortest name (shorter names tend to be the one the
/// user is aiming for when the prefix is short).
///
/// Deleted users are excluded; banned/suspended users are included so
/// admins performing moderation can still target them from the
/// autocomplete.
pub async fn search_users(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<UserSearchQuery>,
) -> Result<impl IntoResponse, AppError> {
    crate::admin::require_admin(&user)?;
    let limit = q
        .limit
        .unwrap_or(USER_SEARCH_MAX / 2)
        .clamp(1, USER_SEARCH_MAX);
    let query = q.q.unwrap_or_default().trim().to_string();

    if query.is_empty() {
        return Ok(Json(UserSearchResponse { users: Vec::new() }));
    }

    // Match on the skeleton so a user searching for "Alice" finds
    // "аlice" (Cyrillic 'а') and vice-versa. The skeleton of the query
    // is lowercased and confusable-folded the same way the stored
    // column is, so a simple `LIKE 'prefix%'` is sufficient.
    let skeleton = display_name_skeleton(&query);
    let pattern = format!(
        "{}%",
        skeleton
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    );

    let rows = sqlx::query!(
        r#"SELECT id, display_name, status, role
         FROM users
         WHERE deleted_at IS NULL
           AND display_name_skeleton LIKE ? ESCAPE '\'
         ORDER BY
           (display_name_skeleton = ?) DESC,
           LENGTH(display_name),
           display_name
         LIMIT ?"#,
        pattern,
        skeleton,
        limit,
    )
    .fetch_all(&state.db)
    .await?;

    let users = rows
        .into_iter()
        .map(|r| {
            // `deleted_at IS NULL` is enforced by the WHERE clause, so
            // the effective status here is the raw column value. Fall
            // back to "active" on any unexpected value rather than
            // surfacing a 500.
            let status = UserStatus::try_from(r.status.as_str()).unwrap_or(UserStatus::Active);
            let status_wire = match status {
                UserStatus::Active => "active",
                UserStatus::Banned => "banned",
                UserStatus::Suspended => "suspended",
                UserStatus::Deleted => "deleted",
            };
            UserChip {
                id: r.id,
                display_name: r.display_name,
                status: status_wire.to_string(),
                role: r.role,
            }
        })
        .collect();

    Ok(Json(UserSearchResponse { users }))
}
