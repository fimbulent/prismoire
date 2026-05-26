use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::display_name::display_name_skeleton;
use crate::error::{AppError, ErrorCode};
use crate::search::{
    MoreSearchRequest, PAGE_SIZE, SUBSTRING_OVERSAMPLE, decode_offset_cursor, encode_offset_cursor,
    escape_like, validate_query_length, validate_seen_ids,
};
use crate::session::{AuthUser, RestrictedAuthUser};
use crate::state::AppState;
use crate::trust::{
    MINIMUM_TRUST_THRESHOLD, TrustPath, TrustStance, UserStatus, UserViewerInfo, load_distrust_set,
    load_tag_map,
};
use unicode_segmentation::UnicodeSegmentation;

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
    pub viewer: UserViewerInfo,
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
    pub viewer: UserViewerInfo,
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
    pub viewer: UserViewerInfo,
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
    pub viewer: UserViewerInfo,
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
    /// Attachments bound to the post's latest revision. Empty for
    /// replies (which can't carry attachments per `docs/attachments.md`
    /// §3) and for thread-OP posts with none; omitted from JSON in that
    /// case so the activity payload stays compact.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<crate::threads::AttachmentResponse>,
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
        tracing::error!(username = %username, error = %e, "unrecognised users.status");
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
        "SELECT trust_type FROM current_trust_edges WHERE source_user = ? AND target_user = ?",
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
        tracing::error!(target_id = %target_id, "invalid target user id");
        AppError::code(ErrorCode::Internal)
    })?;

    let target_tag = if is_self {
        None
    } else {
        sqlx::query!(
            "SELECT tag FROM user_tags WHERE viewer_id = ? AND target_id = ?",
            user.user_id,
            target_id,
        )
        .fetch_optional(&state.db)
        .await?
        .map(|r| r.tag)
    };

    let viewer_delta = state.pending_deltas.get(viewer_uuid);
    let (trust_score, trust) = if is_self {
        (None, UserViewerInfo::self_view())
    } else {
        match graph.trust_between_with_delta(viewer_uuid, target_uuid, &viewer_delta) {
            Some((score, distance)) => (
                Some(score),
                UserViewerInfo {
                    distance,
                    distrusted: you_distrust,
                    status: target_status,
                    tag: target_tag,
                },
            ),
            None => (
                None,
                UserViewerInfo {
                    distance: None,
                    distrusted: you_distrust,
                    status: target_status,
                    tag: target_tag,
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
        viewer: trust,
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
        r#"SELECT COUNT(*) AS "n!: i64" FROM current_trust_edges WHERE source_user = ? AND trust_type = 'trust'"#,
        target_id,
    )
    .fetch_one(&state.db)
    .await?
    .n;

    let trusts_received = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM current_trust_edges WHERE target_user = ? AND trust_type = 'trust'"#,
        target_id,
    )
    .fetch_one(&state.db)
    .await?
    .n;

    let distrusts_issued = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM current_trust_edges WHERE source_user = ? AND trust_type = 'distrust'"#,
        target_id,
    )
    .fetch_one(&state.db)
    .await?
    .n;

    let graph = state.get_trust_graph()?;
    let viewer_uuid = user.uuid();
    let target_uuid = Uuid::parse_str(&target_id).map_err(|_| {
        tracing::error!(target_id = %target_id, "invalid target user id");
        AppError::code(ErrorCode::Internal)
    })?;

    let viewer_delta = state.pending_deltas.get(viewer_uuid);

    // Single forward BFS from viewer — used for trust_between, distance_map, and path enrichment.
    let viewer_scores = graph.forward_scores_with_delta(viewer_uuid, &viewer_delta);

    let mut distance_map: HashMap<Uuid, f32> = viewer_scores
        .into_iter()
        .map(|s| (s.target_user, s.distance as f32))
        .collect();
    // The viewer isn't included in their own distance map; pin them at 0 so
    // they sort first rather than falling through to f64::MAX (untrusted).
    distance_map.insert(viewer_uuid, 0.0);

    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;
    let tag_map = load_tag_map(&state.db, &user.user_id).await?;
    let you_distrust = !is_self && distrust_set.contains(&target_id);

    // When the viewer has distrusted the target, trust is fixed at 0 — skip
    // paths and score reductions since they have no effect.
    let (trust_score, trust, paths, score_reductions) = if is_self || you_distrust {
        let trust = if is_self {
            UserViewerInfo::self_view()
        } else {
            UserViewerInfo {
                distance: None,
                distrusted: true,
                status: target_status,
                tag: tag_map.get(&target_id).cloned(),
            }
        };
        (None, trust, Vec::new(), Vec::new())
    } else {
        let (score, distance) = graph
            .trust_between_with_delta(viewer_uuid, target_uuid, &viewer_delta)
            .map(|(s, d)| (Some(s), d))
            .unwrap_or((None, None));

        let raw_paths = graph.paths_to_with_delta(viewer_uuid, target_uuid, &viewer_delta);

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
                            viewer: UserViewerInfo::build(
                                &id,
                                &distance_map,
                                &distrust_set,
                                &tag_map,
                                vstatus,
                            ),
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
                            viewer: UserViewerInfo::build(
                                &id1,
                                &distance_map,
                                &distrust_set,
                                &tag_map,
                                v1status,
                            ),
                        }),
                        via2: Some(TrustUserRef {
                            display_name: v2name,
                            viewer: UserViewerInfo::build(
                                &id2,
                                &distance_map,
                                &distrust_set,
                                &tag_map,
                                v2status,
                            ),
                        }),
                    }
                }
            })
            .collect();

        let reductions = sqlx::query!(
            "SELECT u.display_name FROM current_trust_edges te \
             JOIN users u ON u.id = te.target_user \
             WHERE te.source_user = ? AND te.trust_type = 'trust' \
             AND te.target_user IN (SELECT target_user FROM current_trust_edges WHERE source_user = ? AND trust_type = 'distrust')",
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
            UserViewerInfo {
                distance,
                distrusted: false,
                status: target_status,
                tag: tag_map.get(&target_id).cloned(),
            },
            built_paths,
            reductions,
        )
    };

    // Trust edge lists: who this user trusts / trusted by
    // Fetch all edges, sort by viewer's trust distance (closest first), then alphabetically.
    let sort_trust_edges = |mut edges: Vec<TrustEdgeUser>| -> Vec<TrustEdgeUser> {
        edges.sort_by(|a, b| {
            let da = a.viewer.distance.unwrap_or(f64::MAX);
            let db = b.viewer.distance.unwrap_or(f64::MAX);
            da.partial_cmp(&db)
                .unwrap()
                .then_with(|| a.display_name.cmp(&b.display_name))
        });
        edges
    };

    let trusts_batch = sqlx::query!(
        "SELECT u.display_name, u.id, u.status, u.deleted_at FROM current_trust_edges te \
         JOIN users u ON u.id = te.target_user \
         WHERE te.source_user = ? AND te.trust_type = 'trust' \
         ORDER BY te.created_at DESC LIMIT ?",
        target_id,
        TRUST_LIST_FETCH,
    )
    .fetch_all(&state.db)
    .await?;

    let trusts_total = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM current_trust_edges WHERE source_user = ? AND trust_type = 'trust'"#,
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
                    viewer: UserViewerInfo::build(
                        &r.id,
                        &distance_map,
                        &distrust_set,
                        &tag_map,
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
        "SELECT u.display_name, u.id, u.status, u.deleted_at FROM current_trust_edges te \
         JOIN users u ON u.id = te.source_user \
         WHERE te.target_user = ? AND te.trust_type = 'trust' \
         ORDER BY te.created_at DESC LIMIT ?",
        target_id,
        TRUST_LIST_FETCH,
    )
    .fetch_all(&state.db)
    .await?;

    let trusted_by_total = sqlx::query!(
        r#"SELECT COUNT(*) AS "n!: i64" FROM current_trust_edges WHERE target_user = ? AND trust_type = 'trust'"#,
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
                    viewer: UserViewerInfo::build(
                        &r.id,
                        &distance_map,
                        &distrust_set,
                        &tag_map,
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
        viewer: trust,
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
        crate::trust::lookup_score(&reverse_map, &target_id)
            .is_some_and(|s| s >= MINIMUM_TRUST_THRESHOLD)
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
    let page_rows: Vec<_> = rows.into_iter().take(ACTIVITY_PAGE_SIZE as usize).collect();

    // Second pass: pull the latest-revision attachment set for every
    // post on this page so the frontend can resolve `![](filename)` refs
    // in the rendered activity body. Reply rows yield empty entries
    // (they can't carry attachments per docs/attachments.md §3), so the
    // join cost stays proportional to OP rows in the page.
    let post_ids: Vec<String> = page_rows.iter().map(|r| r.1.clone()).collect();
    let mut attachments_map =
        crate::threads::fetch_latest_attachments(&state.db, &post_ids).await?;

    let items: Vec<ActivityItem> = page_rows
        .into_iter()
        .map(
            |(activity_type, post_id, thread_id, thread_title, room_slug, body, created_at)| {
                let attachments = attachments_map.remove(&post_id).unwrap_or_default();
                ActivityItem {
                    activity_type,
                    post_id,
                    thread_id,
                    thread_title,
                    room_slug,
                    body,
                    created_at: created_at.clone(),
                    attachments,
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
    let viewer_delta = state.pending_deltas.get(viewer_uuid);
    let cached_dm = graph.distance_map_with_delta(viewer_uuid, &viewer_delta);
    // The viewer isn't included in their own distance map; pin them at 0 so
    // they sort first rather than falling through to f64::MAX (untrusted).
    // TODO: Avoid cloning the entire cached map just to insert one entry.
    //  Check for the viewer's own ID inline at lookup sites instead.
    let mut distance_map = HashMap::clone(&cached_dm);
    distance_map.insert(viewer_uuid, 0.0);

    struct EdgeRow {
        display_name: String,
        id: String,
        status: String,
        deleted_at: Option<String>,
    }

    let rows: Vec<EdgeRow> = match query.direction.as_str() {
        "trusts" => sqlx::query!(
            "SELECT u.display_name, u.id, u.status, u.deleted_at FROM current_trust_edges te \
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
            "SELECT u.display_name, u.id, u.status, u.deleted_at FROM current_trust_edges te \
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
    let tag_map = load_tag_map(&state.db, &user.user_id).await?;

    let mut users: Vec<TrustEdgeUser> = rows
        .into_iter()
        .map(|r| {
            let raw = UserStatus::try_from(r.status.as_str()).unwrap_or(UserStatus::Active);
            let status = UserStatus::effective(raw, r.deleted_at.as_deref());
            let trust =
                UserViewerInfo::build(&r.id, &distance_map, &distrust_set, &tag_map, status);
            TrustEdgeUser {
                display_name: r.display_name,
                viewer: trust,
            }
        })
        .collect();

    users.sort_by(|a, b| {
        let da = a.viewer.distance.unwrap_or(f64::MAX);
        let db = b.viewer.distance.unwrap_or(f64::MAX);
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
///
/// Bio mutations are profile revisions in the signed-object model
/// Every successful update appends one `profile` signed object: a
/// snapshot of the `(display_name, bio, avatar)` tuple at the new
/// bio value. The `display_name` is read fresh from the DB inside
/// the transaction so the snapshot can't drift against a stale
/// auth-user cache, even though display_name is currently immutable
/// post-signup.
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
    // The signed `profile` payload binds `bio` as a required text
    // field (empty string permitted). Project the nullable-DB value
    // onto the empty string for signing so absent bio and explicit
    // empty bio produce the same canonical bytes and the same hash-chain
    // head.
    let bio_for_payload: &str = bio_value.unwrap_or("");

    let now_dt = chrono::Utc::now();
    let created_at_ms = u64::try_from(now_dt.timestamp_millis()).map_err(|_| {
        tracing::error!(
            ts_ms = now_dt.timestamp_millis(),
            "system clock is pre-1970; cannot sign profile revision"
        );
        AppError::code(ErrorCode::Internal)
    })?;

    // BEGIN IMMEDIATE: serializes concurrent profile mutations for the
    // same user so the prior-hash lookup and the new INSERT see a
    // consistent snapshot. Two writers racing on the same user's bio
    // would otherwise both read the same `prior_profile_hash` and
    // fork the signed chain (identical pathology to the trust-edge
    // chain — see `set_trust_edge`).
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    sqlx::query!(
        "UPDATE users SET bio = ? WHERE id = ?",
        bio_value,
        user.user_id,
    )
    .execute(&mut *tx)
    .await?;

    // Read display_name fresh inside the tx (see fn doc). users.id is
    // PK and the row must exist — the auth layer already proved it.
    let user_row = sqlx::query!("SELECT display_name FROM users WHERE id = ?", user.user_id,)
        .fetch_one(&mut *tx)
        .await?;

    let prior_hash = crate::signing::compute_prior_profile_hash(&mut *tx, &user.user_id).await?;

    let signed = crate::signing::sign_profile_revision(
        &mut *tx,
        &user.user_id,
        &user_row.display_name,
        bio_for_payload,
        None,
        created_at_ms,
        prior_hash,
    )
    .await?;
    let payload = signed.payload;
    let signature = signed.signature;
    let canonical_hash = signed.canonical_hash;
    let prior_hash_db: Option<Vec<u8>> = prior_hash.map(|h| h.to_vec());
    let canonical_hash_db: Vec<u8> = canonical_hash.to_vec();
    let created_at_ms_db = i64::try_from(created_at_ms).map_err(|_| {
        tracing::error!(
            created_at_ms,
            "profile revision created_at_ms does not fit in i64"
        );
        AppError::code(ErrorCode::Internal)
    })?;

    let id = Uuid::new_v4().to_string();
    sqlx::query!(
        "INSERT INTO profile_revisions \
            (id, user_id, display_name, bio, avatar_attachment_hash, created_at, \
             signature, prior_profile_hash, canonical_hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        id,
        user.user_id,
        user_row.display_name,
        bio_for_payload,
        None::<Vec<u8>>,
        created_at_ms_db,
        signature,
        prior_hash_db,
        canonical_hash_db,
    )
    .execute(&mut *tx)
    .await?;

    crate::signing::store_signed_object(&mut *tx, "profile", &payload, &signature, &canonical_hash)
        .await?;

    tx.commit().await?;

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
    let (target_id, .., status, _) = resolve_user(&state.db, &username).await?;

    // Refuse trust-edge mutation toward a soft-deleted user. In practice
    // `soft_delete_user` anonymizes the display_name so this path is
    // hard to hit by username, but the check guarantees we never produce
    // a signed edge toward a tombstoned identity (which the signing
    // layer also refuses defensively — see `SignError::TargetDeleted`).
    // Returns `UserNotFound` rather than a distinct code so we don't
    // leak the prior existence of the deleted account. Banned and
    // suspended users are *not* rejected: they can be unbanned/
    // unsuspended, and the relationship should persist across that.
    if status == UserStatus::Deleted {
        return Err(AppError::code(ErrorCode::UserNotFound));
    }

    if user.user_id == target_id {
        return Err(AppError::code(ErrorCode::SelfTrustEdge));
    }

    let (trust_type, new_stance, signed_stance) = match req.edge_type {
        TrustEdgeType::Trust => (
            "trust",
            TrustStance::Trust,
            crate::signed::TrustStance::Trust,
        ),
        TrustEdgeType::Distrust => (
            "distrust",
            TrustStance::Distrust,
            crate::signed::TrustStance::Distrust,
        ),
    };

    // Snapshot the cached graph's current view of this edge before
    // committing. The pending-delta entry needs the cached "before"
    // state to know whether this mutation is an add, a remove, or a
    // flip — see `PendingDeltas::apply`.
    let viewer_uuid = user.uuid();
    let target_uuid = Uuid::parse_str(&target_id).map_err(|_| {
        tracing::error!(target_id = %target_id, "invalid target user id");
        AppError::code(ErrorCode::Internal)
    })?;
    let (cached_was_trust, cached_was_distrust) = {
        let graph = state.get_trust_graph()?;
        (
            graph.has_trust_edge(viewer_uuid, target_uuid),
            graph.has_distrust_edge(viewer_uuid, target_uuid),
        )
    };

    // Producer-side timestamp truncated to whole seconds so the signed
    // millisecond value is reconstructable from the persisted ISO-second
    // value. See create_thread.rs for the longer rationale.
    let now_dt = chrono::Utc::now();
    let now_iso = now_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let created_at_ms = u64::try_from(now_dt.timestamp()).map_err(|_| {
        tracing::error!(
            ts = now_dt.timestamp(),
            "system clock is pre-1970; cannot sign trust-edge"
        );
        AppError::code(ErrorCode::Internal)
    })? * 1000;

    // BEGIN IMMEDIATE: serializes concurrent set/delete on the same
    // pair so the prior-hash lookup and the new INSERT see a
    // consistent snapshot. Without this, two writers could both read
    // the same prior_edge_hash and fork the signed chain — invisible
    // until federation/audit replay (the latest-wins view hides the
    // fork).
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    // Append-only log (Option C): look up the prior signed object for
    // this pair so the new mutation chains to it per §4.3. `None`
    // when this is the first signed mutation for the pair (legacy
    // unsigned priors are skipped — see `compute_prior_edge_hash`).
    let prior_hash =
        crate::signing::compute_prior_edge_hash(&mut *tx, &user.user_id, &target_id).await?;

    let signed = crate::signing::sign_trust_edge(
        &mut tx,
        &user.user_id,
        &target_id,
        signed_stance,
        created_at_ms,
        prior_hash,
    )
    .await?;
    let payload = signed.payload;
    let signature = signed.signature;
    let canonical_hash = signed.canonical_hash;
    let prior_hash_db: Option<Vec<u8>> = prior_hash.map(|h| h.to_vec());
    let canonical_hash_db: Vec<u8> = canonical_hash.to_vec();

    let id = Uuid::new_v4().to_string();
    sqlx::query!(
        "INSERT INTO trust_edges (id, source_user, target_user, trust_type, created_at, signature, prior_edge_hash, canonical_hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        id,
        user.user_id,
        target_id,
        trust_type,
        now_iso,
        signature,
        prior_hash_db,
        canonical_hash_db,
    )
    .execute(&mut *tx)
    .await?;

    // Dual-write the canonical trust-edge bytes into `signed_objects`
    // alongside the projection insert.
    crate::signing::store_signed_object(
        &mut *tx,
        "trust-edge",
        &payload,
        &signature,
        &canonical_hash,
    )
    .await?;

    tx.commit().await?;

    // Record the mutation in the pending-deltas store *after* the commit
    // so the seq counter only advances for durably persisted edges. The
    // rebuild loop's high-water purge relies on this ordering.
    state.pending_deltas.apply(
        viewer_uuid,
        target_uuid,
        cached_was_trust,
        cached_was_distrust,
        new_stance,
    );

    state.trust_graph_notify.notify_one();

    // §7.5 originator-side fanout. The signer is `signed.public_key`
    // (== the viewer's own pubkey). `arrived_from = None` since this
    // is locally-originated. The forwarder spawns its own task and
    // returns immediately, so local request latency is unaffected.
    let wire = crate::federation::envelope::encode_signed_object(&payload, &signature);
    crate::federation::forwarder::forward_signed_object(
        state.clone(),
        canonical_hash,
        crate::federation::routing::ForwardingClass::TrustEdge,
        signed.public_key.to_vec(),
        wire,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /api/users/:username/trust-edge — Go neutral (signed tombstone)
// ---------------------------------------------------------------------------

/// Move the viewer's stance toward this user to `neutral`.
///
/// Append-only log (Option C): instead of removing the row, append a
/// signed `stance = "neutral"` row that chains via `prior_edge_hash`
/// to the prior row for this pair. The `current_trust_edges` view
/// filters out neutral rows, so the trust graph immediately sees no
/// edge.
///
/// Rejects with `NoTrustEdge` if there's no active (non-neutral)
/// edge to revoke — i.e., either no prior row exists or the latest
/// row is already neutral. The semantic check happens against the
/// `current_trust_edges` view, so latest-wins resolution agrees with
/// what the user sees in the UI.
pub async fn delete_trust_edge(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let (target_id, .., status, _) = resolve_user(&state.db, &username).await?;

    // See `set_trust_edge` for the rationale. Deleted users can't be
    // the target of any trust-edge mutation, including a neutral
    // tombstone: their trust state is moot post-deletion and the
    // signing layer would refuse anyway.
    if status == UserStatus::Deleted {
        return Err(AppError::code(ErrorCode::UserNotFound));
    }

    // Snapshot the cached graph's current view of this edge before
    // committing. See `set_trust_edge` for the rationale.
    let viewer_uuid = user.uuid();
    let target_uuid = Uuid::parse_str(&target_id).map_err(|_| {
        tracing::error!(target_id = %target_id, "invalid target user id");
        AppError::code(ErrorCode::Internal)
    })?;
    let (cached_was_trust, cached_was_distrust) = {
        let graph = state.get_trust_graph()?;
        (
            graph.has_trust_edge(viewer_uuid, target_uuid),
            graph.has_distrust_edge(viewer_uuid, target_uuid),
        )
    };

    // Producer-side timestamp truncated to whole seconds so the
    // signed millisecond value is reconstructable from the persisted
    // ISO-second value. See create_thread.rs.
    let now_dt = chrono::Utc::now();
    let now_iso = now_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let created_at_ms = u64::try_from(now_dt.timestamp()).map_err(|_| {
        tracing::error!(
            ts = now_dt.timestamp(),
            "system clock is pre-1970; cannot sign trust-edge neutral"
        );
        AppError::code(ErrorCode::Internal)
    })? * 1000;

    // BEGIN IMMEDIATE — see `set_trust_edge` for rationale. The
    // active-edge check, prior-hash lookup, and INSERT all need to
    // see the same snapshot so two concurrent deletes can't both
    // issue tombstones chained to the same prior.
    let mut tx = state.db.begin_with("BEGIN IMMEDIATE").await?;

    // Refuse to issue a neutral tombstone when nothing is active —
    // surfaces as a 404-ish to the client and avoids growing the log
    // with no-op rows. Checks the view, not the underlying table, so
    // a `neutral`-then-`neutral` sequence rejects the second one.
    let active = sqlx::query!(
        "SELECT 1 AS \"present!: i64\" FROM current_trust_edges \
         WHERE source_user = ? AND target_user = ?",
        user.user_id,
        target_id,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if active.is_none() {
        return Err(AppError::code(ErrorCode::NoTrustEdge));
    }

    // Chain to the prior signed object for this pair. The active
    // check above already established at least one prior row exists,
    // so `compute_prior_edge_hash` will return `Some` whenever that
    // prior row was signed; a legacy unsigned prior (rare and dev-
    // only) yields `None` and starts a fresh chain.
    let prior_hash =
        crate::signing::compute_prior_edge_hash(&mut *tx, &user.user_id, &target_id).await?;

    let signed = crate::signing::sign_trust_edge(
        &mut tx,
        &user.user_id,
        &target_id,
        crate::signed::TrustStance::Neutral,
        created_at_ms,
        prior_hash,
    )
    .await?;
    let payload = signed.payload;
    let signature = signed.signature;
    let canonical_hash = signed.canonical_hash;
    let prior_hash_db: Option<Vec<u8>> = prior_hash.map(|h| h.to_vec());
    let canonical_hash_db: Vec<u8> = canonical_hash.to_vec();

    let id = Uuid::new_v4().to_string();
    sqlx::query!(
        "INSERT INTO trust_edges (id, source_user, target_user, trust_type, created_at, signature, prior_edge_hash, canonical_hash) \
         VALUES (?, ?, ?, 'neutral', ?, ?, ?, ?)",
        id,
        user.user_id,
        target_id,
        now_iso,
        signature,
        prior_hash_db,
        canonical_hash_db,
    )
    .execute(&mut *tx)
    .await?;

    // Dual-write the canonical tombstone bytes into `signed_objects`
    // alongside the projection insert.
    crate::signing::store_signed_object(
        &mut *tx,
        "trust-edge",
        &payload,
        &signature,
        &canonical_hash,
    )
    .await?;

    // Erasure: a `neutral` trust-edge is an erasure authority over
    // every prior signed object in the (source, target) chain. NULL
    // their canonical payload bytes while retaining the canonical
    // hashes so chain walks across the erased history still resolve.
    // The neutral row we just wrote is excluded by canonical_hash.
    crate::signing::erase_trust_edge_chain(&mut *tx, &user.user_id, &target_id, &canonical_hash)
        .await?;

    tx.commit().await?;

    state.pending_deltas.apply(
        viewer_uuid,
        target_uuid,
        cached_was_trust,
        cached_was_distrust,
        TrustStance::Neutral,
    );

    state.trust_graph_notify.notify_one();

    // §7.5 originator-side fanout for the neutral tombstone. See the
    // `set_trust_edge` analogue above for the rationale; tombstones
    // are §9.1 erasure-authority objects so peers MUST observe them
    // alongside the active trust-edges they erase.
    let wire = crate::federation::envelope::encode_signed_object(&payload, &signature);
    crate::federation::forwarder::forward_signed_object(
        state.clone(),
        canonical_hash,
        crate::federation::routing::ForwardingClass::TrustEdge,
        signed.public_key.to_vec(),
        wire,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// PUT /api/users/:username/tag — Set viewer-private tag for another user
// ---------------------------------------------------------------------------

/// Maximum tag length in grapheme clusters (user-perceived characters).
const MAX_TAG_GRAPHEMES: usize = 35;

#[derive(Deserialize)]
pub struct SetUserTagRequest {
    pub tag: String,
}

/// Set or update the viewer's private tag for another user.
///
/// Tags are strictly viewer-scoped — the tagged user is never told. An
/// empty (or whitespace-only) `tag` field deletes the tag (so the
/// frontend can use a single PUT for both edits and clears). Length is
/// measured in grapheme clusters so emoji and combining marks count as
/// one each.
pub async fn set_user_tag(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(username): Path<String>,
    Json(req): Json<SetUserTagRequest>,
) -> Result<impl IntoResponse, AppError> {
    let (target_id, ..) = resolve_user(&state.db, &username).await?;

    if user.user_id == target_id {
        return Err(AppError::code(ErrorCode::SelfTag));
    }

    // Strip control characters (incl. CR/LF) so a tag can't smuggle in
    // line breaks that would mess up inline rendering. Tabs are dropped
    // for the same reason.
    let cleaned: String = req
        .tag
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();

    if cleaned.is_empty() {
        sqlx::query!(
            "DELETE FROM user_tags WHERE viewer_id = ? AND target_id = ?",
            user.user_id,
            target_id,
        )
        .execute(&state.db)
        .await?;
        return Ok(StatusCode::NO_CONTENT);
    }

    if cleaned.graphemes(true).count() > MAX_TAG_GRAPHEMES {
        return Err(AppError::with_message(
            ErrorCode::TagTooLong,
            format!("tag must be at most {MAX_TAG_GRAPHEMES} characters"),
        ));
    }

    sqlx::query!(
        "INSERT INTO user_tags (viewer_id, target_id, tag) VALUES (?, ?, ?) \
         ON CONFLICT(viewer_id, target_id) DO UPDATE SET \
             tag = excluded.tag, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
        user.user_id,
        target_id,
        cleaned,
    )
    .execute(&state.db)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /api/users/:username/tag — Clear viewer-private tag
// ---------------------------------------------------------------------------

/// Explicit clear endpoint for the viewer's private tag. Idempotent —
/// returns 204 even when no tag exists, since the desired post-state
/// (no tag) is the same either way.
pub async fn delete_user_tag(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let (target_id, ..) = resolve_user(&state.db, &username).await?;

    sqlx::query!(
        "DELETE FROM user_tags WHERE viewer_id = ? AND target_id = ?",
        user.user_id,
        target_id,
    )
    .execute(&state.db)
    .await?;

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

// ---------------------------------------------------------------------------
// GET /api/search/users — paginated users search (results page)
// ---------------------------------------------------------------------------

/// Query string for the paginated users search endpoint.
#[derive(Deserialize)]
pub struct PaginatedUserSearchQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// One row in the `/search/users` results page.
#[derive(Serialize)]
pub struct PaginatedUserSearchHit {
    pub id: String,
    pub display_name: String,
    pub viewer: UserViewerInfo,
}

/// Wire response for the paginated users search endpoint.
#[derive(Serialize)]
pub struct PaginatedUserSearchResponse {
    pub users: Vec<PaginatedUserSearchHit>,
    pub next_cursor: Option<String>,
}

/// `GET /api/search/users?q=…&cursor=…` — paginated users.
///
/// Skeleton-prefix match on `users.display_name_skeleton` (the
/// confusable-folded canonical form), filtered through the
/// mutual-visibility predicate from `docs/search.md`:
///
/// ```text
/// visible(A, V) =
///    reverse_score_map[A] >= MINIMUM_TRUST_THRESHOLD
/// || distance_map[A]      >= MINIMUM_TRUST_THRESHOLD
/// ```
///
/// Both maps are already threshold-filtered (see `trust.rs`), so a
/// `contains_key` check on the forward map is equivalent to comparing
/// the score against the threshold. Distrusted users are pruned
/// regardless.
/// `GET /api/search/users?q=…&cursor=…` — page-1 (and SSR) entry
/// point. Subsequent pages should use [`load_more_search_users`] so the
/// client can pass `seen_ids` for cross-page dedup.
pub async fn search_users_paginated(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<PaginatedUserSearchQuery>,
) -> Result<impl IntoResponse, AppError> {
    search_users_core(&state, &user, q.q, q.cursor.as_deref(), &HashSet::new()).await
}

/// `POST /api/search/users/more` — page-2+ entry point. Body carries
/// the query, the previous page's cursor, and `seen_ids` (capped at
/// [`crate::search::MAX_SEEN_IDS`]) for cross-page dedup.
pub async fn load_more_search_users(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(body): Json<MoreSearchRequest>,
) -> Result<impl IntoResponse, AppError> {
    validate_seen_ids(&body.seen_ids)?;
    let seen: HashSet<String> = body.seen_ids.into_iter().collect();
    search_users_core(&state, &user, body.q, Some(body.cursor.as_str()), &seen).await
}

async fn search_users_core(
    state: &Arc<AppState>,
    user: &AuthUser,
    q: Option<String>,
    cursor: Option<&str>,
    seen_ids: &HashSet<String>,
) -> Result<Json<PaginatedUserSearchResponse>, AppError> {
    let raw = q.unwrap_or_default();
    let trimmed = raw.trim();
    let offset = decode_offset_cursor(cursor)?;

    if trimmed.is_empty() {
        return Ok(Json(PaginatedUserSearchResponse {
            users: Vec::new(),
            next_cursor: None,
        }));
    }
    validate_query_length(trimmed)?;

    // Skeleton-fold the query the same way every stored display name was
    // folded at write time, so the `LIKE` runs over comparable shapes.
    // If folding strips everything (the input was nothing but
    // punctuation / combining marks / emoji), there is no possible
    // match — short-circuit before issuing the wildcard `LIKE '%'`,
    // which would scan the full users table.
    let skeleton = display_name_skeleton(trimmed);
    if skeleton.is_empty() {
        return Ok(Json(PaginatedUserSearchResponse {
            users: Vec::new(),
            next_cursor: None,
        }));
    }

    let reader_uuid = user.uuid();
    let graph = state.get_trust_graph()?;
    let reader_delta = state.pending_deltas.get(reader_uuid);
    let trust_map = graph.distance_map_with_delta(reader_uuid, &reader_delta);
    let reverse_map = graph.reverse_score_map(reader_uuid);
    let distrust_set = load_distrust_set(&state.db, &user.user_id).await?;
    let tag_map = load_tag_map(&state.db, &user.user_id).await?;

    let pattern = format!("{}%", escape_like(&skeleton));

    let rows = sqlx::query!(
        r#"SELECT id, display_name, status, deleted_at
           FROM users
           WHERE deleted_at IS NULL
             AND display_name_skeleton LIKE ? ESCAPE '\'
           ORDER BY (display_name_skeleton = ?) DESC,
                    LENGTH(display_name),
                    display_name
           LIMIT ?"#,
        pattern,
        skeleton,
        SUBSTRING_OVERSAMPLE,
    )
    .fetch_all(&state.db)
    .await?;

    let visible: Vec<_> = rows
        .into_iter()
        .filter(|r| {
            is_paginated_search_user_visible(
                &r.id,
                &user.user_id,
                &trust_map,
                &reverse_map,
                &distrust_set,
            )
        })
        .collect();

    let total_visible = visible.len();

    // Drop slice rows already in the client's `seen_ids` (post-slice
    // safety net for cross-page duplicates). Cursor still advances by
    // `PAGE_SIZE` regardless.
    let users: Vec<PaginatedUserSearchHit> = visible
        .into_iter()
        .skip(offset)
        .take(PAGE_SIZE)
        .filter(|r| !seen_ids.contains(&r.id))
        .map(|r| {
            let raw_status = UserStatus::try_from(r.status.as_str()).unwrap_or(UserStatus::Active);
            let status = UserStatus::effective(raw_status, r.deleted_at.as_deref());
            let viewer = UserViewerInfo::build(&r.id, &trust_map, &distrust_set, &tag_map, status);
            PaginatedUserSearchHit {
                id: r.id,
                display_name: r.display_name,
                viewer,
            }
        })
        .collect();

    let next_cursor = encode_offset_cursor(offset + PAGE_SIZE, total_visible);

    Ok(Json(PaginatedUserSearchResponse { users, next_cursor }))
}

/// Mutual-visibility predicate for the paginated users search. Self
/// is always visible — searching for your own name should surface
/// your profile (e.g. as a quick way to check what others see, or to
/// copy a link to it).
fn is_paginated_search_user_visible(
    candidate_id: &str,
    reader_id: &str,
    trust_map: &HashMap<Uuid, f32>,
    reverse_map: &HashMap<Uuid, f32>,
    distrust_set: &HashSet<String>,
) -> bool {
    if candidate_id == reader_id {
        return true;
    }
    if distrust_set.contains(candidate_id) {
        return false;
    }
    let Ok(candidate_uuid) = Uuid::parse_str(candidate_id) else {
        return false;
    };
    let viewer_trusts_them = trust_map.contains_key(&candidate_uuid);
    let they_trust_viewer = reverse_map
        .get(&candidate_uuid)
        .is_some_and(|&s| s as f64 >= MINIMUM_TRUST_THRESHOLD);
    viewer_trusts_them || they_trust_viewer
}
