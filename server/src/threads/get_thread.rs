use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::{AppError, ErrorCode};
use crate::session::OptionalAuthUser;
use crate::state::AppState;
use crate::trust::{MINIMUM_TRUST_THRESHOLD, TrustInfo, UserStatus, load_distrust_set};

use super::common::{
    PostResponse, RepliesPageResponse, SubtreeResponse, ThreadDetailResponse, sql_placeholders,
};

/// Maximum number of top-level replies returned in the initial thread view.
const TOP_LEVEL_LIMIT: usize = 30;

/// Maximum depth of nested replies below the OP (matches frontend MAX_DEPTH=4
/// which renders 5 levels: the top-level reply in the page + 4 ReplyTree
/// recursion levels).
const MAX_DEPTH: usize = 5;

/// Page size for the top-level replies expansion endpoint.
const REPLIES_PAGE_SIZE: usize = 30;

/// Sort mode for thread detail view (post ordering within the tree).
#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
pub enum PostSort {
    #[default]
    #[serde(rename = "trust")]
    Trust,
    #[serde(rename = "new")]
    New,
}

#[derive(Deserialize, Default)]
pub struct ThreadDetailQuery {
    #[serde(default)]
    sort: PostSort,
    focus: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct RepliesQuery {
    #[serde(default)]
    sort: PostSort,
    #[serde(default)]
    offset: usize,
}

#[derive(Deserialize, Default)]
pub struct SubtreeQuery {
    #[serde(default)]
    sort: PostSort,
}

// ---------------------------------------------------------------------------
// Pass 1 metadata row (no body)
// ---------------------------------------------------------------------------

struct PostMeta {
    id: String,
    parent_id: Option<String>,
    author_id: String,
    author_name: String,
    author_status: UserStatus,
    created_at: String,
    retracted_at: Option<String>,
}

// ---------------------------------------------------------------------------
// Shared tree-building infrastructure
// ---------------------------------------------------------------------------

/// Thread-level metadata fetched once and shared across all endpoints.
struct ThreadInfo {
    id: String,
    title: String,
    author_id: String,
    author_name: String,
    created_at: String,
    room_id: String,
    room_slug: String,
    locked: bool,
    is_announcement: bool,
}

/// All the viewer-specific context needed for visibility and sorting.
struct ViewerCtx {
    trust_map: Arc<HashMap<String, f64>>,
    reverse_map: Arc<HashMap<String, f64>>,
    distrust_set: HashSet<String>,
    reader_id: Option<String>,
}

/// Intermediate tree built from metadata (no bodies yet).
struct MetaTree {
    metas: Vec<PostMeta>,
    id_to_index: HashMap<String, usize>,
    children_map: HashMap<usize, Vec<usize>>,
    retracted: HashSet<usize>,
    author_of: Vec<String>,
    parent_author_of: Vec<Option<String>>,
    root_idx: usize,
    op_author_id: String,
}

/// Build the metadata tree from pass-1 rows.
fn build_meta_tree(rows: Vec<PostMeta>) -> Result<MetaTree, AppError> {
    let mut id_to_index: HashMap<String, usize> = HashMap::with_capacity(rows.len());
    let mut retracted: HashSet<usize> = HashSet::new();
    let mut author_of: Vec<String> = Vec::with_capacity(rows.len());
    let mut parent_author_of: Vec<Option<String>> = Vec::with_capacity(rows.len());

    for (idx, meta) in rows.iter().enumerate() {
        id_to_index.insert(meta.id.clone(), idx);
        if meta.retracted_at.is_some() {
            retracted.insert(idx);
        }
        author_of.push(meta.author_id.clone());
        parent_author_of.push(None);
    }

    let mut children_map: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut root_idx: Option<usize> = None;

    for (i, meta) in rows.iter().enumerate() {
        if let Some(ref pid) = meta.parent_id {
            if let Some(&parent_idx) = id_to_index.get(pid) {
                children_map.entry(parent_idx).or_default().push(i);
                parent_author_of[i] = Some(author_of[parent_idx].clone());
            }
        } else {
            root_idx = Some(i);
        }
    }

    let root_idx = root_idx.ok_or_else(|| {
        eprintln!("thread has no opening post");
        AppError::code(ErrorCode::Internal)
    })?;
    let op_author_id = author_of[root_idx].clone();

    Ok(MetaTree {
        metas: rows,
        id_to_index,
        children_map,
        retracted,
        author_of,
        parent_author_of,
        root_idx,
        op_author_id,
    })
}

struct TreeCtx<'a> {
    tree: &'a MetaTree,
    viewer: &'a ViewerCtx,
    is_announcement: bool,
    sort_by_new: bool,
    /// For each post index, true iff that post or any descendant is authored
    /// by the reader. Used to preserve distrust-filtered posts as scaffolding
    /// when the reader has a reply nested below them — otherwise the reader
    /// would lose their own post whenever they distrust an intervening author.
    has_reader_descendant: Vec<bool>,
}

/// Compute `has_reader_descendant` for every post in the tree.
///
/// Post-order traversal from the OP: a node is "load-bearing" if it was
/// authored by the reader, or if any of its descendants was. Returns an
/// all-false vector (cheap short-circuit) when there is no authenticated
/// reader, when the reader has not distrusted anyone, or when no author in
/// the tree is actually in the reader's distrust set — in all those cases
/// `is_visible` never consults this vector, so there's nothing to compute.
fn compute_reader_descendants(
    tree: &MetaTree,
    reader_id: Option<&str>,
    distrust_set: &HashSet<String>,
) -> Vec<bool> {
    let n = tree.metas.len();
    let mut result = vec![false; n];
    if distrust_set.is_empty() {
        return result;
    }
    let Some(reader) = reader_id else {
        return result;
    };
    if !tree.author_of.iter().any(|a| distrust_set.contains(a)) {
        return result;
    }

    fn visit(idx: usize, tree: &MetaTree, reader: &str, result: &mut [bool]) -> bool {
        let mut has = tree.author_of[idx] == reader;
        if let Some(children) = tree.children_map.get(&idx) {
            // Clone indices to avoid aliasing borrow with `result`.
            let child_indices: Vec<usize> = children.clone();
            for ci in child_indices {
                if visit(ci, tree, reader, result) {
                    has = true;
                }
            }
        }
        result[idx] = has;
        has
    }

    visit(tree.root_idx, tree, reader, &mut result);
    result
}

impl TreeCtx<'_> {
    /// Check whether a post at `idx` is visible to the current reader.
    fn is_visible(&self, idx: usize, is_root: bool) -> bool {
        let reader = match self.viewer.reader_id {
            Some(ref r) => r,
            None => return true,
        };
        let author = &self.tree.author_of[idx];
        if author == reader {
            return true;
        }
        // Distrust: prune posts (and thus entire subtrees, since
        // `visible_sorted_children` feeds `build_tree` / `collect_truncated` /
        // `count_visible_replies` recursively) authored by distrusted users.
        // Overrides the announcement carve-out and reply-visibility grant per
        // spec §"Distrust action UX".
        //
        // Exception: if the reader has a post nested below a distrusted
        // author's post, keep the distrusted post in the tree as scaffolding
        // so the reader's own reply remains reachable via permalinks / the
        // activity feed. The body is redacted in `build_tree`.
        if self.viewer.distrust_set.contains(author) {
            return self.has_reader_descendant[idx];
        }
        if is_root && self.is_announcement {
            return true;
        }
        if let Some(&score) = self.viewer.reverse_map.get(author)
            && score >= MINIMUM_TRUST_THRESHOLD
        {
            return true;
        }
        if let Some(ref parent_author) = self.tree.parent_author_of[idx]
            && parent_author == reader
        {
            return true;
        }
        false
    }

    /// Sort child indices according to the current sort mode.
    fn sort_children(&self, children: &mut [usize]) {
        if self.sort_by_new {
            children.sort_by(|&a, &b| {
                let ts_a = self.tree.metas[a].created_at.as_str();
                let ts_b = self.tree.metas[b].created_at.as_str();
                ts_b.cmp(ts_a)
            });
        } else {
            let sort_key = |idx: usize| -> f64 {
                let author = &self.tree.author_of[idx];
                if self.viewer.reader_id.as_ref().is_some_and(|r| r == author) {
                    0.0
                } else {
                    self.viewer
                        .trust_map
                        .get(author)
                        .copied()
                        .unwrap_or(f64::MAX)
                }
            };
            children.sort_by(|&a, &b| {
                sort_key(a)
                    .partial_cmp(&sort_key(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| {
                        let ts_a = self.tree.metas[a].created_at.as_str();
                        let ts_b = self.tree.metas[b].created_at.as_str();
                        ts_a.cmp(ts_b)
                    })
            });
        }
    }

    /// Filter children to only visible posts, sorted according to sort mode.
    fn visible_sorted_children(&self, idx: usize) -> Vec<usize> {
        let mut child_indices: Vec<usize> = self
            .tree
            .children_map
            .get(&idx)
            .cloned()
            .unwrap_or_default();

        self.sort_children(&mut child_indices);

        child_indices
            .into_iter()
            .filter(|&ci| {
                if self.tree.retracted.contains(&ci) && !self.tree.children_map.contains_key(&ci) {
                    return false;
                }
                self.is_visible(ci, false)
            })
            .collect()
    }

    /// Collect post IDs for a subtree, respecting depth limit. Returns the
    /// set of IDs to fetch bodies for and annotates which nodes were truncated.
    /// Nodes on the `focus_path` bypass depth truncation so the full ancestor
    /// chain to a focused post is always included.
    fn collect_truncated(
        &self,
        idx: usize,
        current_depth: usize,
        max_depth: usize,
        ids: &mut Vec<String>,
        truncated: &mut HashSet<usize>,
        focus_path: &HashSet<usize>,
    ) {
        ids.push(self.tree.metas[idx].id.clone());

        let children = self.visible_sorted_children(idx);
        if children.is_empty() {
            return;
        }

        let on_focus_path = focus_path.contains(&idx);
        if current_depth >= max_depth && !on_focus_path {
            truncated.insert(idx);
            return;
        }

        for &ci in &children {
            let child_depth = if on_focus_path && focus_path.contains(&ci) {
                0
            } else if on_focus_path {
                1
            } else {
                current_depth + 1
            };
            self.collect_truncated(ci, child_depth, max_depth, ids, truncated, focus_path);
        }
    }

    /// Build a PostResponse tree from metadata + fetched bodies, respecting
    /// depth limits. Bodies are looked up from the provided map. Nodes on the
    /// `focus_path` bypass depth truncation.
    fn build_tree(
        &self,
        idx: usize,
        current_depth: usize,
        max_depth: usize,
        bodies: &HashMap<String, BodyInfo>,
        focus_path: &HashSet<usize>,
    ) -> PostResponse {
        let meta = &self.tree.metas[idx];
        let body_info = bodies.get(&meta.id);

        let children = self.visible_sorted_children(idx);
        let on_focus_path = focus_path.contains(&idx);
        let has_more_children =
            current_depth >= max_depth && !on_focus_path && !children.is_empty();

        let child_posts: Vec<PostResponse> = if current_depth >= max_depth && !on_focus_path {
            vec![]
        } else {
            children
                .into_iter()
                .map(|ci| {
                    let child_depth = if on_focus_path && focus_path.contains(&ci) {
                        0
                    } else if on_focus_path {
                        1
                    } else {
                        current_depth + 1
                    };
                    self.build_tree(ci, child_depth, max_depth, bodies, focus_path)
                })
                .collect()
        };

        let (body, edited_at, revision) = match body_info {
            Some(bi) => (bi.body.clone(), bi.edited_at.clone(), bi.revision),
            None => (String::new(), None, 0),
        };

        // Distrust scaffold marker: if the author is distrusted but we're
        // rendering the post anyway (because the reader has a descendant
        // reply), flag it so the client can show a hint explaining why a
        // distrusted user's post is visible.
        let is_distrusted_scaffold = self.viewer.reader_id.as_deref()
            != Some(meta.author_id.as_str())
            && self.viewer.distrust_set.contains(&meta.author_id);

        PostResponse {
            trust: TrustInfo::build(
                &meta.author_id,
                &self.viewer.trust_map,
                &self.viewer.distrust_set,
                meta.author_status,
            ),
            id: meta.id.clone(),
            parent_id: meta.parent_id.clone(),
            author_id: meta.author_id.clone(),
            author_name: meta.author_name.clone(),
            body,
            created_at: meta.created_at.clone(),
            edited_at,
            revision,
            is_op: meta.author_id == self.tree.op_author_id,
            retracted_at: meta.retracted_at.clone(),
            children: child_posts,
            has_more_children,
            distrust_scaffold: is_distrusted_scaffold,
        }
    }

    /// Count total visible replies in the full tree (no truncation).
    fn count_visible_replies(&self, idx: usize) -> i64 {
        let children = self.visible_sorted_children(idx);
        let mut count = children.len() as i64;
        for ci in children {
            count += self.count_visible_replies(ci);
        }
        count
    }
}

/// Body data fetched in pass 2.
struct BodyInfo {
    body: String,
    edited_at: Option<String>,
    revision: i64,
}

// ---------------------------------------------------------------------------
// Shared database helpers
// ---------------------------------------------------------------------------

/// Fetch thread metadata (pass 0).
async fn fetch_thread_info(db: &sqlx::SqlitePool, thread_id: &str) -> Result<ThreadInfo, AppError> {
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            bool,
            bool,
        ),
    >(
        "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
         r.id, r.slug, t.locked, (r.slug = 'announcements') AS is_announcement \
         FROM threads t \
         JOIN users u ON u.id = t.author \
         JOIN rooms r ON r.id = t.room \
         WHERE t.id = ?",
    )
    .bind(thread_id)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| AppError::code(ErrorCode::ThreadNotFound))?;

    Ok(ThreadInfo {
        id: row.0,
        title: row.1,
        author_id: row.2,
        author_name: row.3,
        created_at: row.4,
        room_id: row.5,
        room_slug: row.6,
        locked: row.7,
        is_announcement: row.8,
    })
}

/// Gate anonymous thread access to announcement rooms only.
///
/// Anonymous users (the `/public` landing page and the announcement
/// permalinks it links to) are allowed to read announcement threads but
/// nothing else. Any other room requires an authenticated session so the
/// trust-based visibility model applies.
fn require_auth_for_non_announcement(
    user: &Option<crate::session::AuthUser>,
    thread_info: &ThreadInfo,
) -> Result<(), AppError> {
    if user.is_none() && !thread_info.is_announcement {
        return Err(AppError::code(ErrorCode::Unauthenticated));
    }
    Ok(())
}

/// Pass 1: fetch post metadata without bodies.
#[allow(clippy::type_complexity)]
async fn fetch_post_metadata(
    db: &sqlx::SqlitePool,
    thread_id: &str,
) -> Result<Vec<PostMeta>, AppError> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
        ),
    >(
        "SELECT p.id, p.parent, p.author, u.display_name, u.status, u.deleted_at, \
                p.created_at, p.retracted_at \
         FROM posts p \
         JOIN users u ON u.id = p.author \
         WHERE p.thread = ? \
         ORDER BY p.created_at ASC",
    )
    .bind(thread_id)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                parent_id,
                author_id,
                author_name,
                author_status,
                author_deleted_at,
                created_at,
                retracted_at,
            ): (
                String,
                Option<String>,
                String,
                String,
                String,
                Option<String>,
                String,
                Option<String>,
            )| {
                let raw =
                    UserStatus::try_from(author_status.as_str()).unwrap_or(UserStatus::Active);
                PostMeta {
                    id,
                    parent_id,
                    author_id,
                    author_name,
                    author_status: UserStatus::effective(raw, author_deleted_at.as_deref()),
                    created_at,
                    retracted_at,
                }
            },
        )
        .collect())
}

/// Pass 2: fetch bodies for a set of post IDs.
async fn fetch_bodies(
    db: &sqlx::SqlitePool,
    post_ids: &[String],
) -> Result<HashMap<String, BodyInfo>, AppError> {
    if post_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let placeholders = sql_placeholders(post_ids.len());
    let sql = format!(
        "SELECT pr.post_id, pr.body, pr.created_at, pr.revision, \
         (SELECT pr0.created_at FROM post_revisions pr0 WHERE pr0.post_id = pr.post_id AND pr0.revision = 0) AS original_at \
         FROM post_revisions pr \
         WHERE pr.post_id IN {placeholders} \
           AND pr.revision = ( \
               SELECT MAX(pr2.revision) FROM post_revisions pr2 WHERE pr2.post_id = pr.post_id \
           )"
    );

    let mut query = sqlx::query_as::<_, (String, String, String, i64, String)>(&sql);
    for id in post_ids {
        query = query.bind(id);
    }

    let rows = query.fetch_all(db).await?;

    let mut map = HashMap::with_capacity(rows.len());
    for (post_id, body, latest_revision_at, revision, _original_at) in rows {
        let edited_at = if revision > 0 {
            Some(latest_revision_at)
        } else {
            None
        };
        map.insert(
            post_id,
            BodyInfo {
                body,
                edited_at,
                revision,
            },
        );
    }
    Ok(map)
}

/// Load viewer context (trust maps, block set, reader ID).
fn load_viewer_ctx(
    state: &AppState,
    user: &Option<crate::session::AuthUser>,
) -> Result<ViewerCtx, AppError> {
    match user.as_ref() {
        Some(u) => {
            let reader_uuid = Uuid::parse_str(&u.user_id).unwrap_or(Uuid::nil());
            let graph = state.get_trust_graph()?;
            let dm = graph.distance_map(reader_uuid);
            let rm = graph.reverse_score_map(reader_uuid);
            Ok(ViewerCtx {
                trust_map: dm,
                reverse_map: rm,
                distrust_set: HashSet::new(),
                reader_id: Some(u.user_id.clone()),
            })
        }
        None => Ok(ViewerCtx {
            trust_map: Arc::new(HashMap::new()),
            reverse_map: Arc::new(HashMap::new()),
            distrust_set: HashSet::new(),
            reader_id: None,
        }),
    }
}

/// Load viewer context including distrust set (requires async).
async fn load_viewer_ctx_full(
    state: &AppState,
    user: &Option<crate::session::AuthUser>,
) -> Result<ViewerCtx, AppError> {
    let mut ctx = load_viewer_ctx(state, user)?;
    if let Some(u) = user.as_ref() {
        ctx.distrust_set = load_distrust_set(&state.db, &u.user_id).await?;
    }
    Ok(ctx)
}

// ---------------------------------------------------------------------------
// GET /api/threads/{id} — main thread detail (with optional ?focus=)
// ---------------------------------------------------------------------------

/// Get thread detail including all posts as a nested reply tree.
///
/// Uses a two-pass approach: pass 1 fetches metadata only (no bodies),
/// builds the tree, applies visibility filtering / trust sorting /
/// truncation, then pass 2 fetches bodies only for the surviving posts.
///
/// Supports `?focus=POST_ID` to return a focused view centered on a
/// specific post with its ancestor chain.
pub async fn get_thread(
    State(state): State<Arc<AppState>>,
    Path(thread_id): Path<String>,
    Query(query): Query<ThreadDetailQuery>,
    OptionalAuthUser(user): OptionalAuthUser,
) -> Result<Response, AppError> {
    let thread_info = fetch_thread_info(&state.db, &thread_id).await?;
    require_auth_for_non_announcement(&user, &thread_info)?;
    let viewer = load_viewer_ctx_full(&state, &user).await?;
    let meta_rows = fetch_post_metadata(&state.db, &thread_id).await?;
    let meta_tree = build_meta_tree(meta_rows)?;

    let has_reader_descendant = compute_reader_descendants(
        &meta_tree,
        viewer.reader_id.as_deref(),
        &viewer.distrust_set,
    );
    let ctx = TreeCtx {
        tree: &meta_tree,
        viewer: &viewer,
        is_announcement: thread_info.is_announcement,
        sort_by_new: query.sort == PostSort::New,
        has_reader_descendant,
    };

    // If the OP author is distrusted by the reader, the thread disappears
    // entirely. The focus/subtree branches below 404 automatically via
    // `ctx.is_visible`, but the non-focused path unconditionally emits
    // the OP, so guard it here.
    if !ctx.is_visible(meta_tree.root_idx, true) {
        return Err(AppError::code(ErrorCode::ThreadNotFound));
    }

    if let Some(focus_id) = &query.focus {
        return build_focused_response(
            &ctx,
            &meta_tree,
            &thread_info,
            focus_id,
            &state.db,
            &viewer,
        )
        .await
        .map(IntoResponse::into_response);
    }

    let total_reply_count = ctx.count_visible_replies(meta_tree.root_idx);

    let all_top_level = ctx.visible_sorted_children(meta_tree.root_idx);
    let has_more_replies = all_top_level.len() > TOP_LEVEL_LIMIT;
    let top_level: Vec<usize> = all_top_level.into_iter().take(TOP_LEVEL_LIMIT).collect();

    let no_focus = HashSet::new();
    let mut post_ids = vec![meta_tree.metas[meta_tree.root_idx].id.clone()];
    let mut truncated: HashSet<usize> = HashSet::new();

    for &tl_idx in &top_level {
        ctx.collect_truncated(
            tl_idx,
            1,
            MAX_DEPTH,
            &mut post_ids,
            &mut truncated,
            &no_focus,
        );
    }

    let bodies = fetch_bodies(&state.db, &post_ids).await?;

    let op_meta = &meta_tree.metas[meta_tree.root_idx];
    let op_body = bodies.get(&op_meta.id);
    let (op_body_str, op_edited, op_rev) = match op_body {
        Some(bi) => (bi.body.clone(), bi.edited_at.clone(), bi.revision),
        None => (String::new(), None, 0),
    };
    // If the OP author is distrusted (but the thread is still rendering
    // because the reader has a reply below), flag the scaffold marker so
    // the client can show a hint.
    let op_distrust_scaffold = viewer.reader_id.as_deref() != Some(op_meta.author_id.as_str())
        && viewer.distrust_set.contains(&op_meta.author_id);

    let op_children: Vec<PostResponse> = top_level
        .into_iter()
        .map(|ci| ctx.build_tree(ci, 1, MAX_DEPTH, &bodies, &no_focus))
        .collect();

    let reply_count = count_tree_replies(&op_children);

    let op = PostResponse {
        trust: TrustInfo::build(
            &op_meta.author_id,
            &viewer.trust_map,
            &viewer.distrust_set,
            op_meta.author_status,
        ),
        id: op_meta.id.clone(),
        parent_id: None,
        author_id: op_meta.author_id.clone(),
        author_name: op_meta.author_name.clone(),
        body: op_body_str,
        created_at: op_meta.created_at.clone(),
        edited_at: op_edited,
        revision: op_rev,
        is_op: true,
        retracted_at: op_meta.retracted_at.clone(),
        children: op_children,
        has_more_children: false,
        distrust_scaffold: op_distrust_scaffold,
    };

    Ok(Json(ThreadDetailResponse {
        id: thread_info.id,
        title: thread_info.title,
        author_id: thread_info.author_id,
        author_name: thread_info.author_name,
        room_id: thread_info.room_id,
        room_slug: thread_info.room_slug,
        created_at: thread_info.created_at,
        locked: thread_info.locked,
        is_announcement: thread_info.is_announcement,
        post: op,
        reply_count,
        total_reply_count,
        has_more_replies,
        focused_post_id: None,
        top_level_loaded: None,
    })
    .into_response())
}

/// Count replies in an already-built PostResponse tree.
fn count_tree_replies(children: &[PostResponse]) -> i64 {
    let mut count = children.len() as i64;
    for child in children {
        count += count_tree_replies(&child.children);
    }
    count
}

/// Build a focused response that returns a normal `ThreadDetailResponse` with
/// the full tree, ensuring the path from the OP to the focused post is always
/// expanded regardless of depth/pagination limits.
async fn build_focused_response(
    ctx: &TreeCtx<'_>,
    meta_tree: &MetaTree,
    thread_info: &ThreadInfo,
    focus_id: &str,
    db: &sqlx::SqlitePool,
    viewer: &ViewerCtx,
) -> Result<Response, AppError> {
    let focus_idx = meta_tree
        .id_to_index
        .get(focus_id)
        .copied()
        .ok_or_else(|| AppError::code(ErrorCode::PostNotFound))?;

    if !ctx.is_visible(focus_idx, focus_idx == meta_tree.root_idx) {
        return Err(AppError::code(ErrorCode::PostNotFound));
    }

    // Build focus path: set of indices from the focused post up to the root.
    // Including the focused post itself ensures (a) the top-level lookup below
    // matches even when the focused post *is* a direct top-level reply, and
    // (b) the focused post's own subtree bypasses depth truncation so a bit
    // of context below it is visible.
    let mut focus_path: HashSet<usize> = HashSet::new();
    focus_path.insert(focus_idx);
    let mut current = focus_idx;
    while let Some(ref pid) = meta_tree.metas[current].parent_id {
        if let Some(&parent_idx) = meta_tree.id_to_index.get(pid) {
            focus_path.insert(parent_idx);
            current = parent_idx;
        } else {
            break;
        }
    }

    let total_reply_count = ctx.count_visible_replies(meta_tree.root_idx);

    // Determine which top-level child is on the focus path (if any) so we
    // can ensure it's included even if it falls beyond TOP_LEVEL_LIMIT.
    let all_top_level = ctx.visible_sorted_children(meta_tree.root_idx);
    let focus_top_level_idx = all_top_level
        .iter()
        .find(|&&idx| focus_path.contains(&idx))
        .copied();
    let has_more_replies = all_top_level.len() > TOP_LEVEL_LIMIT;
    let mut top_level: Vec<usize> = all_top_level.into_iter().take(TOP_LEVEL_LIMIT).collect();
    let sort_ordered_count = top_level.len();

    // If the focus-path top-level child was beyond the limit, append it.
    // This appended entry is out of sort order, so the frontend must not
    // count it toward the offset used for load-more pagination — see
    // `top_level_loaded` below.
    if let Some(ftl) = focus_top_level_idx
        && !top_level.contains(&ftl)
    {
        top_level.push(ftl);
    }
    let top_level_loaded = if top_level.len() > sort_ordered_count {
        Some(sort_ordered_count)
    } else {
        None
    };

    let mut post_ids = vec![meta_tree.metas[meta_tree.root_idx].id.clone()];
    let mut truncated: HashSet<usize> = HashSet::new();

    for &tl_idx in &top_level {
        ctx.collect_truncated(
            tl_idx,
            1,
            MAX_DEPTH,
            &mut post_ids,
            &mut truncated,
            &focus_path,
        );
    }

    let bodies = fetch_bodies(db, &post_ids).await?;

    let op_meta = &meta_tree.metas[meta_tree.root_idx];
    let op_body = bodies.get(&op_meta.id);
    let (op_body_str, op_edited, op_rev) = match op_body {
        Some(bi) => (bi.body.clone(), bi.edited_at.clone(), bi.revision),
        None => (String::new(), None, 0),
    };
    // If the OP author is distrusted (but the thread is still rendering
    // because the reader has a reply below), flag the scaffold marker so
    // the client can show a hint.
    let op_distrust_scaffold = viewer.reader_id.as_deref() != Some(op_meta.author_id.as_str())
        && viewer.distrust_set.contains(&op_meta.author_id);

    let op_children: Vec<PostResponse> = top_level
        .into_iter()
        .map(|ci| ctx.build_tree(ci, 1, MAX_DEPTH, &bodies, &focus_path))
        .collect();

    let reply_count = count_tree_replies(&op_children);

    let op = PostResponse {
        trust: TrustInfo::build(
            &op_meta.author_id,
            &viewer.trust_map,
            &viewer.distrust_set,
            op_meta.author_status,
        ),
        id: op_meta.id.clone(),
        parent_id: None,
        author_id: op_meta.author_id.clone(),
        author_name: op_meta.author_name.clone(),
        body: op_body_str,
        created_at: op_meta.created_at.clone(),
        edited_at: op_edited,
        revision: op_rev,
        is_op: true,
        retracted_at: op_meta.retracted_at.clone(),
        children: op_children,
        has_more_children: false,
        distrust_scaffold: op_distrust_scaffold,
    };

    Ok(Json(ThreadDetailResponse {
        id: thread_info.id.clone(),
        title: thread_info.title.clone(),
        author_id: thread_info.author_id.clone(),
        author_name: thread_info.author_name.clone(),
        room_id: thread_info.room_id.clone(),
        room_slug: thread_info.room_slug.clone(),
        created_at: thread_info.created_at.clone(),
        locked: thread_info.locked,
        is_announcement: thread_info.is_announcement,
        post: op,
        reply_count,
        total_reply_count,
        has_more_replies,
        focused_post_id: Some(focus_id.to_string()),
        top_level_loaded,
    })
    .into_response())
}

// ---------------------------------------------------------------------------
// GET /api/threads/{id}/replies — paginate top-level replies
// ---------------------------------------------------------------------------

/// Paginate top-level replies (children of the OP) beyond the initial page.
///
/// Uses the same two-pass pattern: full metadata tree → visibility/sort →
/// offset into top-level children → fetch bodies for that page.
pub async fn get_thread_replies(
    State(state): State<Arc<AppState>>,
    Path(thread_id): Path<String>,
    Query(query): Query<RepliesQuery>,
    OptionalAuthUser(user): OptionalAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let thread_info = fetch_thread_info(&state.db, &thread_id).await?;
    require_auth_for_non_announcement(&user, &thread_info)?;
    let viewer = load_viewer_ctx_full(&state, &user).await?;
    let meta_rows = fetch_post_metadata(&state.db, &thread_id).await?;
    let meta_tree = build_meta_tree(meta_rows)?;

    let has_reader_descendant = compute_reader_descendants(
        &meta_tree,
        viewer.reader_id.as_deref(),
        &viewer.distrust_set,
    );
    let ctx = TreeCtx {
        tree: &meta_tree,
        viewer: &viewer,
        is_announcement: thread_info.is_announcement,
        sort_by_new: query.sort == PostSort::New,
        has_reader_descendant,
    };

    let all_top_level = ctx.visible_sorted_children(meta_tree.root_idx);
    let page: Vec<usize> = all_top_level
        .into_iter()
        .skip(query.offset)
        .take(REPLIES_PAGE_SIZE + 1)
        .collect();

    let has_more = page.len() > REPLIES_PAGE_SIZE;
    let page: Vec<usize> = page.into_iter().take(REPLIES_PAGE_SIZE).collect();

    let no_focus = HashSet::new();
    let mut post_ids: Vec<String> = Vec::new();
    let mut truncated: HashSet<usize> = HashSet::new();
    for &tl_idx in &page {
        ctx.collect_truncated(
            tl_idx,
            1,
            MAX_DEPTH,
            &mut post_ids,
            &mut truncated,
            &no_focus,
        );
    }

    let bodies = fetch_bodies(&state.db, &post_ids).await?;

    let replies: Vec<PostResponse> = page
        .into_iter()
        .map(|ci| ctx.build_tree(ci, 1, MAX_DEPTH, &bodies, &no_focus))
        .collect();

    Ok(Json(RepliesPageResponse { replies, has_more }))
}

// ---------------------------------------------------------------------------
// GET /api/threads/{id}/subtree/{post_id} — expand a subtree
// ---------------------------------------------------------------------------

/// Load a subtree rooted at a specific post, for "continue thread" expansion.
///
/// Returns the post and its children truncated to depth D.
pub async fn get_thread_subtree(
    State(state): State<Arc<AppState>>,
    Path((thread_id, post_id)): Path<(String, String)>,
    Query(query): Query<SubtreeQuery>,
    OptionalAuthUser(user): OptionalAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let thread_info = fetch_thread_info(&state.db, &thread_id).await?;
    require_auth_for_non_announcement(&user, &thread_info)?;
    let viewer = load_viewer_ctx_full(&state, &user).await?;
    let meta_rows = fetch_post_metadata(&state.db, &thread_id).await?;
    let meta_tree = build_meta_tree(meta_rows)?;

    let has_reader_descendant = compute_reader_descendants(
        &meta_tree,
        viewer.reader_id.as_deref(),
        &viewer.distrust_set,
    );
    let ctx = TreeCtx {
        tree: &meta_tree,
        viewer: &viewer,
        is_announcement: thread_info.is_announcement,
        sort_by_new: query.sort == PostSort::New,
        has_reader_descendant,
    };

    let subtree_root = meta_tree
        .id_to_index
        .get(&post_id)
        .copied()
        .ok_or_else(|| AppError::code(ErrorCode::PostNotFound))?;

    if !ctx.is_visible(subtree_root, subtree_root == meta_tree.root_idx) {
        return Err(AppError::code(ErrorCode::PostNotFound));
    }

    let no_focus = HashSet::new();
    let mut post_ids: Vec<String> = Vec::new();
    let mut truncated: HashSet<usize> = HashSet::new();
    ctx.collect_truncated(
        subtree_root,
        0,
        MAX_DEPTH,
        &mut post_ids,
        &mut truncated,
        &no_focus,
    );

    let bodies = fetch_bodies(&state.db, &post_ids).await?;
    let post = ctx.build_tree(subtree_root, 0, MAX_DEPTH, &bodies, &no_focus);

    Ok(Json(SubtreeResponse { post }))
}
