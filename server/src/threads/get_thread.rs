use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::session::OptionalAuthUser;
use crate::state::AppState;
use crate::trust::{MINIMUM_TRUST_THRESHOLD, TrustInfo, load_block_set};

use super::common::{PostResponse, ThreadDetailResponse};

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
}

/// Get thread detail including all posts as a nested reply tree.
///
/// Fetches every post in the thread with its latest revision, then
/// reconstructs the parent-child tree in memory. The OP (parent IS NULL)
/// is returned as `post`, with its `children` populated recursively.
///
/// Trust-aware behaviour (authenticated readers only):
/// - **Visibility filtering (reverse trust):** A post is hidden — along with
///   its entire subtree — unless the author's trust in the reader meets
///   `MINIMUM_TRUST_THRESHOLD`. Exceptions: the reader's own posts, OP in
///   public rooms, and the reply visibility grant (the direct parent author
///   can always see a reply to their post).
/// - **Relevance sorting (forward trust):** Within each sibling group,
///   children are sorted by the reader's forward trust distance to the
///   author (ascending — closest/highest trust first), with `created_at`
///   as a tiebreaker.
///
/// Accepts an optional `?sort=new` query parameter (default: trust sort).
pub async fn get_thread(
    State(state): State<Arc<AppState>>,
    Path(thread_id): Path<String>,
    Query(query): Query<ThreadDetailQuery>,
    OptionalAuthUser(user): OptionalAuthUser,
) -> Result<impl IntoResponse, AppError> {
    let sort_by_new = query.sort == PostSort::New;
    let (trust_map, reverse_map, block_set, reader_id) = match user.as_ref() {
        Some(u) => {
            let reader_uuid = Uuid::parse_str(&u.user_id).unwrap_or(Uuid::nil());
            let graph = state.get_trust_graph()?;
            let dm = graph.distance_map(reader_uuid);
            let rm = graph.reverse_score_map(reader_uuid);
            let bs = load_block_set(&state.db, &u.user_id).await?;
            (dm, rm, bs, Some(u.user_id.clone()))
        }
        None => (
            Arc::new(HashMap::new()),
            Arc::new(HashMap::new()),
            HashSet::new(),
            None,
        ),
    };
    let thread = sqlx::query_as::<
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
            bool,
            bool,
        ),
    >(
        "SELECT t.id, t.title, t.author, u.display_name, t.created_at, \
         r.id, r.name, r.slug, t.locked, r.public \
         FROM threads t \
         JOIN users u ON u.id = t.author \
         JOIN rooms r ON r.id = t.room \
         WHERE t.id = ?",
    )
    .bind(&thread_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("thread not found".into()))?;

    let (
        id,
        title,
        thread_author_id,
        thread_author_name,
        created_at,
        room_id,
        room_name,
        room_slug,
        locked,
        room_public,
    ) = thread;

    let rows = sqlx::query_as::<_, (String, Option<String>, String, String, String, String, i64, Option<String>, String)>(
        "SELECT p.id, p.parent, p.author, u.display_name, pr.body, pr.created_at, pr.revision, \
         p.retracted_at, \
         (SELECT pr0.created_at FROM post_revisions pr0 WHERE pr0.post_id = p.id AND pr0.revision = 0) AS original_at \
         FROM posts p \
         JOIN users u ON u.id = p.author \
         JOIN post_revisions pr ON pr.post_id = p.id AND pr.revision = ( \
             SELECT MAX(pr2.revision) FROM post_revisions pr2 WHERE pr2.post_id = p.id \
         ) \
         WHERE p.thread = ? \
         ORDER BY p.created_at ASC",
    )
    .bind(&thread_id)
    .fetch_all(&state.db)
    .await?;

    let op_author_id = thread_author_id.clone();

    let mut posts: Vec<Option<PostResponse>> = Vec::with_capacity(rows.len());
    let mut id_to_index: HashMap<String, usize> = HashMap::new();
    let mut retracted: HashSet<usize> = HashSet::new();
    let mut author_of: Vec<String> = Vec::with_capacity(rows.len());
    let mut parent_author_of: Vec<Option<String>> = Vec::with_capacity(rows.len());

    for (
        post_id,
        parent_id,
        author_id,
        author_name,
        body,
        latest_revision_at,
        revision,
        retracted_at,
        original_at,
    ) in &rows
    {
        let edited_at = if *revision > 0 {
            Some(latest_revision_at.clone())
        } else {
            None
        };
        let idx = posts.len();
        id_to_index.insert(post_id.clone(), idx);
        if retracted_at.is_some() {
            retracted.insert(idx);
        }
        author_of.push(author_id.clone());
        parent_author_of.push(None);
        posts.push(Some(PostResponse {
            trust: TrustInfo::build(author_id, &trust_map, &block_set),
            id: post_id.clone(),
            parent_id: parent_id.clone(),
            author_id: author_id.clone(),
            author_name: author_name.clone(),
            body: body.clone(),
            created_at: original_at.clone(),
            edited_at,
            revision: *revision,
            is_op: author_id == &op_author_id,
            retracted_at: retracted_at.clone(),
            children: vec![],
        }));
    }

    let mut children_map: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut root_idx: Option<usize> = None;

    for (i, post) in posts.iter().enumerate() {
        let post = post.as_ref().expect("post not yet taken");
        if let Some(ref pid) = post.parent_id {
            if let Some(&parent_idx) = id_to_index.get(pid) {
                children_map.entry(parent_idx).or_default().push(i);
                parent_author_of[i] = Some(author_of[parent_idx].clone());
            }
        } else {
            root_idx = Some(i);
        }
    }

    struct TreeCtx<'a> {
        children_map: &'a HashMap<usize, Vec<usize>>,
        retracted: &'a HashSet<usize>,
        reader_id: &'a Option<String>,
        author_of: &'a [String],
        parent_author_of: &'a [Option<String>],
        reverse_map: &'a HashMap<String, f64>,
        trust_map: &'a HashMap<String, f64>,
        room_public: bool,
        sort_by_new: bool,
    }

    impl TreeCtx<'_> {
        /// Check whether a post at `idx` is visible to the current reader.
        ///
        /// A post is visible if any of the following hold:
        /// 1. No authenticated reader (unauthenticated viewers see all).
        /// 2. The reader is the post's author.
        /// 3. The post is the OP in a public room.
        /// 4. The author's trust-in-reader (reverse score) meets the threshold.
        /// 5. Reply visibility grant: the reader authored the direct parent.
        fn is_visible(&self, idx: usize, is_root: bool) -> bool {
            let reader = match self.reader_id {
                Some(r) => r,
                None => return true,
            };
            let author = &self.author_of[idx];
            if author == reader {
                return true;
            }
            if is_root && self.room_public {
                return true;
            }
            if let Some(&score) = self.reverse_map.get(author)
                && score >= MINIMUM_TRUST_THRESHOLD
            {
                return true;
            }
            if let Some(ref parent_author) = self.parent_author_of[idx]
                && parent_author == reader
            {
                return true;
            }
            false
        }

        /// Recursively build the nested reply tree with trust-aware visibility
        /// filtering and relevance sorting.
        fn build_tree(&self, idx: usize, posts: &mut Vec<Option<PostResponse>>) -> PostResponse {
            let mut child_indices: Vec<usize> =
                self.children_map.get(&idx).cloned().unwrap_or_default();

            if self.sort_by_new {
                child_indices.sort_by(|&a, &b| {
                    let ts_a = posts[a]
                        .as_ref()
                        .map(|p| p.created_at.as_str())
                        .unwrap_or("");
                    let ts_b = posts[b]
                        .as_ref()
                        .map(|p| p.created_at.as_str())
                        .unwrap_or("");
                    ts_b.cmp(ts_a)
                });
            } else {
                // Sort key: reader's own posts first (0.0), then by forward trust
                // distance (ascending — closest first), then unknown/untrusted last
                // (f64::MAX). Tiebreaker: created_at ascending.
                let sort_key = |idx: usize| -> f64 {
                    let author = &self.author_of[idx];
                    if self.reader_id.as_ref().is_some_and(|r| r == author) {
                        0.0
                    } else {
                        self.trust_map.get(author).copied().unwrap_or(f64::MAX)
                    }
                };
                child_indices.sort_by(|&a, &b| {
                    sort_key(a)
                        .partial_cmp(&sort_key(b))
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| {
                            let ts_a = posts[a]
                                .as_ref()
                                .map(|p| p.created_at.as_str())
                                .unwrap_or("");
                            let ts_b = posts[b]
                                .as_ref()
                                .map(|p| p.created_at.as_str())
                                .unwrap_or("");
                            ts_a.cmp(ts_b)
                        })
                });
            }

            let children: Vec<PostResponse> = child_indices
                .into_iter()
                .filter_map(|ci| {
                    if self.retracted.contains(&ci) && !self.children_map.contains_key(&ci) {
                        return None;
                    }
                    if !self.is_visible(ci, false) {
                        return None;
                    }
                    Some(self.build_tree(ci, posts))
                })
                .collect();
            let mut post = posts[idx].take().expect("post already taken from tree");
            post.children = children;
            post
        }
    }

    let root_idx =
        root_idx.ok_or_else(|| AppError::Internal("thread has no opening post".into()))?;
    let ctx = TreeCtx {
        children_map: &children_map,
        retracted: &retracted,
        reader_id: &reader_id,
        author_of: &author_of,
        parent_author_of: &parent_author_of,
        reverse_map: &reverse_map,
        trust_map: &trust_map,
        room_public,
        sort_by_new,
    };
    let op = ctx.build_tree(root_idx, &mut posts);

    fn count_replies(post: &PostResponse) -> i64 {
        let mut count = post.children.len() as i64;
        for child in &post.children {
            count += count_replies(child);
        }
        count
    }
    let reply_count = count_replies(&op);

    Ok(Json(ThreadDetailResponse {
        id,
        title,
        author_id: thread_author_id,
        author_name: thread_author_name,
        room_id,
        room_name,
        room_slug,
        created_at,
        locked,
        room_public,
        post: op,
        reply_count,
    }))
}
