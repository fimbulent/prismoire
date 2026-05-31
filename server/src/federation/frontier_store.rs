//! Reverse-frontier edge store (§8.9, §8.12).
//!
//! The pubkey-keyed counterpart to the local-account `trust_edges`
//! table. The multi-source reverse BFS that grows this instance's
//! frontier (§8.9) traverses directed trust edges between
//! pubkey-identified users who are overwhelmingly *remote* — their
//! identity stubs live in `frontier_users`, not `users` — so their
//! edges cannot live in the UUID-keyed, FK-bound `trust_edges` table.
//! They live here, in `frontier_edges`, one row per signed `trust-edge`
//! object, identified by `(source_pubkey, target_pubkey)` and deduped
//! on `canonical_hash`.
//!
//! **Phase 3 / Slice D1 scope.** This module is the store layer only:
//! the schema (migration `…_create_frontier_edges`) plus the read/write
//! helpers below. It is deliberately *not yet* wired into the edge
//! receive path (§9.1) or the reverse BFS — those land in later
//! sub-slices (D2 BFS + stub materialization, D3 cap-at-N admission, D4
//! generational mark-sweep GC). The `generation` column and
//! [`mark_frontier_edge_live`] exist now so the receive/BFS wiring has a
//! stable surface to target.
//!
//! The store is **append-mostly** (§8.12): a row is written once on
//! first receipt and never mutated except to restamp its `generation`
//! GC tag when the reverse BFS marks it live. The active graph (latest
//! stance per pair, `neutral` tombstones dropped) is derived at read
//! time — this is the log, not the resolved graph.

use std::collections::{HashMap, HashSet, VecDeque};

use sqlx::SqlitePool;

use crate::signed::{TrustEdge, TrustStance};

/// Default reverse-frontier traversal depth (§8.9 reverse-hop 0..3).
/// Mirrors `trust::MAX_DEPTH` — the reverse frontier is the set of
/// authors reachable within this many reverse *trust* hops of any local
/// root. Kept as a named constant here (rather than importing the
/// private `trust::MAX_DEPTH`) so the store layer has no dependency on
/// the in-memory graph module; the two MUST stay equal because both
/// govern reachability in the distributed BFS (§8.9 "MUST stay
/// protocol-global").
pub const FRONTIER_MAX_DEPTH: u32 = 3;

/// A lean projection of a stored `frontier_edges` row, carrying exactly
/// what the reverse BFS (§8.9) needs to traverse and resolve the active
/// graph — **without** the (potentially large) signed `payload`, which
/// is fetched on demand via [`load_frontier_edge_payload`] only when a
/// re-forward or backfill response actually needs the original bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontierEdgeRef {
    /// Canonical hash of the signed object — the row's identity and
    /// dedup key.
    pub canonical_hash: [u8; 32],
    /// Truster's Ed25519 key. Becomes a new frontier node when its
    /// target is expanded.
    pub source_pubkey: [u8; 32],
    /// Trustee's Ed25519 key. The reverse-BFS traversal key ("who
    /// trusts this target").
    pub target_pubkey: [u8; 32],
    /// Canonical hash of the previous signed row for the same
    /// `(source, target)` pair, or `None` for the genesis edge.
    pub prior_edge_hash: Option<[u8; 32]>,
    /// Stance carried by this object (`trust` / `distrust` / `neutral`).
    pub stance: TrustStance,
    /// Signed `created_at`, Unix milliseconds UTC — orders the per-pair
    /// chain when resolving the active stance.
    pub created_at: u64,
    /// §8.12 GC generation tag last stamped on this row.
    pub generation: i64,
}

/// Insert a signed trust-edge into the reverse-frontier edge store,
/// deduped on `canonical_hash` (§9 idempotency: a redelivered edge is a
/// no-op). Returns `true` if a new row was written, `false` if the edge
/// was already present.
///
/// `generation` stamps the row's initial GC tag — pass the rebuild
/// generation under which this edge was received/marked live so the
/// §8.12 sweep treats it as fresh.
///
/// This is the store-level write only; chain-continuity validation,
/// orphan buffering (`pending_trust_edges`), and signature verification
/// are the receive path's responsibility (§9.1) and are layered on in a
/// later sub-slice.
pub async fn insert_frontier_edge(
    db: &SqlitePool,
    edge: &TrustEdge,
    canonical_hash: &[u8; 32],
    signature: &[u8; 64],
    payload: &[u8],
    generation: i64,
) -> Result<bool, sqlx::Error> {
    let canonical = canonical_hash.as_slice();
    let source = edge.from_key.as_slice();
    let target = edge.to_key.as_slice();
    let prior = edge.prior_edge_hash.map(|h| h.to_vec());
    let stance = edge.stance.as_str();
    // `created_at` is wire `u64` ms; the column is INTEGER (i64). A
    // value past i64::MAX is ~292M years out — clamp rather than wrap so
    // chain ordering stays monotonic. The exact timestamp is preserved
    // verbatim in `payload`.
    let created_at = i64::try_from(edge.created_at).unwrap_or(i64::MAX);
    let signature = signature.as_slice();

    let result = sqlx::query!(
        "INSERT OR IGNORE INTO frontier_edges \
            (canonical_hash, source_pubkey, target_pubkey, prior_edge_hash, \
             stance, created_at, payload, signature, generation) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        canonical,
        source,
        target,
        prior,
        stance,
        created_at,
        payload,
        signature,
        generation,
    )
    .execute(db)
    .await?;

    Ok(result.rows_affected() != 0)
}

/// Read every stored edge whose `target_pubkey == target` — the reverse
/// BFS expansion hot path ("who trusts this key"), served by
/// `idx_frontier_edges_target`.
///
/// Returns lean [`FrontierEdgeRef`]s (no payload). Rows whose stored
/// key/hash blobs are not the expected width are skipped defensively
/// rather than failing the whole read; the CHECK constraints make that
/// unreachable for rows this store wrote, but the read stays robust
/// against external tampering, mirroring `load_local_age_ceilings`.
pub async fn frontier_edges_by_target(
    db: &SqlitePool,
    target: &[u8; 32],
) -> Result<Vec<FrontierEdgeRef>, sqlx::Error> {
    let target = target.as_slice();
    let rows = sqlx::query!(
        "SELECT canonical_hash AS \"canonical_hash!: Vec<u8>\", \
                source_pubkey AS \"source_pubkey!: Vec<u8>\", \
                target_pubkey AS \"target_pubkey!: Vec<u8>\", \
                prior_edge_hash AS \"prior_edge_hash: Vec<u8>\", \
                stance, created_at, generation \
         FROM frontier_edges \
         WHERE target_pubkey = ?",
        target,
    )
    .fetch_all(db)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(canonical_hash) = to_array_32(&row.canonical_hash) else {
            continue;
        };
        let Some(source_pubkey) = to_array_32(&row.source_pubkey) else {
            continue;
        };
        let Some(target_pubkey) = to_array_32(&row.target_pubkey) else {
            continue;
        };
        let prior_edge_hash = match row.prior_edge_hash {
            Some(ref bytes) => match to_array_32(bytes) {
                Some(h) => Some(h),
                None => continue,
            },
            None => None,
        };
        let Some(stance) = TrustStance::parse(&row.stance) else {
            continue;
        };
        let Ok(created_at) = u64::try_from(row.created_at) else {
            continue;
        };
        out.push(FrontierEdgeRef {
            canonical_hash,
            source_pubkey,
            target_pubkey,
            prior_edge_hash,
            stance,
            created_at,
            generation: row.generation,
        });
    }
    Ok(out)
}

/// Fetch the original signed `payload` and `signature` for a stored
/// edge, looked up by `canonical_hash`. Returns `None` if no such edge
/// is stored. Used by the re-forward (§7.5) and backfill (§9 chain
/// continuity) paths, which need the verbatim bytes the BFS read omits.
pub async fn load_frontier_edge_payload(
    db: &SqlitePool,
    canonical_hash: &[u8; 32],
) -> Result<Option<(Vec<u8>, [u8; 64])>, sqlx::Error> {
    let canonical = canonical_hash.as_slice();
    let row = sqlx::query!(
        "SELECT payload AS \"payload!: Vec<u8>\", \
                signature AS \"signature!: Vec<u8>\" \
         FROM frontier_edges WHERE canonical_hash = ?",
        canonical,
    )
    .fetch_optional(db)
    .await?;

    let Some(row) = row else { return Ok(None) };
    let Ok(signature) = <[u8; 64]>::try_from(row.signature.as_slice()) else {
        return Ok(None);
    };
    Ok(Some((row.payload, signature)))
}

/// Restamp a stored edge's §8.12 GC generation — the mark step of the
/// generational mark-sweep. Called when the reverse-BFS rebuild touches
/// this edge as reachable-and-admitted. A no-op (and `Ok`) if no edge
/// with that hash is stored. Also bumps `updated_at` for operator
/// visibility; the sweep keys off `generation`, not the timestamp.
pub async fn mark_frontier_edge_live(
    db: &SqlitePool,
    canonical_hash: &[u8; 32],
    generation: i64,
) -> Result<(), sqlx::Error> {
    let canonical = canonical_hash.as_slice();
    sqlx::query!(
        "UPDATE frontier_edges \
         SET generation = ?, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE canonical_hash = ?",
        generation,
        canonical,
    )
    .execute(db)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Multi-source reverse BFS (§8.9) + frontier_users materialization (§8.11)
// ---------------------------------------------------------------------------

/// Outcome of the multi-source reverse BFS over the edge store: the
/// structural reverse frontier (§8.9) plus the bookkeeping the §8.12
/// mark phase and the §8.11 materialization produced.
///
/// This is the **uncapped** structural frontier — every author reachable
/// within `max_depth` reverse *trust* hops of any root. The cap-at-`N`
/// admission and forward-score ranking that prune this down to each
/// reader's visible set are a later sub-slice (D3); they do not change
/// which edges the mark phase keeps alive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReverseFrontier {
    /// Every non-root key reached via an active-trust path — the
    /// structural reverse frontier. Includes both remote keys (which get
    /// a `frontier_users` stub when home resolves) and any local key that
    /// happens to sit on a frontier path (which does not).
    pub reachable: HashSet<[u8; 32]>,
    /// Remote frontier nodes for which a `frontier_users` stub was
    /// upserted because home (key + domain) resolved (§8.11).
    pub stubs_materialized: usize,
    /// Remote frontier nodes whose home could not be resolved, so the
    /// stub was deferred. Their edges are still marked live, so GC keeps
    /// them; the stub hydrates once a domain-bearing source lands.
    pub stubs_deferred: usize,
    /// Reached keys that are local users (a `users` row with
    /// `home_instance IS NULL`); they are represented by their existing
    /// local row and never get a frontier stub (§8.11).
    pub locals_skipped: usize,
    /// Active edges generation-marked live during this pass — the §8.12
    /// mark step.
    pub edges_marked: usize,
}

/// Run the multi-source reverse BFS that grows this instance's reverse
/// frontier (§8.9) over the `frontier_edges` store, starting from the
/// union of `roots` (the local readers' keys).
///
/// At each node it reads the inbound edges ("who trusts this node"),
/// resolves the active stance per `(source, target)` pair (latest by
/// `created_at`, tie-broken by `canonical_hash`), and:
///
/// - **marks the active edge live** (§8.12 mark phase) regardless of
///   stance — it is the current truth for a reachable pair, so GC must
///   keep it;
/// - **advances the frontier only along `trust`** (§8.9 "authors who
///   trust them"); `distrust` / `neutral` tombstones are marked but not
///   traversed;
/// - **materializes a `frontier_users` stub** for each newly reached
///   remote key whose home resolves (§8.11), deferring otherwise.
///
/// `generation` is the §8.12 GC tag stamped on every edge/stub this pass
/// touches; the caller (the rebuild loop, wired in D4) supplies the
/// current rebuild generation. `max_depth` bounds the reverse hops —
/// pass [`FRONTIER_MAX_DEPTH`] in production.
///
/// The writes (edge marks, stub upserts) are idempotent and are not
/// wrapped in one transaction: the store is append-mostly and a partial
/// pass is simply re-marked by the next rebuild, so holding a single
/// long write lock across a large BFS would cost more than it buys.
pub async fn reverse_frontier_bfs(
    db: &SqlitePool,
    roots: &[[u8; 32]],
    generation: i64,
    max_depth: u32,
) -> Result<ReverseFrontier, sqlx::Error> {
    let mut frontier = ReverseFrontier::default();
    let mut visited: HashSet<[u8; 32]> = HashSet::new();
    let mut queue: VecDeque<([u8; 32], u32)> = VecDeque::new();

    // Seed with the roots at depth 0. Roots are local readers — never
    // frontier nodes themselves and never stubbed — but they are the
    // targets whose inbound trusters the first hop expands.
    for root in roots {
        if visited.insert(*root) {
            queue.push_back((*root, 0));
        }
    }

    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        let inbound = frontier_edges_by_target(db, &node).await?;
        for edge in active_edges_by_source(inbound) {
            // §8.12 mark: the active edge for a reachable pair is live.
            mark_frontier_edge_live(db, &edge.canonical_hash, generation).await?;
            frontier.edges_marked += 1;

            // Only trust advances the reverse frontier (§8.9).
            if edge.stance != TrustStance::Trust {
                continue;
            }
            let source = edge.source_pubkey;
            if !visited.insert(source) {
                continue;
            }
            match materialize_frontier_node(db, &source, generation).await? {
                NodeMaterialization::Local => frontier.locals_skipped += 1,
                NodeMaterialization::Stub => frontier.stubs_materialized += 1,
                NodeMaterialization::Deferred => frontier.stubs_deferred += 1,
            }
            frontier.reachable.insert(source);
            queue.push_back((source, depth + 1));
        }
    }
    Ok(frontier)
}

/// Collapse a node's inbound edges to one active edge per source: the
/// latest by `(created_at, canonical_hash)`. The `canonical_hash`
/// tiebreak makes the choice deterministic when two rows for the same
/// pair share a `created_at` (e.g. a rapid trust→neutral flip clamped to
/// the same millisecond), so the BFS is reproducible.
fn active_edges_by_source(edges: Vec<FrontierEdgeRef>) -> Vec<FrontierEdgeRef> {
    let mut by_source: HashMap<[u8; 32], FrontierEdgeRef> = HashMap::new();
    for edge in edges {
        match by_source.get(&edge.source_pubkey) {
            Some(existing)
                if (existing.created_at, existing.canonical_hash)
                    >= (edge.created_at, edge.canonical_hash) => {}
            _ => {
                by_source.insert(edge.source_pubkey, edge);
            }
        }
    }
    by_source.into_values().collect()
}

/// How a reached frontier node was materialized.
enum NodeMaterialization {
    /// A local user (`users` row with NULL home) — no stub written.
    Local,
    /// A remote key with resolvable home — a `frontier_users` stub was
    /// upserted.
    Stub,
    /// A remote key with no resolvable home — stub deferred.
    Deferred,
}

/// Decide and apply the §8.11 materialization for one reached key.
async fn materialize_frontier_node(
    db: &SqlitePool,
    key: &[u8; 32],
    generation: i64,
) -> Result<NodeMaterialization, sqlx::Error> {
    if is_local_user(db, key).await? {
        return Ok(NodeMaterialization::Local);
    }
    match resolve_frontier_home(db, key).await? {
        Some((home_key, home_domain)) => {
            upsert_frontier_user_stub(db, key, &home_key, &home_domain, generation).await?;
            Ok(NodeMaterialization::Stub)
        }
        None => Ok(NodeMaterialization::Deferred),
    }
}

/// True iff `key` belongs to a local user — a `users` row with
/// `home_instance IS NULL`. Local users that sit on a frontier path are
/// represented by their existing row and never get a frontier stub
/// (§8.11).
async fn is_local_user(db: &SqlitePool, key: &[u8; 32]) -> Result<bool, sqlx::Error> {
    let key_slice: &[u8] = key.as_slice();
    let row = sqlx::query!(
        "SELECT public_key FROM users WHERE public_key = ? AND home_instance IS NULL",
        key_slice,
    )
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// Resolve a remote frontier key's home as `(home_instance_key,
/// home_instance_domain)`, or `None` when neither is recoverable.
///
/// The `frontier_users` stub needs both the key *and* the domain, but
/// the general receive path only ever stores a home *key*
/// (`resolve_current_home`), so the domain is the binding constraint:
///
/// 1. **`user_homes`** — the authoritative §12.4 projection carries both
///    `current_home_key` and `current_home_domain`. Present for keys
///    that moved, cross-registered, or were trust-code-seeded.
/// 2. **`users.home_instance` ⋈ `peers`** — a remote stub carries the
///    home key; the domain is recoverable iff that home is a *direct
///    peer* (the only table mapping instance key → domain).
///
/// A key with neither resolves to `None` (deferred): its edges are still
/// marked live, and the stub hydrates once a domain-bearing source
/// arrives, matching §8.11's "home last learned through gossip".
async fn resolve_frontier_home(
    db: &SqlitePool,
    key: &[u8; 32],
) -> Result<Option<([u8; 32], String)>, sqlx::Error> {
    let key_slice: &[u8] = key.as_slice();

    let from_homes = sqlx::query!(
        "SELECT current_home_key AS \"current_home_key!: Vec<u8>\", current_home_domain \
         FROM user_homes WHERE user_key = ?",
        key_slice,
    )
    .fetch_optional(db)
    .await?;
    if let Some(row) = from_homes
        && let Some(home_key) = to_array_32(&row.current_home_key)
        && !row.current_home_domain.is_empty()
    {
        return Ok(Some((home_key, row.current_home_domain)));
    }

    let from_peer = sqlx::query!(
        "SELECT u.home_instance AS \"home_instance!: Vec<u8>\", p.instance_domain \
         FROM users u \
         JOIN peers p ON p.instance_pubkey = u.home_instance \
         WHERE u.public_key = ? AND u.home_instance IS NOT NULL",
        key_slice,
    )
    .fetch_optional(db)
    .await?;
    if let Some(row) = from_peer
        && let Some(home_key) = to_array_32(&row.home_instance)
        && !row.instance_domain.is_empty()
    {
        return Ok(Some((home_key, row.instance_domain)));
    }

    Ok(None)
}

/// Upsert a `frontier_users` stub (§8.11) for `key`, refreshing its home
/// pointer and stamping the current §8.12 GC generation. `display_name`
/// is intentionally untouched — it is carried opportunistically by
/// gossip, not by edges, so it stays at whatever a prior profile sync
/// supplied (NULL until then).
async fn upsert_frontier_user_stub(
    db: &SqlitePool,
    key: &[u8; 32],
    home_key: &[u8; 32],
    home_domain: &str,
    generation: i64,
) -> Result<(), sqlx::Error> {
    let key_slice: &[u8] = key.as_slice();
    let home_key_slice: &[u8] = home_key.as_slice();
    sqlx::query!(
        "INSERT INTO frontier_users \
            (user_key, home_instance_key, home_instance_domain, generation) \
         VALUES (?, ?, ?, ?) \
         ON CONFLICT(user_key) DO UPDATE SET \
             home_instance_key = excluded.home_instance_key, \
             home_instance_domain = excluded.home_instance_domain, \
             generation = excluded.generation, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
        key_slice,
        home_key_slice,
        home_domain,
        generation,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Convert a stored BLOB into a fixed 32-byte array, or `None` if it is
/// not exactly 32 bytes.
fn to_array_32(bytes: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn fresh_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    fn sample_edge(source: u8, target: u8, stance: TrustStance, prior: bool) -> TrustEdge {
        TrustEdge {
            from_key: [source; 32],
            to_key: [target; 32],
            stance,
            created_at: 1_700_000_000_000,
            prior_edge_hash: prior.then_some([9u8; 32]),
        }
    }

    #[tokio::test]
    async fn insert_then_read_by_target_round_trips() {
        let pool = fresh_pool().await;
        let edge = sample_edge(1, 2, TrustStance::Trust, false);
        let canonical = [7u8; 32];
        let signature = [3u8; 64];
        let payload = b"signed-bytes".to_vec();

        let inserted = insert_frontier_edge(&pool, &edge, &canonical, &signature, &payload, 5)
            .await
            .unwrap();
        assert!(inserted, "first insert writes a new row");

        let edges = frontier_edges_by_target(&pool, &[2u8; 32]).await.unwrap();
        assert_eq!(edges.len(), 1);
        let got = &edges[0];
        assert_eq!(got.canonical_hash, canonical);
        assert_eq!(got.source_pubkey, [1u8; 32]);
        assert_eq!(got.target_pubkey, [2u8; 32]);
        assert_eq!(got.prior_edge_hash, None);
        assert_eq!(got.stance, TrustStance::Trust);
        assert_eq!(got.created_at, 1_700_000_000_000);
        assert_eq!(got.generation, 5);
    }

    #[tokio::test]
    async fn insert_dedups_on_canonical_hash() {
        let pool = fresh_pool().await;
        let edge = sample_edge(1, 2, TrustStance::Trust, false);
        let canonical = [7u8; 32];
        let signature = [3u8; 64];

        let first = insert_frontier_edge(&pool, &edge, &canonical, &signature, b"a", 1)
            .await
            .unwrap();
        let second = insert_frontier_edge(&pool, &edge, &canonical, &signature, b"a", 2)
            .await
            .unwrap();
        assert!(first, "first insert is new");
        assert!(!second, "redelivery of the same canonical hash is a no-op");

        let edges = frontier_edges_by_target(&pool, &[2u8; 32]).await.unwrap();
        assert_eq!(edges.len(), 1, "dedup keeps exactly one row");
        assert_eq!(
            edges[0].generation, 1,
            "the no-op insert does not overwrite the original generation"
        );
    }

    #[tokio::test]
    async fn by_target_filters_to_the_requested_trustee() {
        let pool = fresh_pool().await;
        // Two edges point at target 2, one at target 4.
        insert_frontier_edge(
            &pool,
            &sample_edge(1, 2, TrustStance::Trust, false),
            &[10u8; 32],
            &[0u8; 64],
            b"x",
            0,
        )
        .await
        .unwrap();
        insert_frontier_edge(
            &pool,
            &sample_edge(3, 2, TrustStance::Distrust, true),
            &[11u8; 32],
            &[0u8; 64],
            b"y",
            0,
        )
        .await
        .unwrap();
        insert_frontier_edge(
            &pool,
            &sample_edge(1, 4, TrustStance::Trust, false),
            &[12u8; 32],
            &[0u8; 64],
            b"z",
            0,
        )
        .await
        .unwrap();

        let mut target_2 = frontier_edges_by_target(&pool, &[2u8; 32]).await.unwrap();
        target_2.sort_by_key(|e| e.source_pubkey);
        assert_eq!(target_2.len(), 2);
        assert_eq!(target_2[0].source_pubkey, [1u8; 32]);
        assert_eq!(target_2[1].source_pubkey, [3u8; 32]);
        assert_eq!(target_2[1].stance, TrustStance::Distrust);
        assert_eq!(target_2[1].prior_edge_hash, Some([9u8; 32]));

        let target_4 = frontier_edges_by_target(&pool, &[4u8; 32]).await.unwrap();
        assert_eq!(target_4.len(), 1);
        assert_eq!(target_4[0].target_pubkey, [4u8; 32]);
    }

    #[tokio::test]
    async fn load_payload_returns_stored_bytes() {
        let pool = fresh_pool().await;
        let edge = sample_edge(1, 2, TrustStance::Trust, false);
        let canonical = [7u8; 32];
        let signature = [42u8; 64];
        let payload = b"the-verbatim-signed-object".to_vec();
        insert_frontier_edge(&pool, &edge, &canonical, &signature, &payload, 0)
            .await
            .unwrap();

        let got = load_frontier_edge_payload(&pool, &canonical).await.unwrap();
        assert_eq!(got, Some((payload, signature)));

        let missing = load_frontier_edge_payload(&pool, &[0u8; 32]).await.unwrap();
        assert_eq!(missing, None);
    }

    #[tokio::test]
    async fn mark_live_restamps_generation() {
        let pool = fresh_pool().await;
        let edge = sample_edge(1, 2, TrustStance::Trust, false);
        let canonical = [7u8; 32];
        insert_frontier_edge(&pool, &edge, &canonical, &[0u8; 64], b"x", 1)
            .await
            .unwrap();

        mark_frontier_edge_live(&pool, &canonical, 4).await.unwrap();
        let edges = frontier_edges_by_target(&pool, &[2u8; 32]).await.unwrap();
        assert_eq!(edges[0].generation, 4);

        // Marking an absent edge is a harmless no-op.
        mark_frontier_edge_live(&pool, &[0u8; 32], 9).await.unwrap();
    }

    // --- D2: reverse BFS + materialization -------------------------------

    fn edge_at(
        source: u8,
        target: u8,
        stance: TrustStance,
        created_at: u64,
        prior: Option<[u8; 32]>,
    ) -> TrustEdge {
        TrustEdge {
            from_key: [source; 32],
            to_key: [target; 32],
            stance,
            created_at,
            prior_edge_hash: prior,
        }
    }

    /// Insert a frontier edge with an explicit canonical hash so tests
    /// can reference it. `tag` becomes every byte of the 32-byte hash.
    async fn put_edge(pool: &SqlitePool, edge: &TrustEdge, tag: u8, generation: i64) {
        insert_frontier_edge(pool, edge, &[tag; 32], &[0u8; 64], b"p", generation)
            .await
            .unwrap();
    }

    async fn seed_user_home(pool: &SqlitePool, user: u8, home: u8, domain: &str) {
        sqlx::query(
            "INSERT INTO user_homes (user_key, current_home_key, current_home_domain) \
             VALUES (?, ?, ?)",
        )
        .bind([user; 32].as_slice())
        .bind([home; 32].as_slice())
        .bind(domain)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn seed_local_user(pool: &SqlitePool, key: u8, name: &str) {
        sqlx::query(
            "INSERT INTO users (id, display_name, signup_method, public_key) \
             VALUES (?, ?, 'admin', ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(name)
        .bind([key; 32].as_slice())
        .execute(pool)
        .await
        .unwrap();
    }

    async fn seed_remote_stub(pool: &SqlitePool, key: u8, name: &str, home: u8) {
        sqlx::query(
            "INSERT INTO users (id, display_name, signup_method, public_key, home_instance) \
             VALUES (?, ?, 'federated', ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(name)
        .bind([key; 32].as_slice())
        .bind([home; 32].as_slice())
        .execute(pool)
        .await
        .unwrap();
    }

    async fn seed_peer(pool: &SqlitePool, instance: u8, domain: &str) {
        sqlx::query(
            "INSERT INTO peers (instance_pubkey, instance_domain, status, direction, request_id) \
             VALUES (?, ?, 'active', 'outbound', ?)",
        )
        .bind([instance; 32].as_slice())
        .bind(domain)
        .bind(vec![instance; 16])
        .execute(pool)
        .await
        .unwrap();
    }

    async fn stored_stub_home(pool: &SqlitePool, key: u8) -> Option<([u8; 32], String)> {
        let row = sqlx::query_as::<_, (Vec<u8>, String)>(
            "SELECT home_instance_key, home_instance_domain FROM frontier_users WHERE user_key = ?",
        )
        .bind([key; 32].as_slice())
        .fetch_optional(pool)
        .await
        .unwrap();
        row.map(|(k, d)| (to_array_32(&k).unwrap(), d))
    }

    #[tokio::test]
    async fn bfs_reaches_truster_and_materializes_stub() {
        let pool = fresh_pool().await;
        // X (key 1) trusts root R (key 9); X is homed on instance 5.
        put_edge(
            &pool,
            &edge_at(1, 9, TrustStance::Trust, 100, None),
            0xA1,
            0,
        )
        .await;
        seed_user_home(&pool, 1, 5, "x.example").await;

        let f = reverse_frontier_bfs(&pool, &[[9u8; 32]], 7, FRONTIER_MAX_DEPTH)
            .await
            .unwrap();

        assert!(f.reachable.contains(&[1u8; 32]));
        assert_eq!(f.stubs_materialized, 1);
        assert_eq!(f.stubs_deferred, 0);
        assert_eq!(f.locals_skipped, 0);
        assert_eq!(f.edges_marked, 1);

        assert_eq!(
            stored_stub_home(&pool, 1).await,
            Some(([5u8; 32], "x.example".into()))
        );
        // The traversed edge was stamped with the pass generation.
        let edges = frontier_edges_by_target(&pool, &[9u8; 32]).await.unwrap();
        assert_eq!(edges[0].generation, 7);
    }

    #[tokio::test]
    async fn bfs_respects_max_depth() {
        let pool = fresh_pool().await;
        // Chain Z(3) -> Y(2) -> X(1) -> R(9), all trust.
        put_edge(
            &pool,
            &edge_at(1, 9, TrustStance::Trust, 100, None),
            0x01,
            0,
        )
        .await;
        put_edge(
            &pool,
            &edge_at(2, 1, TrustStance::Trust, 100, None),
            0x02,
            0,
        )
        .await;
        put_edge(
            &pool,
            &edge_at(3, 2, TrustStance::Trust, 100, None),
            0x03,
            0,
        )
        .await;
        for k in [1u8, 2, 3] {
            seed_user_home(&pool, k, 5, "h.example").await;
        }

        let f = reverse_frontier_bfs(&pool, &[[9u8; 32]], 0, 2)
            .await
            .unwrap();
        // Depth 1 = X, depth 2 = Y reached; Z at depth 3 is beyond the cap.
        assert!(f.reachable.contains(&[1u8; 32]));
        assert!(f.reachable.contains(&[2u8; 32]));
        assert!(!f.reachable.contains(&[3u8; 32]));
        assert_eq!(f.reachable.len(), 2);
    }

    #[tokio::test]
    async fn neutral_tombstone_marked_but_not_traversed() {
        let pool = fresh_pool().await;
        // X's only edge to R is a neutral tombstone — X does not trust R.
        put_edge(
            &pool,
            &edge_at(1, 9, TrustStance::Neutral, 100, None),
            0x55,
            0,
        )
        .await;
        seed_user_home(&pool, 1, 5, "x.example").await;

        let f = reverse_frontier_bfs(&pool, &[[9u8; 32]], 4, FRONTIER_MAX_DEPTH)
            .await
            .unwrap();
        assert!(f.reachable.is_empty(), "a neutral edge is not a trust path");
        assert_eq!(f.stubs_materialized, 0);
        assert_eq!(
            f.edges_marked, 1,
            "the active tombstone is still marked live"
        );
        assert!(stored_stub_home(&pool, 1).await.is_none());

        let edges = frontier_edges_by_target(&pool, &[9u8; 32]).await.unwrap();
        assert_eq!(edges[0].generation, 4);
    }

    #[tokio::test]
    async fn latest_stance_wins_in_a_pair_chain() {
        let pool = fresh_pool().await;
        // X→R: trust at t=100, then a newer neutral at t=200 (revocation).
        let trust = edge_at(1, 9, TrustStance::Trust, 100, None);
        let revoke = edge_at(1, 9, TrustStance::Neutral, 200, Some([0xaau8; 32]));
        put_edge(&pool, &trust, 0xAA, 0).await; // hash referenced as prior
        put_edge(&pool, &revoke, 0xBB, 0).await;
        seed_user_home(&pool, 1, 5, "x.example").await;

        let f = reverse_frontier_bfs(&pool, &[[9u8; 32]], 1, FRONTIER_MAX_DEPTH)
            .await
            .unwrap();
        assert!(f.reachable.is_empty(), "newest stance (neutral) wins");
        assert_eq!(f.edges_marked, 1, "only the active edge is marked");

        // The active (newer) edge got the mark; the superseded one did not.
        let mut edges = frontier_edges_by_target(&pool, &[9u8; 32]).await.unwrap();
        edges.sort_by_key(|e| e.created_at);
        assert_eq!(edges[0].generation, 0, "superseded trust row not re-marked");
        assert_eq!(edges[1].generation, 1, "active neutral row marked");
    }

    #[tokio::test]
    async fn local_user_source_is_skipped_not_stubbed() {
        let pool = fresh_pool().await;
        put_edge(
            &pool,
            &edge_at(1, 9, TrustStance::Trust, 100, None),
            0x01,
            0,
        )
        .await;
        seed_local_user(&pool, 1, "alice").await; // X is one of our own users

        let f = reverse_frontier_bfs(&pool, &[[9u8; 32]], 2, FRONTIER_MAX_DEPTH)
            .await
            .unwrap();
        assert!(f.reachable.contains(&[1u8; 32]));
        assert_eq!(f.locals_skipped, 1);
        assert_eq!(f.stubs_materialized, 0);
        assert_eq!(f.stubs_deferred, 0);
        assert!(stored_stub_home(&pool, 1).await.is_none());
    }

    #[tokio::test]
    async fn unknown_home_defers_stub_but_keeps_edge() {
        let pool = fresh_pool().await;
        // X trusts R but we know nothing about X's home (no user_homes,
        // no users row).
        put_edge(
            &pool,
            &edge_at(1, 9, TrustStance::Trust, 100, None),
            0x01,
            0,
        )
        .await;

        let f = reverse_frontier_bfs(&pool, &[[9u8; 32]], 3, FRONTIER_MAX_DEPTH)
            .await
            .unwrap();
        assert!(f.reachable.contains(&[1u8; 32]));
        assert_eq!(f.stubs_deferred, 1);
        assert_eq!(f.stubs_materialized, 0);
        assert_eq!(f.edges_marked, 1, "edge kept alive despite deferred stub");
        assert!(stored_stub_home(&pool, 1).await.is_none());
    }

    #[tokio::test]
    async fn home_resolves_via_peer_fallback() {
        let pool = fresh_pool().await;
        // No user_homes row; X has a remote stub homed on instance 5, and
        // 5 is a direct peer carrying the domain.
        put_edge(
            &pool,
            &edge_at(1, 9, TrustStance::Trust, 100, None),
            0x01,
            0,
        )
        .await;
        seed_remote_stub(&pool, 1, "x-remote", 5).await;
        seed_peer(&pool, 5, "peer5.example").await;

        let f = reverse_frontier_bfs(&pool, &[[9u8; 32]], 6, FRONTIER_MAX_DEPTH)
            .await
            .unwrap();
        assert_eq!(f.stubs_materialized, 1);
        assert_eq!(
            stored_stub_home(&pool, 1).await,
            Some(([5u8; 32], "peer5.example".into()))
        );
    }

    #[tokio::test]
    async fn multi_source_shares_one_stub_marks_both_edges() {
        let pool = fresh_pool().await;
        // X trusts both roots R1 (9) and R2 (8): two edges, one source.
        put_edge(
            &pool,
            &edge_at(1, 9, TrustStance::Trust, 100, None),
            0x01,
            0,
        )
        .await;
        put_edge(
            &pool,
            &edge_at(1, 8, TrustStance::Trust, 100, None),
            0x02,
            0,
        )
        .await;
        seed_user_home(&pool, 1, 5, "x.example").await;

        let f = reverse_frontier_bfs(&pool, &[[9u8; 32], [8u8; 32]], 1, FRONTIER_MAX_DEPTH)
            .await
            .unwrap();
        assert_eq!(f.reachable.len(), 1, "one shared stub for X");
        assert_eq!(f.stubs_materialized, 1);
        assert_eq!(f.edges_marked, 2, "both inbound edges marked live");
    }
}
