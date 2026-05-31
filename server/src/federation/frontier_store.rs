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

use sqlx::SqlitePool;

use crate::signed::{TrustEdge, TrustStance};

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
}
