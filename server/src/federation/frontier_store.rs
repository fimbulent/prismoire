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

use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};

use sqlx::SqlitePool;
use uuid::Uuid;

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
pub async fn insert_frontier_edge<'e, E>(
    db: E,
    edge: &TrustEdge,
    canonical_hash: &[u8; 32],
    signature: &[u8; 64],
    payload: &[u8],
    generation: i64,
) -> Result<bool, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
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
// Generational counter + sweep (§8.12) — the GC window machinery
// ---------------------------------------------------------------------------

/// Generation window for the §8.12 mark-sweep: how many rebuilds a row may
/// go untouched before it is swept. A `frontier_edges` / `frontier_users`
/// row stamped at generation `g` survives until the current generation
/// reaches `g + K + 1` (the sweep deletes `generation < current - K`).
///
/// `K = 3` means a row missed by three consecutive rebuilds — three passes
/// in which no local reader's cap reached it — is reaped on the fourth.
/// The slack absorbs transient unreachability (a single rebuild racing an
/// in-flight backfill, or a reader briefly offline) without thrashing the
/// store: evidence is kept a few generations past its last sighting so a
/// re-appearing path does not have to re-fetch it.
pub const FRONTIER_GC_K: i64 = 3;

/// Read the current rebuild generation (§8.12) from the singleton
/// `frontier_generation` row. The row is seeded at migration time, so this
/// always finds it; a missing row is a corrupted DB and surfaces as the
/// `RowNotFound` error rather than being papered over with a default.
pub async fn current_generation<'e, E>(db: E) -> Result<i64, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let row = sqlx::query!("SELECT generation FROM frontier_generation WHERE id = 1")
        .fetch_one(db)
        .await?;
    Ok(row.generation)
}

/// The §8.1 advertised-filter key sets reconstructed from the live
/// `frontier_users` stubs of one rebuild generation. Both sets are
/// *remote* keys only — local roots (hop 0) are never stubbed and are
/// unioned in by the caller ([`compute_local_frontier`]).
#[derive(Debug, Default)]
pub struct FrontierStubKeys {
    /// Stubs at reverse-hop 1..3 — the content-interest slice. A peer
    /// ships content from author `X` to us iff `X` is in `visible`
    /// (plus our local roots).
    pub visible: Vec<[u8; 32]>,
    /// Stubs at reverse-hop 1..2 — the edge-interest slice we still
    /// expand past. Strictly contained in `visible`; we never expand the
    /// hop-3 rim, so soliciting edges that target it would be wasted.
    pub expansion: Vec<[u8; 32]>,
}

/// Load the remote frontier stub keys live in `generation`, split into
/// the §8.1 visible (hop ≤3) and expansion (hop ≤2) slices. Reads only
/// rows stamped with the supplied generation — i.e. nodes the most
/// recent rebuild marked live — so swept-but-not-yet-deleted stubs from
/// older generations are excluded. Rows with a malformed (non-32-byte)
/// key are skipped defensively.
pub async fn load_frontier_stub_keys(
    db: &SqlitePool,
    generation: i64,
) -> Result<FrontierStubKeys, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT user_key AS \"user_key!: Vec<u8>\", reverse_hop \
         FROM frontier_users WHERE generation = ?",
        generation,
    )
    .fetch_all(db)
    .await?;
    let mut out = FrontierStubKeys::default();
    for row in rows {
        let Some(key) = to_array_32(&row.user_key) else {
            continue;
        };
        out.visible.push(key);
        if row.reverse_hop <= 2 {
            out.expansion.push(key);
        }
    }
    Ok(out)
}

/// True iff `key` is in our live §8.1 *expansion set* — the targets
/// whose inbound `trust-edge`s we still want, to discover deeper
/// trusters. Membership is either:
///
/// - a **local user** (`users` row with NULL home) — a reverse-BFS root
///   at hop 0, never stubbed; or
/// - a **`frontier_users` stub at reverse-hop ≤ 2** in the current
///   generation — a remote node we still expand past (we never expand
///   the hop-3 rim).
///
/// This is the single-key form of [`load_frontier_stub_keys`]'s
/// expansion split, used at edge-ingest time to decide whether an
/// inbound edge `S → T` is worth recording in the reverse-frontier store
/// even when `S` is not yet hydrated: §8.1 routes edges by target, so we
/// want `S → T` iff `T` is in this set. Gating on it keeps a stranger
/// from injecting reverse-frontier evidence for keys we don't expand.
pub async fn target_in_expansion_set(
    db: &mut sqlx::SqliteConnection,
    key: &[u8; 32],
) -> Result<bool, sqlx::Error> {
    let key_slice: &[u8] = key.as_slice();
    // Hop 0: local users are always reverse-BFS roots, hence always in
    // the expansion set.
    let is_local = sqlx::query_scalar!(
        "SELECT 1 AS \"x!: i64\" FROM users \
         WHERE public_key = ? AND home_instance IS NULL LIMIT 1",
        key_slice,
    )
    .fetch_optional(&mut *db)
    .await?
    .is_some();
    if is_local {
        return Ok(true);
    }
    // Hop 1..2: a remote stub the most recent rebuild marked live. Older
    // generations are swept-but-maybe-not-deleted, so gate on the live
    // generation exactly as `load_frontier_stub_keys` does.
    let generation = current_generation(&mut *db).await?;
    let stub = sqlx::query_scalar!(
        "SELECT 1 AS \"x!: i64\" FROM frontier_users \
         WHERE user_key = ? AND generation = ? AND reverse_hop <= 2 LIMIT 1",
        key_slice,
        generation,
    )
    .fetch_optional(&mut *db)
    .await?
    .is_some();
    Ok(stub)
}

/// Advance the rebuild generation by one (§8.12) and return the new value.
/// Called once at the start of each reverse-frontier rebuild, immediately
/// before the mark phase, so every edge/stub the rebuild touches is stamped
/// with this fresh generation and the sweep's `current - K` watermark moves
/// forward in lockstep. Monotonic and durable (see the migration): it never
/// resets across restarts.
pub async fn advance_generation(db: &SqlitePool) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!(
        "UPDATE frontier_generation \
         SET generation = generation + 1, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE id = 1 \
         RETURNING generation"
    )
    .fetch_one(db)
    .await?;
    Ok(row.generation)
}

/// Tally of rows reaped by one §8.12 sweep, split by store so operators can
/// see whether edges or stubs dominate the eviction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepOutcome {
    /// `frontier_edges` rows deleted (stamp fell more than `K` behind).
    pub edges_swept: u64,
    /// `frontier_users` stub rows deleted (same window).
    pub stubs_swept: u64,
}

/// Sweep the reverse frontier (§8.12): delete every `frontier_edges` and
/// `frontier_users` row whose `generation` has fallen more than `K` behind
/// `current` — i.e. rows untouched by the last `K` rebuilds, presumed no
/// longer reachable from any local reader's cap.
///
/// `current` is the generation the just-finished rebuild stamped (the value
/// [`advance_generation`] returned); pass [`FRONTIER_GC_K`] for `k` unless a
/// caller overrides the window. The watermark is `current - k`: a row at
/// exactly `current - k` is *kept* (it survived the K-th rebuild), one
/// below is reaped. The two deletes are independent — an edge and the stub
/// of the node it points at age on their own stamps — so a node can lose
/// its stub while a still-fresh edge keeps it, or vice versa; the next
/// rebuild reconciles.
pub async fn sweep_frontier(
    db: &SqlitePool,
    current: i64,
    k: i64,
) -> Result<SweepOutcome, sqlx::Error> {
    let watermark = current - k;
    let edges = sqlx::query!("DELETE FROM frontier_edges WHERE generation < ?", watermark)
        .execute(db)
        .await?
        .rows_affected();
    let stubs = sqlx::query!("DELETE FROM frontier_users WHERE generation < ?", watermark)
        .execute(db)
        .await?
        .rows_affected();
    Ok(SweepOutcome {
        edges_swept: edges,
        stubs_swept: stubs,
    })
}

// ---------------------------------------------------------------------------
// Multi-source reverse BFS (§8.9) + frontier_users materialization (§8.11)
// ---------------------------------------------------------------------------

/// A local reader (BFS root) paired with its forward trust scores — the
/// per-reader input to the §8.9 cap-at-`N` admission.
///
/// `forward_scores` is the reader's *own* outbound trust toward every
/// author it can reach (author UUID → combined score ∈ [0, 1]), computed
/// from the in-memory `TrustGraph` (`forward_scores`). It is local and
/// private — forward trust never crosses the wire — so the caller (the
/// rebuild loop) materialises it here and hands it in. A frontier node
/// absent from this map scores `0.0`: it lands in the age-ranked tail
/// (§8.10), admitted only if old enough to beat the cap's worst.
pub struct FrontierReader {
    /// The reader's Ed25519 key — a reverse-BFS root.
    pub key: [u8; 32],
    /// Reader → author-UUID → forward trust score. Authors not present
    /// score `0.0`.
    pub forward_scores: HashMap<Uuid, f64>,
}

/// One reader's cap-at-`N` outcome from the pass — the bounded set of
/// inbound trusters it admitted (§8.9), keyed back to the reader. Slice E
/// reads [`AdmissionCap::worst_admitted`] here to derive the reader's
/// advertised age ceiling (§8.10/§8.3) and walks the admitted set to
/// cleave forward-reachable trusters from the age-ranked tail.
#[derive(Debug)]
pub struct ReaderCapOutcome {
    /// The local reader this cap belongs to.
    pub key: [u8; 32],
    /// The reader's bounded top-`N` admitted inbound trusters.
    pub cap: AdmissionCap,
}

/// Outcome of the multi-source reverse BFS over the edge store: the
/// **capped** reverse frontier (§8.9) plus the bookkeeping the §8.12
/// mark phase, the §8.11 materialization, and the cap-at-`N` admission
/// produced.
///
/// `reachable` is the *expanded* frontier — the nodes that won admission
/// to at least one reader's cap and were therefore traversed deeper.
/// Nodes that were structurally reached but shed by every reader's cap
/// are counted in `nodes_pruned` and not expanded (online §8.9 expansion
/// pruning); their inbound edges are still marked live so GC keeps the
/// evidence for the next rebuild, where admission may differ.
#[derive(Debug, Default)]
pub struct ReverseFrontier {
    /// Every admitted-and-expanded non-root key. Includes remote keys
    /// (which get a `frontier_users` stub when home resolves) and any
    /// local key that won admission on a frontier path (which does not
    /// get a stub).
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
    /// Structurally-reached nodes shed by every reader's cap and so not
    /// expanded — the §8.9 online expansion-pruning count.
    pub nodes_pruned: usize,
    /// Per-reader cap-at-`N` outcomes, parallel to the `readers` passed
    /// in. Slice E consumes these to derive age ceilings.
    pub caps: Vec<ReaderCapOutcome>,
}

/// Run the multi-source reverse BFS that grows this instance's reverse
/// frontier (§8.9) over the `frontier_edges` store, starting from the
/// union of `readers` (the local readers' keys), bounded per reader by
/// the cap-at-`N` admission.
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
/// - **offers each newly reached source to every reader's cap** (§8.9),
///   ranked `(forward_score desc, genesis_at asc)`. A source admitted to
///   at least one reader's cap is **expanded** (materialized + traversed
///   deeper); a source shed by *every* reader's cap is **pruned** — not
///   expanded, not stubbed, counted in `nodes_pruned`. This is the online
///   §8.9 expansion pruning: BFS visits in distance order, which roughly
///   tracks forward-score rank, so a node that cannot beat any reader's
///   worst-admitted at the moment it is reached is unlikely to ever, and
///   its subtree is not worth traversing.
///
/// Each source's `forward_score` for a reader is that reader's local
/// forward trust toward the source (`FrontierReader::forward_scores`,
/// `0.0` if absent — the age-ranked tail, §8.10); its `genesis_at` is the
/// instance-attested account age from `user_genesis` (`None` if no
/// attestation, the tail-spam floor). `cap_n` is the per-instance cap
/// (default [`DEFAULT_FRONTIER_CAP`]); it is never carried on the wire.
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
    readers: &[FrontierReader],
    cap_n: usize,
    generation: i64,
    max_depth: u32,
) -> Result<ReverseFrontier, sqlx::Error> {
    let mut frontier = ReverseFrontier::default();
    let mut visited: HashSet<[u8; 32]> = HashSet::new();
    let mut queue: VecDeque<([u8; 32], u32)> = VecDeque::new();

    // One cap per reader, positionally parallel to `readers`.
    let mut caps: Vec<AdmissionCap> = readers.iter().map(|_| AdmissionCap::new(cap_n)).collect();

    // Seed with the roots at depth 0. Roots are local readers — never
    // frontier nodes themselves, never stubbed, never offered to a cap —
    // but they are the targets whose inbound trusters the first hop
    // expands.
    for reader in readers {
        if visited.insert(reader.key) {
            queue.push_back((reader.key, 0));
        }
    }

    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        let inbound = frontier_edges_by_target(db, &node).await?;
        for edge in active_edges_by_source(inbound) {
            // §8.12 mark: the active edge for a reachable pair is live,
            // regardless of whether its source survives the cap below.
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

            // §8.9 cap-at-N admission. Resolve the source's UUID once (to
            // index each reader's forward-score map) and its attested age,
            // then offer it to every reader's cap. The source is expanded
            // iff at least one reader admitted it.
            let source_uuid = resolve_user_uuid(db, &source).await?;
            let genesis_at = load_genesis_at(db, &source).await?;
            let mut admitted_any = false;
            for (reader, cap) in readers.iter().zip(caps.iter_mut()) {
                let forward_score = source_uuid
                    .and_then(|u| reader.forward_scores.get(&u))
                    .copied()
                    .unwrap_or(0.0);
                let admission = Admission {
                    truster: source,
                    forward_score,
                    genesis_at,
                };
                if cap.admit(admission) {
                    admitted_any = true;
                }
            }

            if !admitted_any {
                // Shed by every reader's cap: prune the subtree (§8.9).
                // The inbound edge stays marked live above, so GC retains
                // the evidence for the next rebuild.
                frontier.nodes_pruned += 1;
                continue;
            }

            match materialize_frontier_node(db, &source, generation, depth + 1).await? {
                NodeMaterialization::Local => frontier.locals_skipped += 1,
                NodeMaterialization::Stub => frontier.stubs_materialized += 1,
                NodeMaterialization::Deferred => frontier.stubs_deferred += 1,
            }
            frontier.reachable.insert(source);
            queue.push_back((source, depth + 1));
        }
    }

    frontier.caps = readers
        .iter()
        .zip(caps)
        .map(|(reader, cap)| ReaderCapOutcome {
            key: reader.key,
            cap,
        })
        .collect();
    Ok(frontier)
}

/// One full §8.12 mark-sweep rebuild: the generation that drove it, the
/// BFS outcome (mark phase + cap admissions), and the sweep tally.
#[derive(Debug)]
pub struct RebuildOutcome {
    /// The generation [`rebuild_reverse_frontier`] advanced to and stamped
    /// on everything the mark phase touched.
    pub generation: i64,
    /// The §8.9 reverse-BFS result — reachable set, materialization counts,
    /// per-reader caps (the §8.10 ceiling derivation reads these).
    pub frontier: ReverseFrontier,
    /// Rows reaped after the mark phase (§8.12 sweep).
    pub sweep: SweepOutcome,
    /// §8.10 outbound cleave map reconciled from the caps: roots published
    /// vs cleared this pass.
    pub ceilings: CeilingPublication,
}

/// Drive one complete generational mark-sweep rebuild of the reverse
/// frontier (§8.12) — the cadence entry point the rebuild loop calls.
///
/// Three steps, strictly ordered:
///
/// 1. **Advance** the durable generation counter ([`advance_generation`]).
/// 2. **Mark** by running the multi-source reverse BFS
///    ([`reverse_frontier_bfs`]) under that generation — every edge/stub it
///    touches is restamped fresh.
/// 3. **Sweep** ([`sweep_frontier`]) every row left more than `K`
///    generations behind.
/// 4. **Publish** ([`publish_local_age_ceilings`]) the §8.10 outbound
///    cleave map from the finished caps.
///
/// Order matters: the advance must precede the mark so the watermark and
/// the fresh stamps move together, and the sweep must follow the mark so a
/// row re-marked this pass is never a sweep candidate. The publish runs last
/// because it reads the caps the mark phase filled. The steps are
/// deliberately *not* one transaction — a crash partway just leaves stale
/// rows / a stale ceiling for the next rebuild to reconcile, which the
/// K-generation slack and the §8.10 opportunistic backstop already tolerate,
/// and avoids holding a write lock across the whole BFS (consistent with the
/// BFS's own per-write idempotent approach).
///
/// `readers`, `cap_n`, and `max_depth` are forwarded to the BFS; pass
/// [`FRONTIER_GC_K`] for `k` unless an operator overrides the GC window.
pub async fn rebuild_reverse_frontier(
    db: &SqlitePool,
    readers: &[FrontierReader],
    cap_n: usize,
    max_depth: u32,
    k: i64,
) -> Result<RebuildOutcome, sqlx::Error> {
    let generation = advance_generation(db).await?;
    let frontier = reverse_frontier_bfs(db, readers, cap_n, generation, max_depth).await?;
    let sweep = sweep_frontier(db, generation, k).await?;
    let ceilings = publish_local_age_ceilings(db, &frontier).await?;
    Ok(RebuildOutcome {
        generation,
        frontier,
        sweep,
        ceilings,
    })
}

/// Collapse a node's inbound edges to one active edge per source: the
/// latest by `(created_at, canonical_hash)`. The `canonical_hash`
/// tiebreak makes the choice deterministic when two rows for the same
/// pair share a `created_at` (e.g. a rapid trust→neutral flip clamped to
/// the same millisecond).
///
/// The returned vector is sorted by `source_pubkey` so the BFS offers
/// sources to the caps in a stable order. Under the §8.9 *online*
/// expansion pruning the cap admission is order-sensitive (a node
/// admitted then evicted by a later better candidate may already have
/// been expanded), so a deterministic offer order is what makes a rebuild
/// reproducible.
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
    let mut active: Vec<FrontierEdgeRef> = by_source.into_values().collect();
    active.sort_by_key(|edge| edge.source_pubkey);
    active
}

// ---------------------------------------------------------------------------
// Cap-at-N admission (§8.9) — the per-reader bounded inbound-truster set
// ---------------------------------------------------------------------------

/// Default per-reader cap on admitted inbound trusters (§8.9 cap-at-`N`).
///
/// A reader keeps at most this many inbound trusters in their visible
/// frontier; the rest are shed (§8.10). This is a per-instance operator
/// knob — it is **never** carried on the wire (peers learn only the
/// resulting age ceiling, §8.3, derived in Slice E), so two instances may
/// run different caps without protocol divergence.
pub const DEFAULT_FRONTIER_CAP: usize = 100_000;

/// One inbound truster competing for a reader's bounded admission set
/// (§8.9). Ordered "better is greater": higher `forward_score` wins, then
/// older account (smaller `genesis_at`) wins, with an unknown/unattested
/// genesis ranking worst of all (the tail-spam floor — a freshly minted
/// key with no instance-vouched age cannot outrank an attested old one).
///
/// `forward_score` is the reader's *own* forward trust toward this truster
/// (local, private — computed from the in-memory `TrustGraph`); a truster
/// the reader does not forward-trust scores `0.0` and lands in the
/// age-ranked tail (§8.10). `genesis_at` is the instance-attested account
/// birth (`user_genesis.genesis_at`, Slice B), `None` when no attestation
/// is on file.
#[derive(Debug, Clone, Copy)]
pub struct Admission {
    /// The inbound truster's Ed25519 key — the frontier node competing
    /// for admission.
    pub truster: [u8; 32],
    /// Reader's forward trust toward `truster` ∈ [0, 1]; `0.0` for the
    /// no-forward-trust age-ranked tail (§8.10).
    pub forward_score: f64,
    /// Instance-attested account birth (unix ms), `None` when unattested.
    /// Older (smaller) ranks higher; `None` ranks worst.
    pub genesis_at: Option<i64>,
}

impl Admission {
    /// Compare by admission desirability — "greater is more admittable",
    /// so the worst candidate is the `min`, which the cap's min-heap keeps
    /// at its root for O(1) eviction. `forward_score` dominates; ties
    /// break to the older account (`Reverse(genesis_at)`, with `None`
    /// sorting below every `Some` as the tail-spam floor); the final
    /// `truster` tiebreak makes the total order deterministic so equal
    /// candidates are distinguishable (required for a consistent `Eq`).
    fn desirability(&self, other: &Self) -> Ordering {
        self.forward_score
            .total_cmp(&other.forward_score)
            .then_with(|| {
                self.genesis_at
                    .map(Reverse)
                    .cmp(&other.genesis_at.map(Reverse))
            })
            .then_with(|| self.truster.cmp(&other.truster))
    }
}

impl Ord for Admission {
    fn cmp(&self, other: &Self) -> Ordering {
        self.desirability(other)
    }
}

impl PartialOrd for Admission {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Admission {
    fn eq(&self, other: &Self) -> bool {
        self.desirability(other) == Ordering::Equal
    }
}

impl Eq for Admission {}

/// A reader's bounded top-`N` set of admitted inbound trusters (§8.9
/// cap-at-`N`). Backed by a min-heap keyed by [`Admission`] desirability
/// so the worst-admitted sits at the root: offering a better candidate
/// once the set is full evicts that worst in O(log N), and the surviving
/// root is exactly the cleave point §8.10/Slice E reads to derive this
/// reader's age ceiling.
///
/// **Caller contract:** offer each distinct truster at most once per
/// reader. The cap does not dedup by key — it is fed from a single
/// reverse-BFS pass whose global visited set already guarantees one offer
/// per frontier node, so an internal dedup set would be dead weight.
#[derive(Debug)]
pub struct AdmissionCap {
    cap: usize,
    heap: BinaryHeap<Reverse<Admission>>,
}

impl AdmissionCap {
    /// Create an empty cap admitting at most `cap` trusters. `cap == 0`
    /// is a valid degenerate setting that admits nothing.
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            heap: BinaryHeap::new(),
        }
    }

    /// Would `adm` be admitted if offered now — i.e. is there spare
    /// capacity, or does `adm` strictly outrank the current worst? This is
    /// the §8.9 **expansion-pruning** predicate: a frontier node worth
    /// admitting for at least one reader is worth expanding ("who trusts
    /// it") to grow the frontier deeper. Pure (no mutation), so the BFS
    /// can test a node against every reader before committing to expand.
    pub fn would_admit(&self, adm: &Admission) -> bool {
        if self.cap == 0 {
            return false;
        }
        if self.heap.len() < self.cap {
            return true;
        }
        // Full: admit only if strictly better than the worst-admitted.
        match self.heap.peek() {
            Some(Reverse(worst)) => adm > worst,
            None => true,
        }
    }

    /// Offer `adm` to the cap, evicting the previous worst if the set is
    /// full and `adm` outranks it. Returns whether `adm` ended up
    /// admitted.
    pub fn admit(&mut self, adm: Admission) -> bool {
        if self.cap == 0 {
            return false;
        }
        if self.heap.len() < self.cap {
            self.heap.push(Reverse(adm));
            return true;
        }
        match self.heap.peek() {
            Some(Reverse(worst)) if adm > *worst => {
                self.heap.pop();
                self.heap.push(Reverse(adm));
                true
            }
            _ => false,
        }
    }

    /// The worst currently-admitted candidate — the §8.10/Slice E cleave
    /// point whose `genesis_at` becomes this reader's advertised age
    /// ceiling. `None` until something is admitted.
    pub fn worst_admitted(&self) -> Option<&Admission> {
        self.heap.peek().map(|Reverse(adm)| adm)
    }

    /// Number of admitted trusters.
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// True when nothing is admitted yet.
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// True once the set has reached its cap — past this point admission
    /// requires displacing the worst.
    pub fn is_full(&self) -> bool {
        self.cap != 0 && self.heap.len() >= self.cap
    }

    /// Drain the admitted set (unordered).
    pub fn into_admitted(self) -> Vec<Admission> {
        self.heap.into_iter().map(|Reverse(adm)| adm).collect()
    }
}

// ---------------------------------------------------------------------------
// Age-ceiling production (§8.10) — the source-side celebrity cleave
// ---------------------------------------------------------------------------

/// Derive the §8.10 age ceiling a reader's cap advertises, or `None` when
/// the reader is **not** age-cleaved and should keep flooding its whole
/// tail.
///
/// A ceiling is published iff two conditions hold:
///
/// 1. **The cap is saturated** ([`AdmissionCap::is_full`]). With spare
///    capacity every inbound truster still fits, so nothing is shed and
///    there is no cleave to advertise — absence of a row means "admit all"
///    (§8.3 wire semantics).
/// 2. **The worst-admitted has an attested `genesis_at`**. The cutoff is a
///    `genesis_at` watermark; a worst-admitted at the unattested floor
///    (`None`) cannot be expressed as an age, and publishing one would
///    falsely shed every attested-age source. So when the marginal slot is
///    held by an unattested key we publish nothing and let those losers
///    flow to the receiver's cap heap (the §8.10 opportunistic backstop).
///
/// When set, the cutoff is exactly the worst-admitted account's
/// `genesis_at` — the cleave point: a peer forwards `S → R` only when
/// `genesis_at(S) ≤ cutoff` (§8.3), so any source younger than the worst
/// admitted is shed at the source.
pub fn derive_age_ceiling(cap: &AdmissionCap) -> Option<i64> {
    if !cap.is_full() {
        return None;
    }
    cap.worst_admitted().and_then(|worst| worst.genesis_at)
}

/// Reconcile this instance's outbound §8.10 cleave map
/// (`local_frontier_age_ceilings`) against a finished rebuild's per-reader
/// caps. For every local root: publish (UPSERT) the [`derive_age_ceiling`]
/// cutoff when the root is cleaved, else clear (DELETE) any stale ceiling
/// it no longer warrants. The existing §8.3/§8.4 producer
/// (`compute_local_frontier`) reads this table, so a written row reaches the
/// wire on the next announce/delta with no further plumbing.
///
/// Returns the count of roots published vs cleared this pass. The two
/// writes per root are independent UPSERT/DELETE statements, not one
/// transaction: the map is advisory (a stale row only mis-sheds a tail
/// truster the receiver's cap recovers anyway, §8.10), so a partial
/// reconcile is self-correcting on the next rebuild.
pub async fn publish_local_age_ceilings(
    db: &SqlitePool,
    frontier: &ReverseFrontier,
) -> Result<CeilingPublication, sqlx::Error> {
    let mut published = 0u64;
    let mut cleared = 0u64;
    for outcome in &frontier.caps {
        match derive_age_ceiling(&outcome.cap) {
            Some(cutoff) => {
                upsert_local_age_ceiling(db, &outcome.key, cutoff).await?;
                published += 1;
            }
            None => {
                if delete_local_age_ceiling(db, &outcome.key).await? {
                    cleared += 1;
                }
            }
        }
    }
    Ok(CeilingPublication { published, cleared })
}

/// Tally from one [`publish_local_age_ceilings`] reconcile.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CeilingPublication {
    /// Roots for which a ceiling was UPSERTed (cleaved this pass).
    pub published: u64,
    /// Roots whose stale ceiling row was DELETEd (no longer cleaved).
    pub cleared: u64,
}

/// UPSERT one local root's advertised §8.10 cutoff (unix ms). Bumps
/// `updated_at` so operators can audit when the §8.10 controller last
/// tightened the root.
async fn upsert_local_age_ceiling(
    db: &SqlitePool,
    root_key: &[u8; 32],
    cutoff: i64,
) -> Result<(), sqlx::Error> {
    let key_slice: &[u8] = root_key.as_slice();
    sqlx::query!(
        "INSERT INTO local_frontier_age_ceilings (root_key, cutoff) \
         VALUES (?, ?) \
         ON CONFLICT(root_key) DO UPDATE SET \
             cutoff = excluded.cutoff, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
        key_slice,
        cutoff,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Clear a local root's advertised ceiling. Returns `true` if a row was
/// actually removed (the root had been cleaved before and is not now), so
/// the caller can count genuine clears rather than no-op deletes.
async fn delete_local_age_ceiling(
    db: &SqlitePool,
    root_key: &[u8; 32],
) -> Result<bool, sqlx::Error> {
    let key_slice: &[u8] = root_key.as_slice();
    let deleted = sqlx::query!(
        "DELETE FROM local_frontier_age_ceilings WHERE root_key = ?",
        key_slice,
    )
    .execute(db)
    .await?
    .rows_affected();
    Ok(deleted > 0)
}

// ---------------------------------------------------------------------------
// Source-side shedding (§8.10) — the forwarder honouring a peer's ceiling
// ---------------------------------------------------------------------------

/// The §8.10 ceiling predicate: may an edge whose source has
/// `source_genesis_at` be forwarded under a root carrying `cutoff`?
///
/// Honouring is **opportunistic and fail-open** (§8.3/§8.10): the edge is
/// shed *only* when the forwarder positively knows the source is younger
/// than the cutoff. So it forwards when —
///
/// - `source_genesis_at` is `None`: the source's instance-attested age is
///   unknown here, so the ceiling cannot be evaluated; the edge flows and
///   loses (or wins) at the receiver's cap heap.
/// - `genesis_at ≤ cutoff`: the source is at least as old as the worst
///   admitted, so it is on the keep side of the cleave.
///
/// and sheds only when `genesis_at > cutoff` (strictly younger). The cutoff
/// MUST come from an instance-attested `genesis_at` (§12); a self-attested
/// age must never satisfy a ceiling, which is why the resolver
/// [`peer_ceiling_admits_source`] reads `user_genesis` and never a
/// self-reported field.
pub fn ceiling_admits(cutoff: i64, source_genesis_at: Option<i64>) -> bool {
    match source_genesis_at {
        Some(genesis_at) => genesis_at <= cutoff,
        None => true,
    }
}

/// Resolve the full §8.10 forward/shed decision for one edge `source → root`
/// being relayed toward `peer`: look up the ceiling `peer` advertised for
/// `root`, and if one exists, evaluate the source's attested age against it.
///
/// Returns `true` (forward) when the peer advertises **no** ceiling for the
/// root, or when [`ceiling_admits`] passes. Returns `false` (shed) only on a
/// positive younger-than-cutoff match. The forwarder's §8.10 source-side
/// pre-filter (`forward_inner`) consults this before relaying a trust-edge;
/// it composes the pure [`ceiling_admits`] predicate with the two store reads
/// (`peer_frontier_age_ceilings` and `user_genesis`).
pub async fn peer_ceiling_admits_source(
    db: &SqlitePool,
    peer: &[u8; 32],
    root: &[u8; 32],
    source: &[u8; 32],
) -> Result<bool, sqlx::Error> {
    let Some(cutoff) = load_peer_age_ceiling(db, peer, root).await? else {
        // No ceiling for this root ⇒ admit all (§8.3 absent-root semantics).
        return Ok(true);
    };
    let source_genesis_at = load_genesis_at(db, source).await?;
    Ok(ceiling_admits(cutoff, source_genesis_at))
}

/// Read the §8.10 cutoff `peer` currently advertises for `root` from
/// `peer_frontier_age_ceilings`, or `None` when the peer publishes no
/// ceiling for that root (the common case — the map is sparse).
async fn load_peer_age_ceiling(
    db: &SqlitePool,
    peer: &[u8; 32],
    root: &[u8; 32],
) -> Result<Option<i64>, sqlx::Error> {
    let peer_slice: &[u8] = peer.as_slice();
    let root_slice: &[u8] = root.as_slice();
    let row = sqlx::query!(
        "SELECT cutoff FROM peer_frontier_age_ceilings \
         WHERE peer_pubkey = ? AND root_key = ?",
        peer_slice,
        root_slice,
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| r.cutoff))
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
///
/// `reverse_hop` is the key's shortest BFS distance from a local root,
/// recorded on the stub so the §8.1 filter split can be reconstructed.
async fn materialize_frontier_node(
    db: &SqlitePool,
    key: &[u8; 32],
    generation: i64,
    reverse_hop: u32,
) -> Result<NodeMaterialization, sqlx::Error> {
    if is_local_user(db, key).await? {
        return Ok(NodeMaterialization::Local);
    }
    match resolve_frontier_home(db, key).await? {
        Some((home_key, home_domain)) => {
            upsert_frontier_user_stub(db, key, &home_key, &home_domain, generation, reverse_hop)
                .await?;
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

/// Resolve a frontier key to its local `users.id` (UUID), or `None` when
/// no `users` row exists for it. The UUID indexes a reader's
/// forward-score map (§8.9 admission): a key with a `users` row — a local
/// account or a hydrated remote stub a local user explicitly trusts —
/// participates in the in-memory `TrustGraph` and so may carry a non-zero
/// forward score. A frontier-only key (a `frontier_users` stub with no
/// `users` row) returns `None` and scores `0.0` for every reader (the
/// age-ranked tail, §8.10).
async fn resolve_user_uuid(db: &SqlitePool, key: &[u8; 32]) -> Result<Option<Uuid>, sqlx::Error> {
    let key_slice: &[u8] = key.as_slice();
    let row = sqlx::query!("SELECT id FROM users WHERE public_key = ?", key_slice)
        .fetch_optional(db)
        .await?;
    Ok(row.and_then(|r| Uuid::parse_str(&r.id).ok()))
}

/// Read a key's instance-attested account-birth anchor
/// (`user_genesis.genesis_at`, unix ms; Slice B), or `None` when no
/// genesis attestation is on file. The §8.9 cap age-ranks by this value;
/// `None` is the tail-spam floor (ranks worst), so a freshly minted key
/// with no instance-vouched age cannot forge seniority to beat the cap.
async fn load_genesis_at(db: &SqlitePool, key: &[u8; 32]) -> Result<Option<i64>, sqlx::Error> {
    let key_slice: &[u8] = key.as_slice();
    let row = sqlx::query!(
        "SELECT genesis_at AS \"genesis_at!: i64\" FROM user_genesis WHERE user_key = ?",
        key_slice,
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| r.genesis_at))
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
/// pointer, its §8.1 reverse-BFS hop distance, and stamping the current
/// §8.12 GC generation. `display_name` is intentionally untouched — it is
/// carried opportunistically by gossip, not by edges, so it stays at
/// whatever a prior profile sync supplied (NULL until then).
///
/// `reverse_hop` is the node's shortest distance from any local root in
/// this rebuild's BFS (1..3). The visited-gate in [`reverse_frontier_bfs`]
/// guarantees a node is materialized once per pass at its shortest hop, so
/// the value written is the slice boundary `compute_local_frontier` reads
/// to split the visible (hop ≤3) and expansion (hop ≤2) filters.
async fn upsert_frontier_user_stub(
    db: &SqlitePool,
    key: &[u8; 32],
    home_key: &[u8; 32],
    home_domain: &str,
    generation: i64,
    reverse_hop: u32,
) -> Result<(), sqlx::Error> {
    let key_slice: &[u8] = key.as_slice();
    let home_key_slice: &[u8] = home_key.as_slice();
    let reverse_hop = i64::from(reverse_hop);
    sqlx::query!(
        "INSERT INTO frontier_users \
            (user_key, home_instance_key, home_instance_domain, generation, reverse_hop) \
         VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT(user_key) DO UPDATE SET \
             home_instance_key = excluded.home_instance_key, \
             home_instance_domain = excluded.home_instance_domain, \
             generation = excluded.generation, \
             reverse_hop = excluded.reverse_hop, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
        key_slice,
        home_key_slice,
        home_domain,
        generation,
        reverse_hop,
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

        let f = reverse_frontier_bfs(&pool, &readers(&[9]), BIG_CAP, 7, FRONTIER_MAX_DEPTH)
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

        let f = reverse_frontier_bfs(&pool, &readers(&[9]), BIG_CAP, 0, 2)
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

        let f = reverse_frontier_bfs(&pool, &readers(&[9]), BIG_CAP, 4, FRONTIER_MAX_DEPTH)
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

        let f = reverse_frontier_bfs(&pool, &readers(&[9]), BIG_CAP, 1, FRONTIER_MAX_DEPTH)
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

        let f = reverse_frontier_bfs(&pool, &readers(&[9]), BIG_CAP, 2, FRONTIER_MAX_DEPTH)
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

        let f = reverse_frontier_bfs(&pool, &readers(&[9]), BIG_CAP, 3, FRONTIER_MAX_DEPTH)
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

        let f = reverse_frontier_bfs(&pool, &readers(&[9]), BIG_CAP, 6, FRONTIER_MAX_DEPTH)
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

        let f = reverse_frontier_bfs(&pool, &readers(&[9, 8]), BIG_CAP, 1, FRONTIER_MAX_DEPTH)
            .await
            .unwrap();
        assert_eq!(f.reachable.len(), 1, "one shared stub for X");
        assert_eq!(f.stubs_materialized, 1);
        assert_eq!(f.edges_marked, 2, "both inbound edges marked live");
    }

    // --- D3: cap-at-N admission -----------------------------------------

    fn adm(truster: u8, forward_score: f64, genesis_at: Option<i64>) -> Admission {
        Admission {
            truster: [truster; 32],
            forward_score,
            genesis_at,
        }
    }

    #[test]
    fn cap_admits_up_to_capacity_then_evicts_worst() {
        let mut cap = AdmissionCap::new(2);
        assert!(cap.admit(adm(1, 0.9, Some(100))));
        assert!(cap.admit(adm(2, 0.5, Some(100))));
        assert!(cap.is_full());
        // A better candidate than the worst (truster 2, score 0.5) is
        // admitted, evicting truster 2.
        assert!(cap.admit(adm(3, 0.7, Some(100))));
        assert_eq!(cap.len(), 2);
        let trusters: HashSet<[u8; 32]> =
            cap.into_admitted().into_iter().map(|a| a.truster).collect();
        assert!(trusters.contains(&[1u8; 32]));
        assert!(trusters.contains(&[3u8; 32]));
        assert!(!trusters.contains(&[2u8; 32]), "the worst was evicted");
    }

    #[test]
    fn cap_rejects_candidate_no_better_than_worst() {
        let mut cap = AdmissionCap::new(2);
        cap.admit(adm(1, 0.9, Some(100)));
        cap.admit(adm(2, 0.5, Some(100)));
        // Strictly worse than the current worst (0.4 < 0.5) — rejected.
        assert!(!cap.would_admit(&adm(3, 0.4, Some(100))));
        assert!(!cap.admit(adm(3, 0.4, Some(100))));
        assert_eq!(cap.len(), 2);
    }

    #[test]
    fn forward_score_dominates_genesis() {
        let mut cap = AdmissionCap::new(1);
        // Younger but higher forward score beats older with lower score.
        cap.admit(adm(1, 0.2, Some(1))); // ancient account, weak trust
        assert!(cap.admit(adm(2, 0.8, Some(9_999)))); // newer, strong trust
        assert_eq!(cap.worst_admitted().unwrap().truster, [2u8; 32]);
    }

    #[test]
    fn older_account_breaks_forward_score_tie() {
        let mut cap = AdmissionCap::new(1);
        cap.admit(adm(1, 0.5, Some(500))); // younger
        // Same score, older (smaller genesis_at) wins.
        assert!(cap.admit(adm(2, 0.5, Some(100))));
        assert_eq!(cap.worst_admitted().unwrap().truster, [2u8; 32]);
    }

    #[test]
    fn unknown_genesis_ranks_worst_on_a_tie() {
        let mut cap = AdmissionCap::new(1);
        cap.admit(adm(1, 0.5, None)); // unattested age — tail-spam floor
        // Any attested age at the same score outranks the unknown one.
        assert!(cap.admit(adm(2, 0.5, Some(i64::MAX))));
        assert_eq!(cap.worst_admitted().unwrap().truster, [2u8; 32]);
        // And an unknown-genesis candidate cannot displace an attested one.
        assert!(!cap.would_admit(&adm(3, 0.5, None)));
    }

    #[test]
    fn worst_admitted_is_the_cleave_point() {
        let mut cap = AdmissionCap::new(3);
        cap.admit(adm(1, 0.9, Some(100)));
        cap.admit(adm(2, 0.3, Some(200)));
        cap.admit(adm(3, 0.6, Some(150)));
        // The least desirable admitted candidate sits at the cleave point;
        // Slice E reads its genesis_at as the advertised age ceiling.
        let worst = cap.worst_admitted().unwrap();
        assert_eq!(worst.truster, [2u8; 32]);
        assert_eq!(worst.forward_score, 0.3);
        assert_eq!(worst.genesis_at, Some(200));
    }

    #[test]
    fn cap_zero_admits_nothing() {
        let mut cap = AdmissionCap::new(0);
        assert!(!cap.would_admit(&adm(1, 1.0, Some(1))));
        assert!(!cap.admit(adm(1, 1.0, Some(1))));
        assert!(cap.is_empty());
        assert!(cap.worst_admitted().is_none());
    }

    #[test]
    fn would_admit_matches_admit_when_full() {
        let mut cap = AdmissionCap::new(2);
        cap.admit(adm(1, 0.9, Some(100)));
        cap.admit(adm(2, 0.5, Some(100)));
        // would_admit is the pure mirror of admit's decision.
        let candidate = adm(3, 0.7, Some(100));
        assert_eq!(cap.would_admit(&candidate), cap.admit(candidate));
    }

    // --- D3: cap-at-N woven into the reverse BFS -------------------------

    /// A cap large enough that the D2 structural tests above admit every
    /// reached node, so the cap never alters their traversal.
    const BIG_CAP: usize = 1_000;

    /// Build readers with no forward trust (every frontier node scores
    /// 0.0 — the pure age-ranked tail). The D2 structural tests use this.
    fn readers(keys: &[u8]) -> Vec<FrontierReader> {
        keys.iter()
            .map(|&k| FrontierReader {
                key: [k; 32],
                forward_scores: HashMap::new(),
            })
            .collect()
    }

    /// Build one reader with an explicit forward-score map (author UUID →
    /// score), for the §8.9 admission-ranking tests.
    fn reader_scored(key: u8, scores: &[(Uuid, f64)]) -> FrontierReader {
        FrontierReader {
            key: [key; 32],
            forward_scores: scores.iter().copied().collect(),
        }
    }

    async fn seed_user_with_id(pool: &SqlitePool, key: u8, id: Uuid) {
        sqlx::query(
            "INSERT INTO users (id, display_name, signup_method, public_key) \
             VALUES (?, ?, 'admin', ?)",
        )
        .bind(id.to_string())
        .bind(format!("u{key}"))
        .bind([key; 32].as_slice())
        .execute(pool)
        .await
        .unwrap();
    }

    async fn seed_genesis(pool: &SqlitePool, key: u8, genesis_at: i64) {
        sqlx::query(
            "INSERT INTO user_genesis \
                (user_key, genesis_at, birth_instance_key, attestation_sig) \
             VALUES (?, ?, ?, ?)",
        )
        .bind([key; 32].as_slice())
        .bind(genesis_at)
        .bind([0xEEu8; 32].as_slice())
        .bind(vec![0u8; 64])
        .execute(pool)
        .await
        .unwrap();
    }

    fn cap_for(f: &ReverseFrontier, key: u8) -> &AdmissionCap {
        &f.caps.iter().find(|c| c.key == [key; 32]).unwrap().cap
    }

    #[tokio::test]
    async fn cap_sheds_younger_truster_and_prunes_its_subtree() {
        let pool = fresh_pool().await;
        // Both A(1) and B(2) trust root R(9); A is the older account.
        // C(3) trusts A, D(4) trusts B — the next hop behind each.
        put_edge(
            &pool,
            &edge_at(1, 9, TrustStance::Trust, 100, None),
            0x01,
            0,
        )
        .await;
        put_edge(
            &pool,
            &edge_at(2, 9, TrustStance::Trust, 100, None),
            0x02,
            0,
        )
        .await;
        put_edge(
            &pool,
            &edge_at(3, 1, TrustStance::Trust, 100, None),
            0x03,
            0,
        )
        .await;
        put_edge(
            &pool,
            &edge_at(4, 2, TrustStance::Trust, 100, None),
            0x04,
            0,
        )
        .await;
        seed_genesis(&pool, 1, 100).await; // A older
        seed_genesis(&pool, 2, 200).await; // B younger

        // Cap of 1, no forward trust: pure age ranking. A (older) wins the
        // single slot; B is shed, so D (only reachable via B) is never seen.
        let f = reverse_frontier_bfs(&pool, &readers(&[9]), 1, 5, FRONTIER_MAX_DEPTH)
            .await
            .unwrap();

        assert_eq!(f.reachable, HashSet::from([[1u8; 32]]), "only A expanded");
        assert!(!f.reachable.contains(&[2u8; 32]), "B shed by the cap");
        assert!(!f.reachable.contains(&[4u8; 32]), "D unreachable behind B");
        // B (younger direct truster) and C (behind A, but A's slot is the
        // worst and C cannot beat it) are both reached-but-shed.
        assert_eq!(f.nodes_pruned, 2);
        assert_eq!(f.edges_marked, 3, "A→R, B→R, C→A marked; D→B never read");

        let cap = cap_for(&f, 9);
        assert_eq!(cap.len(), 1);
        assert_eq!(cap.worst_admitted().unwrap().truster, [1u8; 32]);
    }

    #[tokio::test]
    async fn forward_trust_admits_over_an_older_tail() {
        let pool = fresh_pool().await;
        // A(1) and B(2) both trust R(9). R forward-trusts A strongly; B is
        // an older account R does not trust back.
        let a_id = Uuid::new_v4();
        put_edge(
            &pool,
            &edge_at(1, 9, TrustStance::Trust, 100, None),
            0x01,
            0,
        )
        .await;
        put_edge(
            &pool,
            &edge_at(2, 9, TrustStance::Trust, 100, None),
            0x02,
            0,
        )
        .await;
        seed_user_with_id(&pool, 1, a_id).await; // A is a known local user
        seed_genesis(&pool, 2, 100).await; // B is ancient, but untrusted

        let reader = reader_scored(9, &[(a_id, 0.9)]);
        let f = reverse_frontier_bfs(
            &pool,
            std::slice::from_ref(&reader),
            1,
            5,
            FRONTIER_MAX_DEPTH,
        )
        .await
        .unwrap();

        // Forward score 0.9 beats B's attested age at score 0.
        assert!(f.reachable.contains(&[1u8; 32]));
        assert!(!f.reachable.contains(&[2u8; 32]), "older tail shed");
        assert_eq!(f.nodes_pruned, 1);
        assert_eq!(f.locals_skipped, 1, "A is local — admitted but not stubbed");
        let worst = cap_for(&f, 9).worst_admitted().unwrap();
        assert_eq!(worst.truster, [1u8; 32]);
        assert_eq!(worst.forward_score, 0.9);
    }

    #[tokio::test]
    async fn caps_are_independent_per_reader() {
        let pool = fresh_pool().await;
        // X(1) trusts both roots R1(9) and R2(8); Y(2) trusts only R1.
        // R1 forward-trusts X; R2 trusts no one. Y is an older account.
        let x_id = Uuid::new_v4();
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
        put_edge(
            &pool,
            &edge_at(2, 9, TrustStance::Trust, 100, None),
            0x03,
            0,
        )
        .await;
        seed_user_with_id(&pool, 1, x_id).await;
        seed_genesis(&pool, 2, 100).await; // Y older

        let r1 = reader_scored(9, &[(x_id, 0.9)]);
        let r2 = reader_scored(8, &[]);
        let f = reverse_frontier_bfs(&pool, &[r1, r2], 1, 5, FRONTIER_MAX_DEPTH)
            .await
            .unwrap();

        // R1 keeps X on forward trust; R2 (no forward trust) ranks by age,
        // so Y's attested age displaces X from R2's single slot.
        assert_eq!(cap_for(&f, 9).worst_admitted().unwrap().truster, [1u8; 32]);
        assert_eq!(cap_for(&f, 8).worst_admitted().unwrap().truster, [2u8; 32]);
        // Both X and Y were admitted by at least one reader, so both expand.
        assert!(f.reachable.contains(&[1u8; 32]));
        assert!(f.reachable.contains(&[2u8; 32]));
    }

    // -- §8.12 generational mark-sweep GC ---------------------------------

    /// Count surviving `frontier_edges` rows regardless of target.
    async fn edge_count(pool: &SqlitePool) -> i64 {
        sqlx::query!("SELECT COUNT(*) AS \"n!: i64\" FROM frontier_edges")
            .fetch_one(pool)
            .await
            .unwrap()
            .n
    }

    /// Count surviving `frontier_users` stub rows.
    async fn stub_count(pool: &SqlitePool) -> i64 {
        sqlx::query!("SELECT COUNT(*) AS \"n!: i64\" FROM frontier_users")
            .fetch_one(pool)
            .await
            .unwrap()
            .n
    }

    #[tokio::test]
    async fn generation_seeds_at_zero_and_advances_monotonically() {
        let pool = fresh_pool().await;
        assert_eq!(current_generation(&pool).await.unwrap(), 0, "seeded at 0");
        assert_eq!(advance_generation(&pool).await.unwrap(), 1);
        assert_eq!(advance_generation(&pool).await.unwrap(), 2);
        assert_eq!(
            current_generation(&pool).await.unwrap(),
            2,
            "reads back the latest advance"
        );
    }

    #[tokio::test]
    async fn sweep_evicts_rows_more_than_k_behind_and_keeps_the_watermark() {
        let pool = fresh_pool().await;
        // Edges stamped at generations 0..=5, one per (source,target) pair.
        for g in 0..=5i64 {
            let src = (g + 1) as u8;
            put_edge(
                &pool,
                &edge_at(src, 9, TrustStance::Trust, 100, None),
                src,
                g,
            )
            .await;
        }
        assert_eq!(edge_count(&pool).await, 6);

        // current = 5, K = 3 → watermark = 2; rows with generation < 2
        // (i.e. 0 and 1) are reaped; generation 2 sits exactly on the
        // watermark and is kept.
        let outcome = sweep_frontier(&pool, 5, 3).await.unwrap();
        assert_eq!(outcome.edges_swept, 2, "generations 0 and 1 reaped");
        assert_eq!(outcome.stubs_swept, 0);
        assert_eq!(edge_count(&pool).await, 4, "generations 2..=5 survive");

        // The exact-watermark row (generation 2) is still present.
        let survivor = frontier_edges_by_target(&pool, &[9u8; 32]).await.unwrap();
        assert!(
            survivor.iter().any(|e| e.generation == 2),
            "row at current-K is kept, not swept"
        );
    }

    #[tokio::test]
    async fn sweep_evicts_stale_stubs_on_the_same_window() {
        let pool = fresh_pool().await;
        upsert_frontier_user_stub(&pool, &[1u8; 32], &[7u8; 32], "old.example", 0, 1)
            .await
            .unwrap();
        upsert_frontier_user_stub(&pool, &[2u8; 32], &[7u8; 32], "fresh.example", 4, 1)
            .await
            .unwrap();
        assert_eq!(stub_count(&pool).await, 2);

        // current = 4, K = 3 → watermark = 1; the generation-0 stub is
        // reaped, the generation-4 stub survives.
        let outcome = sweep_frontier(&pool, 4, FRONTIER_GC_K).await.unwrap();
        assert_eq!(outcome.stubs_swept, 1);
        assert_eq!(stub_count(&pool).await, 1);
    }

    #[tokio::test]
    async fn rebuild_advances_marks_live_rows_and_sweeps_stale_ones() {
        let pool = fresh_pool().await;
        // A reachable edge A(1)→R(9) left from an earlier era, plus a stale
        // orphan edge B(2)→C(3) no reader reaches. Both start at generation
        // 0; bump the counter to 4 so the orphan is already K-stale.
        put_edge(
            &pool,
            &edge_at(1, 9, TrustStance::Trust, 100, None),
            0x01,
            0,
        )
        .await;
        put_edge(
            &pool,
            &edge_at(2, 3, TrustStance::Trust, 100, None),
            0x02,
            0,
        )
        .await;
        for _ in 0..4 {
            advance_generation(&pool).await.unwrap();
        }

        // Rebuild from root R(9): advances to generation 5, marks A→R live
        // at 5, then sweeps with K=3 (watermark 2) — the untouched orphan
        // at generation 0 falls away.
        let outcome = rebuild_reverse_frontier(
            &pool,
            &readers(&[9]),
            BIG_CAP,
            FRONTIER_MAX_DEPTH,
            FRONTIER_GC_K,
        )
        .await
        .unwrap();

        assert_eq!(outcome.generation, 5, "advanced once from 4");
        assert!(
            outcome.frontier.reachable.contains(&[1u8; 32]),
            "A expanded"
        );
        assert_eq!(outcome.sweep.edges_swept, 1, "stale orphan B→C reaped");

        // A→R was re-marked at the new generation; B→C is gone.
        let live = frontier_edges_by_target(&pool, &[9u8; 32]).await.unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].generation, 5, "reachable edge restamped fresh");
        assert!(
            frontier_edges_by_target(&pool, &[3u8; 32])
                .await
                .unwrap()
                .is_empty(),
            "orphan target has no surviving inbound edge"
        );
    }

    // -- §8.10 age-ceiling production (E1) --------------------------------

    /// A saturated cap (capacity 1) whose lone — hence worst — admitted
    /// entry is `a`.
    fn full_cap(a: Admission) -> AdmissionCap {
        let mut cap = AdmissionCap::new(1);
        cap.admit(a);
        cap
    }

    /// Read a local root's stored cutoff, if any.
    async fn stored_local_ceiling(pool: &SqlitePool, root: u8) -> Option<i64> {
        let root_slice: &[u8] = &[root; 32];
        sqlx::query!(
            "SELECT cutoff FROM local_frontier_age_ceilings WHERE root_key = ?",
            root_slice,
        )
        .fetch_optional(pool)
        .await
        .unwrap()
        .map(|r| r.cutoff)
    }

    #[test]
    fn derive_ceiling_none_until_cap_saturates() {
        // Cap of 2 holding one entry has room — no cleave, flood all.
        let mut cap = AdmissionCap::new(2);
        cap.admit(adm(1, 0.0, Some(100)));
        assert_eq!(derive_age_ceiling(&cap), None);
    }

    #[test]
    fn derive_ceiling_is_the_worst_admitted_genesis() {
        let cap = full_cap(adm(1, 0.0, Some(150)));
        assert_eq!(derive_age_ceiling(&cap), Some(150));
    }

    #[test]
    fn derive_ceiling_none_when_worst_is_unattested() {
        // Saturated, but the marginal slot holds a key with no attested
        // age: a genesis_at cutoff cannot be expressed, so no ceiling.
        let cap = full_cap(adm(1, 0.0, None));
        assert_eq!(derive_age_ceiling(&cap), None);
    }

    #[tokio::test]
    async fn publish_writes_cleaved_and_clears_uncleaved_roots() {
        let pool = fresh_pool().await;

        // Root 9 is cleaved (full cap, attested worst); root 8 is not
        // (room to spare). Build the outcome the rebuild would hand us.
        let mut frontier = ReverseFrontier::default();
        frontier.caps.push(ReaderCapOutcome {
            key: [9u8; 32],
            cap: full_cap(adm(1, 0.0, Some(150))),
        });
        let mut roomy = AdmissionCap::new(2);
        roomy.admit(adm(2, 0.0, Some(100)));
        frontier.caps.push(ReaderCapOutcome {
            key: [8u8; 32],
            cap: roomy,
        });

        let pub1 = publish_local_age_ceilings(&pool, &frontier).await.unwrap();
        assert_eq!(pub1.published, 1);
        assert_eq!(pub1.cleared, 0);
        assert_eq!(stored_local_ceiling(&pool, 9).await, Some(150));
        assert_eq!(stored_local_ceiling(&pool, 8).await, None);

        // Root 9 un-cleaves on the next pass (cap no longer full): its
        // stale ceiling is cleared.
        let mut frontier2 = ReverseFrontier::default();
        let mut roomy9 = AdmissionCap::new(2);
        roomy9.admit(adm(1, 0.0, Some(150)));
        frontier2.caps.push(ReaderCapOutcome {
            key: [9u8; 32],
            cap: roomy9,
        });
        let pub2 = publish_local_age_ceilings(&pool, &frontier2).await.unwrap();
        assert_eq!(pub2.published, 0);
        assert_eq!(pub2.cleared, 1);
        assert_eq!(stored_local_ceiling(&pool, 9).await, None);
    }

    #[tokio::test]
    async fn rebuild_publishes_ceiling_from_a_saturated_root() {
        let pool = fresh_pool().await;
        // Two attested inbound trusters of root R(9); A(1) older than B(2).
        put_edge(
            &pool,
            &edge_at(1, 9, TrustStance::Trust, 100, None),
            0x01,
            0,
        )
        .await;
        put_edge(
            &pool,
            &edge_at(2, 9, TrustStance::Trust, 100, None),
            0x02,
            0,
        )
        .await;
        seed_genesis(&pool, 1, 100).await; // A older — wins the single slot
        seed_genesis(&pool, 2, 200).await; // B younger — shed; the cleave point

        // Cap of 1 saturates: A admitted, so the worst-admitted is A(100).
        let outcome =
            rebuild_reverse_frontier(&pool, &readers(&[9]), 1, FRONTIER_MAX_DEPTH, FRONTIER_GC_K)
                .await
                .unwrap();

        assert_eq!(outcome.ceilings.published, 1);
        assert_eq!(
            stored_local_ceiling(&pool, 9).await,
            Some(100),
            "advertised cutoff is the worst-admitted genesis_at"
        );
    }

    // -- §8.10 source-side shedding (E2) ----------------------------------

    /// Seed the FK chain (`peers` → `peer_frontiers` → ceiling) so a peer
    /// advertises `cutoff` for `root`.
    async fn seed_peer_ceiling(pool: &SqlitePool, peer: u8, root: u8, cutoff: i64) {
        seed_peer(pool, peer, "peer.example").await;
        sqlx::query(
            "INSERT INTO peer_frontiers ( \
                 peer_pubkey, applied_version, epoch_start, \
                 visible_family, visible_k, visible_m, visible_n_est, visible_fpr_target, visible_bytes, \
                 expansion_family, expansion_k, expansion_m, expansion_n_est, expansion_fpr_target, expansion_bytes, \
                 cursor) \
             VALUES (?, 1, 0, \
                 'prismoire-bloom-v1', 1, 64, 0, 0.01, ?, \
                 'prismoire-bloom-v1', 1, 64, 0, 0.01, ?, \
                 ?)",
        )
        .bind([peer; 32].as_slice())
        .bind(vec![0u8; 8])
        .bind(vec![0u8; 8])
        .bind(vec![0u8; 0])
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO peer_frontier_age_ceilings (peer_pubkey, root_key, cutoff) \
             VALUES (?, ?, ?)",
        )
        .bind([peer; 32].as_slice())
        .bind([root; 32].as_slice())
        .bind(cutoff)
        .execute(pool)
        .await
        .unwrap();
    }

    #[test]
    fn ceiling_admits_keeps_older_sheds_younger_and_passes_unknown() {
        assert!(ceiling_admits(150, None), "unknown age flows (fail-open)");
        assert!(ceiling_admits(150, Some(100)), "older than cutoff kept");
        assert!(ceiling_admits(150, Some(150)), "exactly at cutoff kept");
        assert!(!ceiling_admits(150, Some(200)), "younger than cutoff shed");
    }

    #[tokio::test]
    async fn peer_ceiling_forwards_when_root_has_no_ceiling() {
        let pool = fresh_pool().await;
        // No ceiling rows at all — every edge forwards.
        let pass = peer_ceiling_admits_source(&pool, &[7u8; 32], &[9u8; 32], &[1u8; 32])
            .await
            .unwrap();
        assert!(pass, "absent root ⇒ admit all");
    }

    #[tokio::test]
    async fn peer_ceiling_sheds_younger_keeps_older_and_passes_unattested() {
        let pool = fresh_pool().await;
        // Peer 7 advertises cutoff 150 for root 9.
        seed_peer_ceiling(&pool, 7, 9, 150).await;
        seed_genesis(&pool, 1, 100).await; // older source — kept
        seed_genesis(&pool, 2, 200).await; // younger source — shed
        // source 3 has no genesis attestation — flows (fail-open).

        assert!(
            peer_ceiling_admits_source(&pool, &[7u8; 32], &[9u8; 32], &[1u8; 32])
                .await
                .unwrap(),
            "older-than-cutoff source forwarded"
        );
        assert!(
            !peer_ceiling_admits_source(&pool, &[7u8; 32], &[9u8; 32], &[2u8; 32])
                .await
                .unwrap(),
            "younger-than-cutoff source shed"
        );
        assert!(
            peer_ceiling_admits_source(&pool, &[7u8; 32], &[9u8; 32], &[3u8; 32])
                .await
                .unwrap(),
            "unattested source flows and loses at the receiver's cap"
        );
    }
}
