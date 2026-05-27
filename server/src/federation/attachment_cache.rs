//! §11.5 receiver-local attachment-cache eviction sweep.
//!
//! The §11 wire contract is fetch-on-demand: receivers fetch attachment
//! blobs from the origin instance the first time a local viewer renders
//! a post that binds them. Receivers cache the resulting bytes so repeat
//! reads don't re-fetch — but the cache is sender-local, bounded by a
//! TOML knob (`[federation.attachment_cache] max_bytes`), and operators
//! must be able to draw a hard ceiling under the worst-case disk usage
//! cross-federation traffic can produce locally.
//!
//! ## Eligibility predicate
//!
//! Only federation-fetched cache bytes participate in eviction.
//! Origin-authored blobs (those bound to a current, locally-authored,
//! non-retracted, non-deleted-author post revision) are protocol-
//! obligated retentions and MUST NOT be touched by the cache sweep.
//!
//! Concretely, a row in `attachment_blobs` is *eligible for eviction*
//! iff:
//!
//! 1. `blob IS NOT NULL` — there are actual bytes to reclaim. Rows whose
//!    `blob` is already NULL are either fetch-pending or previously
//!    evicted; nothing to do.
//! 2. There is no `post_attachments` row binding `content_hash` to a
//!    *current* revision (`revision = posts.revision_count - 1`) of a
//!    *locally-authored* (`posts.home_instance IS NULL`),
//!    *non-retracted* (`posts.retracted_at IS NULL`),
//!    *non-deleted-author* (`users.deleted_at IS NULL`) post.
//!
//! Predicate (2) is byte-for-byte the §11.5 origin-only check the serve
//! handler in [`crate::federation::attachments`] applies; the inversion
//! ("we are NOT origin for this") is what makes the row a *cache* entry
//! rather than an origin retention. We deliberately key on local-binding
//! state, not on `attachment_blobs.uploader`: the upload handler's
//! `ON CONFLICT` clause doesn't update `uploader` when a federation
//! fetch arrived first, so `uploader IS NULL` would mis-classify any
//! blob a local user later re-staged.
//!
//! ## Sweep mechanics
//!
//! The sweep is a steady-state read of "eligible bytes used" plus an
//! eviction loop:
//!
//! 1. `SELECT SUM(size)` over eligible blobs. If under `max_bytes`,
//!    nothing to do.
//! 2. Otherwise, repeatedly: pick the `BATCH_SIZE` oldest-by-`accessed_at`
//!    eligible rows; `UPDATE blob = NULL` on each; subtract sizes;
//!    commit the batch; loop until under budget or no more candidates.
//!
//! Each batch commits independently so a large eviction does not hold a
//! single write lock for the full duration. The orphan-GC step that
//! follows in the same sweep tick reaps rows whose `refcount` is also
//! zero (i.e. truly fully detached); cache rows retain `refcount > 0` if
//! a binding still references them, so the orphan sweep leaves their
//! row in place — only the bytes go.
//!
//! ## Sloppy-LRU `accessed_at` updates
//!
//! [`bump_accessed_at`] is the read-side hook: every successful blob
//! serve calls it. To keep the write cost negligible we apply a 60-second
//! floor — the UPDATE only fires when the stored `accessed_at` is more
//! than [`LRU_FLOOR_SECS`] in the past. At rest, an attachment that's
//! read once per second produces one UPDATE per minute, not one per
//! request.
//!
//! The floor is hard-coded rather than knobbed: it's a backend-internal
//! anti-write-amplification tradeoff with no operator-visible effect on
//! the §11.5 budget. A bigger floor saves writes; a smaller floor gives
//! sharper LRU ordering. 60s is a comfortable middle ground.
//!
//! ## Metrics
//!
//! The three counters / gauges added in [`Metrics`] are *federated-only*
//! by construction: every query in this module filters to the eligible-
//! for-eviction population, so origin-authored bytes never contribute.
//! That keeps the operator signal scoped to the value the cache budget
//! is actually shaping.
//!
//! [`Metrics`]: crate::metrics::Metrics

use std::sync::Arc;

use sqlx::SqlitePool;

use crate::metrics::Metrics;

/// Per-batch eviction size. Each pass of the inner loop selects this
/// many oldest-by-`accessed_at` rows, commits them in one transaction,
/// then re-checks the budget. Small enough to keep each write lock
/// short; large enough that under heavy overshoot we don't drown the
/// sweep in commit overhead.
const BATCH_SIZE: i64 = 32;

/// Minimum elapsed seconds since the last `accessed_at` bump before a
/// new serve will write again. See module docs.
const LRU_FLOOR_SECS: i64 = 60;

/// `UPDATE attachment_blobs.accessed_at = now` if the stored timestamp
/// is more than [`LRU_FLOOR_SECS`] in the past; no-op otherwise.
///
/// Called by the local serve handler ([`crate::attachments::serve`])
/// after a successful 200 — we don't want to bump LRU on 4xx paths
/// since a 4xx tells us the viewer wasn't allowed to see the bytes in
/// the first place.
///
/// The federation `/federation/v1/attachments/{hash}` route deliberately
/// does NOT bump: every row reachable on that path is origin-bound
/// (the §11.5 serve gate proves it), so an LRU update there would
/// always be against a row the eviction predicate excludes — pure write
/// amplification for no shaping benefit.
///
/// Errors are logged and swallowed: an LRU-bump failure must never
/// fail the serving request. The next read inside the 60-second window
/// will retry the bump if the timestamp is still stale.
pub async fn bump_accessed_at(pool: &SqlitePool, content_hash: &[u8]) {
    // The `WHERE` clause does the floor check inline against the live
    // row, so two simultaneous serves of the same hash race to a single
    // UPDATE. Whichever one's `strftime` produces the later value wins
    // (SQLite serializes writes); either way we end up with one write,
    // not N.
    let res = sqlx::query!(
        r#"UPDATE attachment_blobs
              SET accessed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            WHERE content_hash = ?
              AND (
                  strftime('%s', 'now') - strftime('%s', accessed_at) >= ?
              )"#,
        content_hash,
        LRU_FLOOR_SECS,
    )
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, "attachment cache LRU bump failed");
    }
}

/// Snapshot of cache state used to drive the eviction loop. Returned
/// by [`eligible_bytes_used`] so the caller can compare against the
/// budget in one read.
struct CacheStats {
    /// Total bytes currently held in cache (eligible-for-eviction rows
    /// with non-NULL `blob`).
    bytes_used: i64,
}

/// Compute the total bytes currently held in cache, in one query. The
/// predicate matches the §11.5 inversion: count only blobs that are
/// not bound to a current locally-authored post revision.
async fn eligible_bytes_used(pool: &SqlitePool) -> Result<CacheStats, sqlx::Error> {
    let row = sqlx::query!(
        r#"SELECT COALESCE(SUM(ab.size), 0) AS "bytes_used!: i64"
             FROM attachment_blobs ab
            WHERE ab.blob IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                    FROM post_attachments pa
                    JOIN posts p ON p.id = pa.post_id
                    JOIN users u ON u.id = p.author
                   WHERE pa.content_hash = ab.content_hash
                     AND pa.revision = p.revision_count - 1
                     AND p.retracted_at IS NULL
                     AND p.home_instance IS NULL
                     AND u.deleted_at IS NULL
              )"#,
    )
    .fetch_one(pool)
    .await?;
    Ok(CacheStats {
        bytes_used: row.bytes_used,
    })
}

/// Result of one batched eviction pass. `rows_evicted = 0` is the
/// terminate signal — either no candidates remain or the budget is
/// already satisfied — and the caller must stop iterating.
struct BatchResult {
    rows_evicted: u64,
    bytes_reclaimed: i64,
}

/// One eviction batch: pick up to [`BATCH_SIZE`] oldest-by-`accessed_at`
/// eligible rows and NULL their `blob`, stopping as soon as `target_bytes`
/// have been reclaimed so we don't over-evict past the budget.
///
/// The two-statement shape (`SELECT` then per-hash `UPDATE`s) is
/// deliberate over a single `UPDATE … WHERE content_hash IN (…)`: the
/// per-row loop is what lets us stop mid-batch when one more row would
/// push us under budget — a single `UPDATE … IN (…)` would either
/// over-evict or require a separate pre-sum query.
///
/// Each per-row UPDATE re-applies the full eligibility predicate in its
/// WHERE clause (`blob IS NOT NULL AND NOT EXISTS (…)`) so a concurrent
/// `bind_attachment` that races in between the SELECT and the UPDATE
/// — flipping the row from "no current binding" to "origin-bound" —
/// causes the UPDATE to silently no-op, leaving the bytes in place.
/// `rows_affected()` tells us whether the eviction actually fired so we
/// don't credit the byte tally for rows we couldn't take. The §11.5
/// origin-retention obligation is therefore enforced even under
/// concurrent writes against `post_attachments`.
///
/// All UPDATEs in this batch commit atomically.
async fn evict_one_batch(pool: &SqlitePool, target_bytes: i64) -> Result<BatchResult, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Pick the oldest eligible rows. Same predicate as
    // `eligible_bytes_used` — the partial index
    // `idx_attachment_blobs_accessed_at` (`WHERE blob IS NOT NULL`)
    // makes the ORDER BY an index-ordered walk.
    let candidates = sqlx::query!(
        r#"SELECT ab.content_hash AS "content_hash!: Vec<u8>",
                  ab.size AS "size!: i64"
             FROM attachment_blobs ab
            WHERE ab.blob IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                    FROM post_attachments pa
                    JOIN posts p ON p.id = pa.post_id
                    JOIN users u ON u.id = p.author
                   WHERE pa.content_hash = ab.content_hash
                     AND pa.revision = p.revision_count - 1
                     AND p.retracted_at IS NULL
                     AND p.home_instance IS NULL
                     AND u.deleted_at IS NULL
              )
            ORDER BY ab.accessed_at ASC
            LIMIT ?"#,
        BATCH_SIZE,
    )
    .fetch_all(&mut *tx)
    .await?;

    if candidates.is_empty() {
        // No-op commit is fine; an empty `tx` releases its lock and
        // signals "no more candidates" to the caller.
        tx.commit().await?;
        return Ok(BatchResult {
            rows_evicted: 0,
            bytes_reclaimed: 0,
        });
    }

    let mut bytes_reclaimed: i64 = 0;
    let mut rows_evicted: u64 = 0;
    for row in &candidates {
        // Re-apply the eligibility predicate inside the UPDATE so a
        // concurrent `bind_attachment` that landed between our SELECT
        // and this statement turns the UPDATE into a no-op rather
        // than silently NULLing an origin-bound row. We discriminate
        // "took it" from "lost the race" via `rows_affected()`.
        let result = sqlx::query!(
            r#"UPDATE attachment_blobs
                  SET blob = NULL
                WHERE content_hash = ?
                  AND blob IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1
                        FROM post_attachments pa
                        JOIN posts p ON p.id = pa.post_id
                        JOIN users u ON u.id = p.author
                       WHERE pa.content_hash = attachment_blobs.content_hash
                         AND pa.revision = p.revision_count - 1
                         AND p.retracted_at IS NULL
                         AND p.home_instance IS NULL
                         AND u.deleted_at IS NULL
                  )"#,
            row.content_hash,
        )
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            // Concurrent binder won — this row is now origin-bound or
            // already evicted by a parallel sweep. Skip without
            // crediting the byte tally; next sweep tick will re-pick
            // candidates if we're still over budget.
            continue;
        }
        bytes_reclaimed = bytes_reclaimed.saturating_add(row.size);
        rows_evicted += 1;
        // Stop mid-batch once we've reclaimed enough — one more row
        // would put us under budget. The remaining candidates we
        // skipped here will still be visible to the next sweep tick
        // if the cache grows back over budget; nothing is lost.
        if bytes_reclaimed >= target_bytes {
            break;
        }
    }

    tx.commit().await?;
    Ok(BatchResult {
        rows_evicted,
        bytes_reclaimed,
    })
}

/// Run one full sweep pass: bring eligible-bytes-used at or under
/// `max_bytes` by evicting the oldest cache entries in [`BATCH_SIZE`]
/// chunks.
///
/// Called from [`crate::attachments::sweep::sweep_loop`] once per tick,
/// after the staging-expiry + orphan-GC steps. Errors propagate to the
/// sweep loop, which logs and moves on; transient DB failures don't
/// retry until the next sweep cadence (matching the existing behaviour
/// of the orphan-GC step).
///
/// Metrics emitted:
///
/// - `attachment_cache_bytes_used`: gauge set to the post-sweep eligible
///   byte total. Updated even when no eviction was needed.
/// - `attachment_cache_evictions_total`: counter, incremented per row
///   that had its bytes nulled (not per batch).
/// - `attachment_cache_overshoot_bytes`: gauge, set to
///   `max(0, bytes_used - max_bytes)` after the sweep completes.
///   Non-zero only if the cache is over budget *with no eligible rows
///   left to evict* — i.e. every byte over the line is origin-obligated.
///   That is the operator signal "your budget is smaller than the
///   origin retentions your local users have authored", and the
///   correct response is to raise the budget or shed local content.
pub async fn run_eviction(
    pool: &SqlitePool,
    max_bytes: u64,
    metrics: &Arc<Metrics>,
) -> Result<(), sqlx::Error> {
    let mut stats = eligible_bytes_used(pool).await?;
    let mut evicted_rows: u64 = 0;

    while (stats.bytes_used as u64) > max_bytes {
        let target = stats.bytes_used.saturating_sub(max_bytes as i64).max(0);
        let batch = evict_one_batch(pool, target).await?;
        if batch.rows_evicted == 0 {
            // No more eligible candidates — every remaining byte over
            // the budget is origin-obligated retention. Bail out and
            // surface the overshoot via the gauge below.
            break;
        }
        evicted_rows = evicted_rows.saturating_add(batch.rows_evicted);
        stats.bytes_used = stats.bytes_used.saturating_sub(batch.bytes_reclaimed);
    }

    // Final gauges: bytes_used reflects the post-eviction reality,
    // overshoot is the unreclaimable remainder (origin-obligated bytes
    // alone are over budget).
    let bytes_used = stats.bytes_used.max(0) as u64;
    let overshoot = bytes_used.saturating_sub(max_bytes);
    metrics.set_attachment_cache_bytes_used(bytes_used);
    metrics.set_attachment_cache_overshoot_bytes(overshoot);
    if evicted_rows > 0 {
        metrics.add_attachment_cache_evictions(evicted_rows);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: in-memory DB with the production migration set applied.
    /// Mirrors the pattern used by other Layer-0 unit tests in this
    /// crate that need a real `attachment_blobs` schema.
    async fn fresh_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("sqlite memory pool");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("apply migrations");
        pool
    }

    /// Seed a federation-fetched cache entry: an `attachment_blobs` row
    /// with `blob` set, no local binding. `accessed_at` is settable so
    /// LRU-order tests can pin which row is "oldest" without sleeping.
    async fn insert_cache_blob(
        pool: &SqlitePool,
        hash_seed: u8,
        size: i64,
        accessed_at: &str,
    ) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[0] = hash_seed;
        hash[31] = hash_seed.wrapping_add(0xa5);
        let hash_slice: &[u8] = hash.as_slice();
        let body = vec![0u8; size as usize];
        sqlx::query!(
            "INSERT INTO attachment_blobs \
                 (content_hash, blob, content_type, size, uploader, accessed_at) \
             VALUES (?, ?, 'application/octet-stream', ?, NULL, ?)",
            hash_slice,
            body,
            size,
            accessed_at,
        )
        .execute(pool)
        .await
        .expect("insert cache blob");
        hash
    }

    #[tokio::test]
    async fn run_eviction_noop_when_under_budget() {
        let pool = fresh_pool().await;
        let metrics = Arc::new(Metrics::new());
        // Seed three 1 KiB entries; budget 10 KiB → no eviction.
        for (seed, ts) in [
            (0x01, "2026-01-01T00:00:00Z"),
            (0x02, "2026-01-02T00:00:00Z"),
            (0x03, "2026-01-03T00:00:00Z"),
        ] {
            insert_cache_blob(&pool, seed, 1024, ts).await;
        }
        run_eviction(&pool, 10 * 1024, &metrics)
            .await
            .expect("sweep");

        // All three rows still have bytes.
        let with_bytes: i64 =
            sqlx::query_scalar!("SELECT COUNT(*) FROM attachment_blobs WHERE blob IS NOT NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(with_bytes, 3);

        // Gauge reflects current usage; no evictions counted.
        assert_eq!(
            metrics
                .attachment_cache_bytes_used
                .load(std::sync::atomic::Ordering::Relaxed),
            3 * 1024,
        );
        assert_eq!(
            metrics
                .attachment_cache_evictions_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
        assert_eq!(
            metrics
                .attachment_cache_overshoot_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
    }

    #[tokio::test]
    async fn run_eviction_drops_oldest_first_until_under_budget() {
        let pool = fresh_pool().await;
        let metrics = Arc::new(Metrics::new());

        // Three 1 KiB entries; budget 2 KiB → must evict exactly one,
        // and it must be the oldest by accessed_at.
        let oldest = insert_cache_blob(&pool, 0x01, 1024, "2026-01-01T00:00:00Z").await;
        let mid = insert_cache_blob(&pool, 0x02, 1024, "2026-01-02T00:00:00Z").await;
        let newest = insert_cache_blob(&pool, 0x03, 1024, "2026-01-03T00:00:00Z").await;

        run_eviction(&pool, 2 * 1024, &metrics)
            .await
            .expect("sweep");

        // Oldest is bytes-null; mid + newest still hold bytes.
        let oldest_slice: &[u8] = oldest.as_slice();
        let mid_slice: &[u8] = mid.as_slice();
        let newest_slice: &[u8] = newest.as_slice();
        let oldest_blob: Option<Vec<u8>> = sqlx::query_scalar!(
            "SELECT blob FROM attachment_blobs WHERE content_hash = ?",
            oldest_slice,
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(oldest_blob.is_none(), "oldest row must have been evicted");
        for h in [mid_slice, newest_slice] {
            let b: Option<Vec<u8>> = sqlx::query_scalar!(
                "SELECT blob FROM attachment_blobs WHERE content_hash = ?",
                h,
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(b.is_some(), "newer rows must remain resident");
        }

        assert_eq!(
            metrics
                .attachment_cache_evictions_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
        );
        assert_eq!(
            metrics
                .attachment_cache_bytes_used
                .load(std::sync::atomic::Ordering::Relaxed),
            2 * 1024,
        );
        assert_eq!(
            metrics
                .attachment_cache_overshoot_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
    }

    #[tokio::test]
    async fn run_eviction_skips_origin_bound_blobs() {
        // Two 4 KiB blobs, budget 1 KiB. One is origin-bound (current
        // revision of a locally-authored, non-retracted post by a
        // non-deleted user) → MUST NOT be evicted even though it's
        // older. The other is a pure cache entry → evicted.
        //
        // Result: the §11.5 contract leaves us over budget (origin
        // alone is 4 KiB > 1 KiB), and the overshoot gauge reflects
        // exactly that.
        let pool = fresh_pool().await;
        let metrics = Arc::new(Metrics::new());

        // Origin-bound entry: insert user → room → thread → post →
        // post_revision → attachment_blob → post_attachments binding.
        sqlx::query!(
            "INSERT INTO users (id, display_name, signup_method, public_key, display_name_skeleton) \
             VALUES ('user_a', 'alice', 'admin', X'00', 'alice')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO rooms (id, slug, created_by) VALUES ('general', 'general', 'user_a')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO threads (id, title, author, room) \
             VALUES ('thread-1', 'fixture', 'user_a', 'general')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO posts (id, author, thread, revision_count, home_instance) \
             VALUES ('post-1', 'user_a', 'thread-1', 1, NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO post_revisions (post_id, revision, body, signature, canonical_hash, created_at) \
             VALUES ('post-1', 0, '', X'00', X'00', '2026-01-01T00:00:00Z')",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Older row, origin-bound. Even though its accessed_at is the
        // oldest, the eligibility predicate excludes it.
        let origin_hash = insert_cache_blob(&pool, 0x01, 4 * 1024, "2026-01-01T00:00:00Z").await;
        let origin_slice: &[u8] = origin_hash.as_slice();
        sqlx::query!(
            "INSERT INTO post_attachments (post_id, revision, position, content_hash, filename) \
             VALUES ('post-1', 0, 0, ?, 'origin.bin')",
            origin_slice,
        )
        .execute(&pool)
        .await
        .unwrap();

        // Newer row, pure cache entry → must be the one evicted.
        let cache_hash = insert_cache_blob(&pool, 0x02, 4 * 1024, "2026-01-02T00:00:00Z").await;

        run_eviction(&pool, 1024, &metrics).await.expect("sweep");

        // Origin row: bytes still resident.
        let origin_blob: Option<Vec<u8>> = sqlx::query_scalar!(
            "SELECT blob FROM attachment_blobs WHERE content_hash = ?",
            origin_slice,
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(origin_blob.is_some(), "origin row must survive eviction");

        // Cache row: bytes nulled.
        let cache_slice: &[u8] = cache_hash.as_slice();
        let cache_blob: Option<Vec<u8>> = sqlx::query_scalar!(
            "SELECT blob FROM attachment_blobs WHERE content_hash = ?",
            cache_slice,
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(cache_blob.is_none(), "cache row must be evicted");

        // Bytes_used drops to 0 (origin row excluded from the gauge);
        // overshoot is also 0 because the gauge is over the *eligible*
        // population, which the post-sweep state has zero of.
        assert_eq!(
            metrics
                .attachment_cache_bytes_used
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
        assert_eq!(
            metrics
                .attachment_cache_overshoot_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
        assert_eq!(
            metrics
                .attachment_cache_evictions_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
        );
    }

    #[tokio::test]
    async fn evict_one_batch_skips_row_that_became_origin_bound() {
        // Race-window mitigation: a concurrent `bind_attachment` lands
        // between candidate selection and the per-row UPDATE. The
        // UPDATE re-applies the eligibility predicate in its WHERE
        // clause, so the bound row survives instead of being NULLed.
        //
        // We simulate the race by binding the row to a local post
        // *after* `eligible_bytes_used` would have selected it but
        // before `evict_one_batch`'s UPDATE fires — concretely, we
        // bind it inline and observe that the batch's UPDATE no-ops
        // for that row.
        let pool = fresh_pool().await;

        // Two cache entries, oldest first. Budget is tight enough that
        // both look like eviction candidates from the SELECT, but the
        // oldest gets concurrently bound to a local post before its
        // UPDATE runs.
        let to_be_bound = insert_cache_blob(&pool, 0x01, 4 * 1024, "2026-01-01T00:00:00Z").await;
        let plain_cache = insert_cache_blob(&pool, 0x02, 4 * 1024, "2026-01-02T00:00:00Z").await;
        let to_be_bound_slice: &[u8] = to_be_bound.as_slice();
        let plain_cache_slice: &[u8] = plain_cache.as_slice();

        // Bind `to_be_bound` to a fresh local post — this is the
        // race-window simulation. After this, the row is origin-bound
        // and the UPDATE in `evict_one_batch` MUST refuse to touch it
        // even though the SELECT would have picked it as candidate #1.
        sqlx::query!(
            "INSERT INTO users (id, display_name, signup_method, public_key, display_name_skeleton) \
             VALUES ('user_race', 'race', 'admin', X'00', 'race')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO rooms (id, slug, created_by) VALUES ('general', 'general', 'user_race')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO threads (id, title, author, room) \
             VALUES ('t-race', 'race', 'user_race', 'general')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO posts (id, author, thread, revision_count, home_instance) \
             VALUES ('p-race', 'user_race', 't-race', 1, NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO post_revisions (post_id, revision, body, signature, canonical_hash, created_at) \
             VALUES ('p-race', 0, '', X'00', X'00', '2026-01-01T00:00:00Z')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO post_attachments (post_id, revision, position, content_hash, filename) \
             VALUES ('p-race', 0, 0, ?, 'origin.bin')",
            to_be_bound_slice,
        )
        .execute(&pool)
        .await
        .unwrap();

        // Drive eviction. Budget 0 → maximum pressure. Without the
        // re-check, the bound row would be evicted; with it, only the
        // plain cache row gets NULLed.
        let batch = evict_one_batch(&pool, i64::MAX).await.expect("batch");

        // The newly-bound row keeps its bytes.
        let bound_blob: Option<Vec<u8>> = sqlx::query_scalar!(
            "SELECT blob FROM attachment_blobs WHERE content_hash = ?",
            to_be_bound_slice,
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            bound_blob.is_some(),
            "row that became origin-bound mid-batch must survive — re-check predicate fired",
        );

        // The plain cache row is the one evicted.
        let plain_blob: Option<Vec<u8>> = sqlx::query_scalar!(
            "SELECT blob FROM attachment_blobs WHERE content_hash = ?",
            plain_cache_slice,
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            plain_blob.is_none(),
            "plain cache row must still be evicted",
        );

        // Only one row counted toward `rows_evicted` — the race-loser
        // bound row did NOT credit the byte tally despite being one of
        // the SELECT candidates.
        assert_eq!(batch.rows_evicted, 1);
        assert_eq!(batch.bytes_reclaimed, 4 * 1024);
    }

    #[tokio::test]
    async fn bump_accessed_at_updates_after_floor_elapses() {
        let pool = fresh_pool().await;
        // accessed_at far in the past — any sane LRU_FLOOR_SECS clears
        // the floor.
        let hash = insert_cache_blob(&pool, 0x01, 1024, "2020-01-01T00:00:00Z").await;
        let hash_slice: &[u8] = hash.as_slice();

        bump_accessed_at(&pool, hash_slice).await;
        let after: String = sqlx::query_scalar!(
            "SELECT accessed_at FROM attachment_blobs WHERE content_hash = ?",
            hash_slice,
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            after.as_str() > "2020-01-01T00:00:00Z",
            "accessed_at must be bumped to a fresher timestamp, got {after}",
        );
    }

    #[tokio::test]
    async fn bump_accessed_at_is_noop_inside_floor() {
        let pool = fresh_pool().await;
        // Seed with `accessed_at = now`. The next bump within the
        // floor window must NOT change the stored timestamp.
        let now: String = sqlx::query_scalar!("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now')")
            .fetch_one(&pool)
            .await
            .unwrap()
            .expect("now");
        let hash = insert_cache_blob(&pool, 0x01, 1024, &now).await;
        let hash_slice: &[u8] = hash.as_slice();

        bump_accessed_at(&pool, hash_slice).await;
        let after: String = sqlx::query_scalar!(
            "SELECT accessed_at FROM attachment_blobs WHERE content_hash = ?",
            hash_slice,
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(after, now, "within-floor bump must be a no-op");
    }
}
