//! Background TTL sweep + orphan-GC + §11.5 cache eviction for
//! attachments (`docs/attachments.md` §3 "Staging GC", §5 GC predicate;
//! `docs/federation-protocol.md` §11.5 receiver-local cache).
//!
//! Once per `sweep_interval_seconds`:
//!
//! 1. Delete `attachment_staging` rows past `expires_at`.
//! 2. Delete any `attachment_blobs` row whose `refcount = 0` and no
//!    `attachment_staging` row still references it. This sweeps both
//!    just-expired staged uploads and any blob whose last binding was
//!    removed since the previous pass.
//! 3. Enforce the §11.5 receiver-local cache budget: null out the
//!    oldest-by-`accessed_at` cache entries (federation-fetched bytes
//!    with no current locally-authored binding) until under
//!    `max_bytes`. Delegated to
//!    [`crate::federation::attachment_cache::run_eviction`].
//!
//! Budget is **not** refunded on staging expiry (matches spec: "deleting
//! a post or attachment does not reclaim allowance").

use std::sync::Arc;
use std::time::Duration;

use sqlx::SqlitePool;

use super::bind::gc_orphan_blobs;
use crate::federation::attachment_cache;
use crate::metrics::Metrics;

/// Spawn target: runs the staging-expiry + orphan-blob GC pass + §11.5
/// cache eviction at the configured cadence. Errors are logged but
/// never propagated — a transient DB failure should not take the server
/// down, and the next sweep catches up.
pub async fn sweep_loop(
    pool: SqlitePool,
    sweep_interval_seconds: u64,
    cache_max_bytes: u64,
    metrics: Arc<Metrics>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(sweep_interval_seconds));
    // Skip the first immediate tick; let the server finish starting
    // up before we touch the DB with a maintenance pass.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        if let Err(e) = run_sweep(&pool, cache_max_bytes, &metrics).await {
            tracing::error!(error = %e, "attachment staging sweep failed");
        }
    }
}

/// Single pass: TTL-expire staging rows, GC orphan blobs, then evict
/// over-budget cache entries. Split out so unit tests can drive a
/// single pass deterministically.
///
/// Steps 1+2 share one transaction (their atomicity is load-bearing:
/// `gc_orphan_blobs` keys on the post-staging-delete refcount state).
/// Step 3 runs against the pool directly and manages its own per-batch
/// transactions inside [`attachment_cache::run_eviction`] so a large
/// eviction doesn't hold a single write lock for its full duration.
async fn run_sweep(
    pool: &SqlitePool,
    cache_max_bytes: u64,
    metrics: &Arc<Metrics>,
) -> Result<(), sqlx::Error> {
    {
        let mut tx = pool.begin().await?;

        // 1. Expire staging rows whose `expires_at` is in the past.
        sqlx::query!(
            "DELETE FROM attachment_staging \
             WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now')"
        )
        .execute(&mut *tx)
        .await?;

        // 2. Drop any blob whose refcount has reached 0 and which is no
        //    longer tracked by a staging row. Delegated to the shared §5
        //    predicate in `attachments::bind::gc_orphan_blobs` — the
        //    inline handlers (`edit_post`, `retract_post`) and
        //    `privacy::soft_delete_user` all route through the same
        //    function so the GC rule cannot drift across paths.
        gc_orphan_blobs(&mut tx).await?;

        tx.commit().await?;
    }

    // 3. §11.5 receiver-local cache eviction. Federation-only by
    //    construction: origin-authored blobs (those currently bound
    //    to a local post) are excluded from the eligibility predicate
    //    inside `run_eviction`, so the eviction loop only ever touches
    //    cache bytes. Metrics emitted on this path are also scoped to
    //    that population.
    attachment_cache::run_eviction(pool, cache_max_bytes, metrics).await?;

    Ok(())
}
