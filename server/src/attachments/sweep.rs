//! Background TTL sweep + orphan-GC for attachment uploads
//! (`docs/attachments.md` §3 "Staging GC", §5 GC predicate).
//!
//! Once per `sweep_interval_seconds`:
//!
//! 1. Delete `attachment_staging` rows past `expires_at`.
//! 2. Delete any `attachment_blobs` row whose `refcount = 0` and no
//!    `attachment_staging` row still references it. This sweeps both
//!    just-expired staged uploads and any blob whose last binding was
//!    removed since the previous pass.
//!
//! Budget is **not** refunded on staging expiry (matches spec: "deleting
//! a post or attachment does not reclaim allowance").

use std::time::Duration;

use sqlx::SqlitePool;

use super::bind::gc_orphan_blobs;

/// Spawn target: runs the staging-expiry + orphan-blob GC pass at
/// the configured cadence. Errors are logged but never propagated —
/// a transient DB failure should not take the server down, and the
/// next sweep catches up.
pub async fn sweep_loop(pool: SqlitePool, sweep_interval_seconds: u64) {
    let mut ticker = tokio::time::interval(Duration::from_secs(sweep_interval_seconds));
    // Skip the first immediate tick; let the server finish starting
    // up before we touch the DB with a maintenance pass.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        if let Err(e) = run_sweep(&pool).await {
            tracing::error!(error = %e, "attachment staging sweep failed");
        }
    }
}

/// Single pass: TTL-expire staging rows, then GC orphan blobs. Split
/// out so unit tests can drive a single pass deterministically.
async fn run_sweep(pool: &SqlitePool) -> Result<(), sqlx::Error> {
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
    Ok(())
}
