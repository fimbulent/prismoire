//! Remote-author stub hydration helpers (Phase 9.5 of
//! `docs/federation-impl-plan.md`).
//!
//! Phases 5 and 6 deliberately punted projection for signed objects
//! authored by non-local users: `/edges` and `/content` store the
//! canonical bytes and call the result `applied`, but leave the
//! per-class projection rows unwritten. Reads against
//! `post_revisions` / `threads` / `profile_revisions` therefore can't
//! see remote content, and the erasure pipeline (`deactivate`,
//! `admin-rm`, `retract`) has nothing to sweep on the projection
//! side.
//!
//! Phase 9.5 closes that gap by hydrating a **stub `users` row** for
//! each remote pubkey we observe authoring content. The stub looks
//! like any other user row except:
//!
//! - `signup_method = 'federated'` — distinguishes it from rows
//!   created by local signup, admin-grant, invite redemption, or the
//!   §13 cross-instance registration ceremony. Migration
//!   `..165783_add_federated_signup_method.sql` rebuilt the
//!   `users.signup_method` CHECK to accept this value.
//! - `home_instance` is non-NULL — names the instance pubkey
//!   currently authoritative for this user (resolved from
//!   `user_homes` for moved users, or the envelope's `arrived_from`
//!   as the implicit registration home otherwise). The partial-
//!   unique indexes `idx_users_display_name_local` /
//!   `idx_users_display_name_skeleton_local` are scoped
//!   `WHERE home_instance IS NULL`, so stub rows can collide freely
//!   with local rows on display_name — the dotted-form
//!   `/@username.{pubkey-prefix}` URL disambiguates per Phase 9.5's
//!   routing surface.
//!
//! Once a stub exists, the per-class projection branches in
//! `content.rs` can FK-into it from `posts.author` /
//! `threads.author` / `profile_revisions.user_id` exactly as they
//! would for a local author. The wider §11 attachment-serve gate
//! continues to check `posts.home_instance IS NULL` so a stub
//! authoring on a remote home doesn't trip the origin-only rule.
//!
//! ## Why `home_instance` resolution gets its own helper
//!
//! `users.home_instance` and `posts.home_instance` mean different
//! things per `docs/federation-protocol.md` §16.1:
//!
//! - `users.home_instance` tracks the user's **currently-authoritative
//!   home** — it MUST update when a §5.1 `move` lands (Phase 7
//!   retrofit in `moves.rs::apply_one_move`).
//! - `posts.home_instance` is **frozen at receive time** — the home
//!   the post was authored under, captured once and never rewritten
//!   by later moves. It anchors §10.4 admin-rm advisory routing and
//!   the §11.5 attachment forwarding-cache rule.
//!
//! [`resolve_current_home`] returns the "where is K hosted now"
//! answer for the `users` stub; [`resolve_home_at_t`] returns the
//! "where was K hosted when this object was signed" answer for
//! `posts.home_instance` / `threads.home_instance`. Both fall back to
//! the envelope's `arrived_from` when no move chain is on file —
//! that's the §12.4 implicit registration home for a user who has
//! never moved off their original instance.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::display_name::display_name_skeleton;
use crate::signed::{SignedPayload, TrustEdge, TrustStance};
use crate::signing::erase_trust_edge_chain;

/// Strip control codepoints, bidi-override format characters, and
/// zero-width chars from a remote-signed display name before INSERT.
///
/// The local `validate_display_name` pipeline rejects these
/// categories outright; we can't refuse a cryptographically-verified
/// remote payload over name-shape disagreements, but we also can't
/// trust the bytes to render safely in popovers / search / the
/// disambiguation page. A name carrying U+202E (right-to-left
/// override) can be made to *visually* match a local username while
/// hashing to a totally different skeleton — easy spoofing surface.
///
/// Strategy: strip the dangerous categories, leave everything else
/// untouched. If the result is empty (the remote name was nothing
/// *but* control/format chars) substitute the first 8 hex chars of
/// the pubkey as a placeholder so we always have *something*
/// renderable. The canonical bytes still carry the original name
/// for forensic / future-policy use.
fn sanitize_remote_display_name(raw: &str, public_key: &[u8; 32]) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| {
            // Reject:
            //   - C0 controls (U+0000..U+001F) and DEL (U+007F)
            //   - C1 controls (U+0080..U+009F)
            //   - Zero-width / format chars (cat Cf): ZWSP, ZWNJ,
            //     ZWJ, LRM/RLM, LRE/RLE/PDF, LRO/RLO, LRI/RLI/FSI/
            //     PDI, BOM, etc. Catches the bidi-override family
            //     and the invisible joiner family in one predicate.
            !c.is_control()
                && !matches!(
                    *c,
                    '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2060}'..='\u{2064}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{FEFF}'
                )
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        // Fall back to an unambiguous, renderable placeholder.
        let mut out = String::with_capacity(8);
        for b in public_key.iter().take(4) {
            out.push_str(&format!("{b:02x}"));
        }
        out
    } else {
        trimmed.to_string()
    }
}

/// Hydrate a `users` row for a remote author keyed by `public_key`.
///
/// Returns the local `users.id` (text-UUID) so callers can FK into
/// `posts.author`, `threads.author`, `profile_revisions.user_id`,
/// etc.
///
/// Three-way semantics on the existing-row case, gated by
/// `signup_method`:
///
/// 1. **No row.** INSERT a fresh stub with `signup_method = 'federated'`,
///    the supplied `display_name` / `display_name_skeleton` / `home_instance`,
///    and a freshly-minted text-UUID id. Return the new id.
/// 2. **Row exists, `signup_method = 'federated'`.** UPDATE the mutable
///    metadata (`display_name`, `display_name_skeleton`, `home_instance`)
///    so a later profile-rev with a renamed user — or a move that lands
///    after the stub was first hydrated — reflects promptly. Return the
///    existing id.
/// 3. **Row exists, `signup_method != 'federated'`.** Local user, §13
///    cross-instance-register, admin grant, etc. — the row is locally
///    authoritative and a federation receive MUST NOT mutate its
///    metadata. Return the existing id without touching the row; the
///    caller can still FK projection rows (profile_revisions, posts) to
///    that id, which is the right behaviour for the cross-instance-
///    registered case where the user has authored content elsewhere
///    that we want to surface alongside their local content.
///    (Phase 9.7 — §13 stub upgrade-in-place — covers the inverse
///    direction: a federated stub becoming a §13 registered local
///    user.)
///
/// The caller is responsible for choosing the `home_instance` value —
/// typically via [`resolve_current_home`] for profile-rev hydration.
/// We do not consult `user_homes` ourselves so this helper stays a
/// pure "write a row" primitive that the caller can compose with the
/// resolution logic appropriate to its use site.
///
/// ## Display-name handling
///
/// `display_name` is **not** put through `validate_display_name` —
/// the local-signup validator enforces 3..=20 Unicode scalar values,
/// no separators at boundaries, etc., and a remote signer may have
/// followed their own rules. We can't refuse to project a payload we
/// already cryptographically verified over name-shape disagreements.
///
/// We *do* run a narrow defensive sanitizer
/// ([`sanitize_remote_display_name`]) that strips control chars,
/// bidi-override format chars, and zero-width chars: those categories
/// don't ship in any legitimate display name and they enable visual
/// spoofing (e.g. U+202E flipping name rendering in popovers / search
/// / the disambiguation page). The canonical bytes still carry the
/// original; only the projected row's `display_name` is sanitized.
///
/// The partial-unique indexes on `display_name` / `display_name_skeleton`
/// are scoped `WHERE home_instance IS NULL`, so a remote `alice` and a
/// local `alice` coexist without collision; the dotted-form
/// `/@alice.{pubkey-prefix}` URL distinguishes them at the read surface.
///
/// `display_name_skeleton` is computed locally via
/// [`display_name_skeleton`] so the §13 / dotted-form lookups by
/// confusable-collapsed skeleton work consistently across local and
/// remote rows.
pub async fn hydrate_stub_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    public_key: &[u8; 32],
    display_name: &str,
    home_instance: &[u8; 32],
) -> Result<String, sqlx::Error> {
    let pubkey_slice: &[u8] = public_key.as_slice();
    let home_slice: &[u8] = home_instance.as_slice();
    let sanitized_name = sanitize_remote_display_name(display_name, public_key);
    let skeleton = display_name_skeleton(&sanitized_name);

    // Look up the existing row by pubkey. SELECT-then-INSERT-or-UPDATE
    // is safe under the caller's BEGIN IMMEDIATE: any concurrent
    // federation writer for the same pubkey serialises behind us, so
    // the window between SELECT and INSERT/UPDATE can't race a
    // sibling INSERT.
    let existing = sqlx::query!(
        "SELECT id AS \"id!: String\", signup_method AS \"signup_method!: String\" \
           FROM users WHERE public_key = ?",
        pubkey_slice,
    )
    .fetch_optional(&mut **tx)
    .await?;

    if let Some(row) = existing {
        if row.signup_method == "federated" {
            // Federated stub — refresh mutable metadata.
            sqlx::query!(
                "UPDATE users SET \
                    display_name          = ?, \
                    display_name_skeleton = ?, \
                    home_instance         = ? \
                  WHERE public_key = ?",
                sanitized_name,
                skeleton,
                home_slice,
                pubkey_slice,
            )
            .execute(&mut **tx)
            .await?;
        }
        // signup_method != 'federated': locally-authoritative row —
        // do not mutate. Caller still gets the id for FK use.
        return Ok(row.id);
    }

    // No existing row — INSERT a fresh federated stub.
    let new_id = Uuid::new_v4().to_string();
    sqlx::query!(
        "INSERT INTO users (id, display_name, display_name_skeleton, signup_method, \
                            public_key, home_instance) \
         VALUES (?, ?, ?, 'federated', ?, ?)",
        new_id,
        sanitized_name,
        skeleton,
        pubkey_slice,
        home_slice,
    )
    .execute(&mut **tx)
    .await?;
    Ok(new_id)
}

/// Resolve the chain-grounded current home of a user key.
///
/// Consults `user_homes` (the Phase 7 §12.4 latest-wins projection).
/// If a row exists, returns its `current_home_key` — the instance
/// pubkey naming the user's currently-authoritative home as resolved
/// from the move chain. Otherwise falls back to the envelope's
/// `arrived_from`: a user with no observed `move` declaration is, by
/// §12.4, still hosted on their original (registration) instance, and
/// `arrived_from` is the best available approximation when we haven't
/// independently learned the registration home (the sender is itself
/// either the home or a forwarder, and forwarders only relay objects
/// they've already accepted into their own gossip).
///
/// Used by [`hydrate_stub_user`] callers writing `users.home_instance`
/// at the time a profile-rev (or any first-sighting object) lands.
pub async fn resolve_current_home(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_key: &[u8; 32],
    arrived_from: &[u8; 32],
) -> Result<[u8; 32], sqlx::Error> {
    let key_slice: &[u8] = user_key.as_slice();
    let row = sqlx::query!(
        "SELECT current_home_key AS \"current_home_key!: Vec<u8>\" \
           FROM user_homes WHERE user_key = ?",
        key_slice,
    )
    .fetch_optional(&mut **tx)
    .await?;

    match row {
        Some(r) if r.current_home_key.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&r.current_home_key);
            Ok(out)
        }
        Some(_) => {
            // CHECK constraint on user_homes pins length = 32, so a
            // mismatched-length read is local-state corruption. Don't
            // pretend the row exists; fall back to arrived_from rather
            // than crash the receive path.
            tracing::error!(
                user_key = ?user_key,
                "user_homes.current_home_key has unexpected length",
            );
            Ok(*arrived_from)
        }
        None => Ok(*arrived_from),
    }
}

/// Resolve the home that authored a signed object at signing time `t`.
///
/// Walks `user_moves` (the Phase 7 §12.3-backfill index) to find the
/// latest move with `created_at <= t` and returns its `to_instance_key`
/// (the home the user was on as of that move). When `t` predates every
/// recorded move, returns the earliest move's `from_instance_key` —
/// that's the implicit registration home, captured verbatim from the
/// signed `move` declaration. When no moves at all are on file, falls
/// back to `arrived_from`.
///
/// Used to populate `posts.home_instance` / `threads.home_instance` for
/// projected remote rows. Unlike [`resolve_current_home`], the answer
/// here is **frozen at receive time** — later moves never rewrite an
/// already-projected row's `home_instance` per §16.1.
///
/// ## Decoding moves
///
/// Move payloads aren't stored in a typed table; `user_moves` just
/// indexes the chain by `(user_key, created_at, canonical_hash)`. To
/// extract `to_instance_key` / `from_instance_key` we join to
/// `signed_objects.payload` and parse the canonical CBOR. Parse failures
/// (corruption, format-version drift) fall back to `arrived_from`
/// rather than fail the receive — the projection still gets *a* home,
/// just the conservative one, and the caller's signed_objects copy
/// remains the durable source of truth.
pub async fn resolve_home_at_t(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_key: &[u8; 32],
    t: u64,
    arrived_from: &[u8; 32],
) -> Result<[u8; 32], sqlx::Error> {
    let key_slice: &[u8] = user_key.as_slice();
    let t_db = i64::try_from(t).unwrap_or(i64::MAX);

    // Latest move with created_at <= t. Tiebreak by canonical_hash
    // mirrors §12.4 (smaller wins) so two peers projecting the same
    // post-rev pick the same home in pathological tied-timestamp cases.
    let latest_before = sqlx::query!(
        "SELECT canonical_hash AS \"canonical_hash!: Vec<u8>\" \
           FROM user_moves \
          WHERE user_key = ? AND created_at <= ? \
          ORDER BY created_at DESC, canonical_hash ASC \
          LIMIT 1",
        key_slice,
        t_db,
    )
    .fetch_optional(&mut **tx)
    .await?;

    if let Some(row) = latest_before {
        if let Some(home) = load_move_to_key(&mut **tx, &row.canonical_hash).await? {
            return Ok(home);
        }
        // Fall through to fallback on parse / load failure.
    } else {
        // No move with created_at <= t. The user may have moved
        // *after* this object was signed; if so, the earliest move's
        // from_instance_key names the home at signing time. (If the
        // user has never moved at all, this query also returns
        // nothing and we drop to arrived_from below.)
        let earliest = sqlx::query!(
            "SELECT canonical_hash AS \"canonical_hash!: Vec<u8>\" \
               FROM user_moves \
              WHERE user_key = ? \
              ORDER BY created_at ASC, canonical_hash ASC \
              LIMIT 1",
            key_slice,
        )
        .fetch_optional(&mut **tx)
        .await?;

        if let Some(row) = earliest
            && let Some(home) = load_move_from_key(&mut **tx, &row.canonical_hash).await?
        {
            return Ok(home);
        }
    }

    Ok(*arrived_from)
}

/// Outcome of a single `try_project_trust_edge` attempt. Shared
/// between the §9.1 receive path (`edges.rs::apply_one_edge`) and the
/// Phase 9.6 sweep path below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustEdgeProjection {
    /// Row inserted into `trust_edges`. If `stance == Neutral` the
    /// helper also ran [`erase_trust_edge_chain`] for the pair.
    Projected,
    /// One or both endpoint pubkeys have no matching `users` row.
    /// Caller stores the canonical bytes so a later sweep can retry.
    EndpointMissing,
    /// A sibling row for `(source, target, prior_edge_hash)` is
    /// already projected — §9.4 fork: both bytes preserved, neither
    /// is active.
    ChainFork,
    /// `prior_edge_hash` is `Some(h)` but `(source, target, h)` is
    /// not yet projected. §9.1 deferral: caller does NOT persist the
    /// signed object on the receive path (§9.3 backfill / re-push
    /// closes the gap); on the sweep path the bytes are already
    /// durable so deferral is a no-op for storage.
    Deferred,
}

/// Project a verified trust-edge into the local `trust_edges` table.
///
/// Shared by:
/// - `edges.rs::apply_one_edge` (the §9.1 receive path)
/// - [`sweep_pending_projections`] (Phase 9.6 catch-up after a stub
///   hydrates)
///
/// The caller is responsible for [`store_signed_object`] semantics —
/// this helper only mutates `trust_edges` and, on neutral arrivals,
/// the `signed_objects.payload` blanks driven by
/// [`erase_trust_edge_chain`]. Caller MUST run inside a `BEGIN
/// IMMEDIATE` transaction so chain-fork / chain-continuity and the
/// INSERT observe one consistent snapshot.
///
/// Idempotency: a duplicate `canonical_hash` already in `trust_edges`
/// short-circuits to `Projected` without re-inserting. This lets sweep
/// safely re-run after a receive-path projection landed the same row.
pub(crate) async fn try_project_trust_edge(
    tx: &mut sqlx::SqliteConnection,
    edge: &TrustEdge,
    canonical_hash: &[u8; 32],
    signature: &[u8],
) -> Result<TrustEdgeProjection, sqlx::Error> {
    // Resolve both endpoints to local `users.id`. A federated stub
    // qualifies — Phase 9.5 hydration writes the same `users` table
    // local signup writes to, so the FK target is satisfied either
    // way.
    let from_slice: &[u8] = edge.from_key.as_slice();
    let to_slice: &[u8] = edge.to_key.as_slice();
    let source_id = sqlx::query_scalar!("SELECT id FROM users WHERE public_key = ?", from_slice)
        .fetch_optional(&mut *tx)
        .await?;
    let target_id = sqlx::query_scalar!("SELECT id FROM users WHERE public_key = ?", to_slice)
        .fetch_optional(&mut *tx)
        .await?;
    let (Some(source_id), Some(target_id)) = (source_id, target_id) else {
        return Ok(TrustEdgeProjection::EndpointMissing);
    };

    // Idempotency short-circuit. Hit when sweep re-runs over an edge
    // the receive path already projected.
    let canonical_slice: &[u8] = canonical_hash.as_slice();
    let already = sqlx::query_scalar!(
        "SELECT 1 AS \"present!: i64\" FROM trust_edges \
         WHERE canonical_hash = ? LIMIT 1",
        canonical_slice,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if already.is_some() {
        return Ok(TrustEdgeProjection::Projected);
    }

    // §9.4 chain-fork: a sibling already applied with the same
    // `prior_edge_hash` (NULL-matches-NULL via the OR). Caller leaves
    // both bytes durable; neither row drives visibility.
    let prior_for_query: Option<Vec<u8>> = edge.prior_edge_hash.map(|h| h.to_vec());
    let fork = sqlx::query_scalar!(
        "SELECT 1 AS \"present!: i64\" FROM trust_edges \
         WHERE source_user = ? AND target_user = ? \
           AND ((prior_edge_hash IS NULL AND ? IS NULL) \
                OR prior_edge_hash = ?) \
           AND canonical_hash IS NOT NULL \
           AND canonical_hash != ? \
         LIMIT 1",
        source_id,
        target_id,
        prior_for_query,
        prior_for_query,
        canonical_slice,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if fork.is_some() {
        return Ok(TrustEdgeProjection::ChainFork);
    }

    // §9.1 chain-continuity: `prior_edge_hash = Some(h)` requires the
    // pair to already have a row with `canonical_hash = h`. If not,
    // we're an orphan.
    if let Some(prior) = edge.prior_edge_hash {
        let prior_slice: &[u8] = prior.as_slice();
        let prior_row = sqlx::query_scalar!(
            "SELECT 1 AS \"present!: i64\" FROM trust_edges \
             WHERE source_user = ? AND target_user = ? AND canonical_hash = ? \
             LIMIT 1",
            source_id,
            target_id,
            prior_slice,
        )
        .fetch_optional(&mut *tx)
        .await?;
        if prior_row.is_none() {
            return Ok(TrustEdgeProjection::Deferred);
        }
    }

    // Project. `created_at` schema type is TEXT ISO-8601; we route the
    // wire `u64` ms through `try_from` so a >i64::MAX value falls into
    // the now() fallback rather than silently wrapping into a bogus
    // 1970 row. The canonical CBOR retains the signed timestamp
    // verbatim.
    let created_at_iso = i64::try_from(edge.created_at)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());

    let trust_type = edge.stance.as_str();
    let id = Uuid::new_v4().to_string();
    let prior_for_insert: Option<Vec<u8>> = edge.prior_edge_hash.map(|h| h.to_vec());
    let canonical_for_insert: Vec<u8> = canonical_hash.to_vec();
    let signature_for_insert: Vec<u8> = signature.to_vec();
    sqlx::query!(
        "INSERT INTO trust_edges \
            (id, source_user, target_user, trust_type, created_at, signature, prior_edge_hash, canonical_hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        id,
        source_id,
        target_id,
        trust_type,
        created_at_iso,
        signature_for_insert,
        prior_for_insert,
        canonical_for_insert,
    )
    .execute(&mut *tx)
    .await?;

    // §9.1 on-receipt erasure: a neutral edge is the erasure authority
    // over the prior chain for this pair. The new neutral row itself
    // is excluded by canonical_hash.
    if matches!(edge.stance, TrustStance::Neutral) {
        erase_trust_edge_chain(&mut *tx, &source_id, &target_id, canonical_hash).await?;
    }

    Ok(TrustEdgeProjection::Projected)
}

/// Phase 9.5/9.6 sweep: project previously-stored signed objects whose
/// projection was deferred because a prerequisite (`users` stub, FK
/// target, chain predecessor) was missing at receive time. Called from
/// `content.rs::project_remote_profile` after a fresh profile-rev
/// hydrates the stub for `user_key`.
///
/// Phase 9.6 covers `trust-edge` orphans:
///
/// - Scans `signed_objects` for live trust-edges that are NOT yet in
///   `trust_edges.canonical_hash`.
/// - Filters to entries where the just-hydrated `user_key` is either
///   endpoint — projecting an unrelated edge wouldn't be wrong, but
///   it'd do speculative work the next per-pair sweep is going to
///   redo anyway.
/// - Re-runs the §9.4 chain-fork and §9.1 chain-continuity checks at
///   projection time. A stored edge that passed receive-time
///   validation might still need a second look: later edges from the
///   same pair could have arrived in the meantime and turned this
///   edge into a fork or moved the chain head.
/// - Loops to fixed point so an ordered chain (E1 → E2 → E3) projects
///   in one sweep call regardless of `signed_objects` row order.
///
/// **TODO (Phase 9.5/9.6 follow-up):** post-rev / thread-create
/// orphan projection still needs writing. The `content.rs` per-class
/// branches already store-only when prerequisites are missing; the
/// matching extension to this function will mirror the trust-edge
/// loop below. Until then, those orphans remain durable but
/// unprojected (reads see them only after a re-push or §9.3 backfill
/// triggers re-receive in a state where the stub already exists).
pub async fn sweep_pending_projections(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_key: &[u8; 32],
) -> Result<(), sqlx::Error> {
    // Snapshot the candidate set: live (payload-bearing) trust-edges
    // whose canonical_hash is not yet in `trust_edges`. Parse + filter
    // by `user_key` in app code — adding a payload-extracted index for
    // this would need a schema change and the candidate set is bounded
    // by recent deferrals in practice (steady-state pending count is
    // small relative to the total federated edge corpus).
    let rows = sqlx::query!(
        "SELECT canonical_hash AS \"canonical_hash!: Vec<u8>\", \
                payload        AS \"payload!: Vec<u8>\", \
                signature      AS \"signature!: Vec<u8>\" \
           FROM signed_objects \
          WHERE inner_class = 'trust-edge' \
            AND payload IS NOT NULL \
            AND canonical_hash NOT IN ( \
                SELECT canonical_hash FROM trust_edges \
                 WHERE canonical_hash IS NOT NULL)",
    )
    .fetch_all(&mut **tx)
    .await?;

    // Parse + filter once. Each retained candidate carries its own
    // `canonical_hash`, parsed `TrustEdge`, and signature so the
    // fixed-point loop below can call `try_project_trust_edge`
    // without re-touching `signed_objects`.
    let mut pending: Vec<(TrustEdge, [u8; 32], Vec<u8>)> = Vec::new();
    for row in rows {
        let Ok(parsed) = SignedPayload::parse(&row.payload) else {
            // Schema-invalid bytes shouldn't be sitting in
            // signed_objects (the §9.1 receive path rejects them
            // before storing), so a parse failure here is local
            // corruption. Skip and log; don't fail the sweep.
            tracing::warn!(
                canonical_hash = %crate::users::hex_lower(&row.canonical_hash),
                "stored signed_object tagged trust-edge but payload failed to parse",
            );
            continue;
        };
        let SignedPayload::TrustEdge(edge) = parsed else {
            tracing::warn!(
                canonical_hash = %crate::users::hex_lower(&row.canonical_hash),
                "stored signed_object tagged trust-edge but payload class mismatched",
            );
            continue;
        };
        if &edge.from_key != user_key && &edge.to_key != user_key {
            continue;
        }
        if row.canonical_hash.len() != 32 {
            tracing::error!(
                canonical_hash = %crate::users::hex_lower(&row.canonical_hash),
                "signed_objects.canonical_hash has unexpected length",
            );
            continue;
        }
        let mut canonical = [0u8; 32];
        canonical.copy_from_slice(&row.canonical_hash);
        pending.push((edge, canonical, row.signature));
    }

    // Fixed-point loop: a successful projection in one pass may
    // unblock a later edge in the same chain (E2 was Deferred while
    // E1 was still pending — once E1 lands, E2 satisfies
    // chain-continuity). `ChainFork` and `EndpointMissing` are
    // terminal for this sweep call; `Deferred` rolls into the next
    // pass. Loop terminates because each pass either projects at
    // least one edge (decreasing the candidate set) or makes no
    // progress (the break condition).
    loop {
        let mut progressed = false;
        let mut still_deferred: Vec<(TrustEdge, [u8; 32], Vec<u8>)> = Vec::new();
        for (edge, canonical, signature) in std::mem::take(&mut pending) {
            match try_project_trust_edge(tx, &edge, &canonical, &signature).await? {
                TrustEdgeProjection::Projected => {
                    progressed = true;
                }
                TrustEdgeProjection::Deferred => {
                    still_deferred.push((edge, canonical, signature));
                }
                // EndpointMissing: the *other* endpoint still has no
                // stub. A future sweep keyed on that endpoint will
                // catch this row. Drop from this pass.
                // ChainFork: §9.4 evidence-only, bytes stay durable
                // in signed_objects but never project. Drop.
                TrustEdgeProjection::EndpointMissing | TrustEdgeProjection::ChainFork => {}
            }
        }
        pending = still_deferred;
        if !progressed {
            break;
        }
    }

    Ok(())
}

/// Load and parse a `move` from `signed_objects`, returning
/// `to_instance_key`. `None` on row-absent / payload-NULL (erased) /
/// parse failure / wrong class — callers fall back to a conservative
/// default rather than fail the receive.
async fn load_move_to_key<'e, E>(
    executor: E,
    canonical_hash: &[u8],
) -> Result<Option<[u8; 32]>, sqlx::Error>
where
    E: sqlx::SqliteExecutor<'e>,
{
    let mv = match fetch_move(executor, canonical_hash).await? {
        Some(m) => m,
        None => return Ok(None),
    };
    Ok(Some(mv.to_instance_key))
}

/// Sibling of [`load_move_to_key`] returning `from_instance_key`.
async fn load_move_from_key<'e, E>(
    executor: E,
    canonical_hash: &[u8],
) -> Result<Option<[u8; 32]>, sqlx::Error>
where
    E: sqlx::SqliteExecutor<'e>,
{
    let mv = match fetch_move(executor, canonical_hash).await? {
        Some(m) => m,
        None => return Ok(None),
    };
    Ok(Some(mv.from_instance_key))
}

/// Fetch + parse a `move` signed object by canonical_hash.
async fn fetch_move<'e, E>(
    executor: E,
    canonical_hash: &[u8],
) -> Result<Option<crate::signed::Move>, sqlx::Error>
where
    E: sqlx::SqliteExecutor<'e>,
{
    let row = sqlx::query!(
        "SELECT payload AS \"payload?: Vec<u8>\" \
           FROM signed_objects \
          WHERE canonical_hash = ? AND inner_class = 'move'",
        canonical_hash,
    )
    .fetch_optional(executor)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let Some(payload) = row.payload else {
        // Erased move (payload NULLed by §3.1 deactivate cascade).
        // We retain the hash for chain walks but can't extract the
        // home_instance pin; caller falls back to arrived_from.
        return Ok(None);
    };

    match SignedPayload::parse(&payload) {
        Ok(SignedPayload::Move(mv)) => {
            // Defence-in-depth: the canonical_hash we fetched by SHOULD
            // be SHA-256(payload); if it isn't, we've got a corrupted
            // row in signed_objects and shouldn't trust the parsed
            // fields. Log and return None so the caller falls back.
            let mut hasher = Sha256::new();
            hasher.update(&payload);
            let computed: [u8; 32] = hasher.finalize().into();
            if computed.as_slice() != canonical_hash {
                tracing::error!(
                    canonical_hash = ?canonical_hash,
                    "signed_objects.payload hash mismatch",
                );
                return Ok(None);
            }
            Ok(Some(mv))
        }
        Ok(_) => {
            // Wrong class — schema invariant says inner_class='move'
            // implies the payload parses as Move. A mismatch is local
            // corruption.
            tracing::error!(
                canonical_hash = ?canonical_hash,
                "signed_objects row tagged inner_class='move' but payload parses as a \
                 different class",
            );
            Ok(None)
        }
        Err(e) => {
            tracing::error!(
                canonical_hash = ?canonical_hash,
                error = ?e,
                "failed to parse move payload from signed_objects",
            );
            Ok(None)
        }
    }
}
