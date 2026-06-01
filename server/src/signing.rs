use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::Digest;
use sqlx::{SqliteExecutor, SqlitePool};
use uuid::Uuid;

use crate::federation::instance_key::InstanceKey;
use crate::signed::{
    self, AdminRemoval, AttachmentRef, Deactivation, GenesisAttestation, Move, PostRevision,
    ProfileRevision, Report, ReportReason, Retraction, SignedPayload, ThreadCreate, ThreadStatus,
    ThreadStatusKind, TrustEdge, TrustStance, UserStatus, UserStatusKind,
};

/// Output of signing a class-specific payload.
pub struct SigningOutput {
    /// Canonical CBOR bytes that were signed. These go into
    /// `signed_objects.payload` verbatim (see `store_signed_object`).
    pub payload: Vec<u8>,
    /// 64-byte Ed25519 signature over the canonical CBOR payload.
    pub signature: Vec<u8>,
    /// 32-byte Ed25519 public key of the active signing key.
    pub public_key: [u8; 32],
    /// SHA-256 of the canonical payload bytes that were signed.
    ///
    /// For trust-edges this is persisted alongside the signature in
    /// `trust_edges.canonical_hash` so the next mutation can chain
    /// to it via `prior_edge_hash` without reconstructing the prior
    /// row's canonical CBOR (which would re-bind whichever
    /// `signing_keys` row is currently `active = 1` and silently
    /// fork the chain across key rotations). For other classes the
    /// field is informational and can be ignored by callers.
    pub canonical_hash: [u8; 32],
}

/// Generate a fresh Ed25519 keypair without touching the database.
///
/// The verifying half is the canonical federation identity that the
/// caller must persist into `users.public_key`. The signing half is
/// stored separately via [`store_signing_key`] inside the same
/// transaction that creates the user row.
///
/// Returned as a value (not a `Result`) because key generation is
/// infallible — `rand::rngs::OsRng` panics on RNG failure, which is
/// the correct response for a process that can no longer mint
/// identities safely.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Persist a pre-generated [`SigningKey`] into the `signing_keys`
/// table after verifying the identity-binding invariant.
///
/// The helper SELECTs `users.public_key` for `user_id` and compares
/// it against the verifying half of `signing_key`. The pair
/// `(users.public_key, signing_keys.private_key)` is the load-bearing
/// federation identity: if these two ever disagree, every signed
/// payload the user mints will fail external verification (peers
/// re-verify against the public key carried in the canonical bytes,
/// which the signer pulls from `users`). Catching the mismatch here
/// turns a programming bug into a 500 instead of letting it persist
/// silently and corrupt the user's chain.
///
/// Errors:
/// - [`SignError::NoUser`] — no `users` row for `user_id` (caller
///   forgot to INSERT users first, or the user_id is bogus).
/// - [`SignError::IdentityMismatch`] — `users.public_key` doesn't
///   match `signing_key.verifying_key()`. Caller mixed up keys.
/// - [`SignError::Db`] — SQL error on either query.
///
/// The federation-identity column is write-once: a second invocation
/// for the same user_id with the *same* key would create a second
/// `signing_keys` row (with the per-user `active = 1` partial-unique
/// index disallowing two active keys, so the INSERT fails) but would
/// never silently rebind `users.public_key` — that can only happen
/// via an explicit, audited key-rotation path (signed rotation
/// object), not by re-calling this helper.
///
/// `signing_keys` is a pure private-key vault: the public half lives
/// only on `users.public_key`. To recover the verifying key from a
/// stored row, derive it from the private bytes via
/// `SigningKey::verifying_key()`.
///
/// Takes `&mut SqliteConnection` so the SELECT and INSERT run on the
/// same connection — callers pass `&mut *tx` from the surrounding
/// signup transaction so the verification observes the just-inserted
/// `users` row.
///
/// Returns the row ID of the new `signing_keys` row.
pub async fn store_signing_key(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    signing_key: &SigningKey,
) -> Result<String, SignError> {
    let derived_pub = signing_key.verifying_key().to_bytes();

    let user_row = sqlx::query!("SELECT public_key FROM users WHERE id = ?", user_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(SignError::Db)?
        .ok_or(SignError::NoUser)?;

    if user_row.public_key.as_slice() != derived_pub.as_slice() {
        tracing::error!(
            user_id = %user_id,
            "store_signing_key: users.public_key does not match signing_key.verifying_key()"
        );
        return Err(SignError::IdentityMismatch);
    }

    let id = Uuid::new_v4().to_string();
    let private_bytes = signing_key.to_bytes();
    let private_key: &[u8] = private_bytes.as_slice();
    sqlx::query!(
        "INSERT INTO signing_keys (id, user_id, private_key) VALUES (?, ?, ?)",
        id,
        user_id,
        private_key,
    )
    .execute(&mut *conn)
    .await
    .map_err(SignError::Db)?;
    Ok(id)
}

/// Persist a signed object's canonical bytes into `signed_objects`.
///
/// `INSERT OR IGNORE` is correct here: the table is keyed on
/// `canonical_hash`, so re-storing the same payload (received twice
/// from federation gossip, or backfilled twice during recovery) is a
/// no-op rather than a constraint violation.
///
/// Callers must pass the *exact* bytes that were signed (typically
/// `SigningOutput::payload`) — never re-encode here. The canonical-form
/// invariant is that the bytes are stored verbatim and a peer that
/// re-verifies the signature against `payload + signature` succeeds.
///
/// **`inner_class` and `canonical_hash` are co-bound.** The canonical
/// CBOR payload includes a `t = "<class>"` field, so the same bytes
/// can only have one valid class — the SHA-256 of those bytes is
/// what we key on. A caller passing the wrong `inner_class` for given
/// bytes is a programming bug whose `INSERT OR IGNORE` no-op is the
/// *symptom*, not the *cause*: the row already exists with the
/// correct class. (A new payload differing only in the wire class
/// hashes differently and would not collide.)
pub async fn store_signed_object<'e, E: SqliteExecutor<'e>>(
    executor: E,
    inner_class: &str,
    payload: &[u8],
    signature: &[u8],
    canonical_hash: &[u8; 32],
) -> Result<(), sqlx::Error> {
    let canonical_hash_slice: &[u8] = canonical_hash.as_slice();
    sqlx::query!(
        "INSERT OR IGNORE INTO signed_objects (canonical_hash, inner_class, payload, signature) \
         VALUES (?, ?, ?, ?)",
        canonical_hash_slice,
        inner_class,
        payload,
        signature,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Erase the canonical payloads of every signed `post-rev` belonging to a post.
///
/// Implements the "payload erasure" effect of a `retract` (and the
/// retract-side of `deactivate`). The row stays in `signed_objects` so
/// hash-chain walks across the erased predecessor still work; only the
/// `payload` bytes are NULLed and `erased_at` stamped.
///
/// `post_revisions.canonical_hash` is NOT NULL by schema, so the
/// subquery is a clean join. The `payload IS NOT NULL` guard makes the
/// helper idempotent across replay.
///
/// `authority_hash` records the canonical_hash of the signed object
/// (retract / admin-rm / deactivate) that authorised the erasure, so
/// the §10.5.3 "410 Gone" backfill path can return it without scanning.
/// Pass `None` when no local authority is known (e.g. a self-delete
/// path without an active signing key) — `signed_objects.erased_by` is
/// nullable for this case.
///
/// No `inner_class` narrowing: `signed_objects.canonical_hash` is the
/// primary key, and each canonical_hash uniquely identifies one row
/// across all classes (the class is bound into the canonical bytes —
/// see `store_signed_object`).
pub async fn erase_post_rev_payloads<'e, E: SqliteExecutor<'e>>(
    executor: E,
    post_id: &str,
    authority_hash: Option<&[u8; 32]>,
) -> Result<(), sqlx::Error> {
    let authority: Option<&[u8]> = authority_hash.map(|h| h.as_slice());
    sqlx::query!(
        "UPDATE signed_objects \
         SET payload = NULL, \
             erased_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
             erased_by = COALESCE(erased_by, ?) \
         WHERE payload IS NOT NULL \
           AND canonical_hash IN ( \
               SELECT canonical_hash FROM post_revisions WHERE post_id = ? \
           )",
        authority,
        post_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Erase the canonical payloads of every prior trust-edge between a pair.
///
/// Implements the "payload erasure" effect of a `neutral`
/// trust-edge. The newly written neutral row is identified by
/// `except_canonical_hash` and excluded so the chain-terminating
/// erasure-authority object is itself retained verbatim.
///
/// Chain continuity is preserved: every erased row keeps its
/// `canonical_hash` (the chain walk operates on hashes, not payload
/// bytes).
///
/// `trust_edges` is the append-only signed log, so the subquery
/// enumerates every historical mutation for the pair — not just the
/// current one. `current_trust_edges` is a separate view; we
/// deliberately query the table here.
///
/// No `inner_class` narrowing: `canonical_hash` is the primary key
/// on `signed_objects` (one row per hash across all classes), and
/// the class is bound into the canonical bytes — see
/// `store_signed_object`.
pub async fn erase_trust_edge_chain<'e, E: SqliteExecutor<'e>>(
    executor: E,
    source_user_id: &str,
    target_user_id: &str,
    except_canonical_hash: &[u8; 32],
) -> Result<(), sqlx::Error> {
    // The exception hash *is* the erasure authority (the neutral edge
    // itself), so we also stamp `erased_by` on every payload-NULLed row
    // for the §10.5.3 410-Gone lookup.
    let except: &[u8] = except_canonical_hash.as_slice();
    sqlx::query!(
        "UPDATE signed_objects \
         SET payload = NULL, \
             erased_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
             erased_by = COALESCE(erased_by, ?) \
         WHERE payload IS NOT NULL \
           AND canonical_hash != ? \
           AND canonical_hash IN ( \
               SELECT canonical_hash FROM trust_edges \
               WHERE source_user = ? AND target_user = ? \
                 AND canonical_hash IS NOT NULL \
           )",
        except,
        except,
        source_user_id,
        target_user_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Erase the canonical payloads of every trust-edge the user signed.
///
/// Used by account deletion / deactivation (`privacy::soft_delete_user`).
/// The neutral-trust-edge code path normally narrows erasure to one
/// pair; here we erase across every pair the user authored. Caller is
/// expected to invoke this *before* deleting the `trust_edges` rows —
/// once the projection rows are gone the `canonical_hash IN (SELECT ...)`
/// subquery returns nothing.
///
/// `trust_edges` is the append-only signed log, so this picks up every
/// historical mutation the user authored across every counterparty —
/// not just their currently-active outbound edges. See
/// `erase_trust_edge_chain` for the same invariant in a per-pair context.
///
/// No `inner_class` narrowing — `canonical_hash` is the PK on
/// `signed_objects` and uniquely identifies one row across all classes.
pub async fn erase_user_trust_edge_payloads<'e, E: SqliteExecutor<'e>>(
    executor: E,
    user_id: &str,
    authority_hash: Option<&[u8; 32]>,
) -> Result<(), sqlx::Error> {
    let authority: Option<&[u8]> = authority_hash.map(|h| h.as_slice());
    sqlx::query!(
        "UPDATE signed_objects \
         SET payload = NULL, \
             erased_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
             erased_by = COALESCE(erased_by, ?) \
         WHERE payload IS NOT NULL \
           AND canonical_hash IN ( \
               SELECT canonical_hash FROM trust_edges \
               WHERE source_user = ? AND canonical_hash IS NOT NULL \
           )",
        authority,
        user_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Erase the canonical payloads of every profile revision the user signed.
///
/// Used by account deletion (`privacy::soft_delete_user`). Direct
/// analog of [`erase_user_trust_edge_payloads`]: NULL the
/// `signed_objects.payload` bytes for every signed `profile` row
/// the user authored, *before* the projection rows are dropped. Once
/// the projection rows are gone the `canonical_hash IN (SELECT ...)`
/// subquery returns nothing.
///
/// No `inner_class` narrowing — `canonical_hash` is the PK on
/// `signed_objects` and uniquely identifies one row across all classes.
pub async fn erase_user_profile_revision_payloads<'e, E: SqliteExecutor<'e>>(
    executor: E,
    user_id: &str,
    authority_hash: Option<&[u8; 32]>,
) -> Result<(), sqlx::Error> {
    let authority: Option<&[u8]> = authority_hash.map(|h| h.as_slice());
    sqlx::query!(
        "UPDATE signed_objects \
         SET payload = NULL, \
             erased_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
             erased_by = COALESCE(erased_by, ?) \
         WHERE payload IS NOT NULL \
           AND canonical_hash IN ( \
               SELECT canonical_hash FROM profile_revisions \
               WHERE user_id = ? \
           )",
        authority,
        user_id,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Load the user's active signing key from the `signing_keys` table.
///
/// Returns the dalek `SigningKey`. The public key is derived from the
/// `SigningKey` itself (not read from the row) so the signed payload's
/// `author` field is by-construction coherent with what the signature
/// actually verifies under.
///
/// Generic over `SqliteExecutor` so callers can run this inside an
/// outer transaction (`&mut *tx`) when key-load + sign + insert must
/// be atomic with respect to other writers.
pub async fn load_active_signing_key<'e, E: SqliteExecutor<'e>>(
    db: E,
    user_id: &str,
) -> Result<SigningKey, SignError> {
    let row = sqlx::query!(
        "SELECT private_key FROM signing_keys WHERE user_id = ? AND active = 1",
        user_id,
    )
    .fetch_optional(db)
    .await
    .map_err(SignError::Db)?
    .ok_or(SignError::NoKey)?;

    let private_bytes: [u8; 32] = row.private_key.try_into().map_err(|v: Vec<u8>| {
        tracing::error!(
            user_id = %user_id,
            length = v.len(),
            "signing key has invalid private-key length (expected 32 bytes)"
        );
        SignError::InvalidKey
    })?;

    Ok(SigningKey::from_bytes(&private_bytes))
}

/// Sign a `post-rev` canonical payload with an already-loaded key.
///
/// Builds a [`PostRevision`] with the key's public bytes as `author`,
/// encodes it to canonical CBOR per [signed-payload-format.md] §4.1,
/// and signs the resulting bytes. The caller is responsible for
/// ensuring `created_at_ms` is the timestamp it will persist — the
/// bound bytes include this value and re-verification per §6 must
/// reproduce them.
#[allow(clippy::too_many_arguments)]
pub fn sign_post_revision_with_key(
    key: &SigningKey,
    post_id: &Uuid,
    thread_id: &Uuid,
    parent_id: Option<&Uuid>,
    revision: u64,
    body: &str,
    created_at_ms: u64,
    attachments: Vec<AttachmentRef>,
) -> SigningOutput {
    let public_key = *key.verifying_key().as_bytes();
    let payload = PostRevision {
        post_id: *post_id.as_bytes(),
        author: public_key,
        thread_id: *thread_id.as_bytes(),
        parent_id: parent_id.map(|u| *u.as_bytes()),
        revision,
        body: body.to_string(),
        created_at: created_at_ms,
        attachments,
    };
    let payload_bytes = SignedPayload::PostRevision(payload).encode();
    let signature = key.sign(&payload_bytes).to_bytes().to_vec();
    let canonical_hash: [u8; 32] = sha2::Sha256::digest(&payload_bytes).into();
    SigningOutput {
        payload: payload_bytes,
        signature,
        public_key,
        canonical_hash,
    }
}

/// Sign a `retract` canonical payload with an already-loaded key.
///
/// See [signed-payload-format.md] §4.2. `created_at_ms` must match the
/// retraction timestamp the caller persists.
pub fn sign_retraction_with_key(
    key: &SigningKey,
    post_id: &Uuid,
    created_at_ms: u64,
) -> SigningOutput {
    let public_key = *key.verifying_key().as_bytes();
    let payload = Retraction {
        post_id: *post_id.as_bytes(),
        author: public_key,
        created_at: created_at_ms,
    };
    let payload_bytes = SignedPayload::Retraction(payload).encode();
    let signature = key.sign(&payload_bytes).to_bytes().to_vec();
    let canonical_hash: [u8; 32] = sha2::Sha256::digest(&payload_bytes).into();
    SigningOutput {
        payload: payload_bytes,
        signature,
        public_key,
        canonical_hash,
    }
}

/// Sign a `trust-edge` canonical payload with an already-loaded key.
///
/// See [signed-payload-format.md] §4.3. The signer (`key`) is bound
/// as `from_key` in the payload — `to_key` is the target user's
/// Ed25519 public key, supplied by the caller. `created_at_ms` and
/// `prior_edge_hash` must match the values the caller persists; the
/// canonical CBOR encoding binds both.
///
/// The caller is responsible for computing `prior_edge_hash` (SHA-256
/// of the canonical bytes of the most recent prior signed object for
/// the same `(from_key, to_key)` pair, or `None` for the first
/// mutation of the pair).
pub fn sign_trust_edge_with_key(
    key: &SigningKey,
    to_key: &[u8; 32],
    stance: TrustStance,
    created_at_ms: u64,
    prior_edge_hash: Option<[u8; 32]>,
) -> SigningOutput {
    let public_key = *key.verifying_key().as_bytes();
    let payload = TrustEdge {
        from_key: public_key,
        to_key: *to_key,
        stance,
        created_at: created_at_ms,
        prior_edge_hash,
    };
    let payload_bytes = SignedPayload::TrustEdge(payload).encode();
    let signature = key.sign(&payload_bytes).to_bytes().to_vec();
    let canonical_hash: [u8; 32] = sha2::Sha256::digest(&payload_bytes).into();
    SigningOutput {
        payload: payload_bytes,
        signature,
        public_key,
        canonical_hash,
    }
}

/// Sign a `post-rev` canonical payload for the given user.
///
/// DB-fetching wrapper around [`sign_post_revision_with_key`] —
/// convenience for handler call sites that don't already hold the
/// user's `SigningKey`.
#[allow(clippy::too_many_arguments)]
pub async fn sign_post_revision(
    db: &SqlitePool,
    user_id: &str,
    post_id: &Uuid,
    thread_id: &Uuid,
    parent_id: Option<&Uuid>,
    revision: u64,
    body: &str,
    created_at_ms: u64,
    attachments: Vec<AttachmentRef>,
) -> Result<SigningOutput, SignError> {
    let key = load_active_signing_key(db, user_id).await?;
    Ok(sign_post_revision_with_key(
        &key,
        post_id,
        thread_id,
        parent_id,
        revision,
        body,
        created_at_ms,
        attachments,
    ))
}

/// Sign a `trust-edge` canonical payload for the given source user.
///
/// DB-fetching wrapper around [`sign_trust_edge_with_key`] — looks up
/// the source's private signing key (from `signing_keys`) and the
/// target's identity pubkey (from `users.public_key`, the canonical
/// identity column since Phase C), then signs.
///
/// Errors:
/// - [`SignError::NoKey`] — source user has no active row in
///   `signing_keys`. `privacy::soft_delete_user` flips the source's
///   `active` to 0, so this is the source-side soft-delete defense.
/// - [`SignError::NoUser`] — no `users` row for `target_user_id`.
///   (`users.public_key` is NOT NULL post-Phase-C, so the only way
///   this can fire is the row being absent entirely, not the column
///   being NULL.)
/// - [`SignError::TargetDeleted`] — target user is soft-deleted
///   (`users.deleted_at IS NOT NULL`). This is the target-side
///   counterpart to the source-side `active = 0` defense.
///   Handlers (`set_trust_edge`, `delete_trust_edge`) are responsible
///   for rejecting deleted targets at the request layer (a deleted
///   user's display_name is anonymized, so display_name lookups
///   already 404); this check is defense-in-depth against a path that
///   skips display_name resolution.
///
/// Takes a `&mut SqliteConnection` (rather than a pool) so callers
/// can run the key lookups inside an outer transaction together
/// with [`compute_prior_edge_hash`] and the eventual INSERT — that
/// way two concurrent mutations on the same `(source, target)` pair
/// can't both read the same prior hash and fork the chain. From a
/// `sqlx::Transaction<'_, Sqlite>` callers pass `&mut *tx`.
pub async fn sign_trust_edge(
    conn: &mut sqlx::SqliteConnection,
    source_user_id: &str,
    target_user_id: &str,
    stance: TrustStance,
    created_at_ms: u64,
    prior_edge_hash: Option<[u8; 32]>,
) -> Result<SigningOutput, SignError> {
    let key = load_active_signing_key(&mut *conn, source_user_id).await?;
    let target_row = sqlx::query!(
        "SELECT public_key, deleted_at FROM users WHERE id = ?",
        target_user_id,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(SignError::Db)?
    .ok_or(SignError::NoUser)?;
    if target_row.deleted_at.is_some() {
        return Err(SignError::TargetDeleted);
    }
    let to_key: [u8; 32] = target_row.public_key.try_into().map_err(|v: Vec<u8>| {
        tracing::error!(
            user_id = %target_user_id,
            length = v.len(),
            "target identity pubkey has invalid length (expected 32 bytes)"
        );
        SignError::InvalidKey
    })?;
    Ok(sign_trust_edge_with_key(
        &key,
        &to_key,
        stance,
        created_at_ms,
        prior_edge_hash,
    ))
}

/// Look up the `prior_edge_hash` for a new trust-edge mutation.
///
/// Returns the canonical hash of the most recent prior signed object
/// for the `(source, target)` pair — that's the value the caller
/// puts in the new mutation's `prior_edge_hash` field (and the bytes
/// signed under it). Returns `None` when there is no signed prior,
/// i.e., the new mutation is the chain head for the pair.
///
/// All stances participate as priors, including `neutral` tombstones
/// (chain continuity must cover tombstones — see
/// [signed-payload-format.md] §4.3).
///
/// **Pure lookup.** Each signed row persists its canonical hash in
/// `trust_edges.canonical_hash` at insert time, so this function
/// never reconstructs canonical bytes and never reads
/// `signing_keys`. That's what immunises the chain against key
/// rotation: the hash a peer signed under is what we hand back here,
/// byte-for-byte, regardless of any subsequent key changes.
///
/// **Ties.** Two prior rows at the same `(created_at, id)` are
/// resolved by bytewise comparison of `canonical_hash`, larger wins
/// (spec §4.3 — the comparison is over the hash rather than the
/// underlying payload bytes, but both yield a stable total order
/// over distinct signed objects).
///
/// **Legacy unsigned priors.** Rows predating the signing migration
/// have `canonical_hash IS NULL` and are excluded from the prior
/// lookup. The chain genuinely begins at the first signed mutation
/// for each pair — the unsigned past has no representable hash, and
/// federation peers wouldn't have those bytes either. Accepted
/// limitation, documented on the migration.
/// Pick the bytewise-maximum 32-byte canonical hash from a set of
/// candidate rows, returning `None` if the iterator is empty.
///
/// Shared tie-break for the `compute_prior_*_hash` family: each caller
/// pulls every row tied at the latest `created_at` for its chain key
/// and feeds the `(row_id, canonical_hash_bytes)` pairs in here.
/// `table` is the originating table name (e.g. `"trust_edges"`,
/// `"profile_revisions"`) and only appears in the error-path tracing
/// event when a `canonical_hash` column violates the 32-byte
/// invariant — the application enforces it on insert, so this branch
/// fires only if someone bypassed the writer.
fn pick_max_canonical_hash<I>(rows: I, table: &'static str) -> Result<Option<[u8; 32]>, SignError>
where
    I: IntoIterator<Item = (String, Vec<u8>)>,
{
    let mut best: Option<[u8; 32]> = None;
    for (row_id, hash_bytes) in rows {
        let hash: [u8; 32] = hash_bytes.as_slice().try_into().map_err(|_| {
            tracing::error!(
                table = %table,
                row_id = %row_id,
                len = hash_bytes.len(),
                "canonical_hash is not 32 bytes"
            );
            SignError::InvalidData
        })?;
        match best {
            None => best = Some(hash),
            Some(current) if hash > current => best = Some(hash),
            _ => {}
        }
    }
    Ok(best)
}

pub async fn compute_prior_edge_hash<'e, E: SqliteExecutor<'e>>(
    db: E,
    source_user_id: &str,
    target_user_id: &str,
) -> Result<Option<[u8; 32]>, SignError> {
    // Pull every signed row for this pair tied at the latest
    // `created_at` so the bytewise tiebreaker can run on ties. The
    // common case is one row; ties only occur when two mutations
    // happen to truncate to the same second-grain timestamp.
    let rows = sqlx::query!(
        r#"SELECT
              te.id AS "id!: String",
              te.canonical_hash AS "canonical_hash!: Vec<u8>"
           FROM trust_edges te
           WHERE te.source_user = ?
             AND te.target_user = ?
             AND te.canonical_hash IS NOT NULL
             AND te.created_at = (
                 SELECT MAX(created_at) FROM trust_edges
                 WHERE source_user = ?
                   AND target_user = ?
                   AND canonical_hash IS NOT NULL
             )"#,
        source_user_id,
        target_user_id,
        source_user_id,
        target_user_id,
    )
    .fetch_all(db)
    .await
    .map_err(SignError::Db)?;

    pick_max_canonical_hash(
        rows.into_iter().map(|r| (r.id, r.canonical_hash)),
        "trust_edges",
    )
}

/// Sign a `profile` canonical payload with an already-loaded key.
///
/// The signer (`key`) is bound as `user` in the payload.
/// `created_at_ms` and `prior_profile_hash` must match the values
/// the caller persists; the canonical CBOR encoding binds both.
///
/// The caller is responsible for computing `prior_profile_hash`
/// (SHA-256 of the canonical bytes of the most recent prior signed
/// `profile` for the user, or `None` for the first revision).
pub fn sign_profile_revision_with_key(
    key: &SigningKey,
    display_name: &str,
    bio: &str,
    avatar_attachment_hash: Option<[u8; 32]>,
    created_at_ms: u64,
    prior_profile_hash: Option<[u8; 32]>,
) -> SigningOutput {
    let public_key = *key.verifying_key().as_bytes();
    let payload = ProfileRevision {
        user: public_key,
        display_name: display_name.to_string(),
        bio: bio.to_string(),
        avatar_attachment_hash,
        created_at: created_at_ms,
        prior_profile_hash,
    };
    let payload_bytes = SignedPayload::ProfileRevision(payload).encode();
    let signature = key.sign(&payload_bytes).to_bytes().to_vec();
    let canonical_hash: [u8; 32] = sha2::Sha256::digest(&payload_bytes).into();
    SigningOutput {
        payload: payload_bytes,
        signature,
        public_key,
        canonical_hash,
    }
}

/// Sign a `profile` canonical payload for the given user.
///
/// DB-fetching wrapper around [`sign_profile_revision_with_key`].
/// Looks up the user's active signing key and signs in one step;
/// callers that need to chain via `prior_profile_hash` should
/// invoke [`compute_prior_profile_hash`] before calling this.
///
/// Errors:
/// - [`SignError::NoKey`] — user has no active row in `signing_keys`
///   (soft-deleted or legacy unsigned user).
pub async fn sign_profile_revision<'e, E: SqliteExecutor<'e>>(
    db: E,
    user_id: &str,
    display_name: &str,
    bio: &str,
    avatar_attachment_hash: Option<[u8; 32]>,
    created_at_ms: u64,
    prior_profile_hash: Option<[u8; 32]>,
) -> Result<SigningOutput, SignError> {
    let key = load_active_signing_key(db, user_id).await?;
    Ok(sign_profile_revision_with_key(
        &key,
        display_name,
        bio,
        avatar_attachment_hash,
        created_at_ms,
        prior_profile_hash,
    ))
}

/// Look up the `prior_profile_hash` for a new profile revision.
///
/// Direct analog of [`compute_prior_edge_hash`] (see that function
/// for the rationale on hash persistence vs. byte reconstruction,
/// and tie-breaking by bytewise canonical_hash comparison).
///
/// Returns the canonical hash of the most recent prior signed
/// profile for `user_id`. Returns `None` when there is no prior
/// (the new revision is the user's first).
pub async fn compute_prior_profile_hash<'e, E: SqliteExecutor<'e>>(
    db: E,
    user_id: &str,
) -> Result<Option<[u8; 32]>, SignError> {
    let rows = sqlx::query!(
        r#"SELECT
              id AS "id!: String",
              canonical_hash AS "canonical_hash!: Vec<u8>"
           FROM profile_revisions
           WHERE user_id = ?
             AND created_at = (
                 SELECT MAX(created_at) FROM profile_revisions
                 WHERE user_id = ?
             )"#,
        user_id,
        user_id,
    )
    .fetch_all(db)
    .await
    .map_err(SignError::Db)?;

    pick_max_canonical_hash(
        rows.into_iter().map(|r| (r.id, r.canonical_hash)),
        "profile_revisions",
    )
}

/// Mint a self-signed *genesis* `profile` revision for a freshly
/// created local account.
///
/// `profile` is the only signed object that carries a user's
/// `display_name`, and it is the object the federation stub-hydration
/// path needs to turn a remote stub into a named, projectable user
/// (§11.9.5 bootstrap recovery). Yet `bio` is the only field a user can
/// edit, so before this helper existed an account that never touched
/// its bio had no `profile` revision at all — leaving peers with
/// nothing to hydrate its stub from, so an inbound trust edge naming it
/// stayed `EndpointMissing` and never projected. Minting an empty-bio
/// genesis at account birth guarantees every locally-born identity is
/// federatable from the moment it exists.
///
/// Writes, inside the caller's transaction:
/// - signs an empty-bio `profile` payload (absent bio projected onto
///   `""` so the canonical bytes match a later explicit-empty edit —
///   see [`crate::users::update_bio`] for that unification rationale),
/// - INSERTs the `profile_revisions` row,
/// - dual-writes the canonical bytes into `signed_objects`.
///
/// Returns the [`SigningOutput`] so the caller can fan the revision out
/// post-commit (`ForwardingClass::Authored`, routing key = user pubkey).
///
/// MUST be called after [`store_signing_key`] within the same
/// transaction — [`sign_profile_revision`] loads the user's active
/// signing key from `signing_keys`.
pub async fn mint_genesis_profile_revision(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    display_name: &str,
    created_at_ms: u64,
) -> Result<SigningOutput, crate::error::AppError> {
    let bio_for_payload = "";

    // Robust against being called when prior revisions somehow exist:
    // chains onto the latest rather than forking a second root. At true
    // account birth there are none, so this returns `None` (genesis).
    let prior_hash = compute_prior_profile_hash(&mut *conn, user_id).await?;

    let signed = sign_profile_revision(
        &mut *conn,
        user_id,
        display_name,
        bio_for_payload,
        None,
        created_at_ms,
        prior_hash,
    )
    .await?;

    let prior_hash_db: Option<Vec<u8>> = prior_hash.map(|h| h.to_vec());
    let canonical_hash_db: Vec<u8> = signed.canonical_hash.to_vec();
    let created_at_ms_db = i64::try_from(created_at_ms).map_err(|_| {
        tracing::error!(
            created_at_ms,
            "genesis profile revision created_at_ms does not fit in i64"
        );
        crate::error::AppError::code(crate::error::ErrorCode::Internal)
    })?;

    let id = Uuid::new_v4().to_string();
    sqlx::query!(
        "INSERT INTO profile_revisions \
            (id, user_id, display_name, bio, avatar_attachment_hash, created_at, \
             signature, prior_profile_hash, canonical_hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        id,
        user_id,
        display_name,
        bio_for_payload,
        None::<Vec<u8>>,
        created_at_ms_db,
        signed.signature,
        prior_hash_db,
        canonical_hash_db,
    )
    .execute(&mut *conn)
    .await?;

    store_signed_object(
        &mut *conn,
        "profile",
        &signed.payload,
        &signed.signature,
        &signed.canonical_hash,
    )
    .await?;

    Ok(signed)
}

/// Sign a `retract` canonical payload for the given user.
///
/// DB-fetching wrapper around [`sign_retraction_with_key`].
pub async fn sign_retraction(
    db: &SqlitePool,
    user_id: &str,
    post_id: &Uuid,
    created_at_ms: u64,
) -> Result<SigningOutput, SignError> {
    let key = load_active_signing_key(db, user_id).await?;
    Ok(sign_retraction_with_key(&key, post_id, created_at_ms))
}

/// Sign a `thread-create` canonical payload with an already-loaded key.
///
/// See [signed-payload-format.md] §5.9 and
/// [federation-protocol.md] §10. The signer (`key`) is bound as
/// `author` in the payload. `room_slug`, `title`, `link_url`, and
/// `op_post_id` must match the values the caller persists; the
/// canonical CBOR encoding binds all of them.
pub fn sign_thread_create_with_key(
    key: &SigningKey,
    thread_id: &Uuid,
    room_slug: &str,
    title: &str,
    link_url: Option<&str>,
    op_post_id: &Uuid,
    created_at_ms: u64,
) -> SigningOutput {
    let public_key = *key.verifying_key().as_bytes();
    let payload = ThreadCreate {
        thread_id: *thread_id.as_bytes(),
        author: public_key,
        room_slug: room_slug.to_string(),
        title: title.to_string(),
        link_url: link_url.map(str::to_string),
        op_post_id: *op_post_id.as_bytes(),
        created_at: created_at_ms,
    };
    let payload_bytes = SignedPayload::ThreadCreate(payload).encode();
    let signature = key.sign(&payload_bytes).to_bytes().to_vec();
    let canonical_hash: [u8; 32] = sha2::Sha256::digest(&payload_bytes).into();
    SigningOutput {
        payload: payload_bytes,
        signature,
        public_key,
        canonical_hash,
    }
}

/// Sign an `admin-rm` canonical payload with the instance signing key.
///
/// See [signed-payload-format.md] §5.2 and
/// [federation-protocol.md] §10.4. Admin removals are *instance-signed*
/// (not user-signed): the authority is the operator of the signing
/// instance, expressed via the instance's long-lived signing key.
///
/// Takes `&InstanceKey` rather than the raw `&SigningKey` so the
/// instance-key security boundary is not widened. [`InstanceKey::sign`]
/// is the only privileged call needed to mint the signature.
///
/// `signing_instance` MUST equal the bare canonical domain whose
/// signing key signs this object — the receiver re-derives it from
/// `peers.instance_domain` and refuses on mismatch.
pub fn sign_admin_removal_with_instance_key(
    key: &InstanceKey,
    post_id: &Uuid,
    target_author: &[u8; 32],
    signing_instance: &str,
    created_at_ms: u64,
    reason: Option<&str>,
) -> SigningOutput {
    let public_key = *key.public_bytes();
    let payload = AdminRemoval {
        post_id: *post_id.as_bytes(),
        target_author: *target_author,
        signing_instance: signing_instance.to_string(),
        created_at: created_at_ms,
        reason: reason.map(str::to_string),
    };
    let payload_bytes = SignedPayload::AdminRemoval(payload).encode();
    let signature = key.sign(&payload_bytes).to_vec();
    let canonical_hash: [u8; 32] = sha2::Sha256::digest(&payload_bytes).into();
    SigningOutput {
        payload: payload_bytes,
        signature,
        public_key,
        canonical_hash,
    }
}

/// Sign a `move` canonical payload (`signed-payload-format.md` §5.1)
/// with an already-loaded user `SigningKey`.
///
/// Moves are *user-signed*: the authority is the moving identity K
/// itself. The Phase 7 registration ceremony (`docs/federation-protocol.md`
/// §13) calls this immediately after a successful challenge redemption
/// to mint the §5.1 move declaration that propagates per §12.
///
/// `from_instance_key` / `to_instance_key` are the source and
/// destination instances' `instance_pubkey`s as observed at signing
/// time; `from_instance` / `to_instance` are the bare canonical domains.
/// Both are bound jointly per the §5.1 verification rule (see also
/// §12 "Joint binding of pubkey and domain"). Pass `from_instance_key`
/// / `from_instance` as `None` for a **genesis declaration** (the key
/// was born at `to_instance`, no predecessor — §12.8); they are
/// coupled, so either both `Some` or both `None`. `genesis_at_ms` is
/// the immutable account-birth time, re-stated in every declaration;
/// `genesis_attestation` is the birth-instance counter-signature (build
/// it with [`build_genesis_attestation`] when this instance is the
/// birth instance, or forward-carry the original on a re-home).
/// `prior_move_hash` chains to K's previous move's canonical hash;
/// `None` for the user's first (genesis) declaration.
#[allow(clippy::too_many_arguments)]
pub fn sign_move_with_key(
    key: &SigningKey,
    from_instance_key: Option<&[u8; 32]>,
    from_instance: Option<&str>,
    to_instance_key: &[u8; 32],
    to_instance: &str,
    created_at_ms: u64,
    genesis_at_ms: u64,
    genesis_attestation: GenesisAttestation,
    prior_move_hash: Option<&[u8; 32]>,
) -> SigningOutput {
    let public_key = *key.verifying_key().as_bytes();
    let payload = Move {
        key: public_key,
        from_instance_key: from_instance_key.copied(),
        from_instance: from_instance.map(str::to_string),
        to_instance_key: *to_instance_key,
        to_instance: to_instance.to_string(),
        created_at: created_at_ms,
        genesis_at: genesis_at_ms,
        genesis_attestation,
        prior_move_hash: prior_move_hash.copied(),
    };
    let payload_bytes = SignedPayload::Move(payload).encode();
    let signature = key.sign(&payload_bytes).to_bytes().to_vec();
    let canonical_hash: [u8; 32] = sha2::Sha256::digest(&payload_bytes).into();
    SigningOutput {
        payload: payload_bytes,
        signature,
        public_key,
        canonical_hash,
    }
}

/// Build a birth-instance [`GenesisAttestation`] (§5.1) by
/// counter-signing the `{key, genesis_at, birth_instance_key}` triple
/// with this instance's signing key.
///
/// Used when *this* instance is the birth instance — i.e. at local
/// signup, where the instance both hosts the account at creation and
/// vouches its age. `birth_instance_key` is set to this instance's
/// `instance_pubkey`. The resulting attestation is embedded verbatim in
/// the genesis declaration and re-carried by every subsequent move in
/// the chain, so a peer enforcing an age ceiling (§8.10) can convert the
/// user-signed `genesis_at` into an instance-vouched age.
pub fn build_genesis_attestation(
    instance_key: &InstanceKey,
    user_key: &[u8; 32],
    genesis_at_ms: u64,
) -> GenesisAttestation {
    let birth_instance_key = *instance_key.public_bytes();
    let signing_bytes =
        signed::genesis_attestation_signing_bytes(user_key, genesis_at_ms, &birth_instance_key);
    let sig = instance_key.sign(&signing_bytes);
    GenesisAttestation {
        key: *user_key,
        genesis_at: genesis_at_ms,
        birth_instance_key,
        sig,
    }
}

/// Sign a `deactivate` canonical payload with an already-loaded key.
///
/// See [signed-payload-format.md] §5.11. Terminal authority over every
/// signed object whose inner author key is the signer's public key.
/// `created_at_ms` must be later than or equal to the `created_at` of
/// every prior object by `user` for the §5.11 ordering rule to hold;
/// callers should pass `chrono::Utc::now().timestamp_millis() as u64`.
pub fn sign_deactivation_with_key(key: &SigningKey, created_at_ms: u64) -> SigningOutput {
    let public_key = *key.verifying_key().as_bytes();
    let payload = Deactivation {
        user: public_key,
        created_at: created_at_ms,
    };
    let payload_bytes = SignedPayload::Deactivation(payload).encode();
    let signature = key.sign(&payload_bytes).to_bytes().to_vec();
    let canonical_hash: [u8; 32] = sha2::Sha256::digest(&payload_bytes).into();
    SigningOutput {
        payload: payload_bytes,
        signature,
        public_key,
        canonical_hash,
    }
}

/// Sign a `user-status` canonical payload with the instance signing key.
///
/// See [signed-payload-format.md] §5.10 and [federation-protocol.md] §16.
/// User-status objects are *instance-signed*: the authority is the
/// subject's home instance, expressed via its long-lived signing key.
/// Takes `&InstanceKey` so the instance-key boundary is not widened.
///
/// `signing_instance` MUST equal the bare canonical domain whose signing
/// key signs this object — the §16.1 receiver re-derives it from
/// `peers.instance_domain` and refuses on mismatch. `prior_status_hash`
/// chains to `subject`'s previous status object; `None` for the first.
#[allow(clippy::too_many_arguments)]
pub fn sign_user_status_with_key(
    key: &InstanceKey,
    subject: &[u8; 32],
    status: UserStatusKind,
    suspended_until: Option<u64>,
    signing_instance: &str,
    reason: Option<&str>,
    created_at_ms: u64,
    prior_status_hash: Option<&[u8; 32]>,
) -> SigningOutput {
    let public_key = *key.public_bytes();
    let payload = UserStatus {
        subject: *subject,
        status,
        suspended_until,
        signing_instance: signing_instance.to_string(),
        reason: reason.map(str::to_string),
        created_at: created_at_ms,
        prior_status_hash: prior_status_hash.copied(),
    };
    let payload_bytes = SignedPayload::UserStatus(payload).encode();
    let signature = key.sign(&payload_bytes).to_vec();
    let canonical_hash: [u8; 32] = sha2::Sha256::digest(&payload_bytes).into();
    SigningOutput {
        payload: payload_bytes,
        signature,
        public_key,
        canonical_hash,
    }
}

/// Sign a `thread-status` canonical payload with the instance signing key.
///
/// See [signed-payload-format.md] §5.12 and [federation-protocol.md] §17.
/// Thread-status objects are *instance-signed* by the thread's home
/// instance. Takes `&InstanceKey` so the instance-key boundary is not
/// widened.
///
/// `signing_instance` MUST equal the bare canonical domain whose signing
/// key signs this object AND be the thread's home — the §17.1 receiver
/// enforces both. `prior_status_hash` chains to `thread_id`'s previous
/// status object; `None` for the first.
pub fn sign_thread_status_with_key(
    key: &InstanceKey,
    thread_id: &[u8; 16],
    status: ThreadStatusKind,
    signing_instance: &str,
    reason: Option<&str>,
    created_at_ms: u64,
    prior_status_hash: Option<&[u8; 32]>,
) -> SigningOutput {
    let public_key = *key.public_bytes();
    let payload = ThreadStatus {
        thread_id: *thread_id,
        status,
        signing_instance: signing_instance.to_string(),
        reason: reason.map(str::to_string),
        created_at: created_at_ms,
        prior_status_hash: prior_status_hash.copied(),
    };
    let payload_bytes = SignedPayload::ThreadStatus(payload).encode();
    let signature = key.sign(&payload_bytes).to_vec();
    let canonical_hash: [u8; 32] = sha2::Sha256::digest(&payload_bytes).into();
    SigningOutput {
        payload: payload_bytes,
        signature,
        public_key,
        canonical_hash,
    }
}

/// Sign a `report` canonical payload with an already-loaded user key.
///
/// See [signed-payload-format.md] §5.13 and [federation-protocol.md] §18.
/// Reports are *user-signed*: the authority is the reporting identity
/// (`reporter` == the signer's public key). The §18.1 receiver verifies
/// the signature against the report's `reporter` field, which this
/// helper binds to the signer's verifying key.
#[allow(clippy::too_many_arguments)]
pub fn sign_report_with_key(
    key: &SigningKey,
    post_id: &[u8; 16],
    target_author: &[u8; 32],
    reason: ReportReason,
    detail: Option<&str>,
    created_at_ms: u64,
) -> SigningOutput {
    let public_key = *key.verifying_key().as_bytes();
    let payload = Report {
        post_id: *post_id,
        target_author: *target_author,
        reporter: public_key,
        reason,
        detail: detail.map(str::to_string),
        created_at: created_at_ms,
    };
    let payload_bytes = SignedPayload::Report(payload).encode();
    let signature = key.sign(&payload_bytes).to_bytes().to_vec();
    let canonical_hash: [u8; 32] = sha2::Sha256::digest(&payload_bytes).into();
    SigningOutput {
        payload: payload_bytes,
        signature,
        public_key,
        canonical_hash,
    }
}

#[derive(Debug)]
pub enum SignError {
    Db(sqlx::Error),
    /// User exists but has no `active = 1` row in `signing_keys`.
    /// Indicates either a half-built account (signup tx rolled back
    /// between users and signing_keys writes — shouldn't happen after
    /// the signup-atomicity fix) or a legacy row predating server-side
    /// signing.
    NoKey,
    /// No `users` row for the supplied id. Semantically distinct from
    /// [`SignError::NoKey`]: the user themselves is missing, not their
    /// signing key. After Phase C `users.public_key` is NOT NULL, so
    /// "user exists but no public key" is not representable — every
    /// "can't find a pubkey for user X" case is in fact "user X
    /// doesn't exist".
    NoUser,
    /// Target user exists but is soft-deleted (`deleted_at IS NOT
    /// NULL`). Surfaced by [`sign_trust_edge`] as a defense-in-depth
    /// refusal. Handlers should reject deleted targets earlier;
    /// reaching this is a handler-layer slip.
    TargetDeleted,
    InvalidKey,
    /// `users.public_key` and `signing_key.verifying_key()` disagree.
    /// Caller-side identity-binding bug surfaced by
    /// [`store_signing_key`] before the private key is persisted.
    IdentityMismatch,
    /// A persisted row had a malformed shape that the signing layer
    /// could not interpret (unrecognized enum string, wrong-length
    /// hash, unparseable timestamp, etc.). Distinct from
    /// [`SignError::InvalidKey`], which is reserved for cryptographic
    /// key material specifically.
    InvalidData,
    InvalidSignature,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "database error: {e}"),
            Self::NoKey => write!(f, "no active signing key"),
            Self::NoUser => write!(f, "no such user"),
            Self::TargetDeleted => write!(f, "target user is soft-deleted"),
            Self::InvalidKey => write!(f, "invalid key format"),
            Self::IdentityMismatch => {
                write!(f, "users.public_key does not match signing key")
            }
            Self::InvalidData => write!(f, "malformed persisted row"),
            Self::InvalidSignature => write!(f, "invalid signature"),
        }
    }
}

impl From<SignError> for crate::error::AppError {
    fn from(err: SignError) -> Self {
        use crate::error::{AppError, ErrorCode};
        match err {
            SignError::Db(e) => AppError::from(e),
            SignError::NoKey => {
                tracing::error!("signing error: no active signing key for user");
                AppError::code(ErrorCode::Internal)
            }
            SignError::NoUser => {
                tracing::error!("signing error: referenced user does not exist");
                AppError::code(ErrorCode::Internal)
            }
            SignError::TargetDeleted => {
                tracing::error!(
                    "signing error: trust-edge target is soft-deleted (handler should have rejected)"
                );
                AppError::code(ErrorCode::Internal)
            }
            SignError::InvalidKey => {
                tracing::error!("signing error: invalid signing key format");
                AppError::code(ErrorCode::Internal)
            }
            SignError::IdentityMismatch => {
                tracing::error!(
                    "signing error: users.public_key does not match signing key (identity-binding violation)"
                );
                AppError::code(ErrorCode::Internal)
            }
            SignError::InvalidData => {
                tracing::error!("signing error: malformed persisted row");
                AppError::code(ErrorCode::Internal)
            }
            SignError::InvalidSignature => AppError::code(ErrorCode::InvalidSignature),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Layer 0 round-trip coverage for the Pre-Phase-6 sign helpers
    //! (`sign_thread_create_with_key`, `sign_admin_removal_with_instance_key`,
    //! `sign_deactivation_with_key`). Each test signs a payload, parses
    //! the canonical bytes back, asserts every bound field round-trips,
    //! and verifies the Ed25519 signature against the signer's public
    //! key — the same checks a receiver performs in §10 ingest.
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn fixed_key_a() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn fixed_key_b() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    fn verify_sig(public_key: &[u8; 32], payload: &[u8], signature: &[u8]) {
        let vk = VerifyingKey::from_bytes(public_key).expect("valid public key");
        let sig_bytes: [u8; 64] = signature.try_into().expect("64-byte signature");
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(payload, &sig).expect("signature verifies");
    }

    #[test]
    fn thread_create_round_trips_through_canonical_bytes() {
        let key = fixed_key_a();
        let thread_uuid = Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0);
        let op_uuid = Uuid::from_u128(0x0fed_cba9_8765_4321_0fed_cba9_8765_4321);
        let title = "Hello fediverse";
        let room_slug = "general";
        let link = Some("https://example.invalid/post");
        let created_at_ms: u64 = 1_700_000_000_000;

        let out = sign_thread_create_with_key(
            &key,
            &thread_uuid,
            room_slug,
            title,
            link,
            &op_uuid,
            created_at_ms,
        );

        // Signature verifies against the bound author key.
        verify_sig(&out.public_key, &out.payload, &out.signature);
        assert_eq!(out.public_key, *key.verifying_key().as_bytes());
        // canonical_hash is exactly SHA-256(payload).
        let recomputed: [u8; 32] = sha2::Sha256::digest(&out.payload).into();
        assert_eq!(out.canonical_hash, recomputed);

        // Parse the canonical bytes back; each bound field must equal
        // the input value.
        let parsed = SignedPayload::parse(&out.payload).expect("canonical parse");
        let SignedPayload::ThreadCreate(tc) = parsed else {
            panic!("expected ThreadCreate variant");
        };
        assert_eq!(tc.thread_id, *thread_uuid.as_bytes());
        assert_eq!(tc.author, *key.verifying_key().as_bytes());
        assert_eq!(tc.room_slug, room_slug);
        assert_eq!(tc.title, title);
        assert_eq!(tc.link_url.as_deref(), link);
        assert_eq!(tc.op_post_id, *op_uuid.as_bytes());
        assert_eq!(tc.created_at, created_at_ms);
    }

    #[test]
    fn thread_create_without_link_omits_field() {
        let key = fixed_key_a();
        let out =
            sign_thread_create_with_key(&key, &Uuid::nil(), "chatter", "", None, &Uuid::nil(), 0);
        let parsed = SignedPayload::parse(&out.payload).expect("canonical parse");
        let SignedPayload::ThreadCreate(tc) = parsed else {
            panic!("expected ThreadCreate variant");
        };
        assert!(tc.link_url.is_none());
        assert_eq!(tc.title, "");
    }

    #[test]
    fn admin_removal_round_trips_under_instance_key() {
        let signing = fixed_key_a();
        let inst_pub = *signing.verifying_key().as_bytes();
        let instance_key = InstanceKey::new(signing);

        let target_author = *fixed_key_b().verifying_key().as_bytes();
        let post_uuid = Uuid::from_u128(0xabcd_ef01_2345_6789_abcd_ef01_2345_6789);
        let signing_instance = "instance.example.invalid";
        let created_at_ms: u64 = 1_700_000_001_000;
        let reason = Some("violates rule 4");

        let out = sign_admin_removal_with_instance_key(
            &instance_key,
            &post_uuid,
            &target_author,
            signing_instance,
            created_at_ms,
            reason,
        );

        // Public key reported by helper is the instance key's public
        // half — the same value a receiver looks up via peers row.
        assert_eq!(out.public_key, inst_pub);
        verify_sig(&out.public_key, &out.payload, &out.signature);

        let parsed = SignedPayload::parse(&out.payload).expect("canonical parse");
        let SignedPayload::AdminRemoval(ar) = parsed else {
            panic!("expected AdminRemoval variant");
        };
        assert_eq!(ar.post_id, *post_uuid.as_bytes());
        assert_eq!(ar.target_author, target_author);
        assert_eq!(ar.signing_instance, signing_instance);
        assert_eq!(ar.created_at, created_at_ms);
        assert_eq!(ar.reason.as_deref(), reason);
    }

    #[test]
    fn admin_removal_without_reason_round_trips() {
        let instance_key = InstanceKey::new(fixed_key_a());
        let out = sign_admin_removal_with_instance_key(
            &instance_key,
            &Uuid::nil(),
            &[0u8; 32],
            "x.invalid",
            0,
            None,
        );
        let parsed = SignedPayload::parse(&out.payload).expect("canonical parse");
        let SignedPayload::AdminRemoval(ar) = parsed else {
            panic!("expected AdminRemoval variant");
        };
        assert!(ar.reason.is_none());
    }

    #[test]
    fn deactivation_round_trips_and_binds_signer_pubkey() {
        let key = fixed_key_a();
        let created_at_ms: u64 = 1_700_000_002_000;

        let out = sign_deactivation_with_key(&key, created_at_ms);

        // `user` field MUST be the signer's verifying key — that is
        // the §5.11 binding that makes the object an account-wide
        // erasure authority over everything signed by the same key.
        assert_eq!(out.public_key, *key.verifying_key().as_bytes());
        verify_sig(&out.public_key, &out.payload, &out.signature);

        let parsed = SignedPayload::parse(&out.payload).expect("canonical parse");
        let SignedPayload::Deactivation(d) = parsed else {
            panic!("expected Deactivation variant");
        };
        assert_eq!(d.user, *key.verifying_key().as_bytes());
        assert_eq!(d.created_at, created_at_ms);
    }

    #[test]
    fn user_status_round_trips_under_instance_key() {
        let signing = fixed_key_a();
        let inst_pub = *signing.verifying_key().as_bytes();
        let instance_key = InstanceKey::new(signing);

        let subject = *fixed_key_b().verifying_key().as_bytes();
        let signing_instance = "home.example.invalid";
        let created_at_ms: u64 = 1_700_000_003_000;
        let suspended_until = Some(1_700_000_900_000);
        let reason = Some("temporary suspension");
        let prior = [0x55; 32];

        let out = sign_user_status_with_key(
            &instance_key,
            &subject,
            UserStatusKind::Suspended,
            suspended_until,
            signing_instance,
            reason,
            created_at_ms,
            Some(&prior),
        );

        // Instance-signed: reported pubkey is the instance key's public
        // half, the value a §16.1 receiver looks up via the peers row.
        assert_eq!(out.public_key, inst_pub);
        verify_sig(&out.public_key, &out.payload, &out.signature);
        let recomputed: [u8; 32] = sha2::Sha256::digest(&out.payload).into();
        assert_eq!(out.canonical_hash, recomputed);

        let parsed = SignedPayload::parse(&out.payload).expect("canonical parse");
        let SignedPayload::UserStatus(s) = parsed else {
            panic!("expected UserStatus variant");
        };
        assert_eq!(s.subject, subject);
        assert_eq!(s.status, UserStatusKind::Suspended);
        assert_eq!(s.suspended_until, suspended_until);
        assert_eq!(s.signing_instance, signing_instance);
        assert_eq!(s.reason.as_deref(), reason);
        assert_eq!(s.created_at, created_at_ms);
        assert_eq!(s.prior_status_hash, Some(prior));
    }

    #[test]
    fn user_status_banned_omits_optionals() {
        let instance_key = InstanceKey::new(fixed_key_a());
        let out = sign_user_status_with_key(
            &instance_key,
            &[0u8; 32],
            UserStatusKind::Banned,
            None,
            "x.invalid",
            None,
            0,
            None,
        );
        let parsed = SignedPayload::parse(&out.payload).expect("canonical parse");
        let SignedPayload::UserStatus(s) = parsed else {
            panic!("expected UserStatus variant");
        };
        assert_eq!(s.status, UserStatusKind::Banned);
        assert!(s.suspended_until.is_none());
        assert!(s.reason.is_none());
        assert!(s.prior_status_hash.is_none());
    }

    #[test]
    fn thread_status_round_trips_under_instance_key() {
        let signing = fixed_key_a();
        let inst_pub = *signing.verifying_key().as_bytes();
        let instance_key = InstanceKey::new(signing);

        let thread_uuid = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
        let signing_instance = "home.example.invalid";
        let created_at_ms: u64 = 1_700_000_004_000;
        let reason = Some("locked for review");
        let prior = [0x77; 32];

        let out = sign_thread_status_with_key(
            &instance_key,
            thread_uuid.as_bytes(),
            ThreadStatusKind::Locked,
            signing_instance,
            reason,
            created_at_ms,
            Some(&prior),
        );

        assert_eq!(out.public_key, inst_pub);
        verify_sig(&out.public_key, &out.payload, &out.signature);

        let parsed = SignedPayload::parse(&out.payload).expect("canonical parse");
        let SignedPayload::ThreadStatus(s) = parsed else {
            panic!("expected ThreadStatus variant");
        };
        assert_eq!(s.thread_id, *thread_uuid.as_bytes());
        assert_eq!(s.status, ThreadStatusKind::Locked);
        assert_eq!(s.signing_instance, signing_instance);
        assert_eq!(s.reason.as_deref(), reason);
        assert_eq!(s.created_at, created_at_ms);
        assert_eq!(s.prior_status_hash, Some(prior));
    }

    #[test]
    fn report_round_trips_and_binds_reporter_pubkey() {
        let key = fixed_key_a();
        let post_uuid = Uuid::from_u128(0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0000);
        let target_author = *fixed_key_b().verifying_key().as_bytes();
        let created_at_ms: u64 = 1_700_000_005_000;
        let detail = Some("see linked screenshot");

        let out = sign_report_with_key(
            &key,
            post_uuid.as_bytes(),
            &target_author,
            ReportReason::RulesViolation,
            detail,
            created_at_ms,
        );

        // User-signed: `reporter` MUST be the signer's verifying key —
        // the §18.1 receiver verifies the signature against it.
        assert_eq!(out.public_key, *key.verifying_key().as_bytes());
        verify_sig(&out.public_key, &out.payload, &out.signature);

        let parsed = SignedPayload::parse(&out.payload).expect("canonical parse");
        let SignedPayload::Report(r) = parsed else {
            panic!("expected Report variant");
        };
        assert_eq!(r.post_id, *post_uuid.as_bytes());
        assert_eq!(r.target_author, target_author);
        assert_eq!(r.reporter, *key.verifying_key().as_bytes());
        assert_eq!(r.reason, ReportReason::RulesViolation);
        assert_eq!(r.detail.as_deref(), detail);
        assert_eq!(r.created_at, created_at_ms);
    }
}
