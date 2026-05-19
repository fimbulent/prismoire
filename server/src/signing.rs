use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::Digest;
use sqlx::{SqliteExecutor, SqlitePool};
use uuid::Uuid;

use crate::signed::{PostRevision, Retraction, SignedPayload, TrustEdge, TrustStance};

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

/// Generate an Ed25519 keypair and store it in the `signing_keys` table.
///
/// Also writes the public key onto the user row (`users.public_key`),
/// so the federation-identity lookup path can resolve `pubkey →
/// user_id` without joining `signing_keys`. Both writes happen in one
/// transaction: there is no window in which a `signing_keys` row
/// exists but the matching `users.public_key` column is NULL.
///
/// Returns the signing key row ID.
pub async fn create_signing_key(db: &SqlitePool, user_id: &str) -> Result<String, sqlx::Error> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let id = Uuid::new_v4().to_string();
    let public_key = verifying_key.as_bytes().as_slice();
    let private_key = signing_key.to_bytes();
    let private_key = private_key.as_slice();

    let mut tx = db.begin().await?;
    sqlx::query!(
        "INSERT INTO signing_keys (id, user_id, public_key, private_key) VALUES (?, ?, ?, ?)",
        id,
        user_id,
        public_key,
        private_key,
    )
    .execute(&mut *tx)
    .await?;
    // `public_key IS NULL` guard: the federation-identity column is
    // write-once. A second `create_signing_key` call (resurrection,
    // retry, or any future key-rotation path) MUST NOT silently
    // rebind `users.public_key` — historical `canonical_hash` chains
    // are bound to the original key, and a rebind would orphan their
    // verifiability. Key rotation, when it lands, has to be an
    // explicit, audited migration (new `signing_keys` row + spec'd
    // wire object), not a side effect of this helper.
    sqlx::query!(
        "UPDATE users SET public_key = ? WHERE id = ? AND public_key IS NULL",
        public_key,
        user_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

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
/// No `inner_class` narrowing: `signed_objects.canonical_hash` is the
/// primary key, and each canonical_hash uniquely identifies one row
/// across all classes (the class is bound into the canonical bytes —
/// see `store_signed_object`).
pub async fn erase_post_rev_payloads<'e, E: SqliteExecutor<'e>>(
    executor: E,
    post_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE signed_objects \
         SET payload = NULL, erased_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE payload IS NOT NULL \
           AND canonical_hash IN ( \
               SELECT canonical_hash FROM post_revisions WHERE post_id = ? \
           )",
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
    let except: &[u8] = except_canonical_hash.as_slice();
    sqlx::query!(
        "UPDATE signed_objects \
         SET payload = NULL, erased_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE payload IS NOT NULL \
           AND canonical_hash != ? \
           AND canonical_hash IN ( \
               SELECT canonical_hash FROM trust_edges \
               WHERE source_user = ? AND target_user = ? \
                 AND canonical_hash IS NOT NULL \
           )",
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
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE signed_objects \
         SET payload = NULL, erased_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE payload IS NOT NULL \
           AND canonical_hash IN ( \
               SELECT canonical_hash FROM trust_edges \
               WHERE source_user = ? AND canonical_hash IS NOT NULL \
           )",
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
    ))
}

/// Sign a `trust-edge` canonical payload for the given source user.
///
/// DB-fetching wrapper around [`sign_trust_edge_with_key`] — looks up
/// the source's private signing key and the target's public signing
/// key from the `signing_keys` table, then signs. Returns
/// [`SignError::NoKey`] if either user lacks an active signing key.
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
        "SELECT public_key FROM signing_keys WHERE user_id = ? AND active = 1",
        target_user_id,
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(SignError::Db)?
    .ok_or(SignError::NoKey)?;
    let to_key: [u8; 32] = target_row.public_key.try_into().map_err(|v: Vec<u8>| {
        tracing::error!(
            user_id = %target_user_id,
            length = v.len(),
            "target signing key has invalid public-key length (expected 32 bytes)"
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

    if rows.is_empty() {
        return Ok(None);
    }

    let mut best: Option<[u8; 32]> = None;
    for row in rows {
        let hash: [u8; 32] = row.canonical_hash.as_slice().try_into().map_err(|_| {
            tracing::error!(
                edge_id = %row.id,
                len = row.canonical_hash.len(),
                "trust_edges.canonical_hash is not 32 bytes"
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

#[derive(Debug)]
pub enum SignError {
    Db(sqlx::Error),
    NoKey,
    InvalidKey,
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
            Self::InvalidKey => write!(f, "invalid key format"),
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
            SignError::InvalidKey => {
                tracing::error!("signing error: invalid signing key format");
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
