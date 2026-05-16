use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::signed::{PostRevision, Retraction, SignedPayload};

/// Output of signing a class-specific payload.
pub struct SigningOutput {
    /// 64-byte Ed25519 signature over the canonical CBOR payload.
    pub signature: Vec<u8>,
    /// 32-byte Ed25519 public key of the active signing key.
    pub public_key: [u8; 32],
}

/// Generate an Ed25519 keypair and store it in the `signing_keys` table.
///
/// Returns the signing key row ID. The private key is stored server-side
/// in V1; in V2 it moves client-side (PRF-wrapped).
pub async fn create_signing_key(db: &SqlitePool, user_id: &str) -> Result<String, sqlx::Error> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let id = Uuid::new_v4().to_string();
    let public_key = verifying_key.as_bytes().as_slice();
    let private_key = signing_key.to_bytes();
    let private_key = private_key.as_slice();

    sqlx::query!(
        "INSERT INTO signing_keys (id, user_id, public_key, private_key) VALUES (?, ?, ?, ?)",
        id,
        user_id,
        public_key,
        private_key,
    )
    .execute(db)
    .await?;

    Ok(id)
}

/// Load the user's active signing key from the `signing_keys` table.
///
/// Returns the dalek `SigningKey`. The public key is derived from the
/// `SigningKey` itself (not read from the row) so the signed payload's
/// `author` field is by-construction coherent with what the signature
/// actually verifies under.
pub async fn load_active_signing_key(
    db: &SqlitePool,
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
    SigningOutput {
        signature,
        public_key,
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
    SigningOutput {
        signature,
        public_key,
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
    InvalidSignature,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "database error: {e}"),
            Self::NoKey => write!(f, "no active signing key"),
            Self::InvalidKey => write!(f, "invalid key format"),
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
            SignError::InvalidSignature => AppError::code(ErrorCode::InvalidSignature),
        }
    }
}
