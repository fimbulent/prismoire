use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Generate an Ed25519 keypair and store it in the `signing_keys` table.
///
/// Returns the signing key row ID. The private key is stored server-side
/// in V1; in V2 it moves client-side (PRF-wrapped).
pub async fn create_signing_key(db: &SqlitePool, user_id: &str) -> Result<String, sqlx::Error> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO signing_keys (id, user_id, public_key, private_key) VALUES (?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(verifying_key.as_bytes().as_slice())
    .bind(signing_key.to_bytes().as_slice())
    .execute(db)
    .await?;

    Ok(id)
}

/// Sign a message with the user's active Ed25519 signing key.
///
/// Returns the 64-byte signature. Fails if the user has no active signing key.
pub async fn sign_message(
    db: &SqlitePool,
    user_id: &str,
    message: &[u8],
) -> Result<Vec<u8>, SignError> {
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT private_key FROM signing_keys WHERE user_id = ? AND active = 1")
            .bind(user_id)
            .fetch_optional(db)
            .await
            .map_err(SignError::Db)?;

    let (private_key_bytes,) = row.ok_or(SignError::NoKey)?;

    let key_bytes: [u8; 32] = private_key_bytes.try_into().map_err(|v: Vec<u8>| {
        eprintln!(
            "signing key for user {user_id} has invalid length {} (expected 32 bytes)",
            v.len()
        );
        SignError::InvalidKey
    })?;
    let signing_key = SigningKey::from_bytes(&key_bytes);

    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify an Ed25519 signature against a public key.
#[expect(dead_code)]
pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignError> {
    let key_bytes: [u8; 32] = public_key.try_into().map_err(|_| SignError::InvalidKey)?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| SignError::InvalidKey)?;

    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| SignError::InvalidSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify_strict(message, &sig)
        .map_err(|_| SignError::InvalidSignature)
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
                eprintln!("signing error: no active signing key for user");
                AppError::code(ErrorCode::Internal)
            }
            SignError::InvalidKey => {
                eprintln!("signing error: invalid signing key format");
                AppError::code(ErrorCode::Internal)
            }
            SignError::InvalidSignature => AppError::code(ErrorCode::InvalidSignature),
        }
    }
}
