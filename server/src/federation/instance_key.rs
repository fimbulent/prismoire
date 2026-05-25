//! Per-instance Ed25519 signing key.
//!
//! This is the key the §6 envelope verifier expects on the *sender*
//! side of every outbound `/federation/v1/*` request — distinct from
//! per-user signing keys (which authenticate individual signed
//! objects) and distinct from any TLS material (which authenticates
//! the transport hop). Conceptually it is the long-lived "this is
//! instance X" credential; operationally it sits next to the
//! database as a server secret per `federation-protocol.md` §6.2.
//!
//! V1 supports exactly one active key per instance. The schema
//! (`instance_signing_keys`, migration `20260519165768`) allows for
//! at most one row with `active = 1` via a partial unique index;
//! the §6.6 rotation overlap will be added in a later phase, at
//! which point the load/store helpers here grow rotation-aware
//! variants.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sqlx::SqlitePool;

/// In-memory handle to the instance's signing key.
///
/// Holds both halves: the private `SigningKey` for signing
/// outbound envelopes, and the cached `[u8; 32]` public-key bytes
/// for the many places that need to compare against
/// `peers.instance_pubkey` without paying the
/// `VerifyingKey::to_bytes()` re-derivation cost.
pub struct InstanceKey {
    signing: SigningKey,
    public: [u8; 32],
}

impl InstanceKey {
    /// Wrap a freshly-generated or freshly-loaded `SigningKey`.
    pub fn new(signing: SigningKey) -> Self {
        let public = signing.verifying_key().to_bytes();
        Self { signing, public }
    }

    /// Raw 32-byte public key. Suitable for direct use as the
    /// `sender` field of a `fed-envelope` or for binding to
    /// `peers.instance_pubkey` on the wire.
    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }

    /// Typed verifying key, for callers that want to compose with
    /// `ed25519_dalek::Verifier`.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Sign `message` with the instance signing key. Returns the raw
    /// 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// Load the active instance key from the database, generating and
/// persisting a fresh one if none exists yet.
///
/// Returns an `Arc` so the loaded key can be cheaply shared into
/// `AppState` and onward into every handler. The function is
/// idempotent under concurrent calls in the "row already present"
/// path; the bootstrap-generate path is not (concurrent callers
/// would race to insert). In practice this only runs once at
/// startup and once per test `AppState`, so the race is theoretical.
pub async fn load_or_generate(pool: &SqlitePool) -> Result<Arc<InstanceKey>, sqlx::Error> {
    if let Some(row) =
        sqlx::query!("SELECT private_key FROM instance_signing_keys WHERE active = 1 LIMIT 1")
            .fetch_optional(pool)
            .await?
    {
        let bytes: [u8; 32] = row.private_key.as_slice().try_into().map_err(|_| {
            // The CHECK constraints don't enforce private_key length, so
            // a corrupted row would land here. Map to a generic DB error
            // rather than panicking — the operator's recourse is the
            // same (restore from backup or wipe + regenerate).
            sqlx::Error::Decode(
                "instance_signing_keys.private_key is not 32 bytes — DB corruption".into(),
            )
        })?;
        let signing = SigningKey::from_bytes(&bytes);
        return Ok(Arc::new(InstanceKey::new(signing)));
    }

    // Cold start: mint a fresh keypair and persist it. The active=1
    // partial unique index guarantees we never end up with two
    // active rows even under racey concurrent boots; the loser of
    // the race here would fail with a UNIQUE violation, which is
    // unusual enough that we let it surface as a `sqlx::Error`
    // rather than retrying.
    let signing = SigningKey::generate(&mut OsRng);
    let public_bytes = signing.verifying_key().to_bytes();
    let private_bytes = signing.to_bytes();
    let public_slice: &[u8] = &public_bytes;
    let private_slice: &[u8] = &private_bytes;
    sqlx::query!(
        "INSERT INTO instance_signing_keys (public_key, private_key, active) \
         VALUES (?, ?, 1)",
        public_slice,
        private_slice,
    )
    .execute(pool)
    .await?;
    tracing::info!(
        instance_pubkey = %hex(&public_bytes),
        "generated fresh instance signing key on first boot"
    );
    Ok(Arc::new(InstanceKey::new(signing)))
}

/// Hex-encode for log lines. The public key is freely disclosable
/// (it's the federation identity); we just want a stable rendering.
fn hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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

    #[tokio::test]
    async fn first_load_generates_and_persists() {
        let pool = fresh_pool().await;
        let key = load_or_generate(&pool).await.unwrap();
        let public = *key.public_bytes();

        // Second call returns the same key (loaded from the DB row
        // the first call inserted).
        let key2 = load_or_generate(&pool).await.unwrap();
        assert_eq!(key2.public_bytes(), &public);
    }

    #[tokio::test]
    async fn sign_round_trips_against_verifying_key() {
        let pool = fresh_pool().await;
        let key = load_or_generate(&pool).await.unwrap();
        let msg = b"hello federation";
        let sig_bytes = key.sign(msg);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        ed25519_dalek::Verifier::verify(&key.verifying_key(), msg, &signature)
            .expect("self-signed message must verify");
    }
}
