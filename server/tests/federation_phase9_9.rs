//! Phase-9.9 integration tests: §12.6 source-instance key disposal.
//!
//! Spec gate (`docs/federation-protocol.md` §12.6): when an instance
//! applies a Move whose `from_instance_key` equals the receiver's own
//! instance key and `to_instance_key` does not, the receiver MUST
//! destroy the moved-away user's private signing-key material, revoke
//! their active sessions, drop their WebAuthn credentials, and flip
//! `users.signup_method = 'federated'`. The authored content rows
//! (and the `users` row itself) stay — moves do not erase per §10.5.3.
//!
//! - **Layer 1** — Applied outbound-from-self move triggers full
//!   disposal: `signing_keys` / `sessions` / `credentials` rows for
//!   the moved-away user are gone, the `users` row survives but with
//!   `signup_method = 'federated'`.
//! - **Layer 1** — Superseded outbound-from-self move triggers
//!   disposal too. The user signed *something* claiming
//!   `from = self`, which is the testimony the disposal relies on,
//!   independent of which branch of §12.4 latest-wins prevails. Also
//!   exercises the idempotency contract: a second call against an
//!   already-disposed row is a no-op (no error, state unchanged).
//! - **Layer 1** — Inbound-to-self move (`to_instance_key == self`)
//!   does NOT trigger disposal on the receiver. The user is *arriving*
//!   at this instance via §13 cross-instance registration; their local
//!   authority on the source instance (if any) is not this instance's
//!   to dispose.

#![cfg(feature = "test-auth")]

mod common;

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use http::{Method, StatusCode};
use prismoire_server::signed::{self, GenesisAttestation};
use prismoire_server::signing::sign_move_with_key;
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};
use common::setup_admin;

// ---------------------------------------------------------------------------
// Wire-format helpers (mirrored from `federation_phase7.rs`).
// ---------------------------------------------------------------------------

fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

fn encode_moves_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("moves".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + wires.iter().map(|w| w.len()).sum::<usize>());
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

fn parse_results_body(body: &[u8]) -> Vec<([u8; 32], String, Option<String>)> {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("results body is not a map");
    };
    let results = m
        .into_iter()
        .find_map(|(k, v)| match k {
            Value::Text(t) if t == "results" => Some(v),
            _ => None,
        })
        .expect("missing `results` field");
    let Value::Array(arr) = results else {
        panic!("`results` is not an array");
    };
    arr.into_iter()
        .map(|entry| {
            let Value::Map(fields) = entry else {
                panic!("result entry not a map");
            };
            let mut hash: Option<[u8; 32]> = None;
            let mut status: Option<String> = None;
            let mut reason: Option<String> = None;
            for (k, v) in fields {
                if let Value::Text(name) = k {
                    match (name.as_str(), v) {
                        ("canonical_hash", Value::Bytes(b)) => {
                            hash = Some(b.as_slice().try_into().expect("32 bytes"));
                        }
                        ("status", Value::Text(s)) => status = Some(s),
                        ("reason", Value::Text(s)) => reason = Some(s),
                        _ => {}
                    }
                }
            }
            (hash.expect("hash"), status.expect("status"), reason)
        })
        .collect()
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Fixed account-birth time + pinned synthetic birth instance for
/// synthetic move chains. See the equivalent constants in
/// `federation_phase7.rs` for the rationale (constant `genesis_at`
/// satisfies the §5.1/§12.8 immutability gate; off-graph birth instance
/// forges a crypto-valid attestation the receive path accepts).
const GENESIS_AT_MS: u64 = 1_600_000_000_000;
const BIRTH_INSTANCE_SEED: [u8; 32] = [0xe1; 32];

fn test_attestation(user_key: &[u8; 32]) -> GenesisAttestation {
    let birth = SigningKey::from_bytes(&BIRTH_INSTANCE_SEED);
    let birth_instance_key = birth.verifying_key().to_bytes();
    let bytes =
        signed::genesis_attestation_signing_bytes(user_key, GENESIS_AT_MS, &birth_instance_key);
    let sig = birth.sign(&bytes).to_bytes();
    GenesisAttestation {
        key: *user_key,
        genesis_at: GENESIS_AT_MS,
        birth_instance_key,
        sig,
    }
}

/// Mint a signed Move from `user_key`. Mirrors the helper in
/// `federation_phase7.rs`.
#[allow(clippy::too_many_arguments)]
fn mint_move(
    user_key: &SigningKey,
    from_key: &[u8; 32],
    from_domain: &str,
    to_key: &[u8; 32],
    to_domain: &str,
    created_at_ms: u64,
    attestation: GenesisAttestation,
    prior: Option<&[u8; 32]>,
) -> (Vec<u8>, Vec<u8>) {
    // The move's `genesis_at` MUST equal the attestation's, and (for a
    // user with a real birth anchor) the attestation MUST be the one
    // stored in `user_genesis` — §12.8 immutability rejects any
    // declaration whose `genesis_at` / birth instance disagrees.
    let genesis_at = attestation.genesis_at;
    let signed = sign_move_with_key(
        user_key,
        Some(from_key),
        Some(from_domain),
        to_key,
        to_domain,
        created_at_ms,
        genesis_at,
        attestation,
        prior,
    );
    (
        encode_wire(&signed.payload, &signed.signature),
        signed.payload,
    )
}

/// Read a born local user's **real** birth attestation back out of
/// `user_genesis`, so a synthesized outbound move chains onto the
/// genesis that [`crate::common`]'s `setup_admin` minted at birth
/// rather than forging a conflicting one.
async fn read_birth_attestation(db: &SqlitePool, user_pub: &[u8; 32]) -> GenesisAttestation {
    let key: &[u8] = user_pub;
    let row = sqlx::query!(
        "SELECT genesis_at AS \"genesis_at!: i64\", \
                birth_instance_key AS \"birth_instance_key!: Vec<u8>\", \
                attestation_sig AS \"attestation_sig!: Vec<u8>\" \
         FROM user_genesis WHERE user_key = ?",
        key,
    )
    .fetch_one(db)
    .await
    .expect("user_genesis anchor for a born user");
    GenesisAttestation {
        key: *user_pub,
        genesis_at: u64::try_from(row.genesis_at).expect("genesis_at fits u64"),
        birth_instance_key: row
            .birth_instance_key
            .as_slice()
            .try_into()
            .expect("32-byte birth_instance_key"),
        sig: row
            .attestation_sig
            .as_slice()
            .try_into()
            .expect("64-byte attestation_sig"),
    }
}

/// Read a born local user's current move-chain head (the birth genesis
/// move's hash), to use as `prior_move_hash` when chaining a new move.
async fn read_current_move_hash(db: &SqlitePool, user_pub: &[u8; 32]) -> [u8; 32] {
    let key: &[u8] = user_pub;
    let row = sqlx::query!(
        "SELECT current_move_hash AS \"h!: Vec<u8>\" FROM user_homes WHERE user_key = ?",
        key,
    )
    .fetch_one(db)
    .await
    .expect("user_homes row for a born user");
    row.h
        .as_slice()
        .try_into()
        .expect("32-byte current_move_hash")
}

// ---------------------------------------------------------------------------
// DB-introspection helpers
// ---------------------------------------------------------------------------

/// Pull a local user's stored private signing key bytes out of the DB
/// so a test can sign moves as that user. `signing_keys.private_key`
/// is `SigningKey::to_bytes()` (32 bytes) — see `signing::store_signing_key`.
async fn extract_user_signing_key(db: &SqlitePool, user_id: &str) -> SigningKey {
    let row = sqlx::query!(
        "SELECT private_key AS \"private_key!: Vec<u8>\" \
         FROM signing_keys WHERE user_id = ? AND active = 1",
        user_id,
    )
    .fetch_one(db)
    .await
    .expect("signing_keys row");
    let bytes: [u8; 32] = row
        .private_key
        .as_slice()
        .try_into()
        .expect("32-byte private key");
    SigningKey::from_bytes(&bytes)
}

/// Insert a synthetic WebAuthn `credentials` row for `user_id`. The
/// bypass route `/test/setup-admin` skips the WebAuthn ceremony so no
/// credentials row exists by default; we plant one here so the test can
/// observe §12.6 disposal actually deleting it (otherwise the DELETE is
/// vacuously a no-op).
async fn insert_fake_credential(db: &SqlitePool, user_id: &str) {
    let id = Uuid::new_v4().to_string();
    // 16 random-ish bytes — the UNIQUE constraint on `credential_id`
    // means we just need them distinct across calls within the test.
    let credential_id: Vec<u8> = id.as_bytes().iter().take(16).copied().collect();
    let public_key: Vec<u8> = vec![0u8; 32];
    sqlx::query!(
        "INSERT INTO credentials (id, user_id, credential_id, public_key) \
         VALUES (?, ?, ?, ?)",
        id,
        user_id,
        credential_id,
        public_key,
    )
    .execute(db)
    .await
    .expect("insert credentials");
}

async fn count_signing_keys(db: &SqlitePool, user_id: &str) -> i64 {
    sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"n!: i64\" FROM signing_keys WHERE user_id = ?",
        user_id,
    )
    .fetch_one(db)
    .await
    .expect("count signing_keys")
}

async fn count_sessions(db: &SqlitePool, user_id: &str) -> i64 {
    sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"n!: i64\" FROM sessions WHERE user_id = ?",
        user_id,
    )
    .fetch_one(db)
    .await
    .expect("count sessions")
}

async fn count_credentials(db: &SqlitePool, user_id: &str) -> i64 {
    sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"n!: i64\" FROM credentials WHERE user_id = ?",
        user_id,
    )
    .fetch_one(db)
    .await
    .expect("count credentials")
}

/// Returns `(signup_method, display_name)` for the `users` row, or
/// `None` if no such row exists.
async fn read_user_row(db: &SqlitePool, user_id: &str) -> Option<(String, String)> {
    sqlx::query!(
        "SELECT signup_method AS \"signup_method!: String\", \
                display_name AS \"display_name!: String\" \
         FROM users WHERE id = ?",
        user_id,
    )
    .fetch_optional(db)
    .await
    .expect("query users")
    .map(|r| (r.signup_method, r.display_name))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Done-when (1): an Applied outbound-from-self move on the source
/// instance destroys the moved-away user's signing-key material,
/// active sessions, and WebAuthn credentials, and flips
/// `users.signup_method = 'federated'`. The `users` row itself
/// survives — authored content (per §10.5.3) still resolves to a
/// known identity.
#[tokio::test]
async fn applied_outbound_from_self_disposes_local_authority() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Local user U on A, fully provisioned through the prod-shaped
    // bypass path (users + signing_keys + sessions). Add a synthetic
    // credentials row so the test can observe its deletion too.
    let u = setup_admin(&a.router, "alice").await;
    insert_fake_credential(&a.state.db, &u.user_id).await;

    // Pre-conditions: every authority surface present.
    assert_eq!(count_signing_keys(&a.state.db, &u.user_id).await, 1);
    assert_eq!(count_sessions(&a.state.db, &u.user_id).await, 1);
    assert_eq!(count_credentials(&a.state.db, &u.user_id).await, 1);
    let (signup_method, display_name) = read_user_row(&a.state.db, &u.user_id)
        .await
        .expect("user row present pre-move");
    assert_ne!(
        signup_method, "federated",
        "fixture user starts as a local identity, not a federated stub"
    );

    // Extract U's SigningKey from A's DB so the test can mint a move
    // payload signed by U claiming "U moved from A to B".
    let user_key = extract_user_signing_key(&a.state.db, &u.user_id).await;
    let user_pub: [u8; 32] = *user_key.verifying_key().as_bytes();

    // Alice was born via `setup_admin`, so she carries a real
    // `user_genesis` anchor + a genesis move at the head of her chain.
    // Chain the synthetic outbound move onto *that* genesis (real
    // attestation, prior = birth move hash) so the §12.8 immutability
    // gate accepts it rather than rejecting a forged genesis_at.
    let att = read_birth_attestation(&a.state.db, &user_pub).await;
    let prior = read_current_move_hash(&a.state.db, &user_pub).await;
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    let (wire, _) = mint_move(
        &user_key,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        now_ms(),
        att,
        Some(&prior),
    );

    // B pushes the move to A. (Any active peer of A may gossip a move
    // declaring `from = A`; the disposal trigger is on the receiver
    // detecting `from_instance_key == self`, not on the envelope sender.)
    let body = encode_moves_body(&[wire]);
    let (status, body_bytes) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/moves",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "request-level OK");
    let results = parse_results_body(&body_bytes);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, "applied", "fresh move applies");

    // Post-conditions: §12.6 MUSTs and SHOULDs.
    assert_eq!(
        count_signing_keys(&a.state.db, &u.user_id).await,
        0,
        "signing_keys row destroyed (MUST)"
    );
    assert_eq!(
        count_sessions(&a.state.db, &u.user_id).await,
        0,
        "active sessions revoked (MUST)"
    );
    assert_eq!(
        count_credentials(&a.state.db, &u.user_id).await,
        0,
        "WebAuthn credentials dropped (SHOULD)"
    );
    let (signup_method_after, display_name_after) = read_user_row(&a.state.db, &u.user_id)
        .await
        .expect("users row preserved (authored content keeps resolving)");
    assert_eq!(
        signup_method_after, "federated",
        "signup_method flipped to 'federated' (SHOULD)"
    );
    assert_eq!(
        display_name_after, display_name,
        "display_name preserved across disposal"
    );

    // Sanity: just the `from = self` half of the trigger fired the
    // logic — verify the pub key field on `users` is unchanged so
    // future `/federation/v1/users/{pubkey}/...` requests still resolve.
    let pub_check = sqlx::query_scalar!(
        "SELECT public_key AS \"public_key!: Vec<u8>\" FROM users WHERE id = ?",
        u.user_id,
    )
    .fetch_one(&a.state.db)
    .await
    .expect("users public_key");
    assert_eq!(
        pub_check.as_slice(),
        user_pub.as_slice(),
        "users.public_key unchanged by §12.6 disposal"
    );
}

/// Done-when (2): a Superseded outbound-from-self move ALSO triggers
/// disposal. The user signed *something* asserting `from = self`,
/// which is the testimony §12.6 relies on; whichever branch of §12.4
/// latest-wins prevails on the wire is independent of the receiver's
/// duty to drop local authority.
///
/// Also pins the idempotency contract: applying disposal a second
/// time against an already-`signup_method = 'federated'` row is a
/// no-op rather than an error.
#[tokio::test]
async fn superseded_outbound_from_self_still_disposes() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let u = setup_admin(&a.router, "alice").await;
    insert_fake_credential(&a.state.db, &u.user_id).await;
    let user_key = extract_user_signing_key(&a.state.db, &u.user_id).await;
    let user_pub: [u8; 32] = *user_key.verifying_key().as_bytes();

    // Both synthesized moves chain onto alice's real birth genesis (she
    // was born via `setup_admin`); a forged genesis_at would be rejected
    // by the §12.8 immutability gate before latest-wins even runs.
    let att = read_birth_attestation(&a.state.db, &user_pub).await;
    let prior = read_current_move_hash(&a.state.db, &user_pub).await;
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();

    // First: newer move (applies, triggers initial disposal).
    let newer_ts = now_ms();
    let (newer_wire, _) = mint_move(
        &user_key,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        newer_ts,
        att.clone(),
        Some(&prior),
    );
    let body = encode_moves_body(&[newer_wire]);
    let (status, body_bytes) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/moves",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse_results_body(&body_bytes)[0].1, "applied");

    // After Applied path: every authority row is gone.
    assert_eq!(count_signing_keys(&a.state.db, &u.user_id).await, 0);
    assert_eq!(count_sessions(&a.state.db, &u.user_id).await, 0);
    assert_eq!(count_credentials(&a.state.db, &u.user_id).await, 0);
    let (signup_after_applied, _) = read_user_row(&a.state.db, &u.user_id)
        .await
        .expect("users row preserved");
    assert_eq!(signup_after_applied, "federated");

    // Second: older move (60 s earlier) for the same K. §12.4
    // latest-wins resolves to `superseded`. The disposal call still
    // fires on the Superseded branch — `dispose_local_user_authority`
    // sees `signup_method = 'federated'` and returns a no-op.
    let older_ts = newer_ts.saturating_sub(60_000);
    let (older_wire, _) = mint_move(
        &user_key,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        older_ts,
        att,
        Some(&prior),
    );
    let body = encode_moves_body(&[older_wire]);
    let (status, body_bytes) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/moves",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        parse_results_body(&body_bytes)[0].1,
        "superseded",
        "older move loses §12.4 latest-wins"
    );

    // State unchanged from after the Applied push: idempotency holds.
    assert_eq!(count_signing_keys(&a.state.db, &u.user_id).await, 0);
    assert_eq!(count_sessions(&a.state.db, &u.user_id).await, 0);
    assert_eq!(count_credentials(&a.state.db, &u.user_id).await, 0);
    let (signup_final, _) = read_user_row(&a.state.db, &u.user_id)
        .await
        .expect("users row still present");
    assert_eq!(
        signup_final, "federated",
        "Superseded branch did not resurrect local authority"
    );
}

/// Done-when (3): an inbound move (`to_instance_key == self`,
/// `from_instance_key != self`) does NOT touch the receiver's own
/// `signing_keys` / `sessions` / `credentials`. The §12.6 trigger is
/// strictly "I am the source the user is leaving" — the destination
/// gains a user via §13 cross-instance registration, not via disposal.
///
/// Concrete shape of this test: on B, set up a *local* admin V (not
/// the move subject U). Push a move declaring "U moved from A to B"
/// to B. Assert V's authority on B is untouched — the inbound move's
/// only DB effect on B is the §12 projection layer.
#[tokio::test]
async fn inbound_to_self_does_not_dispose_other_local_users() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // V is a local admin on B who has nothing to do with U's move.
    // Pre-§12.6, this distinction did not exist (no disposal logic
    // ran at all); post-§12.6, we need to confirm the disposal logic
    // doesn't over-fire on inbound moves and clobber unrelated locals.
    let v = setup_admin(&b.router, "victor").await;
    insert_fake_credential(&b.state.db, &v.user_id).await;

    // U is a synthetic federated user whose private key never sat on
    // either instance — they exist purely as a signer for the move
    // payload. (`OsRng` keeps this independent of any harness state.)
    let user_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let user_pub: [u8; 32] = *user_key.verifying_key().as_bytes();

    // U has no real birth anchor on either instance, so the synthetic
    // move forges a crypto-valid genesis attestation (off-graph birth
    // instance) that the receive path accepts as a first sighting.
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    let (wire, _) = mint_move(
        &user_key,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        now_ms(),
        test_attestation(&user_pub),
        None,
    );
    let body = encode_moves_body(&[wire]);
    let (status, body_bytes) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/moves",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse_results_body(&body_bytes)[0].1, "applied");

    // V's local authority on B is intact — the move was about U, and
    // even for U the receiver is the *destination*, not the source.
    assert_eq!(count_signing_keys(&b.state.db, &v.user_id).await, 1);
    assert_eq!(count_sessions(&b.state.db, &v.user_id).await, 1);
    assert_eq!(count_credentials(&b.state.db, &v.user_id).await, 1);
    let (v_signup, _) = read_user_row(&b.state.db, &v.user_id)
        .await
        .expect("V's users row");
    assert_ne!(
        v_signup, "federated",
        "V's signup_method must not be flipped by an unrelated inbound move"
    );
}
