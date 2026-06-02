#![cfg(feature = "test-auth")]
//! Cross-instance account/identity MOVE integration tests (§12 / §12.3 /
//! §12.6).
//!
//! Consolidates two formerly-separate phase files into the single
//! protocol surface they both exercise — a user migrating between
//! instances, from the §12.1 receive-path state machine through the
//! §12.3 chain backfill and the §12.6 source-side key disposal:
//!
//! - **§12.1 push receive path.** `POST /federation/v1/moves` from an
//!   active peer dispatches the per-object state machine: a
//!   chain-grounded move `applied`s — landing canonical bytes in
//!   `signed_objects`, a chain row in `user_moves`, the new home in
//!   `user_homes`, and the §5.1/§12.8 birth anchor in `user_genesis`.
//!   §12.4 latest-wins surfaces a stale replay as `superseded` (chain
//!   row kept, home pinned to the newer move). A move whose
//!   `prior_move_hash` predecessor is absent locally is `deferred` (no
//!   persist). The §12.7 skew gate `rejected`s a future-dated move with
//!   `skew_exceeded`; a bogus attestation and a divergent `genesis_at`
//!   for an already-grounded key are both `schema_invalid`. None of the
//!   rejected/deferred classes persist anything.
//! - **Request-level rejects.** A batch past `MAX_MOVE_BATCH` 400s with
//!   `batch_too_large`; a batch past the §10.6 per-source rolling-hour
//!   budget 400s with `rate_limited` — both before any per-object work.
//! - **§12.3 chain backfill.** `GET /federation/v1/moves/backfill?key=`
//!   walks the chain for a known key (single-page round-trip:
//!   `complete: true`, no `next_cursor`, payload re-hashes to the move
//!   hash) and 400s `unknown_chain` for a key never seen.
//! - **§12.6 source-instance key disposal.** When an applied (or even
//!   §12.4-superseded) move declares `from_instance_key == self` and
//!   `to_instance_key != self`, the receiver destroys the moved-away
//!   user's `signing_keys` / `sessions` / `credentials` and flips
//!   `users.signup_method = 'federated'` while preserving the `users`
//!   row + pubkey (idempotent on a re-fire). An inbound move
//!   (`to_instance_key == self`) does NOT dispose any local user.
//!
//! Cross-instance registration (§13) Layer-1 coverage is deliberately
//! out of scope: the §13 complete path runs `webauthn-rs`'s
//! `finish_passkey_registration`, which needs a real browser-side
//! attestation. Layer-0 unit tests in `federation/registration.rs` cover
//! the §13.2 constant pins; the wire-level happy path is covered by the
//! Layer-2 smoke suite (which speaks real WebAuthn end-to-end).
//!
//! These scenarios drive the §12.1 receive handler and the §12.3
//! backfill route (the functions under test) directly via signed
//! envelopes, so they do not use the [`settle`](common::federation::settle)
//! convergence driver — there is no `frontier_fanout_loop` + poll race to
//! replace here.

mod common;

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use http::{Method, StatusCode};
use prismoire_server::federation::moves::{
    MAX_CLOCK_SKEW_MS, MAX_MOVE_BATCH, MAX_MOVE_OBJECTS_PER_HOUR,
};
use prismoire_server::signed::{self, GenesisAttestation};
use prismoire_server::signing::sign_move_with_key;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{
    MultiInstanceHarness, establish_active_peering, send_envelope_signed,
    send_envelope_signed_split,
};
use common::setup_admin;

// ---------------------------------------------------------------------------
// Wire-format helpers (the WireFormat `{ "p", "s" }` shape is the same for
// any signed-object class).
// ---------------------------------------------------------------------------

/// Encode a §6.3 WireFormat `{ "p", "s" }` blob from a (payload, sig).
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

/// Build the `POST /federation/v1/moves` body: `{ "moves": [bstr, ...] }`.
fn encode_moves_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("moves".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + wires.iter().map(|w| w.len()).sum::<usize>());
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// Decode `{ "results": [{ canonical_hash, status, reason? }, …] }` →
/// `Vec<(hash, status, reason)>`.
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

/// Decode the §12.3 backfill body
/// `{ "objects": [bstr, …], "next_cursor"?: bstr, "complete": bool }`.
struct BackfillBody {
    objects: Vec<Vec<u8>>,
    next_cursor: Option<Vec<u8>>,
    complete: bool,
}

fn parse_backfill_body(body: &[u8]) -> BackfillBody {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("backfill body is not a map");
    };
    let mut objects: Vec<Vec<u8>> = Vec::new();
    let mut next_cursor: Option<Vec<u8>> = None;
    let mut complete: Option<bool> = None;
    for (k, v) in m {
        let Value::Text(name) = k else {
            continue;
        };
        match (name.as_str(), v) {
            ("objects", Value::Array(arr)) => {
                for item in arr {
                    let Value::Bytes(b) = item else {
                        panic!("object entry not bstr");
                    };
                    objects.push(b);
                }
            }
            ("next_cursor", Value::Bytes(b)) => next_cursor = Some(b),
            ("complete", Value::Bool(b)) => complete = Some(b),
            _ => {}
        }
    }
    BackfillBody {
        objects,
        next_cursor,
        complete: complete.expect("complete field"),
    }
}

/// Pull the `error` field from a request-level 400 body.
fn parse_error_body(body: &[u8]) -> String {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("error body is not a map");
    };
    for (k, v) in m {
        if let (Value::Text(t), Value::Text(s)) = (&k, v)
            && t == "error"
        {
            return s;
        }
    }
    panic!("missing `error` field");
}

// ---------------------------------------------------------------------------
// Test-side move-signing helpers
// ---------------------------------------------------------------------------

/// Generate a fresh Ed25519 keypair for a synthetic federated user K.
fn fresh_user_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Current wall clock in Unix ms. Matches the receiver's `now_ms`
/// source so a move minted "now" sits comfortably inside `MAX_CLOCK_SKEW`.
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Fixed account-birth time for synthetic move chains. Well before any
/// test's `created_at_ms` (which is `now_ms()`), and constant so every
/// move minted for a given user re-states the same immutable `genesis_at`
/// — satisfying the §5.1/§12.8 immutability gate on the receive side.
const GENESIS_AT_MS: u64 = 1_600_000_000_000;

/// Pinned synthetic birth-instance seed. The receive path verifies the
/// attestation `sig` against `birth_instance_key`; it does not require
/// that key to match `from`/`to`, so a fixed off-graph birth instance is
/// sufficient to forge a crypto-valid attestation for these chains.
const BIRTH_INSTANCE_SEED: [u8; 32] = [0xe1; 32];

/// Forge a §5.1 birth-instance attestation for `user_key` over the given
/// `genesis_at`, signed by the pinned [`BIRTH_INSTANCE_SEED`]. The
/// `key`/`genesis_at` mirror the outer move so parse's inner==outer bind
/// passes, and the sig verifies on the receive side.
fn attestation_with_genesis(user_key: &[u8; 32], genesis_at_ms: u64) -> GenesisAttestation {
    let birth = SigningKey::from_bytes(&BIRTH_INSTANCE_SEED);
    let birth_instance_key = birth.verifying_key().to_bytes();
    let bytes =
        signed::genesis_attestation_signing_bytes(user_key, genesis_at_ms, &birth_instance_key);
    let sig = birth.sign(&bytes).to_bytes();
    GenesisAttestation {
        key: *user_key,
        genesis_at: genesis_at_ms,
        birth_instance_key,
        sig,
    }
}

/// Forge a §5.1 attestation over the fixed [`GENESIS_AT_MS`].
fn test_attestation(user_key: &[u8; 32]) -> GenesisAttestation {
    attestation_with_genesis(user_key, GENESIS_AT_MS)
}

/// Mint a signed Move from `user_key` carrying the supplied attestation.
/// The move's `genesis_at` is taken from the attestation (§12.8 binds the
/// two). Returns `(canonical_hash, wire-bytes, payload)` so callers can
/// assert on the hash, send the wire verbatim, or re-hash the payload.
#[allow(clippy::too_many_arguments)]
fn mint_move_with_attestation(
    user_key: &SigningKey,
    from_key: &[u8; 32],
    from_domain: &str,
    to_key: &[u8; 32],
    to_domain: &str,
    created_at_ms: u64,
    attestation: GenesisAttestation,
    prior: Option<&[u8; 32]>,
) -> ([u8; 32], Vec<u8>, Vec<u8>) {
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
    let wire = encode_wire(&signed.payload, &signed.signature);
    (signed.canonical_hash, wire, signed.payload)
}

/// Mint a move with the default fixed-genesis attestation. Returns
/// `(canonical_hash, wire-bytes)`.
fn mint_move(
    user_key: &SigningKey,
    from_key: &[u8; 32],
    from_domain: &str,
    to_key: &[u8; 32],
    to_domain: &str,
    created_at_ms: u64,
    prior: Option<&[u8; 32]>,
) -> ([u8; 32], Vec<u8>) {
    let user_pub = user_key.verifying_key().to_bytes();
    let (hash, wire, _payload) = mint_move_with_attestation(
        user_key,
        from_key,
        from_domain,
        to_key,
        to_domain,
        created_at_ms,
        test_attestation(&user_pub),
        prior,
    );
    (hash, wire)
}

/// Mint a move carrying a structurally-valid but **cryptographically
/// bogus** attestation: the embedded `sig` does not verify against
/// `birth_instance_key`. The outer move signature is still valid (we sign
/// the whole payload with the user key), so the receive path's Step-4b
/// attestation check is what must reject it.
fn mint_move_bad_attestation(
    user_key: &SigningKey,
    from_key: &[u8; 32],
    from_domain: &str,
    to_key: &[u8; 32],
    to_domain: &str,
    created_at_ms: u64,
) -> ([u8; 32], Vec<u8>) {
    let user_pub = user_key.verifying_key().to_bytes();
    let birth = SigningKey::from_bytes(&BIRTH_INSTANCE_SEED);
    let attestation = GenesisAttestation {
        key: user_pub,
        genesis_at: GENESIS_AT_MS,
        birth_instance_key: birth.verifying_key().to_bytes(),
        // Garbage signature: 64 zero bytes never verify.
        sig: [0u8; 64],
    };
    let (hash, wire, _payload) = mint_move_with_attestation(
        user_key,
        from_key,
        from_domain,
        to_key,
        to_domain,
        created_at_ms,
        attestation,
        None,
    );
    (hash, wire)
}

// ---------------------------------------------------------------------------
// DB-introspection helpers (assert the projections that `apply_one_move`
// writes — these are the read paths the rest of the server consults).
// ---------------------------------------------------------------------------

/// Read the `user_genesis` birth anchor for K: `(genesis_at,
/// birth_instance_key, attestation_sig)`.
async fn read_user_genesis(
    db: &SqlitePool,
    user_key: &[u8; 32],
) -> Option<(i64, Vec<u8>, Vec<u8>)> {
    let key: &[u8] = user_key.as_slice();
    sqlx::query!(
        "SELECT genesis_at AS \"genesis_at!: i64\", \
                birth_instance_key AS \"birth_instance_key!: Vec<u8>\", \
                attestation_sig AS \"attestation_sig!: Vec<u8>\" \
         FROM user_genesis WHERE user_key = ?",
        key,
    )
    .fetch_optional(db)
    .await
    .expect("query user_genesis")
    .map(|r| (r.genesis_at, r.birth_instance_key, r.attestation_sig))
}

/// Read a born local user's **real** birth attestation back out of
/// `user_genesis`, so a synthesized outbound move chains onto the genesis
/// that `setup_admin` minted at birth rather than forging a conflicting
/// one.
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

async fn read_user_home(db: &SqlitePool, user_key: &[u8; 32]) -> Option<(Vec<u8>, String, i64)> {
    let key: &[u8] = user_key.as_slice();
    sqlx::query!(
        "SELECT current_move_hash AS \"current_move_hash!: Vec<u8>\", \
                current_home_domain AS \"current_home_domain!: String\", \
                current_created_at AS \"current_created_at!: i64\" \
         FROM user_homes WHERE user_key = ?",
        key,
    )
    .fetch_optional(db)
    .await
    .expect("query user_homes")
    .map(|r| {
        (
            r.current_move_hash,
            r.current_home_domain,
            r.current_created_at,
        )
    })
}

async fn count_user_moves(db: &SqlitePool, user_key: &[u8; 32]) -> i64 {
    let key: &[u8] = user_key.as_slice();
    sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"n!: i64\" FROM user_moves WHERE user_key = ?",
        key,
    )
    .fetch_one(db)
    .await
    .expect("count user_moves")
}

async fn signed_object_present(db: &SqlitePool, canonical_hash: &[u8; 32]) -> bool {
    let h: &[u8] = canonical_hash.as_slice();
    sqlx::query_scalar!(
        "SELECT 1 AS \"n!: i64\" FROM signed_objects \
         WHERE canonical_hash = ? AND payload IS NOT NULL LIMIT 1",
        h,
    )
    .fetch_optional(db)
    .await
    .expect("query signed_objects")
    .is_some()
}

/// Pull a local user's stored private signing key bytes out of the DB so
/// a test can sign moves as that user. `signing_keys.private_key` is
/// `SigningKey::to_bytes()` (32 bytes) — see `signing::store_signing_key`.
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

/// Returns `(signup_method, display_name)` for the `users` row, or `None`
/// if no such row exists.
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

// ===========================================================================
// §12.1 push receive path — applied happy path + genesis anchor
// ===========================================================================

/// A chain-grounded move from active-peer A applies on B: the canonical
/// bytes land in `signed_objects`, the chain row lands in `user_moves`,
/// `user_homes` reflects the new home, and the §5.1/§12.8 birth anchor is
/// projected into `user_genesis` (copying `genesis_at` and
/// `birth_instance_key` verbatim — the row the §8.10 age-ceiling slice
/// reads).
#[tokio::test]
async fn move_push_applies_and_projects_all_state() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    // No prior_move_hash — this is the user's first move ever.
    let created = now_ms();
    let (canonical_hash, wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        created,
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
    assert_eq!(status, StatusCode::OK, "push accepted");

    let results = parse_results_body(&body_bytes);
    assert_eq!(results.len(), 1, "one result per move");
    assert_eq!(results[0].0, canonical_hash);
    assert_eq!(results[0].1, "applied");
    assert_eq!(results[0].2, None, "no reason on `applied`");

    // signed_objects holds the canonical bytes.
    assert!(
        signed_object_present(&b.state.db, &canonical_hash).await,
        "signed_objects has the move payload"
    );

    // user_moves projects exactly one chain row for K.
    assert_eq!(
        count_user_moves(&b.state.db, &user_pub).await,
        1,
        "exactly one user_moves row"
    );

    // user_homes resolves to the move's `to_instance` / `to_instance_key`.
    let home = read_user_home(&b.state.db, &user_pub)
        .await
        .expect("user_homes row created");
    assert_eq!(
        home.0,
        canonical_hash.to_vec(),
        "home points at this move's hash"
    );
    assert_eq!(
        home.1, b.state.instance_domain,
        "home_domain copied verbatim"
    );
    assert_eq!(home.2, created as i64, "created_at copied verbatim");

    // user_genesis carries the §12.8 birth anchor copied verbatim.
    let expected_birth_key = SigningKey::from_bytes(&BIRTH_INSTANCE_SEED)
        .verifying_key()
        .to_bytes()
        .to_vec();
    let (genesis_at, birth_key, _sig) = read_user_genesis(&b.state.db, &user_pub)
        .await
        .expect("user_genesis anchor persisted");
    assert_eq!(
        genesis_at, GENESIS_AT_MS as i64,
        "genesis_at copied verbatim"
    );
    assert_eq!(
        birth_key, expected_birth_key,
        "birth_instance_key copied verbatim"
    );
}

// ===========================================================================
// §12.4 latest-wins resolution
// ===========================================================================

/// After applying a newer move, an older move for the same K is
/// `superseded` — the older chain row is persisted (chain evidence per
/// §12.5) but `user_homes` keeps the newer entry.
#[tokio::test]
async fn older_move_after_newer_is_superseded() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();

    // First push: newer move (now). This applies and pins user_homes.
    let newer_ts = now_ms();
    let (newer_hash, newer_wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        newer_ts,
        None,
    );
    let body = encode_moves_body(&[newer_wire]);
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
    let r = parse_results_body(&body_bytes);
    assert_eq!(r[0].1, "applied");

    // Second push: an older move (60 seconds earlier). §12.4 latest-wins
    // says this one loses — `superseded`. The chain row still lands in
    // `user_moves` so §12.3 backfill can serve both branches of the fork.
    let older_ts = newer_ts.saturating_sub(60_000);
    let (older_hash, older_wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        older_ts,
        None,
    );
    let body = encode_moves_body(&[older_wire]);
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
    let r = parse_results_body(&body_bytes);
    assert_eq!(r[0].0, older_hash);
    assert_eq!(r[0].1, "superseded");

    // user_homes still pins the newer move.
    let home = read_user_home(&b.state.db, &user_pub)
        .await
        .expect("user_homes still populated");
    assert_eq!(
        home.0,
        newer_hash.to_vec(),
        "user_homes pinned to newer move's hash"
    );
    assert_eq!(home.2, newer_ts as i64);

    // user_moves carries both rows — §12.5 chain evidence.
    assert_eq!(
        count_user_moves(&b.state.db, &user_pub).await,
        2,
        "both newer and superseded land in user_moves"
    );
    assert!(signed_object_present(&b.state.db, &newer_hash).await);
    assert!(signed_object_present(&b.state.db, &older_hash).await);
}

// ===========================================================================
// §12.1 chain-grounding → deferred
// ===========================================================================

/// A move whose `prior_move_hash` predecessor is not present locally
/// returns `deferred` — Phase 7 ships the one-shot status; Phase 8 adds
/// the pending-validation buffer + autonomous backfill issuance.
/// Critically: the deferred move is NOT persisted (neither
/// `signed_objects` nor `user_moves` nor `user_homes`).
#[tokio::test]
async fn move_with_missing_prior_is_deferred_and_not_persisted() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();

    // Concoct a synthetic prior-hash that B has definitely never seen
    // (we never push a predecessor). SHA-256 of a known-unique nonce
    // gives us a 32-byte value with no chance of accidental collision.
    let fake_prior: [u8; 32] = Sha256::digest(b"moves-test-no-such-predecessor").into();

    let (canonical_hash, wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        now_ms(),
        Some(&fake_prior),
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

    let results = parse_results_body(&body_bytes);
    assert_eq!(results[0].0, canonical_hash);
    assert_eq!(results[0].1, "deferred");
    assert_eq!(results[0].2, None);

    // Nothing persisted.
    assert!(!signed_object_present(&b.state.db, &canonical_hash).await);
    assert_eq!(count_user_moves(&b.state.db, &user_pub).await, 0);
    assert!(read_user_home(&b.state.db, &user_pub).await.is_none());
}

// ===========================================================================
// §12.7 skew gate + §5.1/§12.8 attestation rejects (all `not persisted`)
// ===========================================================================

/// §12.7: a future-dated move outside `MAX_CLOCK_SKEW_MS` is rejected
/// with `skew_exceeded` and is NOT persisted (neither in `signed_objects`
/// nor in any §12 projection).
#[tokio::test]
async fn move_push_with_skew_is_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    // 2× the cap into the future — well past any plausible legit drift.
    let far_future = now_ms() + MAX_CLOCK_SKEW_MS * 2;
    let (canonical_hash, wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        far_future,
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
    assert_eq!(
        status,
        StatusCode::OK,
        "request-level OK; per-object reject"
    );

    let results = parse_results_body(&body_bytes);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, canonical_hash);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("skew_exceeded"));

    // Nothing landed.
    assert!(!signed_object_present(&b.state.db, &canonical_hash).await);
    assert_eq!(count_user_moves(&b.state.db, &user_pub).await, 0);
    assert!(read_user_home(&b.state.db, &user_pub).await.is_none());
}

/// §5.1/§12.8: a move whose attestation `sig` does not verify against
/// `birth_instance_key` is rejected as `schema_invalid` at Step 4b, and
/// nothing is persisted — not the signed object, not the genesis anchor.
#[tokio::test]
async fn move_push_with_bad_attestation_is_rejected_and_not_persisted() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    let (canonical_hash, wire) = mint_move_bad_attestation(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        now_ms(),
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
    assert_eq!(
        status,
        StatusCode::OK,
        "request-level OK; per-object reject"
    );
    let results = parse_results_body(&body_bytes);
    assert_eq!(results[0].0, canonical_hash);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("schema_invalid"));

    assert!(
        !signed_object_present(&b.state.db, &canonical_hash).await,
        "bad-attestation move not stored"
    );
    assert!(
        read_user_genesis(&b.state.db, &user_pub).await.is_none(),
        "no genesis anchor written for a rejected move"
    );
}

/// §5.1/§12.8 immutability: once a key's birth time is grounded, a later
/// declaration claiming a *different* `genesis_at` is `schema_invalid`.
/// The first move applies and pins the anchor; the divergent second move
/// is rejected and the anchor is unchanged.
#[tokio::test]
async fn divergent_genesis_at_for_same_key_is_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();

    // First declaration grounds genesis_at = GENESIS_AT_MS.
    let (first_hash, first_wire, _) = mint_move_with_attestation(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        now_ms(),
        test_attestation(&user_pub),
        None,
    );
    let body = encode_moves_body(&[first_wire]);
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
    let results = parse_results_body(&body_bytes);
    assert_eq!(results[0].0, first_hash);
    assert_eq!(results[0].1, "applied");

    // Second declaration for the same key claims a *different* birth time.
    let divergent_genesis = GENESIS_AT_MS + 86_400_000; // +1 day
    let (second_hash, second_wire, _) = mint_move_with_attestation(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        now_ms() + 1,
        attestation_with_genesis(&user_pub, divergent_genesis),
        None,
    );
    let body = encode_moves_body(&[second_wire]);
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
    let results = parse_results_body(&body_bytes);
    assert_eq!(results[0].0, second_hash);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("schema_invalid"));

    // Anchor still pins the original birth time.
    let (genesis_at, _birth_key, _sig) = read_user_genesis(&b.state.db, &user_pub)
        .await
        .expect("original anchor retained");
    assert_eq!(
        genesis_at, GENESIS_AT_MS as i64,
        "birth time unchanged by the rejected move"
    );
}

// ===========================================================================
// Request-level rejects: batch_too_large, rate_limited
// ===========================================================================

/// `batch_too_large`: a push with `MAX_MOVE_BATCH + 1` entries is rejected
/// at request-level (single `{"error": "batch_too_large"}` body, no
/// per-object results). Guards against a hostile peer trying to amplify
/// per-batch DB write pressure.
#[tokio::test]
async fn move_push_batch_too_large_rejected_with_error_body() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();

    // MAX + 1 fresh moves. The handler rejects at the batch-size check
    // before any per-object work, so reuse one key across all entries;
    // the request-level reject fires first.
    let user = fresh_user_key();
    let mut wires = Vec::with_capacity(MAX_MOVE_BATCH + 1);
    for i in 0..=MAX_MOVE_BATCH {
        // Vary `created_at` by 1 ms per entry so the canonical bytes
        // differ across entries (otherwise every move shares a hash
        // and a hypothetical future "batch-size after dedup" change
        // would mask this test).
        let ts = now_ms() + i as u64;
        let (_h, wire) = mint_move(
            &user,
            &from_key,
            &a.state.instance_domain,
            &to_key,
            &b.state.instance_domain,
            ts,
            None,
        );
        wires.push(wire);
    }
    let body = encode_moves_body(&wires);
    let (status, body_bytes) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/moves",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&body_bytes), "batch_too_large");
}

/// `rate_limited`: a push whose batch size + already-consumed budget
/// exceeds `MAX_MOVE_OBJECTS_PER_HOUR` is rejected at request-level.
/// Pre-fill the limiter via a direct count to the same source key, then
/// send one more move and assert the whole batch is rejected.
#[tokio::test]
async fn move_push_rate_limited_when_budget_exhausted() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Drive the limiter directly to one-under-budget. The handler routes
    // a real batch through this exact instance, so consuming it here
    // counts against the same source-keyed window. Filling via
    // `check_and_count` (true → counter incremented) is the same
    // operation the handler performs on inbound.
    let sender = *a.state.instance_key.public_bytes();
    let admitted = b
        .state
        .move_rate_limiter
        .check_and_count(sender, MAX_MOVE_OBJECTS_PER_HOUR);
    assert!(admitted, "pre-fill should fit within the empty window");

    // Now send one more move. Budget is exhausted → whole-batch reject.
    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    let (canonical_hash, wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        now_ms(),
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
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&body_bytes), "rate_limited");

    // Nothing landed.
    assert!(!signed_object_present(&b.state.db, &canonical_hash).await);
    assert_eq!(count_user_moves(&b.state.db, &user_pub).await, 0);
}

// ===========================================================================
// §12.3 chain backfill
// ===========================================================================

/// `GET /federation/v1/moves/backfill?key=<hex>` walks the §12.3 chain
/// for a key that has at least one accepted move. Single-page round-trip:
/// one applied move → one object in the body, `complete: true`, no
/// `next_cursor`, and the returned payload re-hashes to the move hash.
#[tokio::test]
async fn move_backfill_returns_chain_for_known_key() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Seed B with one applied move via the §12.1 push path.
    let user = fresh_user_key();
    let user_pub = *user.verifying_key().as_bytes();
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    let (move_hash, wire) = mint_move(
        &user,
        &from_key,
        &a.state.instance_domain,
        &to_key,
        &b.state.instance_domain,
        now_ms(),
        None,
    );
    let push_body = encode_moves_body(std::slice::from_ref(&wire));
    let (status, _) = send_envelope_signed(
        &harness,
        "a",
        "b",
        Method::POST,
        "/federation/v1/moves",
        &push_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Now A asks B for the chain. The signed envelope is over the
    // *path-without-query*; we dispatch against the query-bearing URI so
    // the `Query` extractor sees it. See `send_envelope_signed_split`.
    let key_hex: String = user_pub.iter().map(|b| format!("{b:02x}")).collect();
    let path = "/federation/v1/moves/backfill";
    let uri = format!("{path}?key={key_hex}");
    let (status, body_bytes) =
        send_envelope_signed_split(&harness, "a", "b", Method::GET, path, &uri, &[]).await;
    assert_eq!(status, StatusCode::OK, "backfill returns OK");

    let parsed = parse_backfill_body(&body_bytes);
    assert_eq!(parsed.objects.len(), 1, "one object in the chain");
    assert!(parsed.complete, "single-page response is complete");
    assert!(parsed.next_cursor.is_none(), "no next_cursor when complete");

    // The returned object's wire bytes hash to the same canonical hash we
    // computed at mint time (re-derive: pop the payload back out and
    // SHA-256 it — `encode_signed_object` puts the canonical payload in
    // the `p` field).
    let v: Value = ciborium::de::from_reader(parsed.objects[0].as_slice()).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("object not a map");
    };
    let payload = m
        .into_iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(t), Value::Bytes(b)) if t == "p" => Some(b),
            _ => None,
        })
        .expect("payload field");
    let got_hash: [u8; 32] = Sha256::digest(&payload).into();
    assert_eq!(
        got_hash, move_hash,
        "returned payload re-hashes to move hash"
    );
}

/// Backfill for a key this instance has never seen returns
/// `unknown_chain` (request-level 400). Distinguishes "never-moved key"
/// from "you have everything we have" (the latter returns `complete:
/// true` mid-walk).
#[tokio::test]
async fn move_backfill_returns_unknown_chain_for_never_seen_key() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // A key whose owner has never pushed a move through B.
    let stranger = fresh_user_key();
    let key_hex: String = stranger
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let path = "/federation/v1/moves/backfill";
    let uri = format!("{path}?key={key_hex}");
    let (status, body_bytes) =
        send_envelope_signed_split(&harness, "a", "b", Method::GET, path, &uri, &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&body_bytes), "unknown_chain");
}

// ===========================================================================
// §12.6 source-instance key disposal
// ===========================================================================

/// An Applied outbound-from-self move on the source instance destroys the
/// moved-away user's signing-key material, active sessions, and WebAuthn
/// credentials, and flips `users.signup_method = 'federated'`. The `users`
/// row itself (and its pubkey) survives — authored content per §10.5.3
/// still resolves to a known identity.
#[tokio::test]
async fn applied_outbound_from_self_disposes_local_authority() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Local user U on A, fully provisioned through the prod-shaped bypass
    // path (users + signing_keys + sessions). Add a synthetic credentials
    // row so the test can observe its deletion too.
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
    // attestation, prior = birth move hash) so the §12.8 immutability gate
    // accepts it rather than rejecting a forged genesis_at.
    let att = read_birth_attestation(&a.state.db, &user_pub).await;
    let prior = read_current_move_hash(&a.state.db, &user_pub).await;
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    let (_hash, wire, _payload) = mint_move_with_attestation(
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

    // Sanity: the pub key field on `users` is unchanged so future
    // `/federation/v1/users/{pubkey}/...` requests still resolve.
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

/// A Superseded outbound-from-self move ALSO triggers disposal. The user
/// signed *something* asserting `from = self`, which is the testimony
/// §12.6 relies on; whichever branch of §12.4 latest-wins prevails on the
/// wire is independent of the receiver's duty to drop local authority.
/// Also pins the idempotency contract: applying disposal a second time
/// against an already-`signup_method = 'federated'` row is a no-op rather
/// than an error.
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
    let (_h, newer_wire, _p) = mint_move_with_attestation(
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

    // Second: older move (60 s earlier) for the same K. §12.4 latest-wins
    // resolves to `superseded`. The disposal call still fires on the
    // Superseded branch — `dispose_local_user_authority` sees
    // `signup_method = 'federated'` and returns a no-op.
    let older_ts = newer_ts.saturating_sub(60_000);
    let (_h, older_wire, _p) = mint_move_with_attestation(
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

/// An inbound move (`to_instance_key == self`, `from_instance_key !=
/// self`) does NOT touch the receiver's own `signing_keys` / `sessions` /
/// `credentials`. The §12.6 trigger is strictly "I am the source the user
/// is leaving" — the destination gains a user via §13 cross-instance
/// registration, not via disposal.
///
/// Concrete shape: on B, set up a *local* admin V (not the move subject
/// U). Push a move declaring "U moved from A to B" to B. Assert V's
/// authority on B is untouched — the inbound move's only DB effect on B is
/// the §12 projection layer.
#[tokio::test]
async fn inbound_to_self_does_not_dispose_other_local_users() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // V is a local admin on B who has nothing to do with U's move.
    let v = setup_admin(&b.router, "victor").await;
    insert_fake_credential(&b.state.db, &v.user_id).await;

    // U is a synthetic federated user whose private key never sat on
    // either instance — they exist purely as a signer for the move
    // payload. (`OsRng` keeps this independent of any harness state.)
    let user_key = fresh_user_key();
    let user_pub: [u8; 32] = *user_key.verifying_key().as_bytes();

    // U has no real birth anchor on either instance, so the synthetic move
    // forges a crypto-valid genesis attestation (off-graph birth instance)
    // that the receive path accepts as a first sighting.
    let from_key = *a.state.instance_key.public_bytes();
    let to_key = *b.state.instance_key.public_bytes();
    let (_hash, wire, _payload) = mint_move_with_attestation(
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

    // V's local authority on B is intact — the move was about U, and even
    // for U the receiver is the *destination*, not the source.
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
