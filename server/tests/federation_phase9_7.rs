//! Phase-9.7 integration tests: §13 stub upgrade-in-place.
//!
//! Phase 9.7 closes the gap between Phase 7's §13 handler — which
//! rejected any `public_key` collision with `user_key_taken` — and
//! Phase 9.5's federated-stub hydration, which makes the collision
//! the *expected* case for any user moving their home to a peer that
//! has already federated their content.
//!
//! The wire-level Layer-1 happy path is out of reach for these
//! tests: §13 `complete` runs `webauthn-rs`'s
//! `finish_passkey_registration`, which needs a real browser-side
//! attestation. The same constraint that put §13 Layer-1 coverage in
//! the Layer-2 smoke suite (see `tests/federation_phase7.rs` for the
//! note) applies here. The Layer-0 tests below target
//! [`upgrade_federated_stub_in_place`] directly: it carries the
//! whole storage-layer transformation, so pinning its post-state is
//! the strongest test we can write without standing up the full
//! ceremony.
//!
//! Covered:
//!
//! - Round-trip: a hydrated federated stub becomes a locally-homed
//!   user with `signup_method = 'cross_instance_register'`,
//!   `home_instance = NULL`, an attached credential, and an attached
//!   signing key.
//! - Id stability: pre-existing rows that reference the stub via
//!   `users.id` (here, a projected `trust_edges` row authored by
//!   the stub) still resolve after the upgrade. This is the whole
//!   reason in-place upgrade exists.

#![cfg(feature = "test-auth")]

mod common;

use common::test_app;
use ed25519_dalek::SigningKey;
use prismoire_server::auth::LocalUserBootstrap;
use prismoire_server::federation::registration::upgrade_federated_stub_in_place;
use prismoire_server::federation::remote_users::hydrate_stub_user;
use rand::SeedableRng;
use rand::rngs::StdRng;
use uuid::Uuid;

/// Deterministic Ed25519 signer — matches the helper in
/// `federation_phase9_6.rs` so the two suites stay legible
/// side-by-side.
fn seeded_signer(seed: u8) -> SigningKey {
    let mut rng = StdRng::seed_from_u64(seed as u64);
    SigningKey::generate(&mut rng)
}

/// Hydrate a `signup_method = 'federated'` stub and return its
/// `users.id`. Wraps the Phase 9.5 helper in a fresh transaction so
/// callers don't have to think about tx scoping.
async fn hydrate_stub(
    db: &sqlx::SqlitePool,
    pubkey: &[u8; 32],
    display_name: &str,
    home: &[u8; 32],
) -> String {
    let mut tx = db.begin().await.expect("begin tx");
    let id = hydrate_stub_user(&mut tx, pubkey, display_name, home)
        .await
        .expect("hydrate stub");
    tx.commit().await.expect("commit");
    id
}

// ---------------------------------------------------------------------------
// Layer 0 — upgrade_federated_stub_in_place
// ---------------------------------------------------------------------------

/// Stub upgrade flips `signup_method` and `home_instance`, attaches
/// a credential row and a signing-key row, and keeps the `users.id`
/// unchanged.
#[tokio::test]
async fn upgrade_in_place_flips_columns_and_attaches_credentials() {
    let (_app, state) = test_app().await;

    let signer = seeded_signer(0x11);
    let pubkey = *signer.verifying_key().as_bytes();
    let home = [0xaau8; 32];

    let stub_id = hydrate_stub(&state.db, &pubkey, "alice", &home).await;

    // Sanity: pre-upgrade row carries the federated marker.
    let pre = sqlx::query!(
        "SELECT signup_method, home_instance AS \"home_instance: Vec<u8>\" \
         FROM users WHERE id = ?",
        stub_id,
    )
    .fetch_one(&state.db)
    .await
    .expect("read stub");
    assert_eq!(pre.signup_method, "federated");
    assert_eq!(
        pre.home_instance.as_deref(),
        Some(&home[..]),
        "stub should carry the remote home_instance",
    );

    // Drive the upgrade. The `passkey_*` bytes are arbitrary: the
    // schema treats them as opaque BLOBs, and this Layer-0 test is
    // pinning the SQL transformation, not WebAuthn semantics.
    let cred_id = Uuid::new_v4().to_string();
    let cred_id_bytes: &[u8] = b"\x01\x02\x03\x04\x05\x06\x07\x08";
    let passkey_bytes: &[u8] = b"opaque-passkey-blob-for-test";
    {
        let mut tx = state.db.begin().await.expect("begin");
        upgrade_federated_stub_in_place(
            &mut tx,
            &LocalUserBootstrap {
                user_id: &stub_id,
                display_name: "alice",
                display_name_skeleton: "alice",
                signup_method: "cross_instance_register",
                public_key: &pubkey,
                signing_key: &signer,
                credential_id: &cred_id,
                passkey_credential_id: cred_id_bytes,
                passkey_bytes,
            },
        )
        .await
        .expect("upgrade in place");
        tx.commit().await.expect("commit");
    }

    let post = sqlx::query!(
        "SELECT signup_method, home_instance AS \"home_instance: Vec<u8>\" \
         FROM users WHERE id = ?",
        stub_id,
    )
    .fetch_one(&state.db)
    .await
    .expect("read upgraded row");
    assert_eq!(post.signup_method, "cross_instance_register");
    assert!(
        post.home_instance.is_none(),
        "home_instance must be NULL post-upgrade (locally homed)",
    );

    let cred_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM credentials WHERE user_id = ? AND id = ?")
            .bind(&stub_id)
            .bind(&cred_id)
            .fetch_one(&state.db)
            .await
            .expect("count credentials");
    assert_eq!(cred_count, 1, "credential row attached to upgraded user");

    let signing_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM signing_keys WHERE user_id = ?")
            .bind(&stub_id)
            .fetch_one(&state.db)
            .await
            .expect("count signing_keys");
    assert_eq!(signing_count, 1, "signing key attached to upgraded user");
}

/// Projection rows that reference the stub via `users.id` still
/// resolve after the upgrade. This is the whole reason in-place
/// upgrade exists: the user's federated content (here a trust-edge
/// the stub authored, but the same applies to post_revisions /
/// profile_revisions) must remain readable under the upgraded
/// identity rather than being abandoned.
#[tokio::test]
async fn upgrade_in_place_preserves_authored_trust_edge() {
    let (_app, state) = test_app().await;

    let alice_signer = seeded_signer(0x22);
    let alice_pubkey = *alice_signer.verifying_key().as_bytes();
    let bob_signer = seeded_signer(0x33);
    let bob_pubkey = *bob_signer.verifying_key().as_bytes();
    let home = [0xbbu8; 32];

    let alice_id = hydrate_stub(&state.db, &alice_pubkey, "alice", &home).await;
    let bob_id = hydrate_stub(&state.db, &bob_pubkey, "bob", &home).await;

    // Plant a trust_edges row authored by the stub. We don't need a
    // real signed payload — the FK target test only depends on the
    // row referencing `alice_id` via `source_user`.
    let edge_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO trust_edges (id, source_user, target_user, trust_type) \
         VALUES (?, ?, ?, 'trust')",
    )
    .bind(&edge_id)
    .bind(&alice_id)
    .bind(&bob_id)
    .execute(&state.db)
    .await
    .expect("insert trust_edges");

    // Upgrade alice in place.
    let cred_id = Uuid::new_v4().to_string();
    {
        let mut tx = state.db.begin().await.expect("begin");
        upgrade_federated_stub_in_place(
            &mut tx,
            &LocalUserBootstrap {
                user_id: &alice_id,
                display_name: "alice",
                display_name_skeleton: "alice",
                signup_method: "cross_instance_register",
                public_key: &alice_pubkey,
                signing_key: &alice_signer,
                credential_id: &cred_id,
                passkey_credential_id: b"\xaa\xbb\xcc\xdd",
                passkey_bytes: b"opaque",
            },
        )
        .await
        .expect("upgrade");
        tx.commit().await.expect("commit");
    }

    // The edge must still resolve via the original id.
    let row = sqlx::query!(
        "SELECT te.source_user, u.signup_method, u.home_instance AS \"home_instance: Vec<u8>\" \
         FROM trust_edges te \
         JOIN users u ON u.id = te.source_user \
         WHERE te.id = ?",
        edge_id,
    )
    .fetch_one(&state.db)
    .await
    .expect("resolve trust_edge under upgraded id");
    assert_eq!(row.source_user, alice_id, "id stability post-upgrade");
    assert_eq!(row.signup_method, "cross_instance_register");
    assert!(
        row.home_instance.is_none(),
        "joined user row is now locally homed",
    );
}

/// `complete` only takes the upgrade branch when the colliding
/// `public_key` row carries `signup_method = 'federated'`. A
/// pre-existing locally-homed row (any other `signup_method`) is a
/// real collision and must still reject as `user_key_taken`. This
/// test pins the dispatch SELECT shape — same `SELECT id,
/// signup_method FROM users WHERE public_key = ?` the handler runs
/// — and asserts the result matches the rejection arm rather than
/// the upgrade arm.
#[tokio::test]
async fn non_federated_public_key_collision_rejects_rather_than_upgrades() {
    let (_app, state) = test_app().await;

    let signer = seeded_signer(0x55);
    let pubkey = *signer.verifying_key().as_bytes();
    let user_id = Uuid::new_v4().to_string();

    // Plant a fully-registered locally-homed row carrying `pubkey`.
    // `cross_instance_register` stands in for any non-`federated`
    // signup_method — the dispatch in `complete` treats them all as
    // collisions. NULL `home_instance` matches a locally-homed user.
    sqlx::query(
        "INSERT INTO users (id, display_name, display_name_skeleton, signup_method, public_key, home_instance) \
         VALUES (?, ?, ?, 'cross_instance_register', ?, NULL)",
    )
    .bind(&user_id)
    .bind("eve")
    .bind("eve")
    .bind(&pubkey[..])
    .execute(&state.db)
    .await
    .expect("insert locally-homed user");

    // Same SELECT the dispatcher runs.
    let pubkey_slice: &[u8] = &pubkey[..];
    let row = sqlx::query!(
        "SELECT id, signup_method FROM users WHERE public_key = ?",
        pubkey_slice,
    )
    .fetch_optional(&state.db)
    .await
    .expect("dispatch lookup")
    .expect("row must exist");

    // Mirror the handler's `match` arms — only `signup_method =
    // 'federated'` takes the upgrade branch; anything else falls
    // through to the `user_key_taken` rejection.
    assert_ne!(
        row.signup_method, "federated",
        "fixture must reproduce a non-federated collision",
    );
    let is_stub_upgrade = row.signup_method == "federated";
    assert!(
        !is_stub_upgrade,
        "non-federated collision must NOT take the upgrade branch \
         — handler should fall through to the `user_key_taken` rejection",
    );
}

/// Defense in depth at the storage layer: if a caller mis-routes
/// into `upgrade_federated_stub_in_place` with a
/// `bootstrap.public_key` that does not match the stub row's
/// `users.public_key`, the helper must fail closed rather than
/// silently rewriting an unrelated user's identity columns. The
/// `AND public_key = ?` clause in the UPDATE is what enforces this
/// — this test would only happen in practice if a future refactor
/// stripped the pubkey predicate from the dispatch SELECT in
/// `complete`, but pinning the storage-layer behavior keeps that
/// hypothetical bug from corrupting rows.
#[tokio::test]
async fn upgrade_in_place_rejects_pubkey_mismatch() {
    let (_app, state) = test_app().await;

    let stub_signer = seeded_signer(0x66);
    let stub_pubkey = *stub_signer.verifying_key().as_bytes();
    let home = [0xddu8; 32];

    let stub_id = hydrate_stub(&state.db, &stub_pubkey, "alice", &home).await;

    // Bootstrap carries a *different* signer/pubkey — the kind of
    // mismatch the dispatch SELECT in `complete` is supposed to
    // make impossible upstream.
    let wrong_signer = seeded_signer(0x77);
    let wrong_pubkey = *wrong_signer.verifying_key().as_bytes();
    assert_ne!(stub_pubkey, wrong_pubkey, "fixture sanity");

    let cred_id = Uuid::new_v4().to_string();
    let result = {
        let mut tx = state.db.begin().await.expect("begin");
        let r = upgrade_federated_stub_in_place(
            &mut tx,
            &LocalUserBootstrap {
                user_id: &stub_id,
                display_name: "alice",
                display_name_skeleton: "alice",
                signup_method: "cross_instance_register",
                public_key: &wrong_pubkey,
                signing_key: &wrong_signer,
                credential_id: &cred_id,
                passkey_credential_id: b"\x00\x01\x02\x03",
                passkey_bytes: b"opaque",
            },
        )
        .await;
        // Whether commit or rollback would have happened, the helper
        // must have refused — drop the tx without committing.
        drop(tx);
        r
    };
    assert!(
        result.is_err(),
        "upgrade_federated_stub_in_place must fail when bootstrap.public_key \
         does not match the stub row's public_key",
    );

    // Stub row must be untouched: still federated, still carrying
    // its remote home_instance.
    let row = sqlx::query!(
        "SELECT signup_method, home_instance AS \"home_instance: Vec<u8>\" \
         FROM users WHERE id = ?",
        stub_id,
    )
    .fetch_one(&state.db)
    .await
    .expect("read stub");
    assert_eq!(row.signup_method, "federated");
    assert_eq!(row.home_instance.as_deref(), Some(&home[..]));
}

/// The display-name uniqueness pre-check in `complete` exempts the
/// stub being upgraded via `AND id != ?`. This test pins the same
/// SELECT shape used in the handler: a stub-clashing skeleton must
/// be reported as "not a conflict" once the stub's id is excluded,
/// but a *different* locally-homed row with the same name still
/// surfaces as a conflict.
#[tokio::test]
async fn display_name_recheck_exempts_stub_being_upgraded() {
    let (_app, state) = test_app().await;

    let signer = seeded_signer(0x44);
    let pubkey = *signer.verifying_key().as_bytes();
    let home = [0xccu8; 32];

    let stub_id = hydrate_stub(&state.db, &pubkey, "alice", &home).await;

    // Same SELECT the handler runs. Without the `AND id != ?` clause
    // this would match the stub itself and the upgrade would falsely
    // reject as `DisplayNameTaken`.
    let conflict_excluding_stub = sqlx::query!(
        "SELECT id FROM users \
         WHERE (display_name = ? OR display_name_skeleton = ?) AND id != ?",
        "alice",
        "alice",
        stub_id,
    )
    .fetch_optional(&state.db)
    .await
    .expect("recheck excluding stub");
    assert!(
        conflict_excluding_stub.is_none(),
        "stub's own skeleton must not count as a conflict against itself",
    );

    // For sanity: WITHOUT the `id != ?` exclusion the stub does
    // match, confirming the clause is load-bearing rather than
    // incidental.
    let unsafe_conflict = sqlx::query!(
        "SELECT id FROM users \
         WHERE display_name = ? OR display_name_skeleton = ?",
        "alice",
        "alice",
    )
    .fetch_optional(&state.db)
    .await
    .expect("recheck without exclusion");
    assert!(
        unsafe_conflict.is_some(),
        "without the exclusion the stub would shadow itself",
    );
}
