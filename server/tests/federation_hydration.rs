#![cfg(feature = "test-auth")]
//! Cross-instance stub hydration + upgrade integration tests (§13 / Phase 9.5 / 9.7).
//!
//! Consolidates the two formerly-separate phase files that both concern
//! filling in placeholder/stub rows for remote authors on demand and
//! later promoting such a stub to a fully-homed local account:
//!
//! - **Phase 9.5 stub hydration + disambiguation.** `hydrate_stub_user`
//!   inserts a `signup_method = 'federated'` row on first receipt and is
//!   idempotent on re-receive (same `users.id`, no duplicate row). A
//!   federated stub coexists with a local user sharing the same
//!   display-name skeleton because the partial-UNIQUE index is scoped
//!   `WHERE home_instance IS NULL`; a *second local* skeleton collision
//!   still rejects. `GET /api/users/{username}/resolve` returns `unique`
//!   for a single match, `ambiguous` when a local + federated row share a
//!   skeleton, dispatches the dotted long form `/@alice.{8hex}` to the
//!   matching pubkey-prefix row, and 404s both on a no-prefix-match dotted
//!   form and on an unknown skeleton.
//! - **Phase 9.7 §13 stub upgrade-in-place.** `upgrade_federated_stub_in_place`
//!   flips `signup_method` → `cross_instance_register` and `home_instance`
//!   → NULL, attaches a credential row and a signing-key row, and keeps the
//!   `users.id` stable so pre-existing projection rows that reference the
//!   stub (here a stub-authored `trust_edges` row) still resolve under the
//!   upgraded identity. The helper fails closed on a `public_key` mismatch
//!   between bootstrap and stub row (the stub stays untouched), and the
//!   display-name recheck the `complete` handler runs exempts the stub
//!   being upgraded via `AND id != ?`.
//!
//! The wire-level Layer-1 happy path for §13 `complete` is out of reach
//! here: it runs `webauthn-rs`'s `finish_passkey_registration`, which
//! needs a real browser-side attestation (covered by the Layer-2 smoke
//! suite). The Layer-0 tests target `hydrate_stub_user` /
//! `upgrade_federated_stub_in_place` directly — they carry the whole
//! storage-layer transformation — and the Layer-1 tests probe the live
//! `/resolve` route.
//!
//! Every scenario drives the function under test directly or probes a
//! handler over the in-process router, so none use the
//! [`settle`](common::federation::settle) convergence driver — there is no
//! `frontier_fanout_loop` + poll race to replace.

mod common;

use common::{body_json, get_request, send, setup_admin, test_app};
use ed25519_dalek::SigningKey;
use http::StatusCode;
use prismoire_server::auth::LocalUserBootstrap;
use prismoire_server::federation::registration::upgrade_federated_stub_in_place;
use prismoire_server::federation::remote_users::hydrate_stub_user;
use rand::SeedableRng;
use rand::rngs::StdRng;
use uuid::Uuid;

/// Build a deterministic 32-byte pubkey from a seed byte. Avoids pulling
/// in a CSPRNG just to mint test-distinct (non-Ed25519) keys for the
/// hydration-layer tests, which treat the pubkey as an opaque BLOB.
fn seeded_key(seed: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = seed;
    k[31] = seed.wrapping_add(0xa5);
    k
}

/// Deterministic Ed25519 signer for the upgrade-layer tests, which need
/// a real verifying key whose bytes become the stub's `public_key`.
fn seeded_signer(seed: u8) -> SigningKey {
    let mut rng = StdRng::seed_from_u64(seed as u64);
    SigningKey::generate(&mut rng)
}

/// Hydrate a `signup_method = 'federated'` stub and return its
/// `users.id`. Wraps `hydrate_stub_user` in a fresh transaction so
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
// Phase 9.5 — hydrate_stub_user (Layer 0)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hydrate_stub_user_is_idempotent_on_re_receive() {
    let (_app, state) = test_app().await;
    let pubkey = seeded_key(0x11);
    let home = seeded_key(0x22);

    // First receipt — inserts a fresh `'federated'` row.
    let id_first = hydrate_stub(&state.db, &pubkey, "remote_alice", &home).await;

    // Second receipt with the same pubkey — must return the same id, and
    // must not insert a second row.
    let id_second = hydrate_stub(&state.db, &pubkey, "remote_alice", &home).await;

    assert_eq!(
        id_first, id_second,
        "second hydrate must return the same users.id"
    );

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE public_key = ?")
        .bind(&pubkey[..])
        .fetch_one(&state.db)
        .await
        .expect("count");
    assert_eq!(count, 1, "no duplicate users row inserted");
}

#[tokio::test]
#[ignore = "fakes setup state via raw INSERT; rewrite to drive real APIs before re-enabling"]
async fn local_and_federated_users_share_skeleton_without_collision() {
    let (app, state) = test_app().await;

    // Seed a local user named "alice" via the test-auth bypass. The setup
    // route inserts as `signup_method='admin'` with `home_instance` NULL —
    // partial-UNIQUE index applies.
    let _admin = setup_admin(&app, "alice").await;

    // A federated stub with a different pubkey but the same name (and
    // therefore the same skeleton) must hydrate without tripping the
    // partial-UNIQUE index, because the index is `WHERE home_instance IS
    // NULL` and the stub's home is set.
    let remote_pubkey = seeded_key(0x33);
    let remote_home = seeded_key(0x44);
    hydrate_stub(&state.db, &remote_pubkey, "alice", &remote_home).await;

    // Both rows are present.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE display_name_skeleton = ?")
            .bind("alice")
            .fetch_one(&state.db)
            .await
            .expect("count");
    assert_eq!(count, 2, "both local and federated alice should exist");

    // Sanity: the partial-UNIQUE index still rejects a *second* local
    // alice. We insert directly with `home_instance = NULL` to simulate a
    // hypothetical second local signup with a colliding skeleton; the index
    // is `WHERE home_instance IS NULL`, so this collides with the existing
    // admin row.
    let dup_pubkey = seeded_key(0x55);
    let dup_id = uuid::Uuid::new_v4().to_string();
    let pubkey_slice: &[u8] = dup_pubkey.as_slice();
    let res = sqlx::query(
        "INSERT INTO users (id, display_name, display_name_skeleton, signup_method, \
                            public_key, home_instance) \
         VALUES (?, ?, ?, 'invited', ?, NULL)",
    )
    .bind(&dup_id)
    .bind("alice")
    .bind("alice")
    .bind(pubkey_slice)
    .execute(&state.db)
    .await;
    assert!(
        res.is_err(),
        "second local alice should violate the partial-UNIQUE skeleton index"
    );
}

// ---------------------------------------------------------------------------
// Phase 9.5 — GET /api/users/{username}/resolve (Layer 1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_endpoint_returns_unique_for_single_match() {
    let (app, _state) = test_app().await;
    let admin = setup_admin(&app, "alice").await;

    let req = get_request("/api/users/alice/resolve", Some(&admin.cookie));
    let response = send(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;

    assert_eq!(body["kind"], "unique");
    assert_eq!(body["user"]["display_name"], "alice");
    let hex = body["user"]["public_key_hex"]
        .as_str()
        .expect("public_key_hex string");
    assert_eq!(hex.len(), 64, "public_key_hex is 32 bytes hex-encoded");
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "public_key_hex must be lowercase hex"
    );
    assert!(
        body["user"]["home_instance_hex"].is_null(),
        "local user has home_instance NULL"
    );
}

#[tokio::test]
async fn resolve_endpoint_returns_ambiguous_for_skeleton_collision() {
    let (app, state) = test_app().await;
    let admin = setup_admin(&app, "alice").await;

    // Hydrate a federated stub that shares the same skeleton.
    let remote_pubkey = seeded_key(0xaa);
    let remote_home = seeded_key(0xbb);
    hydrate_stub(&state.db, &remote_pubkey, "alice", &remote_home).await;

    let req = get_request("/api/users/alice/resolve", Some(&admin.cookie));
    let response = send(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;

    assert_eq!(body["kind"], "ambiguous");
    let matches = body["matches"].as_array().expect("matches is an array");
    assert_eq!(matches.len(), 2, "two users share the skeleton");

    // One match should be the local admin (home_instance_hex null); the
    // other the federated stub (non-null hex matching remote_home).
    let mut saw_local = false;
    let mut saw_remote = false;
    for m in matches {
        if m["home_instance_hex"].is_null() {
            saw_local = true;
        } else if let Some(h) = m["home_instance_hex"].as_str() {
            // The 32-byte remote_home maps to a 64-hex-char string.
            assert_eq!(h.len(), 64);
            saw_remote = true;
        }
    }
    assert!(saw_local && saw_remote, "matches must cover both rows");
}

#[tokio::test]
async fn resolve_endpoint_dotted_form_selects_specific_match() {
    let (app, state) = test_app().await;
    let admin = setup_admin(&app, "alice").await;

    let remote_pubkey = seeded_key(0xcc);
    let remote_home = seeded_key(0xdd);
    hydrate_stub(&state.db, &remote_pubkey, "alice", &remote_home).await;

    // The remote stub's pubkey starts with `cc` — so the suffix `cc0000...`
    // (first 8 hex chars of the seeded key) selects it.
    let suffix: String = remote_pubkey[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(suffix.len(), 8);

    let path = format!("/api/users/alice.{suffix}/resolve");
    let req = get_request(&path, Some(&admin.cookie));
    let response = send(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;

    assert_eq!(body["kind"], "unique");
    let hex = body["user"]["public_key_hex"]
        .as_str()
        .expect("public_key_hex string");
    assert!(
        hex.starts_with(&suffix),
        "selected row's pubkey-prefix must match the dotted suffix"
    );
}

#[tokio::test]
async fn resolve_endpoint_dotted_form_404s_on_no_prefix_match() {
    let (app, _state) = test_app().await;
    let admin = setup_admin(&app, "alice").await;

    // `00000000` deliberately does not match the seeded admin pubkey.
    // setup_admin generates a real Ed25519 keypair so the prefix is
    // effectively random — but starting with eight zeros is still a 2^-32
    // chance, well below test-flake territory.
    let req = get_request("/api/users/alice.00000000/resolve", Some(&admin.cookie));
    let response = send(&app, req).await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "dotted form with no matching prefix is 404"
    );
}

#[tokio::test]
async fn resolve_endpoint_404s_unknown_skeleton() {
    let (app, _state) = test_app().await;
    let admin = setup_admin(&app, "alice").await;

    let req = get_request("/api/users/nobody/resolve", Some(&admin.cookie));
    let response = send(&app, req).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Phase 9.7 — upgrade_federated_stub_in_place (Layer 0)
// ---------------------------------------------------------------------------

/// Stub upgrade flips `signup_method` and `home_instance`, attaches a
/// credential row and a signing-key row, and keeps the `users.id`
/// unchanged. (Implicitly pins the upgrade *arm* of `complete`'s
/// `public_key`-collision dispatch: a `'federated'` row is the case that
/// promotes, vs. any other `signup_method` which must reject.)
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

    // Drive the upgrade. The `passkey_*` bytes are arbitrary: the schema
    // treats them as opaque BLOBs, and this Layer-0 test is pinning the SQL
    // transformation, not WebAuthn semantics.
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

/// Projection rows that reference the stub via `users.id` still resolve
/// after the upgrade. This is the whole reason in-place upgrade exists: the
/// user's federated content (here a trust-edge the stub authored, but the
/// same applies to post_revisions / profile_revisions) must remain readable
/// under the upgraded identity rather than being abandoned.
#[tokio::test]
#[ignore = "fakes setup state via raw INSERT; rewrite to drive real APIs before re-enabling"]
async fn upgrade_in_place_preserves_authored_trust_edge() {
    let (_app, state) = test_app().await;

    let alice_signer = seeded_signer(0x22);
    let alice_pubkey = *alice_signer.verifying_key().as_bytes();
    let bob_signer = seeded_signer(0x33);
    let bob_pubkey = *bob_signer.verifying_key().as_bytes();
    let home = [0xbbu8; 32];

    let alice_id = hydrate_stub(&state.db, &alice_pubkey, "alice", &home).await;
    let bob_id = hydrate_stub(&state.db, &bob_pubkey, "bob", &home).await;

    // Plant a trust_edges row authored by the stub. We don't need a real
    // signed payload — the FK target test only depends on the row
    // referencing `alice_id` via `source_user`.
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

/// Defense in depth at the storage layer: if a caller mis-routes into
/// `upgrade_federated_stub_in_place` with a `bootstrap.public_key` that
/// does not match the stub row's `users.public_key`, the helper must fail
/// closed rather than silently rewriting an unrelated user's identity
/// columns. The `AND public_key = ?` clause in the UPDATE is what enforces
/// this — this would only happen in practice if a future refactor stripped
/// the pubkey predicate from the dispatch SELECT in `complete`, but pinning
/// the storage-layer behavior keeps that hypothetical bug from corrupting
/// rows.
#[tokio::test]
async fn upgrade_in_place_rejects_pubkey_mismatch() {
    let (_app, state) = test_app().await;

    let stub_signer = seeded_signer(0x66);
    let stub_pubkey = *stub_signer.verifying_key().as_bytes();
    let home = [0xddu8; 32];

    let stub_id = hydrate_stub(&state.db, &stub_pubkey, "alice", &home).await;

    // Bootstrap carries a *different* signer/pubkey — the kind of mismatch
    // the dispatch SELECT in `complete` is supposed to make impossible
    // upstream.
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
        // Whether commit or rollback would have happened, the helper must
        // have refused — drop the tx without committing.
        drop(tx);
        r
    };
    assert!(
        result.is_err(),
        "upgrade_federated_stub_in_place must fail when bootstrap.public_key \
         does not match the stub row's public_key",
    );

    // Stub row must be untouched: still federated, still carrying its
    // remote home_instance.
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

/// The display-name uniqueness pre-check in `complete` exempts the stub
/// being upgraded via `AND id != ?`. This test pins the same SELECT shape
/// used in the handler: a stub-clashing skeleton must be reported as "not a
/// conflict" once the stub's id is excluded, but the same SELECT without
/// the exclusion still matches the stub — confirming the clause is
/// load-bearing rather than incidental.
#[tokio::test]
async fn display_name_recheck_exempts_stub_being_upgraded() {
    let (_app, state) = test_app().await;

    let signer = seeded_signer(0x44);
    let pubkey = *signer.verifying_key().as_bytes();
    let home = [0xccu8; 32];

    let stub_id = hydrate_stub(&state.db, &pubkey, "alice", &home).await;

    // Same SELECT the handler runs. Without the `AND id != ?` clause this
    // would match the stub itself and the upgrade would falsely reject as
    // `DisplayNameTaken`.
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

    // For sanity: WITHOUT the `id != ?` exclusion the stub does match,
    // confirming the clause is load-bearing rather than incidental.
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
