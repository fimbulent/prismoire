//! Phase-9.5 integration tests: remote-author projection hydration.
//!
//! Covers the test gates from `docs/federation-impl-plan.md` Phase 9.5
//! that are reachable without standing up the full multi-instance
//! signed-payload pipeline:
//!
//! - Layer 0: `hydrate_stub_user` is idempotent on re-receive.
//! - Layer 0: local + federated rows with the same display-name
//!   skeleton coexist; the partial-UNIQUE index still rejects a
//!   second *local* collision.
//! - Layer 1: `GET /api/users/{username}/resolve` returns `unique`
//!   for the single-match case, `ambiguous` when two users share a
//!   skeleton, and dispatches the dotted long form
//!   `/@alice.{8hex}` to the matching row.
//!
//! Layer-1 projection tests for inbound `post-rev` / `thread-create`
//! payloads live in the multi-instance harness — they need a remote
//! peer signing real envelopes, and Phase 9 already exercises the
//! envelope dispatch end-to-end. The narrower tests here pin the
//! pieces Phase 9.5 introduced.

#![cfg(feature = "test-auth")]

mod common;

use common::{body_json, get_request, send, setup_admin, test_app};
use http::StatusCode;
use prismoire_server::federation::remote_users::hydrate_stub_user;

/// Build a deterministic 32-byte pubkey from a seed byte. Avoids
/// pulling in a CSPRNG just to mint test-distinct keys.
fn seeded_key(seed: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = seed;
    k[31] = seed.wrapping_add(0xa5);
    k
}

// ---------------------------------------------------------------------------
// Layer 0 — direct `hydrate_stub_user` exercises
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hydrate_stub_user_is_idempotent_on_re_receive() {
    let (_app, state) = test_app().await;
    let pubkey = seeded_key(0x11);
    let home = seeded_key(0x22);

    // First receipt — inserts a fresh `'federated'` row.
    let id_first = {
        let mut tx = state.db.begin().await.expect("begin tx");
        let id = hydrate_stub_user(&mut tx, &pubkey, "remote_alice", &home)
            .await
            .expect("first hydrate");
        tx.commit().await.expect("commit");
        id
    };

    // Second receipt with the same pubkey — must return the same id,
    // and must not insert a second row.
    let id_second = {
        let mut tx = state.db.begin().await.expect("begin tx");
        let id = hydrate_stub_user(&mut tx, &pubkey, "remote_alice", &home)
            .await
            .expect("second hydrate");
        tx.commit().await.expect("commit");
        id
    };

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
async fn local_and_federated_users_share_skeleton_without_collision() {
    let (app, state) = test_app().await;

    // Seed a local user named "alice" via the test-auth bypass. The
    // setup route inserts as `signup_method='admin'` with
    // `home_instance` NULL — partial-UNIQUE index applies.
    let _admin = setup_admin(&app, "alice").await;

    // A federated stub with a different pubkey but the same name
    // (and therefore the same skeleton) must hydrate without
    // tripping the partial-UNIQUE index, because the index is
    // `WHERE home_instance IS NULL` and the stub's home is set.
    let remote_pubkey = seeded_key(0x33);
    let remote_home = seeded_key(0x44);
    {
        let mut tx = state.db.begin().await.expect("begin tx");
        hydrate_stub_user(&mut tx, &remote_pubkey, "alice", &remote_home)
            .await
            .expect("federated stub hydrate must succeed despite skeleton clash");
        tx.commit().await.expect("commit");
    }

    // Both rows are present.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE display_name_skeleton = ?")
            .bind("alice")
            .fetch_one(&state.db)
            .await
            .expect("count");
    assert_eq!(count, 2, "both local and federated alice should exist");

    // Sanity: the partial-UNIQUE index still rejects a *second* local
    // alice. We insert directly with `home_instance = NULL` to
    // simulate a hypothetical second local signup with a colliding
    // skeleton; the index is `WHERE home_instance IS NULL`, so this
    // collides with the existing admin row.
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
// Layer 1 — `GET /api/users/{username}/resolve`
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
    {
        let mut tx = state.db.begin().await.expect("begin tx");
        hydrate_stub_user(&mut tx, &remote_pubkey, "alice", &remote_home)
            .await
            .expect("hydrate stub");
        tx.commit().await.expect("commit");
    }

    let req = get_request("/api/users/alice/resolve", Some(&admin.cookie));
    let response = send(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;

    assert_eq!(body["kind"], "ambiguous");
    let matches = body["matches"].as_array().expect("matches is an array");
    assert_eq!(matches.len(), 2, "two users share the skeleton");

    // One match should be the local admin (home_instance_hex null);
    // the other the federated stub (non-null hex matching remote_home).
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
    {
        let mut tx = state.db.begin().await.expect("begin tx");
        hydrate_stub_user(&mut tx, &remote_pubkey, "alice", &remote_home)
            .await
            .expect("hydrate stub");
        tx.commit().await.expect("commit");
    }

    // The remote stub's pubkey starts with `cc` — so the suffix
    // `cc0000...` (first 8 hex chars of the seeded key) selects it.
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
    // effectively random — but starting with eight zeros is still a
    // 2^-32 chance, well below test-flake territory.
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
