#![cfg(feature = "test-auth")]

//! §11.9.5 cross-instance trust bootstrap (trust codes).
//!
//! Exercises the mint endpoint (`GET /api/me/trust-code`) and the redeem
//! endpoint (`POST /api/users/by-trust-code`) across the three resolution
//! branches (local row / known-remote stub / never-seen → seed) plus the
//! self and malformed-input guards and the first-seed-wins home rule.

mod common;

use axum::http::{Method, StatusCode};
use common::{
    body_json, json_request, send, setup_admin, signup_as, test_app, test_app_with_transport,
};
use prismoire_server::federation::trust_code;
use serde_json::json;

/// Decode 64-char lowercase hex into 32 bytes (test-side mirror of the
/// server's strict decoder).
fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "pubkey hex must be 64 chars");
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[tokio::test]
async fn mint_returns_parseable_code() {
    let (app, _state) = test_app().await;
    let alice = setup_admin(&app, "alice").await;

    let resp = send(
        &app,
        common::get_request("/api/me/trust-code", Some(&alice.cookie)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let code = body["code"].as_str().expect("code field");

    let parsed = trust_code::parse(code).expect("minted code round-trips");
    assert_eq!(parsed.display_name, "alice");
    assert_eq!(parsed.home_domain, "test.local");
    assert_eq!(hex_lower(&parsed.user_pubkey), alice.public_key_hex);
}

#[tokio::test]
async fn redeem_new_remote_seeds_stub_and_edge() {
    let (app, state) = test_app().await;
    let alice = setup_admin(&app, "alice").await;

    let user_pk = [0x07u8; 32];
    let inst_pk = [0x09u8; 32];
    let code = trust_code::mint("remotebob", "remote.example", &user_pk, &inst_pk);

    let resp = send(
        &app,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&alice.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["created"], true);
    assert_eq!(body["is_local"], false);
    assert_eq!(body["edge_type"], "trust");
    assert_eq!(body["pubkey_hex"], hex_lower(&user_pk));
    assert_eq!(body["home_instance_hex"], hex_lower(&inst_pk));

    // A federated stub row now exists, homed on the code's instance.
    let pk_slice: &[u8] = &user_pk;
    let home: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT home_instance FROM users WHERE public_key = ?")
            .bind(pk_slice)
            .fetch_one(&state.db)
            .await
            .expect("stub user row exists");
    assert_eq!(home.as_deref(), Some(&inst_pk[..]));

    // user_homes seeded with NULL move state (move-less seed).
    let row = sqlx::query_as::<_, (Vec<u8>, String, Option<Vec<u8>>, Option<i64>)>(
        "SELECT current_home_key, current_home_domain, current_move_hash, current_created_at \
         FROM user_homes WHERE user_key = ?",
    )
    .bind(pk_slice)
    .fetch_one(&state.db)
    .await
    .expect("user_homes seed exists");
    assert_eq!(row.0, inst_pk.to_vec());
    assert_eq!(row.1, "remote.example");
    assert_eq!(row.2, None, "move hash must be NULL on a trust-code seed");
    assert_eq!(
        row.3, None,
        "move created_at must be NULL on a trust-code seed"
    );

    // A live trust edge from alice toward the stub now exists.
    let edge_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM current_trust_edges cte \
           JOIN users tu ON tu.id = cte.target_user \
          WHERE cte.source_user = ? AND tu.public_key = ? AND cte.trust_type = 'trust'",
    )
    .bind(&alice.user_id)
    .bind(pk_slice)
    .fetch_one(&state.db)
    .await
    .expect("edge query");
    assert_eq!(edge_count, 1);
}

#[tokio::test]
async fn dry_run_does_not_mutate() {
    let (app, state) = test_app().await;
    let alice = setup_admin(&app, "alice").await;

    let user_pk = [0x11u8; 32];
    let inst_pk = [0x22u8; 32];
    let code = trust_code::mint("ghost", "remote.example", &user_pk, &inst_pk);

    let resp = send(
        &app,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&alice.cookie),
            &json!({ "code": code, "dry_run": true }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["created"], true, "dry-run reports it would seed");
    assert_eq!(body["display_name"], "ghost");
    assert_eq!(body["home_domain"], "remote.example");

    // Nothing was written.
    let pk_slice: &[u8] = &user_pk;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE public_key = ?")
        .bind(pk_slice)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(n, 0, "dry-run must not seed a stub");
}

#[tokio::test]
async fn redeem_local_user_is_local_no_seed() {
    let (app, state) = test_app().await;
    let alice = setup_admin(&app, "alice").await;
    let bob = signup_as(&app, &alice, "bob").await;
    let carol = signup_as(&app, &alice, "carol").await;

    // Build a code naming local bob, anchored to *this* instance's key.
    let bob_pk = hex32(&bob.public_key_hex);
    let inst_pk = *state.instance_key.public_bytes();
    let code = trust_code::mint("bob", "test.local", &bob_pk, &inst_pk);

    let resp = send(
        &app,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&carol.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["is_local"], true);
    assert_eq!(body["created"], false, "local user is never seeded");

    // Local bob never gets a user_homes row from this path.
    let pk_slice: &[u8] = &bob_pk;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_homes WHERE user_key = ?")
        .bind(pk_slice)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn redeem_existing_remote_keeps_first_home() {
    let (app, state) = test_app().await;
    let alice = setup_admin(&app, "alice").await;

    let user_pk = [0x33u8; 32];
    let inst1 = [0x44u8; 32];
    let inst2 = [0x55u8; 32];

    // First seed wins.
    let code1 = trust_code::mint("u", "first.example", &user_pk, &inst1);
    let r1 = send(
        &app,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&alice.cookie),
            &json!({ "code": code1 }),
        ),
    )
    .await;
    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(body_json(r1).await["created"], true);

    // A conflicting code (different home instance + domain) for the same
    // pubkey must NOT rewrite the established home — first-seed-wins.
    let code2 = trust_code::mint("u", "second.example", &user_pk, &inst2);
    let r2 = send(
        &app,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&alice.cookie),
            &json!({ "code": code2 }),
        ),
    )
    .await;
    assert_eq!(r2.status(), StatusCode::OK);
    let body2 = body_json(r2).await;
    assert_eq!(body2["created"], false, "row already exists");

    let pk_slice: &[u8] = &user_pk;
    let home: Vec<u8> =
        sqlx::query_scalar("SELECT current_home_key FROM user_homes WHERE user_key = ?")
            .bind(pk_slice)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(
        home,
        inst1.to_vec(),
        "home must remain the first-seeded one"
    );
    let domain: String =
        sqlx::query_scalar("SELECT current_home_domain FROM user_homes WHERE user_key = ?")
            .bind(pk_slice)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(domain, "first.example");
}

#[tokio::test]
async fn redeem_self_rejected() {
    let (app, _state) = test_app().await;
    let alice = setup_admin(&app, "alice").await;

    let resp = send(
        &app,
        common::get_request("/api/me/trust-code", Some(&alice.cookie)),
    )
    .await;
    let code = body_json(resp).await["code"].as_str().unwrap().to_string();

    let resp = send(
        &app,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&alice.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "self_trust_edge");
}

#[tokio::test]
async fn redeem_malformed_rejected() {
    let (app, _state) = test_app().await;
    let alice = setup_admin(&app, "alice").await;

    let resp = send(
        &app,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&alice.cookie),
            &json!({ "code": "definitely not a trust code" }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["code"], "invalid_trust_code");
}

#[tokio::test]
async fn admin_peers_surfaces_trust_code_suggestion() {
    let (app, _state) = test_app_with_transport(std::sync::Arc::new(
        prismoire_server::federation::transport::NullTransport,
    ))
    .await;
    let alice = setup_admin(&app, "alice").await;

    // Alice trust-codes a remote user homed on an un-peered instance.
    let user_pk = [0x66u8; 32];
    let inst_pk = [0x77u8; 32];
    let code = trust_code::mint("rmt", "peerless.example", &user_pk, &inst_pk);
    let r = send(
        &app,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&alice.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);

    let resp = send(
        &app,
        common::get_request("/api/admin/federation/peers", Some(&alice.cookie)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let suggestions = body["peering_suggestions"]
        .as_array()
        .expect("peering_suggestions array");
    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0]["domain"], "peerless.example");
    assert_eq!(suggestions[0]["pubkey_hex"], hex_lower(&inst_pk));
    assert_eq!(suggestions[0]["edge_count"], 1);
}
