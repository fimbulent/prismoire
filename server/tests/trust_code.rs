#![cfg(feature = "test-auth")]

//! §11.9.5 cross-instance trust bootstrap (trust codes).
//!
//! Exercises the mint endpoint (`GET /api/me/trust-code`) and the redeem
//! endpoint (`POST /api/users/by-trust-code`) across the three resolution
//! branches (local row / known-remote stub / never-seen → seed) plus the
//! self and malformed-input guards and the first-seed-wins home rule.

mod common;

use axum::http::{Method, StatusCode};
use ciborium::value::Value;
use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};
use common::{
    body_json, get_request, json_request, refresh_trust_graph, send, setup_admin, signup_as,
    test_app, test_app_with_transport,
};
use prismoire_server::federation::frontier::frontier_fanout_loop;
use prismoire_server::federation::trust_code;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Notify;

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

/// §6.3 WireFormat `{ "p", "s" }` for one signed object. Mirrors what a
/// real edge sender puts on the wire (copied from `federation_phase5`).
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

/// §9.1 edges push body `{ "edges": [bstr, ...] }`.
fn encode_edges_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("edges".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + wires.iter().map(|w| w.len()).sum::<usize>());
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// Pull the per-edge `status` strings out of a `/federation/v1/edges`
/// response `{ "results": [{ status, .. }, ..] }`.
fn parse_result_statuses(body: &[u8]) -> Vec<String> {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("results body is not a map");
    };
    let results = m
        .into_iter()
        .find_map(|(k, v)| matches!(&k, Value::Text(t) if t == "results").then_some(v))
        .expect("missing `results` field");
    let Value::Array(arr) = results else {
        panic!("`results` is not an array");
    };
    arr.into_iter()
        .map(|entry| {
            let Value::Map(fields) = entry else {
                panic!("result entry not a map");
            };
            fields
                .into_iter()
                .find_map(|(k, v)| match (k, v) {
                    (Value::Text(name), Value::Text(s)) if name == "status" => Some(s),
                    _ => None,
                })
                .expect("result entry missing `status`")
        })
        .collect()
}

/// Spin until `predicate` is true or `timeout_ms` elapses.
async fn poll_until<F, Fut>(timeout_ms: u64, mut predicate: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        if predicate().await {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
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

    // The redeem path never seeds a *remote* home for a local user.
    // Bob does carry a `user_homes` row — born locally via `signup_as`,
    // his genesis move declares this instance as home — but redeem must
    // leave it pointing at the local instance, never reseed it remote.
    let pk_slice: &[u8] = &bob_pk;
    let inst_pk_slice: &[u8] = &inst_pk;
    let home_key: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT current_home_key FROM user_homes WHERE user_key = ?")
            .bind(pk_slice)
            .fetch_optional(&state.db)
            .await
            .unwrap();
    assert_eq!(
        home_key.as_deref(),
        Some(inst_pk_slice),
        "local bob's home stays this instance; redeem must not reseed it remote"
    );
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

/// §11.9.5 root-cause guard: account birth must mint a genesis `profile`
/// revision, even when the user never edits their bio.
///
/// `profile` is the only signed object carrying `display_name`, so it is
/// what a peer needs to hydrate this identity's stub. Before the birth
/// paths minted one, a setup-admin (or invited signup) that never touched
/// its bio had no `profile` row at all — an inbound trust edge naming it
/// on a peer stayed `EndpointMissing` and never projected, so the trustor
/// never saw the edge. Both birth paths now emit an empty-bio chain-root
/// revision; this locks that in for `setup_complete` and `signup_complete`.
#[tokio::test]
async fn account_birth_mints_genesis_profile_revision() {
    let (app, state) = test_app().await;
    let alice = setup_admin(&app, "alice").await;
    let bob = signup_as(&app, &alice, "bob").await;

    for who in [&alice, &bob] {
        // Exactly one revision, empty bio, NULL prior hash (chain root).
        let row = sqlx::query_as::<_, (i64, String, Option<Vec<u8>>)>(
            "SELECT COUNT(*), COALESCE(MIN(bio), ''), MIN(prior_profile_hash) \
             FROM profile_revisions WHERE user_id = ?",
        )
        .bind(&who.user_id)
        .fetch_one(&state.db)
        .await
        .expect("profile_revisions query");
        assert_eq!(row.0, 1, "expected exactly one genesis profile revision");
        assert_eq!(row.1, "", "genesis bio must be empty");
        assert_eq!(row.2, None, "genesis revision must have NULL prior hash");

        // The canonical bytes were dual-written so federation can serve
        // and verify them (this is what stub-hydration backfills).
        let signed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM signed_objects so \
               JOIN profile_revisions pr ON pr.canonical_hash = so.canonical_hash \
              WHERE pr.user_id = ? AND so.inner_class = 'profile'",
        )
        .bind(&who.user_id)
        .fetch_one(&state.db)
        .await
        .expect("signed_objects query");
        assert_eq!(signed, 1, "genesis profile must be in signed_objects");
    }
}

/// Read-API end-to-end: a cross-instance trust edge created purely
/// through the public `/api` surface (mint a trust code on the target
/// instance, redeem it on the source instance) must then be visible to
/// the trustor through the trust read endpoints. No `/federation/v1`
/// route is driven directly — this is the path a real operator takes,
/// and the read surface at which the §11.9.5 regression (a born user's
/// edge never surfacing for the trustor) was actually felt.
#[tokio::test]
async fn redeemed_cross_instance_edge_surfaces_in_trust_read_api() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // alice is the trustor on A; bob is a genuine remote identity born
    // on B (his trust code names B's instance key + domain, so A resolves
    // him as remote, not local).
    let alice = setup_admin(&a.router, "alice").await;
    let bob = setup_admin(&b.router, "bob").await;

    // Target user mints a trust code via the public mint endpoint.
    let mint = send(
        &b.router,
        get_request("/api/me/trust-code", Some(&bob.cookie)),
    )
    .await;
    assert_eq!(mint.status(), StatusCode::OK);
    let code = body_json(mint).await["code"]
        .as_str()
        .expect("code field")
        .to_string();

    // Source user redeems it — the only edge-creating call, through the
    // public redeem endpoint rather than a federation route.
    let redeem = send(
        &a.router,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&alice.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(redeem.status(), StatusCode::OK);
    let redeem_body = body_json(redeem).await;
    assert_eq!(redeem_body["is_local"], false, "bob is remote to A");
    assert_eq!(redeem_body["edge_type"], "trust");
    assert_eq!(redeem_body["pubkey_hex"], bob.public_key_hex);

    // The list comes from the projected edge table; viewer enrichment
    // reads the graph cache, so refresh it (rebuild_loop isn't spawned
    // in tests).
    refresh_trust_graph(&a.state).await;

    // (1) GET /api/users/{alice}/trust/edges?direction=trusts lists bob.
    let edges = send(
        &a.router,
        get_request(
            &format!(
                "/api/users/{}/trust/edges?direction=trusts",
                alice.public_key_hex
            ),
            Some(&alice.cookie),
        ),
    )
    .await;
    assert_eq!(edges.status(), StatusCode::OK);
    let edges_body = body_json(edges).await;
    assert_eq!(edges_body["total"], 1);
    let bob_edge = edges_body["users"]
        .as_array()
        .expect("users array")
        .iter()
        .find(|u| u["public_key_hex"] == bob.public_key_hex)
        .expect("bob appears in alice's outgoing trust edges");
    assert_eq!(bob_edge["display_name"], "bob");

    // (2) GET /api/users/{alice}/trust surfaces the same edge in its
    //     `trusts` preview list and the aggregate count.
    let detail = send(
        &a.router,
        get_request(
            &format!("/api/users/{}/trust", alice.public_key_hex),
            Some(&alice.cookie),
        ),
    )
    .await;
    assert_eq!(detail.status(), StatusCode::OK);
    let detail_body = body_json(detail).await;
    assert_eq!(detail_body["trusts_given"], 1);
    assert!(
        detail_body["trusts"]
            .as_array()
            .expect("trusts array")
            .iter()
            .any(|u| u["public_key_hex"] == bob.public_key_hex),
        "bob present in alice's trust-detail `trusts` list"
    );
}

/// Receiver-side read-API end-to-end: the home instance of an edge's
/// *target* must surface the remote source in that target's
/// `trusted_by` once the edge is delivered — driven entirely from the
/// target's own genesis state, with no manual profile-publish.
///
/// This is the §11.9.5 regression felt from the other side: sam1 is born
/// on A and mints a code; sam2 (born on B) redeems it, producing a
/// `sam2 -> sam1` edge that B delivers to A. A has never seen sam2, so it
/// must hydrate sam2's stub before it can project the edge — and the only
/// thing it can hydrate from is sam2's *genesis* profile revision. The
/// precedent test in `federation_phase5` had to hand-publish a bio first
/// because the bypass birth route minted no genesis `profile`; now that
/// every birth path mints one, that crutch is gone. If it were still
/// needed, sam2 would never get a display name and this read would show
/// an empty `trusted_by`.
///
/// One `/federation/v1/edges` call is unavoidable: the test harness
/// spawns no frontier loops, so the originator-side auto-forward never
/// fires and the edge has to be hand-delivered. Everything else stays on
/// the public `/api` surface.
#[tokio::test]
async fn received_cross_instance_edge_surfaces_in_trusted_by_read_api() {
    let harness = MultiInstanceHarness::new(2).await;
    // Mutual active peering: B delivers the edge to A, and A pulls sam2's
    // genesis profile back from B to recover the unknown source.
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // sam1: edge target, born on A (A is the receiver under test).
    // sam2: edge source, born on B — genuinely remote to A.
    let sam1 = setup_admin(&a.router, "sam1").await;
    let sam2 = setup_admin(&b.router, "sam2").await;

    // Deliberately NO bio publish for sam2: hydration must work off the
    // genesis profile-rev alone.

    // sam1 mints a code on A; sam2 redeems it on B, signing `sam2 -> sam1`.
    let mint = send(
        &a.router,
        get_request("/api/me/trust-code", Some(&sam1.cookie)),
    )
    .await;
    assert_eq!(mint.status(), StatusCode::OK);
    let code = body_json(mint).await["code"]
        .as_str()
        .expect("code field")
        .to_string();

    let redeem = send(
        &b.router,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&sam2.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(redeem.status(), StatusCode::OK, "sam2 redeems sam1's code");

    // Pull the canonical `sam2 -> sam1` edge bytes B just signed and
    // hand them to A, mirroring the §7.4 forward the harness can't run.
    let (payload, signature): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT payload, signature FROM signed_objects \
         WHERE inner_class = 'trust-edge' AND payload IS NOT NULL LIMIT 1",
    )
    .fetch_one(&b.state.db)
    .await
    .expect("sam2 -> sam1 edge bytes on B");
    let body = encode_edges_body(&[encode_wire(&payload, &signature)]);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        parse_result_statuses(&resp_body),
        vec!["applied".to_string()],
        "§9.1 promises `applied` even for an unknown-source edge",
    );

    // Recovery is async (A backfills sam2's genesis profile from B, then
    // sweeps the pending edge into the projection). Poll the public read
    // endpoint until sam1's `trusted_by` lists sam2; refresh the graph
    // cache each tick since `rebuild_loop` isn't spawned in tests.
    let trusted_by_url = format!(
        "/api/users/{}/trust/edges?direction=trusted_by",
        sam1.public_key_hex
    );
    let surfaced = poll_until(3_000, || async {
        refresh_trust_graph(&a.state).await;
        let resp = send(&a.router, get_request(&trusted_by_url, Some(&sam1.cookie))).await;
        if resp.status() != StatusCode::OK {
            return false;
        }
        body_json(resp).await["users"]
            .as_array()
            .map(|users| {
                users
                    .iter()
                    .any(|u| u["public_key_hex"] == sam2.public_key_hex)
            })
            .unwrap_or(false)
    })
    .await;
    assert!(
        surfaced,
        "A must hydrate sam2 from its genesis profile and surface it in \
         sam1's trusted_by read endpoint",
    );

    // The edge is now visible through both read shapes, with sam2's
    // display name recovered from the genesis profile-rev (not a bio).
    let edges = send(&a.router, get_request(&trusted_by_url, Some(&sam1.cookie))).await;
    let edges_body = body_json(edges).await;
    assert_eq!(edges_body["total"], 1);
    let sam2_edge = edges_body["users"]
        .as_array()
        .expect("users array")
        .iter()
        .find(|u| u["public_key_hex"] == sam2.public_key_hex)
        .expect("sam2 in sam1's incoming edges");
    assert_eq!(sam2_edge["display_name"], "sam2");

    let detail = send(
        &a.router,
        get_request(
            &format!("/api/users/{}/trust", sam1.public_key_hex),
            Some(&sam1.cookie),
        ),
    )
    .await;
    let detail_body = body_json(detail).await;
    assert_eq!(detail_body["trusts_received"], 1);
    assert!(
        detail_body["trusted_by"]
            .as_array()
            .expect("trusted_by array")
            .iter()
            .any(|u| u["public_key_hex"] == sam2.public_key_hex),
        "sam2 present in sam1's trust-detail `trusted_by` list",
    );
}

/// Repro probe for the "content flows both ways" report: with a
/// one-directional edge `sam2 -> sam1` (sam2 trusts sam1), the
/// content-visibility rule is asymmetric — sam1 may see sam2's posts,
/// but sam2 must NOT see sam1's posts (sam1 never trusted sam2).
///
/// Both users author a thread *before* any peering, matching the live
/// repro. After the edge is established and delivered:
///
///   - sam1 viewing sam2's activity: `reverse_trust_ok` (sam2 trusts
///     sam1) → full visibility, `admin_override == false`. sam2's thread
///     is backfilled to A by the §11.9.5 unknown-source recovery and
///     shows up.
///   - sam2 viewing sam1's activity: sam1 does NOT trust sam2, so the
///     trust gate fails; because sam2 is an admin the carve-out opens
///     the feed and stamps `admin_override == true`. The gate is open,
///     so the ONLY thing keeping sam1's posts off sam2's screen is
///     whether sam1's content was replicated to B at all. In this
///     in-process harness (no frontier loops, no mode promotion) it
///     should not be — so the feed is empty despite the open gate.
///
/// If sam1's thread DOES surface here, content replicated to B against
/// the interest model and we have reproduced the leak in test code.
#[tokio::test]
async fn activity_visibility_asymmetry_under_admin_override() {
    let harness = MultiInstanceHarness::new(2).await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let sam1 = setup_admin(&a.router, "sam1").await;
    let sam2 = setup_admin(&b.router, "sam2").await;

    // Author one thread on each instance BEFORE federation, each with a
    // unique needle so a hit unambiguously identifies whose content it is.
    let sam1_thread = send(
        &a.router,
        json_request(
            Method::POST,
            "/api/threads",
            Some(&sam1.cookie),
            &json!({
                "room": "lounge",
                "title": "sam1 thread",
                "body": "tangerine — authored on A by sam1 before federation",
            }),
        ),
    )
    .await;
    assert_eq!(
        sam1_thread.status(),
        StatusCode::CREATED,
        "sam1 authors on A"
    );

    let sam2_thread = send(
        &b.router,
        json_request(
            Method::POST,
            "/api/threads",
            Some(&sam2.cookie),
            &json!({
                "room": "lounge",
                "title": "sam2 thread",
                "body": "kumquat — authored on B by sam2 before federation",
            }),
        ),
    )
    .await;
    assert_eq!(
        sam2_thread.status(),
        StatusCode::CREATED,
        "sam2 authors on B"
    );

    // NOW federate: peer the instances and create the sam2 -> sam1 edge.
    establish_active_peering(&harness, "a", "b").await;

    let mint = send(
        &a.router,
        get_request("/api/me/trust-code", Some(&sam1.cookie)),
    )
    .await;
    assert_eq!(mint.status(), StatusCode::OK);
    let code = body_json(mint).await["code"]
        .as_str()
        .expect("code field")
        .to_string();
    let redeem = send(
        &b.router,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&sam2.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(redeem.status(), StatusCode::OK, "sam2 redeems sam1's code");

    let (payload, signature): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT payload, signature FROM signed_objects \
         WHERE inner_class = 'trust-edge' AND payload IS NOT NULL LIMIT 1",
    )
    .fetch_one(&b.state.db)
    .await
    .expect("sam2 -> sam1 edge bytes on B");
    let body = encode_edges_body(&[encode_wire(&payload, &signature)]);
    let (status, resp_body) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        parse_result_statuses(&resp_body),
        vec!["applied".to_string()]
    );

    refresh_trust_graph(&b.state).await;

    // Expected direction: sam1 sees sam2's activity (sam2 trusts sam1).
    // The edge projects on A asynchronously (unknown-source recovery), so
    // poll — refreshing A's graph each tick — until BOTH the reverse-trust
    // grant is recognised (`admin_override == false`) AND sam2's
    // backfilled post is in the feed.
    let sam2_activity_url = format!("/api/users/{}/activity", sam2.public_key_hex);
    let legit_visibility = poll_until(3_000, || async {
        refresh_trust_graph(&a.state).await;
        let resp = send(
            &a.router,
            get_request(&sam2_activity_url, Some(&sam1.cookie)),
        )
        .await;
        if resp.status() != StatusCode::OK {
            return false;
        }
        let body = body_json(resp).await;
        let kumquat = body["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .any(|i| i["body"].as_str().is_some_and(|b| b.contains("kumquat")))
            })
            .unwrap_or(false);
        body["admin_override"] == false && kumquat
    })
    .await;
    assert!(
        legit_visibility,
        "sam1 should see sam2's post via genuine reverse trust (sam2 trusts \
         sam1), with admin_override == false",
    );

    // The asymmetric direction: sam2 views sam1's activity. The trust
    // gate fails (sam1 never trusted sam2), so admin carve-out opens it.
    let sam1_activity_url = format!("/api/users/{}/activity", sam1.public_key_hex);
    let sam2_view = send(
        &b.router,
        get_request(&sam1_activity_url, Some(&sam2.cookie)),
    )
    .await;
    assert_eq!(sam2_view.status(), StatusCode::OK);
    let sam2_view_body = body_json(sam2_view).await;
    assert_eq!(
        sam2_view_body["admin_override"], true,
        "sam2 (admin) viewing sam1 has no reverse trust → admin carve-out is the only grant",
    );

    // Repro check: the gate is open, so whether sam2 sees sam1's posts
    // comes down to whether sam1's content was replicated to B. The
    // interest model says it must not be (A -> B stays Filtered: sam1 is
    // absent from B's visible_filter). If this fails, the leak reproduces.
    let leaked = sam2_view_body["items"]
        .as_array()
        .expect("items array")
        .iter()
        .any(|i| i["body"].as_str().is_some_and(|b| b.contains("tangerine")));
    assert!(
        !leaked,
        "LEAK: sam1's post replicated to B and is now visible to sam2 — \
         content reached B against the one-directional interest model",
    );
}

/// Reciprocal-edge content flow, end to end — the path the live "sam2
/// sees none of sam1's content" report should exercise.
///
/// Picks up where `activity_visibility_asymmetry_under_admin_override`
/// stops: once the *reciprocal* `sam1 -> sam2` edge exists (sam1 now
/// trusts sam2), sam1 enters B's content closure and sam2 sees sam1's
/// posts — both the thread sam1 authored before federation (`tangerine`)
/// and one authored after (`lychee`).
///
/// Unlike the asymmetry probe, this test drives the *production*
/// frontier triggers — `frontier_fanout_loop` on both instances — so the
/// full chain runs for real:
///
///   1. sam1 redeems sam2's code on A → A's running forwarder delivers
///      the `sam1 -> sam2` edge to B unaided (it routes by target, and
///      sam2 is B-local), because A already holds B's announced frontier.
///   2. B projects the edge; its next reverse-frontier rebuild pulls sam1
///      into the content closure, firing the §7.6 proactive by-author
///      backfill that pulls sam1's *existing* posts from A.
///   3. sam1's *new* post rides the reactive push.
///
/// This passes: with both loops running the mechanism is sound, so it
/// stands as a regression guard for the reciprocal flow. The live report
/// therefore points at something this in-process harness can't reproduce
/// — a missed frontier announce (so A never forwards the edge), an
/// inactive peer, or a restart that landed sam1's arrival on B's
/// first-changed rebuild (where cold-start backfill suppression skips
/// Trigger 3). The diagnostic on live instances is: does instance2's DB
/// hold the `sam1 -> sam2` edge at all?
#[tokio::test]
async fn reciprocal_edge_surfaces_sam1_content_to_sam2() {
    let harness = MultiInstanceHarness::new(2).await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let sam1 = setup_admin(&a.router, "sam1").await;
    let sam2 = setup_admin(&b.router, "sam2").await;
    let sam1_pk = hex32(&sam1.public_key_hex);
    let sam2_pk = hex32(&sam2.public_key_hex);

    // Pre-federation threads, one unique needle each.
    let r = send(
        &a.router,
        json_request(
            Method::POST,
            "/api/threads",
            Some(&sam1.cookie),
            &json!({
                "room": "lounge",
                "title": "sam1 thread",
                "body": "tangerine — authored on A by sam1 before federation",
            }),
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::CREATED, "sam1 authors on A");

    let r = send(
        &b.router,
        json_request(
            Method::POST,
            "/api/threads",
            Some(&sam2.cookie),
            &json!({
                "room": "lounge",
                "title": "sam2 thread",
                "body": "kumquat — authored on B by sam2 before federation",
            }),
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::CREATED, "sam2 authors on B");

    establish_active_peering(&harness, "a", "b").await;

    // --- working direction: sam2 -> sam1 (sam2 trusts sam1) ---
    // sam1 mints on A, sam2 redeems on B, hand-deliver the edge B -> A.
    let code = body_json(
        send(
            &a.router,
            get_request("/api/me/trust-code", Some(&sam1.cookie)),
        )
        .await,
    )
    .await["code"]
        .as_str()
        .expect("code field")
        .to_string();
    let redeem = send(
        &b.router,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&sam2.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(redeem.status(), StatusCode::OK, "sam2 redeems sam1's code");

    let (payload, signature): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT payload, signature FROM signed_objects \
         WHERE inner_class = 'trust-edge' AND payload IS NOT NULL LIMIT 1",
    )
    .fetch_one(&b.state.db)
    .await
    .expect("sam2 -> sam1 edge bytes on B");
    let body = encode_edges_body(&[encode_wire(&payload, &signature)]);
    let (status, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    refresh_trust_graph(&a.state).await;
    refresh_trust_graph(&b.state).await;

    // Sanity: sam1 sees sam2's kumquat via §11.9.5 unknown-source recovery.
    let sam2_activity_url = format!("/api/users/{}/activity", sam2.public_key_hex);
    let sam1_sees_sam2 = poll_until(3_000, || async {
        refresh_trust_graph(&a.state).await;
        let resp = send(
            &a.router,
            get_request(&sam2_activity_url, Some(&sam1.cookie)),
        )
        .await;
        if resp.status() != StatusCode::OK {
            return false;
        }
        body_json(resp).await["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .any(|i| i["body"].as_str().is_some_and(|b| b.contains("kumquat")))
            })
            .unwrap_or(false)
    })
    .await;
    assert!(
        sam1_sees_sam2,
        "working direction broke: sam1 must see sam2's content"
    );

    // --- spawn the production frontier loops on both instances ---
    let a_dirty = Arc::new(Notify::new());
    let b_dirty = Arc::new(Notify::new());
    tokio::spawn(frontier_fanout_loop(a.state.clone(), a_dirty.clone()));
    tokio::spawn(frontier_fanout_loop(b.state.clone(), b_dirty.clone()));

    // Warm-up: B's first changed rebuild consumes the cold-start backfill
    // suppression on a sam1-free closure (only sam2 is local; nobody yet
    // trusts sam2) and re-announces to A. Gate on A storing a
    // peer_frontiers row for B so the reciprocal edge below lands on a
    // *second* rebuild where Trigger 3 is live.
    b_dirty.notify_one();
    a_dirty.notify_one();
    let b_pub = b.state.instance_key.public_bytes().to_vec();
    let warmed = poll_until(3_000, || async {
        let exists: Option<i64> =
            sqlx::query_scalar("SELECT applied_version FROM peer_frontiers WHERE peer_pubkey = ?")
                .bind(&b_pub)
                .fetch_optional(&a.state.db)
                .await
                .unwrap();
        exists.is_some()
    })
    .await;
    assert!(
        warmed,
        "B's frontier loop never re-announced to A (warm-up)"
    );

    // --- reciprocal edge: sam2 mints on B, sam1 redeems on A ---
    let code2 = body_json(
        send(
            &b.router,
            get_request("/api/me/trust-code", Some(&sam2.cookie)),
        )
        .await,
    )
    .await["code"]
        .as_str()
        .expect("code field")
        .to_string();
    let redeem2 = send(
        &a.router,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&sam1.cookie),
            &json!({ "code": code2 }),
        ),
    )
    .await;
    assert_eq!(redeem2.status(), StatusCode::OK, "sam1 redeems sam2's code");

    // The reciprocal edge routes by target (sam2 is B-local), so A's
    // running forwarder delivers it to B on its own — no hand-deliver
    // needed. Wait until B has projected `sam1 -> sam2` into its graph.
    let sam1_id: &[u8] = &sam1_pk;
    let sam2_id: &[u8] = &sam2_pk;
    let edge_on_b = poll_until(3_000, || async {
        refresh_trust_graph(&b.state).await;
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM trust_edges te \
             JOIN users su ON su.id = te.source_user \
             JOIN users tu ON tu.id = te.target_user \
             WHERE su.public_key = ? AND tu.public_key = ? AND te.trust_type = 'trust'",
        )
        .bind(sam1_id)
        .bind(sam2_id)
        .fetch_one(&b.state.db)
        .await
        .unwrap();
        n >= 1
    })
    .await;
    assert!(
        edge_on_b,
        "A's forwarder must deliver the reciprocal sam1 -> sam2 edge to B",
    );

    // sam1 posts a NEW thread on A *after* the reciprocal edge.
    let r = send(
        &a.router,
        json_request(
            Method::POST,
            "/api/threads",
            Some(&sam1.cookie),
            &json!({
                "room": "lounge",
                "title": "sam1 second thread",
                "body": "lychee — authored on A by sam1 after the reciprocal edge",
            }),
        ),
    )
    .await;
    assert_eq!(r.status(), StatusCode::CREATED, "sam1 authors again on A");
    refresh_trust_graph(&a.state).await;

    // Rebuild #2 on B: sam1 now sits in B's content closure, so Trigger 3
    // fires a by-author backfill that should pull both of sam1's threads
    // from A. Re-announce on A so it learns B wants sam1 too.
    b_dirty.notify_one();
    a_dirty.notify_one();

    // sam2 should now see BOTH of sam1's threads.
    let sam1_activity_url = format!("/api/users/{}/activity", sam1.public_key_hex);
    let visible = poll_until(5_000, || async {
        refresh_trust_graph(&b.state).await;
        b_dirty.notify_one();
        let resp = send(
            &b.router,
            get_request(&sam1_activity_url, Some(&sam2.cookie)),
        )
        .await;
        if resp.status() != StatusCode::OK {
            return false;
        }
        let items = body_json(resp).await["items"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let tangerine = items
            .iter()
            .any(|i| i["body"].as_str().is_some_and(|b| b.contains("tangerine")));
        let lychee = items
            .iter()
            .any(|i| i["body"].as_str().is_some_and(|b| b.contains("lychee")));
        tangerine && lychee
    })
    .await;
    assert!(
        visible,
        "sam2 should see sam1's content (tangerine + lychee) once sam1 \
         trusts sam2 and the frontier loop backfills it — if this fails, \
         the live bug reproduces",
    );
}

/// First-contact race repro — the live "sam2 sees none of sam1's content"
/// bug, isolated to its root cause: a trust edge signed *before* the
/// signer's instance holds the target peer's frontier is silently dropped
/// and never replayed.
///
/// Cross-instance edge fan-out is reactive and one-shot. `set_trust_edge`
/// (via `forward_trust_edge`) forwards a freshly-signed edge only to peers
/// already present in `peers_interested_in(target)` at creation time, and
/// nothing replays a dropped edge afterwards. `peers_interested_in`
/// treats a peer with no `peer_frontiers` row as "filtered, empty
/// frontier" (routing.rs) — it matches no key — so an edge toward a
/// B-local target routes nowhere until B's frontier has reached A.
///
/// `establish_active_peering(a, b)` reproduces the live asymmetry for
/// free: the initiate→accept dance fires only A's first-contact announce
/// to B (through A's `handle_peer_response` callback), so afterwards **B
/// holds A's frontier but A holds none for B**. This is the exact live
/// state — instance2 held instance1's frontier early (so `sam2 -> sam1`
/// routed), while instance1 only applied instance2's frontier 18 minutes
/// *after* signing `sam1 -> sam2`.
///
/// The test signs `sam1 -> sam2` on A in that window (dropped), then lets
/// B's frontier finally reach A, and asserts the edge reaches B. It is
/// **expected to FAIL** against current code: applying B's frontier in
/// `handle_frontier_announce` stores the row but never replays the
/// stranded local edge. The fix — replay local-origin edges to a peer
/// whose expansion frontier just arrived — makes this pass.
#[tokio::test]
async fn reciprocal_edge_stranded_when_peer_frontier_absent_at_creation() {
    let harness = MultiInstanceHarness::new(2).await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    let sam1 = setup_admin(&a.router, "sam1").await;
    let sam2 = setup_admin(&b.router, "sam2").await;
    let sam1_pk = hex32(&sam1.public_key_hex);
    let sam2_pk = hex32(&sam2.public_key_hex);
    let sam1_id: &[u8] = &sam1_pk;
    let sam2_id: &[u8] = &sam2_pk;

    // Active peering, A as initiator. The initiate→accept dance fires only
    // A's first-contact announce to B, so B now holds A's frontier while A
    // holds NONE for B — the live race pre-condition.
    establish_active_peering(&harness, "a", "b").await;

    // Pre-condition: A has no peer_frontiers row for B, so any edge A signs
    // toward a B-local target right now has no interested peer to route to.
    let b_pub = b.state.instance_key.public_bytes().to_vec();
    let a_has_b_frontier: Option<i64> =
        sqlx::query_scalar("SELECT applied_version FROM peer_frontiers WHERE peer_pubkey = ?")
            .bind(&b_pub)
            .fetch_optional(&a.state.db)
            .await
            .unwrap();
    assert!(
        a_has_b_frontier.is_none(),
        "pre-condition: A must not yet hold B's frontier, else the race \
         this test reproduces cannot occur",
    );

    // sam1 trusts sam2: sam2 mints on B, sam1 redeems on A. This signs and
    // stores `sam1 -> sam2` on A and fires A's forwarder — which finds no
    // peer interested in sam2 (no B frontier) and drops the edge.
    let code = body_json(
        send(
            &b.router,
            get_request("/api/me/trust-code", Some(&sam2.cookie)),
        )
        .await,
    )
    .await["code"]
        .as_str()
        .expect("code field")
        .to_string();
    let redeem = send(
        &a.router,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&sam1.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(
        redeem.status(),
        StatusCode::OK,
        "sam1 redeems sam2's code on A"
    );

    // The edge is signed and stored on A...
    let count_edge = |db: sqlx::SqlitePool| async move {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM trust_edges te \
             JOIN users su ON su.id = te.source_user \
             JOIN users tu ON tu.id = te.target_user \
             WHERE su.public_key = ? AND tu.public_key = ? AND te.trust_type = 'trust'",
        )
        .bind(sam1_id)
        .bind(sam2_id)
        .fetch_one(&db)
        .await
        .unwrap();
        n
    };
    assert_eq!(
        count_edge(a.state.db.clone()).await,
        1,
        "sam1 -> sam2 edge is signed and stored on A",
    );

    // ...but it was dropped at creation, not delivered: B has no such edge.
    assert_eq!(
        count_edge(b.state.db.clone()).await,
        0,
        "edge had no interested peer at creation, so it is not yet on B",
    );

    // Now B's frontier finally reaches A (the live 03:35 announce). Drive
    // B's fanout loop so it re-announces to A; A applies it via
    // `handle_frontier_announce`.
    let b_dirty = Arc::new(Notify::new());
    tokio::spawn(frontier_fanout_loop(b.state.clone(), b_dirty.clone()));
    b_dirty.notify_one();

    // A now holds B's frontier — so a *fresh* edge would route. The open
    // question is the *already-signed* one.
    let a_now_has_b = poll_until(3_000, || async {
        let v: Option<i64> =
            sqlx::query_scalar("SELECT applied_version FROM peer_frontiers WHERE peer_pubkey = ?")
                .bind(&b_pub)
                .fetch_optional(&a.state.db)
                .await
                .unwrap();
        v.is_some()
    })
    .await;
    assert!(a_now_has_b, "B's frontier announce never reached A");

    // The fix: applying B's frontier must replay the stranded `sam1 -> sam2`
    // edge to B. With the bug, nothing replays it, so B never receives the
    // edge and sam2 sees none of sam1's content.
    let edge_reaches_b = poll_until(3_000, || async {
        count_edge(b.state.db.clone()).await >= 1
    })
    .await;
    assert!(
        edge_reaches_b,
        "BUG: A signed sam1 -> sam2 before holding B's frontier, so it was \
         dropped; applying B's frontier later did not replay it, so sam2 \
         never receives the edge and sees none of sam1's content",
    );
}
