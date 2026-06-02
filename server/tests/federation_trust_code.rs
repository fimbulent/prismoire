#![cfg(feature = "test-auth")]
//! Trust-code cross-instance bootstrap integration tests (§11.9.5).
//!
//! Trust codes are the invite-style bridge that seeds a cross-instance
//! stub user plus a reciprocal trust edge: a target mints a code over
//! `GET /api/me/trust-code`, a source redeems it over
//! `POST /api/users/by-trust-code`, and the resulting edge then has to
//! surface in the trust read / activity-visibility APIs the way a
//! locally-authored edge would. Sections:
//!
//! - **Mint / redeem mechanics (single instance).** A minted code
//!   round-trips through `trust_code::parse`. Redeeming a never-seen
//!   remote code seeds a federated stub user homed on the code's
//!   instance, a move-less `user_homes` row (NULL move hash/created_at),
//!   and a live trust edge from the redeemer. A `dry_run` reports what it
//!   would seed without writing. A code naming a *local* user is
//!   `is_local` and never reseeds a remote home. A conflicting second
//!   code for the same pubkey is first-seed-wins. Redeeming one's own
//!   code is `self_trust_edge`; garbage is `invalid_trust_code`. The
//!   admin peers surface lists an un-peered redeemed home as a peering
//!   suggestion.
//! - **Genesis profile guard.** Both account-birth paths
//!   (`setup_complete` / `signup_complete`) mint an empty-bio genesis
//!   `profile` revision dual-written to `signed_objects` — the only thing
//!   a peer can hydrate a redeemed stub's display name from.
//! - **Read-API / activity surfacing (multi-instance).** A redeemed
//!   cross-instance edge surfaces in the *trustor's* outgoing `trusts`
//!   read endpoints. A *received* remote edge surfaces in the target's
//!   `trusted_by` via §11.9.5 unknown-source recovery — including the
//!   two-remote-sources case where each source homes on a different peer
//!   and the recovery must ask the right home for each. The asymmetric
//!   content rule holds: a one-directional `sam2 -> sam1` edge lets sam1
//!   see sam2's posts but does not leak sam1's posts to sam2 even under
//!   the admin carve-out; the reciprocal `sam1 -> sam2` edge then makes
//!   sam1's content flow to sam2. A hub relays a third-party edge to a
//!   later-interested spoke so the spoke recovers it in `trusted_by`.
//!
//! Convergence-driven scenarios use the [`settle`] harness driver rather
//! than spawning `frontier_fanout_loop` + polling: `settle` round-robins
//! the trust-graph rebuild, an inline `frontier_fanout_once` pass
//! (cold-start suppression disabled), and the outbound drain across all
//! instances until quiescent — deterministic, no spawn-loop race, and it
//! also waits out the §11.9.5 by-author recovery backfill so a recovered
//! edge has landed before the assertion runs.

mod common;

use axum::http::{Method, StatusCode};
use ciborium::value::Value;
use serde_json::json;

use common::federation::{
    MultiInstanceHarness, establish_active_peering, send_envelope_signed, settle,
};
use common::{
    body_json, get_request, json_request, refresh_trust_graph, send, setup_admin, signup_as,
    test_app, test_app_with_transport,
};
use prismoire_server::federation::trust_code;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Lowercase-hex a byte slice (mirror of the server's pubkey rendering).
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// §6.3 WireFormat `{ "p", "s" }` for one signed object — what a real
/// edge sender puts on the wire.
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

/// Count current trust edges `source -> target` (by pubkey) on `db`.
async fn count_edge(db: &sqlx::SqlitePool, source_pk: &[u8], target_pk: &[u8]) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM current_trust_edges cte \
         JOIN users su ON su.id = cte.source_user \
         JOIN users tu ON tu.id = cte.target_user \
         WHERE su.public_key = ? AND tu.public_key = ? AND cte.trust_type = 'trust'",
    )
    .bind(source_pk)
    .bind(target_pk)
    .fetch_one(db)
    .await
    .unwrap()
}

// ---------------------------------------------------------------------------
// Mint / redeem mechanics (single instance)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Genesis profile guard
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Read-API / activity surfacing (multi-instance)
//
// Convergence-driven recovery (unknown-source hydration, frontier replay,
// content backfill) is pumped to quiescence with `settle` rather than the
// old `frontier_fanout_loop` + `poll_until` waits.
// ---------------------------------------------------------------------------

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
    // in tests). bob is seeded locally as a stub by redeem, so no
    // cross-instance recovery is needed here.
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
///     in-process harness (no mode promotion) it should not be — so the
///     feed is empty despite the open gate.
///
/// If sam1's thread DOES surface here, content replicated to B against
/// the interest model and we have reproduced the leak in test code.
///
/// `settle` drives the §11.9.5 unknown-source recovery that hydrates
/// sam2 on A and backfills its content — replacing the old `poll_until`
/// wait on that async backfill.
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

    // Drive the §11.9.5 unknown-source recovery to quiescence: A hydrates
    // sam2 from its genesis profile, projects `sam2 -> sam1`, and
    // backfills sam2's pre-federation thread.
    settle(&harness).await;
    refresh_trust_graph(&a.state).await;

    // Expected direction: sam1 sees sam2's activity (sam2 trusts sam1),
    // with the reverse-trust grant recognised (`admin_override == false`)
    // and sam2's backfilled post in the feed.
    let sam2_activity_url = format!("/api/users/{}/activity", sam2.public_key_hex);
    let resp = send(
        &a.router,
        get_request(&sam2_activity_url, Some(&sam1.cookie)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(
        body["admin_override"], false,
        "sam1 sees sam2 via genuine reverse trust (sam2 trusts sam1)",
    );
    assert!(
        body["items"]
            .as_array()
            .map(|items| items
                .iter()
                .any(|i| i["body"].as_str().is_some_and(|b| b.contains("kumquat"))))
            .unwrap_or(false),
        "sam2's backfilled post must surface in sam1's view",
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
/// `settle` drives the *production* frontier triggers (the inline
/// `frontier_fanout_once` pass with cold-start suppression disabled, plus
/// the trust-graph rebuild and outbound drain across both instances),
/// replacing the old spawn-`frontier_fanout_loop`-and-poll pattern that
/// raced the loop's cold-start Trigger-3 suppression. The full chain runs
/// deterministically:
///
///   1. sam1 redeems sam2's code on A → A forwards the `sam1 -> sam2`
///      edge to B once A holds B's announced frontier.
///   2. B projects the edge; its reverse-frontier rebuild pulls sam1
///      into the content closure, firing the §7.6 proactive by-author
///      backfill that pulls sam1's *existing* posts from A.
///   3. sam1's *new* post rides the reactive push.
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

    // Settle the working-direction recovery; sam1 must see sam2's kumquat
    // via §11.9.5 unknown-source recovery.
    settle(&harness).await;
    refresh_trust_graph(&a.state).await;
    let sam2_activity_url = format!("/api/users/{}/activity", sam2.public_key_hex);
    let resp = send(
        &a.router,
        get_request(&sam2_activity_url, Some(&sam1.cookie)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        body_json(resp).await["items"]
            .as_array()
            .map(|items| items
                .iter()
                .any(|i| i["body"].as_str().is_some_and(|b| b.contains("kumquat"))))
            .unwrap_or(false),
        "working direction broke: sam1 must see sam2's content",
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

    // Drive the reciprocal flow to quiescence: A forwards `sam1 -> sam2`
    // to B (routes by target, sam2 is B-local), B's reverse-frontier
    // rebuild pulls sam1 into its closure, and Trigger-3 backfills both of
    // sam1's threads from A.
    settle(&harness).await;

    // The reciprocal `sam1 -> sam2` edge must have projected on B.
    let sam1_id: &[u8] = &sam1_pk;
    let sam2_id: &[u8] = &sam2_pk;
    assert!(
        count_edge(&b.state.db, sam1_id, sam2_id).await >= 1,
        "A's forwarder must deliver the reciprocal sam1 -> sam2 edge to B",
    );

    // sam2 should now see BOTH of sam1's threads.
    refresh_trust_graph(&b.state).await;
    let sam1_activity_url = format!("/api/users/{}/activity", sam1.public_key_hex);
    let resp = send(
        &b.router,
        get_request(&sam1_activity_url, Some(&sam2.cookie)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
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
    assert!(
        tangerine && lychee,
        "sam2 should see sam1's content (tangerine + lychee) once sam1 \
         trusts sam2 and the frontier fanout backfills it",
    );
}

/// Repro for the "first remote source goes missing from `trusted_by`"
/// report: with TWO remote sources each trusting the same local user —
/// `sam2 -> sam1` (sam2 homed on B) and `sam3 -> sam1` (sam3 homed on C) —
/// both edges arrive at A as §11.9.5 `EndpointMissing` (A has seen neither
/// source). Each triggers `proactive_author_backfill`, which walks A's
/// active peers to pull the source's genesis profile so the stub hydrates
/// and `sweep_pending_projections` can project the edge.
///
/// The bug: `proactive_author_backfill` stops at the first peer that
/// answers `complete: true`, but `GET /backfill/by-author` returns
/// `complete: true` with ZERO objects for an author the peer has never
/// seen (`backfill.rs` remote-author carve-out). A's peer set is the same
/// fixed order for both backfills, and the first-tried peer hosts only one
/// of the two sources — so the other source's real home is never asked,
/// its stub never hydrates, and its edge stays unprojected. Exactly one of
/// {sam2, sam3} is silently dropped from sam1's `trusted_by`, matching the
/// live report.
///
/// One `/federation/v1/edges` call per source is hand-delivered; `settle`
/// then drives the autonomous recovery (genesis-profile backfill against
/// each source's true home, stub hydration, sweep-projection) to
/// quiescence — replacing the old `poll_until` wait on that async work.
#[tokio::test]
async fn two_remote_sources_both_surface_in_trusted_by() {
    let harness = MultiInstanceHarness::new(3).await;
    // Peer a<->b FIRST, then a<->c — so A's most-recently-handshaken peer
    // (tried first by `proactive_author_backfill`) is C, the home of only
    // one of the two sources.
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let c = harness.instance("c");

    // sam1: edge target, born on A (the receiver under test).
    // sam2: source, born on B.   sam3: source, born on C.
    let sam1 = setup_admin(&a.router, "sam1").await;
    let sam2 = setup_admin(&b.router, "sam2").await;
    let sam3 = setup_admin(&c.router, "sam3").await;

    // sam1 mints one code (its identity card); sam2 and sam3 each redeem it
    // on their home instance, signing `sam2 -> sam1` on B and
    // `sam3 -> sam1` on C.
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

    for (inst, who) in [(b, &sam2), (c, &sam3)] {
        let redeem = send(
            &inst.router,
            json_request(
                Method::POST,
                "/api/users/by-trust-code",
                Some(&who.cookie),
                &json!({ "code": code }),
            ),
        )
        .await;
        assert_eq!(
            redeem.status(),
            StatusCode::OK,
            "{} redeems sam1's code",
            who.display_name,
        );
    }

    // Hand-deliver each edge to A, mirroring the §7.5 forward. Each source
    // instance holds exactly its own edge.
    for from in ["b", "c"] {
        let db = &harness.instance(from).state.db;
        let (payload, signature): (Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT payload, signature FROM signed_objects \
             WHERE inner_class = 'trust-edge' AND payload IS NOT NULL LIMIT 1",
        )
        .fetch_one(db)
        .await
        .expect("source -> sam1 edge bytes");
        let body = encode_edges_body(&[encode_wire(&payload, &signature)]);
        let (status, resp_body) = send_envelope_signed(
            &harness,
            from,
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
    }

    // Drive the per-source recovery to quiescence: A backfills each
    // source's genesis profile from its true home, hydrates the stub, and
    // sweeps the pending edge into the projection.
    settle(&harness).await;
    refresh_trust_graph(&a.state).await;

    // sam1's `trusted_by` must list BOTH sources.
    let trusted_by_url = format!(
        "/api/users/{}/trust/edges?direction=trusted_by",
        sam1.public_key_hex
    );
    let resp = send(&a.router, get_request(&trusted_by_url, Some(&sam1.cookie))).await;
    assert_eq!(resp.status(), StatusCode::OK, "trusted_by query on A");
    let arr = body_json(resp).await["users"]
        .as_array()
        .cloned()
        .expect("users array");
    let has = |pk: &str| arr.iter().any(|u| u["public_key_hex"] == pk);
    assert!(
        has(&sam2.public_key_hex) && has(&sam3.public_key_hex),
        "BUG: only one of sam2/sam3 surfaces in sam1's trusted_by — \
         proactive_author_backfill stopped at the first peer's empty \
         `complete:true` and never asked the other source's home",
    );
}

/// Regression test for the live cross-instance asymmetry report: a spoke
/// that becomes interested in a hub user only *after* a third-party
/// (relayed) edge toward that user has already passed through the hub must
/// still recover that edge.
///
/// Topology mirrors the user's setup: hub A federated with spokes B and C;
/// B and C are *not* federated to each other, so a B-authored edge can only
/// reach C if the hub relays it. Users: sam1 on A (the shared trust
/// target), sam2 on B, sam3 on C. Edges (the user's exact set):
///   - `sam2 -> sam1`  third-party, authored on B, hand-delivered to A.
///   - `sam3 -> sam1`  C-local, authored on C.
///   - `sam1 -> sam3`  local-origin on A (sam1 is A-local), target sam3 —
///     this is what puts sam1 into C's reverse frontier (author sam1
///     trusts reader sam3) and reaches C via §7.6 replay.
///
/// Original bug: cross-instance edge fan-out toward a frontier author is
/// one-shot + reactive — `apply_one_edge_inner` (edges.rs) fans a freshly
/// applied edge only to peers interested *at arrival time*, and the one
/// re-fan path (`replay_local_edges_to_peer`, §7.6) filters
/// `home_instance IS NULL`, replaying **local-origin** edges only. So when
/// C expanded sam1 (after sam3 trusts sam1), the replay delivered the
/// local-origin `sam1 -> sam3` but silently skipped the third-party
/// `sam2 -> sam1`, and sam1's `trusted_by` on C omitted sam2 forever.
///
/// Fix (§10.5.4 step 6 + §8.1): when sam1 newly enters C's content
/// frontier, Trigger-3 `proactive_author_backfill` now also pulls sam1's
/// *inbound* edges (`edges-by-key?direction=target`) from A — the peer
/// that hosts sam1 and holds the authoritative inbound set. `sam2 -> sam1`
/// arrives with sam2 unhydrated, so it cannot project into `trust_edges`
/// yet; `apply_one_edge_inner` records it in `frontier_edges` instead
/// (gated on sam1 ∈ C's expansion set), which lets the next reverse-BFS
/// discover sam2, materialize + content-backfill it, hydrate the stub, and
/// finally sweep `sam2 -> sam1` into projection. The user-facing symptom —
/// sam1's `trusted_by` on C — then lists both sam2 and sam3.
///
/// Convergence is driven by [`settle`], which pumps the trust-graph
/// rebuild, the inline `frontier_fanout_once` pass (cold-start
/// suppression disabled), and the outbound drain across all instances
/// until quiescent. This replaces the old spawn-the-loop-and-poll
/// pattern, which raced `frontier_fanout_loop`'s cold-start Trigger-3
/// suppression: under full-suite load sam1 could become visible before
/// the loop's first rebuild, get consumed by the suppressed cold-start
/// diff, and never re-fire Trigger-3 — a permanent stall no timeout
/// could fix.
#[tokio::test]
async fn relayed_third_party_edge_recovered_on_later_interested_spoke() {
    let harness = MultiInstanceHarness::new(3).await;
    // Hub-and-spoke: A peers with B and C; B and C never peer with each
    // other. Matches the user's inst1<->inst2, inst1<->inst3 setup.
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "a", "c").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let c = harness.instance("c");

    let sam1 = setup_admin(&a.router, "sam1").await;
    let sam2 = setup_admin(&b.router, "sam2").await;
    let sam3 = setup_admin(&c.router, "sam3").await;
    let sam1_pk = hex32(&sam1.public_key_hex);
    let sam3_pk = hex32(&sam3.public_key_hex);

    // sam1 mints its identity code; sam2 redeems on B and sam3 on C, signing
    // `sam2 -> sam1` on B and `sam3 -> sam1` on C.
    let sam1_code = body_json(
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
    for (inst, who) in [(b, &sam2), (c, &sam3)] {
        let redeem = send(
            &inst.router,
            json_request(
                Method::POST,
                "/api/users/by-trust-code",
                Some(&who.cookie),
                &json!({ "code": sam1_code }),
            ),
        )
        .await;
        assert_eq!(
            redeem.status(),
            StatusCode::OK,
            "{} redeems",
            who.display_name
        );
    }

    // Both `source -> sam1` edges are local-origin on their authoring
    // spoke (sam2 is B-local, sam3 is C-local), so the §7.5 fanout +
    // §7.6 replay-on-apply delivers them to hub A *on its own* once A
    // announces a frontier whose expansion covers sam1 — which the
    // `sam1 -> sam3` edge below arranges. `settle` (further down) pumps
    // that exchange; no hand-delivery needed.

    // Local-origin control edge: sam1 trusts sam3. sam3 mints on C, sam1
    // redeems on A → `sam1 -> sam3` is signed on A with a *local* source.
    // This is also what puts sam1 into A's frontier expansion, so A's
    // re-announce makes B and C replay their `*-> sam1` edges back to A.
    let sam3_code = body_json(
        send(
            &c.router,
            get_request("/api/me/trust-code", Some(&sam3.cookie)),
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
            &json!({ "code": sam3_code }),
        ),
    )
    .await;
    assert_eq!(
        redeem.status(),
        StatusCode::OK,
        "sam1 redeems sam3's code on A"
    );
    refresh_trust_graph(&a.state).await;
    assert_eq!(
        count_edge(&a.state.db, &sam1_pk, &sam3_pk).await,
        1,
        "sam1 -> sam3 is signed and stored on A (local-origin control)",
    );

    // Pump every instance's background workers to quiescence. This drives
    // C's frontier fanout (announce a winning frontier covering sam1 via
    // sam3 -> sam1 and sam3 itself), the §7.6 replay over C's expansion on
    // A, the resulting `sam1 -> sam3` landing on C (so sam1 enters C's
    // reverse frontier — the precondition for the §10.5.4-step-6 inbound
    // pull), and the whole recovery cascade: pull sam1's inbound edges from
    // hub A → §8.1 frontier-edge discovery reaches sam2 → backfill sam2's
    // profile → hydrate → sweep-project `sam2 -> sam1`. `settle` runs the
    // inline `frontier_fanout_once` with cold-start suppression disabled,
    // so Trigger-3 always fires for sam1 — no race against the loop's
    // cold-start guard.
    settle(&harness).await;

    // Readiness checkpoint: the local-origin `sam1 -> sam3` reached C via
    // §7.6 replay, so sam1 is in C's reverse frontier. Without this the
    // inbound-edge pull is never triggered and the test proves nothing.
    // (Also confirms §7.6 replay still works for the local-origin edge,
    // the path the bug never covered for third-party edges.)
    assert!(
        count_edge(&c.state.db, &sam1_pk, &sam3_pk).await >= 1,
        "setup: §7.6 replay must deliver the local-origin sam1 -> sam3 to C \
         so sam1 enters C's reverse frontier",
    );

    // The user-facing symptom: read sam1's trusted_by on C. Before the fix
    // it listed only sam3 (C-local); with the §10.5.4-step-6 inbound pull +
    // §8.1 frontier-edge discovery, the relayed sam2 -> sam1 is recovered,
    // sam2 hydrates, and the edge projects.
    refresh_trust_graph(&c.state).await;
    let trusted_by_url = format!(
        "/api/users/{}/trust/edges?direction=trusted_by",
        sam1.public_key_hex
    );
    let resp = send(&c.router, get_request(&trusted_by_url, Some(&sam3.cookie))).await;
    assert_eq!(resp.status(), StatusCode::OK, "trusted_by query on C");
    let arr = body_json(resp).await["users"]
        .as_array()
        .cloned()
        .expect("users array");
    let has = |pk: &str| arr.iter().any(|u| u["public_key_hex"] == pk);
    assert!(
        has(&sam2.public_key_hex) && has(&sam3.public_key_hex),
        "C must recover the relayed sam2 -> sam1: once sam1 enters C's \
         frontier, the §10.5.4-step-6 inbound-edge pull fetches who-trusts-\
         sam1 from hub A, §8.1 frontier-edge discovery reaches sam2, and the \
         edge projects — so sam1's trusted_by on C lists both sam2 and sam3",
    );
}
