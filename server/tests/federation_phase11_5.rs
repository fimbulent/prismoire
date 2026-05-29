//! Phase-11.5 integration tests: §16 user-status / §17 thread-status as
//! **selective multi-hop gossip** over the §7.5 forwarder, plus the
//! producer-side **locality gate** on admin moderation.
//!
//! Phase 11 shipped status objects as a point-to-point issuer→peer push.
//! Phase 11.5 routes them through `forward_signed_object` exactly like
//! trust-edges (§9) so a status reaches every *interested* instance, not
//! just the issuer's direct peers — while authority stays signer-bound:
//! every hop re-verifies the inner signature against the subject/thread's
//! resolved **home** pubkey, never the transport sender. This file pins:
//!
//! - **Relay (user-status).** A originates a `banned` user-status for a
//!   subject homed at A; B (interested, adjacent to A) applies and
//!   re-emits; C (interested, adjacent only to B — *not* to A) ends up
//!   with the projection. Proves A→B→C tier-2 fan-out.
//! - **Relay (thread-status).** Same A→B→C shape for a `locked`
//!   thread-status, asserting the §17.4 `threads.locked` mirror on the
//!   non-adjacent C.
//! - **Interest gate.** A peer that announces a frontier *not* covering
//!   the subject never receives the object — the bloom filter, not mere
//!   adjacency, decides delivery.
//! - **Auth flip under gossip.** A forwarder that re-signs a user-status
//!   with its *own* key (rather than relaying the home's signed bytes) is
//!   `rejected/invalid_signature` — the home pubkey is the authority, the
//!   transport sender is not.
//! - **Producer locality gate.** Admin ban / suspend / lock against a
//!   target homed on another instance is `403 remote_moderation_target`,
//!   so a local admin can never issue a status object for content it does
//!   not home.
//!
//! Layer-0/Layer-1 single-hop reception invariants live in
//! `federation_phase11.rs`; the relay machinery itself (dedup-LRU,
//! REDUNDANCY_K, split-horizon) is exercised for trust-edges in
//! `federation_phase5.rs`. This file is the status-object counterpart of
//! the Phase-5 `forwarder_relays_applied_edge_to_interested_peer` test.

#![cfg(feature = "test-auth")]

mod common;

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use prismoire_server::federation::bloom::BloomFilter;
use prismoire_server::federation::frontier::{FilterSpec, FrontierAnnounce};
use prismoire_server::federation::routing::Mode;
use prismoire_server::federation::thread_status::dispatch_local_thread_status;
use prismoire_server::federation::user_status::dispatch_local_user_status;
use prismoire_server::signed::{ThreadStatusKind, UserStatusKind};
use prismoire_server::signing::{SigningOutput, sign_user_status_with_key};
use rand::rngs::OsRng;
use serde_json::json;
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};
use common::{body_json, json_request, send, setup_admin, test_app};

// ---------------------------------------------------------------------------
// Body / response + fixture helpers (mirrors federation_phase11.rs — the
// in-module helpers there are not exported, so the small set this file
// needs is re-declared locally rather than widening the crate surface).
// ---------------------------------------------------------------------------

/// Pack signed objects into the `{ "objects": [bstr, ...] }` push body.
fn encode_push_body(signed: &[&SigningOutput]) -> Vec<u8> {
    let arr: Vec<Value> = signed
        .iter()
        .map(|s| Value::Bytes(encode_wire(&s.payload, &s.signature)))
        .collect();
    let body = Value::Map(vec![(Value::Text("objects".into()), Value::Array(arr))]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&body, &mut buf).expect("ser objects body");
    buf
}

/// Encode a §6.3 WireFormat `{ "p", "s" }`.
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&m, &mut buf).expect("ser wire");
    buf
}

/// Decode `{ "results": [...] }` into `(canonical_hash, status, reason?)`.
fn parse_results(body: &[u8]) -> Vec<([u8; 32], String, Option<String>)> {
    let v: Value = ciborium::de::from_reader(body).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("results body is not a map");
    };
    let results = m
        .into_iter()
        .find_map(|(k, v)| matches!(&k, Value::Text(t) if t == "results").then_some(v))
        .expect("missing `results`");
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

/// Insert a `users` row with a known Ed25519 public key. `home = None`
/// marks the user as local to this DB; `Some(key)` marks it federated
/// with home `key`. Returns the generated UUID.
async fn insert_user(
    db: &SqlitePool,
    display_name: &str,
    pubkey: &[u8; 32],
    home: Option<&[u8; 32]>,
) -> String {
    let id = Uuid::new_v4().to_string();
    let skeleton = display_name.to_lowercase();
    let pubkey_slice: &[u8] = pubkey.as_slice();
    let signup = if home.is_some() { "federated" } else { "admin" };
    let home_slice: Option<&[u8]> = home.map(|h| h.as_slice());
    sqlx::query!(
        "INSERT INTO users (id, display_name, signup_method, public_key, \
                            display_name_skeleton, home_instance) \
         VALUES (?, ?, ?, ?, ?, ?)",
        id,
        display_name,
        signup,
        pubkey_slice,
        skeleton,
        home_slice,
    )
    .execute(db)
    .await
    .expect("insert user");
    id
}

/// Ensure the `general` room exists (idempotent).
async fn ensure_general_room(db: &SqlitePool, created_by: &str) {
    let exists: Option<String> =
        sqlx::query_scalar!("SELECT id FROM rooms WHERE id = 'general' LIMIT 1")
            .fetch_optional(db)
            .await
            .expect("room lookup");
    if exists.is_none() {
        sqlx::query!(
            "INSERT INTO rooms (id, slug, created_by) VALUES ('general', 'general', ?)",
            created_by,
        )
        .execute(db)
        .await
        .expect("insert room");
    }
}

/// Insert a `threads` row with caller-controlled `home_instance`
/// (`None` = locally hosted, `Some(key)` = hosted by `key`).
async fn insert_thread(
    db: &SqlitePool,
    thread_id: &Uuid,
    author_id: &str,
    home: Option<&[u8; 32]>,
) {
    let id_text = thread_id.to_string();
    let home_slice: Option<&[u8]> = home.map(|h| h.as_slice());
    sqlx::query!(
        "INSERT INTO threads (id, title, author, room, home_instance) \
         VALUES (?, 'phase 11.5 fixture thread', ?, 'general', ?)",
        id_text,
        author_id,
        home_slice,
    )
    .execute(db)
    .await
    .expect("insert thread");
}

/// Build a §8.3 `FrontierAnnounce` whose `content_filter` carries
/// `interested_keys`. The content filter is the gate for both the §16
/// user-status OR-filter (`cf || ef`) and the §17 thread-status filter
/// (`cf`), so populating it alone makes the announcer interested in both
/// classes keyed on those bytes. `edge_origin_filter` is a real but empty
/// bloom (it is irrelevant to the status classes under test).
fn announce_with_content_keys(interested_keys: &[&[u8; 32]]) -> FrontierAnnounce {
    let cap = interested_keys.len().max(1) as u64;
    let mut content = BloomFilter::new_empty(7, 1024, cap, 0.01).expect("build content filter");
    for k in interested_keys {
        content.insert(k.as_slice());
    }
    let edge = BloomFilter::new_empty(7, 1024, 1, 0.01).expect("build edge filter");
    FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        content_filter: FilterSpec::from_bloom(&content),
        edge_origin_filter: FilterSpec::from_bloom(&edge),
        mode: Mode::Filtered,
    }
}

/// Wait up to `timeout_ms` for `predicate` to return `true`, polling with
/// a 10ms backoff. Status egress is asynchronous from the upstream push's
/// perspective (per-peer drain worker), so a relayed object lands on the
/// downstream DB after the originating call returns.
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

/// True iff `db` holds a `signed_objects` row for `hash`.
async fn has_signed_object(db: &SqlitePool, hash: &[u8; 32]) -> bool {
    let slice: &[u8] = hash.as_slice();
    sqlx::query_scalar!(
        "SELECT 1 AS \"n!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        slice,
    )
    .fetch_optional(db)
    .await
    .expect("query signed_objects")
    .is_some()
}

// ---------------------------------------------------------------------------
// §16.2 user-status gossip relay
// ---------------------------------------------------------------------------

/// A originates a `banned` user-status for subject S (homed at A). B is
/// adjacent to A and interested in S; C is adjacent only to B and also
/// interested. The status must traverse A → B → C and flip C's
/// `user_statuses` projection, proving the §7.5 forwarder relays status
/// objects to a non-adjacent interested peer.
#[tokio::test]
async fn user_status_relays_to_non_adjacent_interested_peer() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "b", "c").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let c = harness.instance("c");
    let a_pub = *a.state.instance_key.public_bytes();

    // Subject S — a federated user (home A) known to both B and C so the
    // §16.2 home resolution succeeds on each hop and the projection lands.
    let s_key = SigningKey::generate(&mut OsRng);
    let s_pub: [u8; 32] = *s_key.verifying_key().as_bytes();
    insert_user(&b.state.db, "subj", &s_pub, Some(&a_pub)).await;
    insert_user(&c.state.db, "subj", &s_pub, Some(&a_pub)).await;

    // B announces interest in S to A; C announces interest in S to B.
    // Each announce records the downstream peer's frontier in the
    // upstream's `peer_frontiers`, so `peers_interested_in` returns the
    // next hop for a UserStatus keyed on S.
    let announce = announce_with_content_keys(&[&s_pub]).encode();
    let (st, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "B → A announce must apply");
    let (st, _) = send_envelope_signed(
        &harness,
        "c",
        "b",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "C → B announce must apply");

    // A issues the ban as S's home authority and originates the fan-out.
    dispatch_local_user_status(
        &a.state,
        &s_pub,
        UserStatusKind::Banned,
        None,
        Some("ban evasion"),
    )
    .await
    .expect("dispatch_local_user_status");

    // C is two hops from A — its projection appears only if B relayed.
    let c_db = c.state.db.clone();
    let s_slice = s_pub.to_vec();
    let arrived = poll_until(2_000, || {
        let c_db = c_db.clone();
        let s_slice = s_slice.clone();
        async move {
            let subj: &[u8] = &s_slice;
            sqlx::query!("SELECT status FROM user_statuses WHERE subject = ?", subj)
                .fetch_optional(&c_db)
                .await
                .expect("query user_statuses on c")
                .map(|r| r.status == "banned")
                .unwrap_or(false)
        }
    })
    .await;
    assert!(
        arrived,
        "forwarder did not relay the user-status to non-adjacent C"
    );

    // B (the relay) also has the projection — it had to apply before
    // re-emitting, so this confirms the tier-2 forward fired from B.
    let subj: &[u8] = s_pub.as_slice();
    let on_b = sqlx::query!("SELECT status FROM user_statuses WHERE subject = ?", subj)
        .fetch_one(&b.state.db)
        .await
        .expect("user_statuses row on b");
    assert_eq!(on_b.status, "banned");
}

// ---------------------------------------------------------------------------
// §17.2 thread-status gossip relay
// ---------------------------------------------------------------------------

/// A originates a `locked` thread-status for a thread it homes; B and C
/// host a federated mirror of that thread (home A) and announce interest
/// in the OP author (the §17.2 routing key). The lock must reach the
/// non-adjacent C and mirror into `threads.locked` (§17.4).
#[tokio::test]
async fn thread_status_relays_to_non_adjacent_interested_peer() {
    let harness = MultiInstanceHarness::new(3).await;
    establish_active_peering(&harness, "a", "b").await;
    establish_active_peering(&harness, "b", "c").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let c = harness.instance("c");
    let a_pub = *a.state.instance_key.public_bytes();

    // OP author — the routing key. Generated once; same pubkey on every
    // instance. On A the author + thread are locally homed (so A may
    // issue); on B/C they are a federated mirror homed at A.
    let author_key = SigningKey::generate(&mut OsRng);
    let author_pub: [u8; 32] = *author_key.verifying_key().as_bytes();
    let thread_uuid = Uuid::new_v4();

    let a_author = insert_user(&a.state.db, "auth", &author_pub, None).await;
    ensure_general_room(&a.state.db, &a_author).await;
    insert_thread(&a.state.db, &thread_uuid, &a_author, None).await;

    for inst in [b, c] {
        let author_id = insert_user(&inst.state.db, "auth", &author_pub, Some(&a_pub)).await;
        ensure_general_room(&inst.state.db, &author_id).await;
        insert_thread(&inst.state.db, &thread_uuid, &author_id, Some(&a_pub)).await;
    }

    // Interest keyed on the OP author pubkey: B → A, C → B.
    let announce = announce_with_content_keys(&[&author_pub]).encode();
    let (st, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "B → A announce must apply");
    let (st, _) = send_envelope_signed(
        &harness,
        "c",
        "b",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "C → B announce must apply");

    dispatch_local_thread_status(
        &a.state,
        &thread_uuid,
        ThreadStatusKind::Locked,
        Some("off-topic"),
    )
    .await
    .expect("dispatch_local_thread_status");

    // The §17.4 mirror on the non-adjacent C proves the relay reached it.
    let c_db = c.state.db.clone();
    let id_text = thread_uuid.to_string();
    let mirrored = poll_until(2_000, || {
        let c_db = c_db.clone();
        let id_text = id_text.clone();
        async move {
            sqlx::query_scalar!(
                "SELECT locked AS \"locked: bool\" FROM threads WHERE id = ?",
                id_text,
            )
            .fetch_optional(&c_db)
            .await
            .expect("query threads on c")
            .unwrap_or(false)
        }
    })
    .await;
    assert!(
        mirrored,
        "forwarder did not relay the thread-status lock to non-adjacent C"
    );
}

// ---------------------------------------------------------------------------
// Interest gate (negative)
// ---------------------------------------------------------------------------

/// A peer that announces a frontier *not* covering subject S receives
/// nothing when A originates a user-status for S — adjacency alone does
/// not earn delivery; the bloom filter is the gate.
#[tokio::test]
async fn user_status_not_forwarded_to_uninterested_peer() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");
    let a_pub = *a.state.instance_key.public_bytes();

    let s_key = SigningKey::generate(&mut OsRng);
    let s_pub: [u8; 32] = *s_key.verifying_key().as_bytes();
    insert_user(&b.state.db, "subj", &s_pub, Some(&a_pub)).await;

    // B announces interest in some *other* key — its filter does not
    // cover S, so A's `peers_interested_in` must exclude B for S.
    let other_key = SigningKey::generate(&mut OsRng);
    let other_pub: [u8; 32] = *other_key.verifying_key().as_bytes();
    let announce = announce_with_content_keys(&[&other_pub]).encode();
    let (st, _) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/frontier/announce",
        &announce,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "B → A announce must apply");

    dispatch_local_user_status(
        &a.state,
        &s_pub,
        UserStatusKind::Banned,
        None,
        Some("ban evasion"),
    )
    .await
    .expect("dispatch_local_user_status");

    // Poll for the (un)arrival: if B ever projects a status for S the gate
    // leaked. A short budget is enough — the happy relay lands in
    // single-digit ms, so 500ms of silence is a confident negative.
    let leaked = poll_until(500, || {
        let b_db = b.state.db.clone();
        let s_slice = s_pub.to_vec();
        async move {
            let subj: &[u8] = &s_slice;
            sqlx::query_scalar!(
                "SELECT 1 AS \"n!: i64\" FROM user_statuses WHERE subject = ?",
                subj,
            )
            .fetch_optional(&b_db)
            .await
            .expect("query user_statuses on b")
            .is_some()
        }
    })
    .await;
    assert!(
        !leaked,
        "uninterested peer B must not receive the user-status"
    );
}

// ---------------------------------------------------------------------------
// Auth flip under gossip (negative)
// ---------------------------------------------------------------------------

/// A forwarder that re-signs a user-status with its *own* key — rather
/// than relaying the home's signed bytes verbatim — is
/// `rejected/invalid_signature`. Under §16.2 the inner signature is
/// verified against the subject's resolved home pubkey (A), never the
/// transport sender (B), so B cannot forge authority for an A-homed
/// subject by signing fresh bytes.
#[tokio::test]
async fn forwarded_user_status_wrong_inner_signer_rejected() {
    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");
    let b = harness.instance("b");

    // Subject S is a *local* user on A — so A resolves S's home to itself
    // and the authority pubkey is A's own instance key.
    let s_key = SigningKey::generate(&mut OsRng);
    let s_pub: [u8; 32] = *s_key.verifying_key().as_bytes();
    insert_user(&a.state.db, "subj", &s_pub, None).await;

    // B signs the user-status with B's *own* instance key but truthfully
    // labels `signing_instance` as B's domain. The label is consistent;
    // the only defect is that the inner signer is not S's home (A). The
    // home-pubkey signature check (step 5) must reject it before the
    // advisory domain cross-check (step 6) is even reached.
    let signed = sign_user_status_with_key(
        &b.state.instance_key,
        &s_pub,
        UserStatusKind::Banned,
        None,
        &b.state.instance_domain,
        Some("forged ban"),
        1_700_000_000_000,
        None,
    );

    // B pushes its forged object straight to A. A homes S, so it resolves
    // the home pubkey = A and verifies the inner signature against it.
    let (status, body) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/user-status",
        &encode_push_body(&[&signed]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    let results = parse_results(&body);
    assert_eq!(results[0].1, "rejected");
    assert_eq!(results[0].2.as_deref(), Some("invalid_signature"));

    // And the forged bytes were not persisted.
    assert!(
        !has_signed_object(&a.state.db, &signed.canonical_hash).await,
        "rejected forgery must not land in signed_objects",
    );
}

// ---------------------------------------------------------------------------
// Producer locality gate (§13.x): admins moderate only locally-homed
// targets, so a local admin can never issue a status object for content
// homed elsewhere.
// ---------------------------------------------------------------------------

/// Banning a user homed on another instance is `403
/// remote_moderation_target`.
#[tokio::test]
async fn admin_ban_remote_user_rejected() {
    let (app, state) = test_app().await;
    let admin = setup_admin(&app, "admin").await;

    // A federated user whose home is some other instance key.
    let remote_home = [0x11u8; 32];
    let user_key = SigningKey::generate(&mut OsRng);
    let user_pub: [u8; 32] = *user_key.verifying_key().as_bytes();
    let uid = insert_user(&state.db, "remote", &user_pub, Some(&remote_home)).await;

    let req = json_request(
        Method::POST,
        &format!("/api/admin/users/{uid}/ban"),
        Some(&admin.cookie),
        &json!({ "reason": "spam" }),
    );
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "remote_moderation_target");
}

/// Suspending a user homed on another instance is `403
/// remote_moderation_target`.
#[tokio::test]
async fn admin_suspend_remote_user_rejected() {
    let (app, state) = test_app().await;
    let admin = setup_admin(&app, "admin").await;

    let remote_home = [0x22u8; 32];
    let user_key = SigningKey::generate(&mut OsRng);
    let user_pub: [u8; 32] = *user_key.verifying_key().as_bytes();
    let uid = insert_user(&state.db, "remote", &user_pub, Some(&remote_home)).await;

    let req = json_request(
        Method::POST,
        &format!("/api/admin/users/{uid}/suspend"),
        Some(&admin.cookie),
        &json!({ "reason": "cooldown", "duration": "1d" }),
    );
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "remote_moderation_target");
}

/// Locking a thread homed on another instance is `403
/// remote_moderation_target`.
#[tokio::test]
async fn admin_lock_remote_thread_rejected() {
    let (app, state) = test_app().await;
    let admin = setup_admin(&app, "admin").await;

    // Author + room for the threads FK, then a thread homed elsewhere.
    let remote_home = [0x33u8; 32];
    let author_key = SigningKey::generate(&mut OsRng);
    let author_pub: [u8; 32] = *author_key.verifying_key().as_bytes();
    let author_id = insert_user(&state.db, "auth", &author_pub, Some(&remote_home)).await;
    ensure_general_room(&state.db, &author_id).await;
    let thread_uuid = Uuid::new_v4();
    insert_thread(&state.db, &thread_uuid, &author_id, Some(&remote_home)).await;

    let req = json_request(
        Method::POST,
        &format!("/api/admin/threads/{thread_uuid}/lock"),
        Some(&admin.cookie),
        &json!({ "reason": "off-topic" }),
    );
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "remote_moderation_target");
}
