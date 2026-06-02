#![cfg(feature = "test-auth")]
//! Multi-hop gossip-forwarding integration tests (§7.4 / §7.5).
//!
//! `federation_edges.rs` already covers the *single* relay hop
//! (A pushes to B, B forwards to one interested peer C) plus the §8.10
//! shedding and §7.4 routing-direction edge cases. This file exercises
//! the property those tests don't: that the §7.5 interest-routed
//! forwarder chains across *several* hops, converges when redundant
//! paths re-deliver the same object, and stops where interest stops.
//!
//! All three scenarios assert on durable `signed_objects` propagation
//! rather than on the `trust_edges` projection. That's deliberate: per
//! §9.1 a received edge whose endpoints aren't local users still stores
//! its canonical bytes (`EndpointMissing → applied`) and still fans out
//! to interested peers, so the forward path is fully exercised by a
//! synthetic `alice → bob` edge with no local user rows anywhere. The
//! signed edge is legitimate sender-side wire production — nothing about
//! the receivers' DB state is faked, so these tests need no carve-out.
//!
//! Each downstream peer advertises interest by announcing a frontier
//! whose `expansion_filter` carries the edge *target* (`bob`, the §7.4
//! trust-edge routing key) to its upstream. The forwarder dispatches via
//! per-peer outbound queues whose drain workers deliver synchronously
//! through the in-process transport, so [`drain_gossip`] pumps every
//! queue to quiescence and the post-conditions are deterministic.

mod common;

use std::time::Duration;

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use prismoire_server::federation::bloom::BloomFilter;
use prismoire_server::federation::frontier::{FilterSpec, FrontierAnnounce};
use prismoire_server::federation::routing::Mode;
use prismoire_server::signed::TrustStance;
use prismoire_server::signing::sign_trust_edge_with_key;
use rand::rngs::OsRng;
use sqlx::SqlitePool;

use common::federation::{
    MultiInstanceHarness, establish_active_peering, send_envelope_signed, settle,
};
use common::{Session, body_json, get_request, json_request, send, setup_admin};
use serde_json::json;

// ===========================================================================
// §7.5 — multi-hop forwarding
// ===========================================================================

/// A signed trust-edge pushed into one end of a five-instance line gossips
/// all the way to the far end. Topology `A→B→C→D→E`, each link an active
/// peering; every downstream announces interest in the edge target `bob`
/// to its upstream so the §7.5 forwarder picks it as the next hop. A pushes
/// the (synthetic, real-signed) `alice → bob` root edge to B; after the
/// outbound queues drain, the canonical bytes must be durable on every
/// downstream B, C, D, E — and absent on the originator A, which only ever
/// sent the object and (per §7.5 `arrived_from` suppression) is never
/// pushed its own object back.
#[tokio::test]
async fn edge_gossips_across_five_instance_chain() {
    let harness = MultiInstanceHarness::new(5).await;
    let chain = ["a", "b", "c", "d", "e"];
    for pair in chain.windows(2) {
        establish_active_peering(&harness, pair[0], pair[1]).await;
    }

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_pub = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

    // Each downstream tells its upstream "I'm interested in edges targeting
    // bob", so the upstream's `peers_interested_in` returns it as the next
    // forward hop. The originator push A→B needs no announce — A pushes
    // directly to B; the announces only drive the B→C→D→E relay chain.
    announce_interest(&harness, "b", "a", &bob_pub).await;
    announce_interest(&harness, "c", "b", &bob_pub).await;
    announce_interest(&harness, "d", "c", &bob_pub).await;
    announce_interest(&harness, "e", "d", &bob_pub).await;

    let signed = sign_trust_edge_with_key(
        &alice_key,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let hash = signed.canonical_hash.as_slice().to_vec();

    push_edge(&harness, "a", "b", &signed.payload, &signed.signature).await;
    drain_gossip(&harness, &chain).await;

    // Durable on every downstream — the object rode four forward hops.
    for label in ["b", "c", "d", "e"] {
        let db = &harness.instance(label).state.db;
        assert_eq!(
            signed_object_count(db, &hash).await,
            1,
            "edge should have gossiped to instance {label:?} exactly once",
        );
    }

    // The originator never receives its own object back via gossip (§7.5
    // `arrived_from` suppression at B), and a push-originator never stores
    // the object it sent.
    let a_db = &harness.instance("a").state.db;
    assert_eq!(
        signed_object_count(a_db, &hash).await,
        0,
        "originator A must not be pushed its own object back",
    );
}

/// Redundant gossip paths converge to a single stored copy. Diamond
/// topology: B fans out to both C and D (the §7.5 `REDUNDANCY_K = 2`
/// trust-edge cap admits exactly two downstream peers), and both C and D
/// forward to the shared sink E. E therefore receives the same object
/// along two independent paths; §9.1 dedup on `canonical_hash` keeps the
/// second arrival from re-storing or re-forwarding, so E holds exactly one
/// copy. This is the convergence property that makes redundant-path gossip
/// safe — extra paths cost a wire round-trip, never a duplicated row.
#[tokio::test]
async fn redundant_diamond_paths_converge_to_single_copy() {
    let harness = MultiInstanceHarness::new(5).await;
    // a → b, then b fans to {c, d}, then both reconverge on e.
    for (i, j) in [("a", "b"), ("b", "c"), ("b", "d"), ("c", "e"), ("d", "e")] {
        establish_active_peering(&harness, i, j).await;
    }

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_pub = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

    // C and D are both interested to B (so B's REDUNDANCY_K=2 fanout picks
    // both); E is interested to both C and D (so it's the next hop on each
    // arm of the diamond).
    announce_interest(&harness, "c", "b", &bob_pub).await;
    announce_interest(&harness, "d", "b", &bob_pub).await;
    announce_interest(&harness, "e", "c", &bob_pub).await;
    announce_interest(&harness, "e", "d", &bob_pub).await;

    let signed = sign_trust_edge_with_key(
        &alice_key,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let hash = signed.canonical_hash.as_slice().to_vec();

    push_edge(&harness, "a", "b", &signed.payload, &signed.signature).await;
    drain_gossip(&harness, &["a", "b", "c", "d", "e"]).await;

    // Both arms delivered; the sink stored exactly one copy despite the
    // double delivery.
    for label in ["b", "c", "d", "e"] {
        let db = &harness.instance(label).state.db;
        assert_eq!(
            signed_object_count(db, &hash).await,
            1,
            "instance {label:?} should hold exactly one copy of the gossiped edge",
        );
    }
}

/// Gossip stops at the first hop whose downstream advertised no interest.
/// Chain `A→B→C→D`, but only C announces interest (to B); D never announces
/// a frontier at all. Per §7.4/§7.5 a peer with no recorded frontier misses
/// every routing key, so C — which received the edge from B — finds no
/// interested downstream and forwards nothing. The object is durable on B
/// and C and never reaches D. This pins interest-gating as the thing that
/// bounds gossip reach, not mere peering: D is an active peer of C, yet
/// silence keeps it out of the routing population.
#[tokio::test]
async fn uninterested_downstream_halts_gossip_chain() {
    let harness = MultiInstanceHarness::new(4).await;
    for (i, j) in [("a", "b"), ("b", "c"), ("c", "d")] {
        establish_active_peering(&harness, i, j).await;
    }

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_pub = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

    // Only C announces interest (to B). D deliberately stays silent, so it
    // never joins C's routing population.
    announce_interest(&harness, "c", "b", &bob_pub).await;

    let signed = sign_trust_edge_with_key(
        &alice_key,
        &bob_pub,
        TrustStance::Trust,
        1_700_000_000_000,
        None,
    );
    let hash = signed.canonical_hash.as_slice().to_vec();

    push_edge(&harness, "a", "b", &signed.payload, &signed.signature).await;
    drain_gossip(&harness, &["a", "b", "c", "d"]).await;

    for label in ["b", "c"] {
        let db = &harness.instance(label).state.db;
        assert_eq!(
            signed_object_count(db, &hash).await,
            1,
            "edge should reach interested hop {label:?}",
        );
    }
    let d_db = &harness.instance("d").state.db;
    assert_eq!(
        signed_object_count(d_db, &hash).await,
        0,
        "silent peer D advertised no interest, so gossip must not reach it",
    );
}

// ===========================================================================
// §7.5 / §7.6 — end-to-end trust + content visibility across hops
// ===========================================================================

/// The scenario the low-level forwarder tests above stand in for, end to
/// end: a post authored three *trust* hops upstream becomes visible to the
/// reader at the far end of the chain — carried there entirely by the real
/// gossip + reverse-bootstrap machinery, with no hand-fed edges or content.
///
/// Four instances `a, b, c, d`, one admin user on each, fully peered. Through
/// the real trust-code mint/redeem `/api` we build the trust *chain* `userA →
/// userB → userC → userD` (each user trusts the next), and userA authors a
/// thread on A through the real `/api/threads`. Because content visibility is
/// "author's transitive trust in the reader" (§trust), userD sits at exactly
/// the `MAX_DEPTH = 3` horizon with a reverse-trust score of
/// `1.0 × 0.7 × 0.7 = 0.49 ≥ 0.45` — just inside the `0.45` threshold.
///
/// Nothing is hand-delivered. The trust edges fan out along the §7.5
/// interest-routed forwarder, and each one D applies triggers a §10.5.4
/// reverse-bootstrap backfill that hydrates the next upstream user and pulls
/// its content. That widens D's reverse-frontier *expansion interest* by one
/// hop, which attracts the next upstream edge — so the chain grows
/// `userC → userB → userA` one reverse hop at a time until D scores userA at
/// 0.49 and pulls userA's post. [`settle`] drives every instance's rebuild +
/// frontier fan-out + outbound drain to quiescence, the deterministic
/// stand-in for the continuous background loops production runs (the harness
/// deliberately doesn't spawn them).
///
/// This converges deterministically only because the §10.5.5 by-author
/// single-flight guard and the §9.3 outbound-backfill cap are now
/// *per-instance* state on [`AppState`] rather than module statics. In
/// production (one instance per process) those scopings are identical; the
/// per-instance form is what stops the four in-process `AppState`s of this
/// harness from suppressing one another's legitimate same-author backfills —
/// the collision that previously made multi-hop propagation nondeterministic
/// and forced a hand-delivery workaround here.
///
/// The payoff assertion: userD's activity feed for userA shows the post via
/// *genuine* 3-hop reverse trust (`admin_override == false`), not the admin
/// carve-out that would mask a broken trust closure.
#[tokio::test]
async fn post_reaches_user_three_trust_hops_away() {
    let harness = MultiInstanceHarness::new(4).await;
    let labels = ["a", "b", "c", "d"];
    // Full peering mesh so the interest-routed forwarder can carry an edge
    // from any origin to any interested peer (the receive + announce routes
    // sit behind `verify_known_peer`).
    for (i, &p) in labels.iter().enumerate() {
        for &q in &labels[i + 1..] {
            establish_active_peering(&harness, p, q).await;
        }
    }

    let user_a = setup_admin(&harness.instance("a").router, "user-a").await;
    let user_b = setup_admin(&harness.instance("b").router, "user-b").await;
    let user_c = setup_admin(&harness.instance("c").router, "user-c").await;
    let user_d = setup_admin(&harness.instance("d").router, "user-d").await;

    // Build the trust chain A→B→C→D via the real trust-code flow. `trust`
    // makes the first arg trust the second; each redeem signs and stores the
    // real `truster → trustee` edge on the truster's instance.
    trust(&harness, "a", &user_a, "b", &user_b).await;
    trust(&harness, "b", &user_b, "c", &user_c).await;
    trust(&harness, "c", &user_c, "d", &user_d).await;

    // userA authors a post on A. The unique needle makes a hit in D's feed
    // unambiguous evidence the post reached the far end of the chain.
    let needle = "persimmon";
    let create = send(
        &harness.instance("a").router,
        json_request(
            Method::POST,
            "/api/threads",
            Some(&user_a.cookie),
            &json!({
                "room": "lounge",
                "title": "hello from A",
                "body": format!("{needle} — authored on A by user-a"),
            }),
        ),
    )
    .await;
    assert_eq!(create.status(), StatusCode::CREATED, "userA authors on A");

    let activity_url = format!("/api/users/{}/activity", user_a.public_key_hex);

    // Drive the real gossip machinery and read D's view of userA — no
    // hand-delivered edges. Each `settle` pumps every instance's rebuild +
    // interest-routed fan-out + reverse-bootstrap backfill to quiescence; the
    // chain grows one reverse hop per settle round as each applied edge widens
    // D's expansion interest and attracts the next upstream edge. A single
    // `settle` usually carries the whole chain, but we re-settle (bounded)
    // until D's feed shows the post, mirroring production's eventually-
    // consistent convergence under its continuous background loops.
    let mut rounds = 0;
    let resp = loop {
        settle(&harness).await;
        let resp = send(
            &harness.instance("d").router,
            get_request(&activity_url, Some(&user_d.cookie)),
        )
        .await;
        if resp.status() == StatusCode::OK {
            let body = body_json(resp).await;
            let genuine = body["admin_override"] == false
                && body["items"]
                    .as_array()
                    .map(|items| {
                        items
                            .iter()
                            .any(|i| i["body"].as_str().is_some_and(|b| b.contains(needle)))
                    })
                    .unwrap_or(false);
            if genuine {
                break send(
                    &harness.instance("d").router,
                    get_request(&activity_url, Some(&user_d.cookie)),
                )
                .await;
            }
        }
        rounds += 1;
        assert!(
            rounds < 20,
            "userA's post did not reach userD within 20 settle rounds",
        );
    };
    assert_eq!(resp.status(), StatusCode::OK, "userD reads userA activity");
    let body = body_json(resp).await;
    assert_eq!(
        body["admin_override"], false,
        "userD must see userA via genuine 3-hop trust, not the admin carve-out; got {body}",
    );
    let saw_post = body["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .any(|i| i["body"].as_str().is_some_and(|b| b.contains(needle)))
        })
        .unwrap_or(false);
    assert!(
        saw_post,
        "userA's post must gossip three trust hops to userD; got {body}",
    );
}

/// Make `truster` (on `truster_label`) trust `trustee` (on `trustee_label`)
/// through the real trust-code API: the trustee mints a code over
/// `GET /api/me/trust-code`, the truster redeems it over
/// `POST /api/users/by-trust-code`. The redeem seeds a federated stub for
/// the trustee on the truster's instance, signs the `truster → trustee`
/// edge, and hands it to the §7.5 forwarder.
async fn trust(
    harness: &MultiInstanceHarness,
    truster_label: &str,
    truster: &Session,
    trustee_label: &str,
    trustee: &Session,
) {
    let mint = send(
        &harness.instance(trustee_label).router,
        get_request("/api/me/trust-code", Some(&trustee.cookie)),
    )
    .await;
    assert_eq!(mint.status(), StatusCode::OK, "{trustee_label} mints code");
    let code = body_json(mint).await["code"]
        .as_str()
        .expect("code field")
        .to_string();

    let redeem = send(
        &harness.instance(truster_label).router,
        json_request(
            Method::POST,
            "/api/users/by-trust-code",
            Some(&truster.cookie),
            &json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(
        redeem.status(),
        StatusCode::OK,
        "{truster_label} redeems {trustee_label}'s code",
    );
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Announce, from `from` to `to`, a frontier whose `expansion_filter`
/// carries `target` — making `from` an interest-matching forward target on
/// `to` for any trust-edge keyed on `target` (the §7.4 routing key). The
/// two instances must already be actively peered (the announce route runs
/// behind `verify_known_peer`).
async fn announce_interest(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    target: &[u8; 32],
) {
    let body = announce_with_edge_target(target).encode();
    let (status, _) = send_envelope_signed(
        harness,
        from,
        to,
        Method::POST,
        "/federation/v1/frontier/announce",
        &body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{from} → {to} interest announce must apply",
    );
}

/// Push a single signed edge from active-peer `from` to `to` and assert it
/// applied. The push is the originator hop; the forwarder fans the applied
/// edge out from `to` to its interested peers.
async fn push_edge(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    payload: &[u8],
    signature: &[u8],
) {
    let body = encode_edges_body(&[encode_wire(payload, signature)]);
    let (status, resp_body) = send_envelope_signed(
        harness,
        from,
        to,
        Method::POST,
        "/federation/v1/edges",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{from} → {to} edge push must apply");
    assert_eq!(
        parse_first_result_status(&resp_body),
        "applied",
        "pushed edge should report applied",
    );
}

/// Pump every named instance's outbound queue to idle, round-robin, for as
/// many passes as there are instances. Each per-peer drain worker dispatches
/// synchronously through the in-process transport, so a downstream's enqueue
/// is already visible by the time its upstream's `wait_idle` returns; one
/// pass per instance therefore covers the deepest possible propagation
/// chain regardless of drain order.
async fn drain_gossip(harness: &MultiInstanceHarness, labels: &[&str]) {
    for _ in 0..labels.len() {
        for label in labels {
            harness
                .instance(label)
                .state
                .outbound_queues
                .wait_idle(Duration::from_secs(2))
                .await;
        }
    }
}

/// Count rows in `signed_objects` with the given `canonical_hash`.
async fn signed_object_count(db: &SqlitePool, hash: &[u8]) -> i64 {
    sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
        hash,
    )
    .fetch_one(db)
    .await
    .expect("count signed_objects")
}

/// Build a §8.3 frontier announce whose `expansion_filter` holds a single
/// interested edge-target key (and an empty `visible_filter`). Mirrors the
/// minimal interest advertisement `federation_edges.rs` uses for its relay
/// tests: a 1024-bit / k=7 bloom comfortably holds one key at the reference
/// 1% FPR.
fn announce_with_edge_target(target: &[u8; 32]) -> FrontierAnnounce {
    let mut expansion = BloomFilter::new_empty(7, 1024, 1, 0.01).expect("build edge filter");
    expansion.insert(target.as_slice());
    let visible = BloomFilter::new_empty(7, 1024, 0, 0.01).expect("build empty visible filter");
    FrontierAnnounce {
        version: 1,
        epoch_start: 1_700_000_000_000,
        active_horizon_days: 0,
        visible_filter: FilterSpec::from_bloom(&visible),
        expansion_filter: FilterSpec::from_bloom(&expansion),
        mode: Mode::Filtered,
        age_ceilings: Default::default(),
    }
}

/// Wrap a list of WireFormat blobs as the `{ "edges": [bstr, …] }` push
/// body.
fn encode_edges_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("edges".into()), Value::Array(arr))]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&body, &mut buf).expect("ser edges body");
    buf
}

/// Encode a §6.3 WireFormat `{ "p", "s" }` blob — the same shape a sender
/// produces on the wire.
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&m, &mut buf).expect("ser wire");
    buf
}

/// Pull the `status` of the first entry out of an `/edges` push response's
/// `{ "results": [{ status, … }, …] }` body.
fn parse_first_result_status(body: &[u8]) -> String {
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
    let Some(Value::Map(fields)) = arr.into_iter().next() else {
        panic!("results array is empty");
    };
    for (k, v) in fields {
        if let (Value::Text(name), Value::Text(status)) = (&k, &v)
            && name == "status"
        {
            return status.clone();
        }
    }
    panic!("missing `status` field");
}
