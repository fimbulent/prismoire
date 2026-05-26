//! Phase-5 Layer-1 integration tests: §9.3 chain-continuity backfill.
//!
//! Pins Task #17's done-when criteria from
//! `docs/federation-impl-plan.md`:
//!
//! - `GET /federation/v1/edges/backfill?source=<hex>&target=<hex>` from
//!   an active peer returns the chain's signed bytes oldest-first.
//! - Pagination via `limit` + opaque `since` cursor produces a
//!   resumable walk: the first page carries `complete: false` +
//!   `next_cursor`; resuming with that cursor returns the remainder
//!   with `complete: true` and no `next_cursor`.
//! - Unknown `(source, target)` pair → `400 unknown_chain`.
//! - **Partition-heal end-to-end:** D joins late, GETs `/edges/backfill`
//!   against A, replays each returned signed object into D's own
//!   `/edges` push handler, and D's `current_trust_edges` projection
//!   converges to A's latest stance.
//!
//! Layer-0 invariants (cursor encode/decode, hex parsing, response
//! shapes) live in the in-module `#[cfg(test)]` block in
//! `src/federation/backfill.rs`.

#![cfg(feature = "test-auth")]

mod common;

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use prismoire_server::signed::TrustStance;
use prismoire_server::signing::{SigningOutput, sign_trust_edge_with_key};
use rand::rngs::OsRng;
use sqlx::SqlitePool;

use common::federation::{
    MultiInstanceHarness, establish_active_peering, send_envelope_signed,
    send_envelope_signed_split,
};

// ---------------------------------------------------------------------------
// Hex helper (no dep on the `hex` crate — keep the test file self-contained)
// ---------------------------------------------------------------------------

/// Lowercase hex of a 32-byte pubkey. Matches the format
/// `backfill::decode_hex_pubkey` accepts.
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("hi nibble"));
        s.push(char::from_digit((b & 0x0F) as u32, 16).expect("lo nibble"));
    }
    s
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Insert a `users` row with a known Ed25519 public key. Same shape as
/// the helper in `federation_phase5.rs` — duplicated here so this test
/// crate stays self-contained (the two crates can't share a test-only
/// module without an extra `pub` knob in `tests/common/mod.rs`).
async fn insert_user_with_pubkey(db: &SqlitePool, id: &str, display_name: &str, pubkey: &[u8; 32]) {
    let pubkey_slice: &[u8] = pubkey.as_slice();
    let skeleton = display_name.to_lowercase();
    sqlx::query!(
        "INSERT INTO users (id, display_name, signup_method, public_key, display_name_skeleton) \
         VALUES (?, ?, 'admin', ?, ?)",
        id,
        display_name,
        pubkey_slice,
        skeleton,
    )
    .execute(db)
    .await
    .expect("insert user");
}

/// Sign a chain of `(stance, created_at_ms)` mutations, threading each
/// row's `canonical_hash` into the next as `prior_edge_hash`. This is
/// the bare-bones equivalent of what `set_trust_edge` does inside the
/// server, but without touching any DB: every chained edge is
/// reproducible from `(signer_key, target_pub, stances)` alone.
fn sign_chain(
    signer: &SigningKey,
    target_pub: &[u8; 32],
    stances: &[(TrustStance, u64)],
) -> Vec<SigningOutput> {
    let mut chain = Vec::with_capacity(stances.len());
    let mut prior: Option<[u8; 32]> = None;
    for (stance, ts) in stances {
        let signed = sign_trust_edge_with_key(signer, target_pub, *stance, *ts, prior);
        prior = Some(signed.canonical_hash);
        chain.push(signed);
    }
    chain
}

/// Wrap a `(payload, signature)` pair into the §6.3 WireFormat
/// `{ "p": bstr, "s": bstr }` shape that `/edges` accepts.
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

/// Pack a slice of WireFormat blobs under `{ "edges": [bstr, ...] }`,
/// the §9.1 push body. Used here to seed the originator's chain and to
/// replay the backfilled bytes into the late-joiner.
fn encode_edges_body(wires: &[Vec<u8>]) -> Vec<u8> {
    let arr: Vec<Value> = wires.iter().map(|w| Value::Bytes(w.clone())).collect();
    let body = Value::Map(vec![(Value::Text("edges".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + wires.iter().map(|w| w.len()).sum::<usize>());
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// Push every signed edge in `chain` to `receiver` (one edge per
/// request, mirroring the typical real-world flow where edges land
/// over time rather than as one batched gossip blob). Returns when
/// every push has been acknowledged.
async fn push_chain(
    harness: &MultiInstanceHarness,
    sender: &str,
    receiver: &str,
    chain: &[SigningOutput],
) {
    for signed in chain {
        let wire = encode_wire(&signed.payload, &signed.signature);
        let body = encode_edges_body(&[wire]);
        let (status, _resp) = send_envelope_signed(
            harness,
            sender,
            receiver,
            Method::POST,
            "/federation/v1/edges",
            &body,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "push setup must succeed");
    }
}

// ---------------------------------------------------------------------------
// Backfill response parsing
// ---------------------------------------------------------------------------

/// Decoded `{ objects, [next_cursor], complete }` body from
/// `/federation/v1/edges/backfill`.
struct BackfillBody {
    /// Each entry is the raw bytes of one §6.3 WireFormat blob — the
    /// same shape the §9.1 push body expects, so replay is a direct
    /// `encode_edges_body(&objects)`.
    objects: Vec<Vec<u8>>,
    /// Opaque cursor for the next page, present iff `complete = false`.
    next_cursor: Option<Vec<u8>>,
    complete: bool,
}

fn parse_backfill_body(bytes: &[u8]) -> BackfillBody {
    let v: Value = ciborium::de::from_reader(bytes).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("backfill body is not a map");
    };
    let mut objects: Option<Vec<Vec<u8>>> = None;
    let mut next_cursor: Option<Vec<u8>> = None;
    let mut complete: Option<bool> = None;
    for (k, v) in m {
        if let Value::Text(t) = &k {
            match (t.as_str(), v) {
                ("objects", Value::Array(arr)) => {
                    let mut out = Vec::with_capacity(arr.len());
                    for entry in arr {
                        let Value::Bytes(b) = entry else {
                            panic!("objects entry must be bstr");
                        };
                        out.push(b);
                    }
                    objects = Some(out);
                }
                ("next_cursor", Value::Bytes(b)) => next_cursor = Some(b),
                ("complete", Value::Bool(b)) => complete = Some(b),
                _ => {}
            }
        }
    }
    BackfillBody {
        objects: objects.expect("missing `objects`"),
        next_cursor,
        complete: complete.expect("missing `complete`"),
    }
}

/// Pull the `error` string out of a 400 response body.
fn parse_error_body(bytes: &[u8]) -> String {
    let v: Value = ciborium::de::from_reader(bytes).expect("cbor parse");
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

/// Issue `GET /federation/v1/edges/backfill?...` from `from` to `to`,
/// signing under the empty body and the query-less path per §6.5
/// step 9. Returns `(status, body)`.
async fn get_backfill(
    harness: &MultiInstanceHarness,
    from: &str,
    to: &str,
    source_hex: &str,
    target_hex: &str,
    limit: Option<u32>,
    since_b64: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let mut query = format!("source={source_hex}&target={target_hex}");
    if let Some(n) = limit {
        query.push_str(&format!("&limit={n}"));
    }
    if let Some(c) = since_b64 {
        query.push_str(&format!("&since={c}"));
    }
    let signed_path = "/federation/v1/edges/backfill";
    let dispatch_uri = format!("{signed_path}?{query}");
    send_envelope_signed_split(
        harness,
        from,
        to,
        Method::GET,
        signed_path,
        &dispatch_uri,
        b"",
    )
    .await
}

// ---------------------------------------------------------------------------
// Done-when scenarios
// ---------------------------------------------------------------------------

/// A holds a 3-mutation chain on (alice, bob). A late-joining D peers
/// with A, GETs `/edges/backfill`, and receives all three signed
/// objects in oldest-first order with `complete: true` and no
/// `next_cursor`. Pins the unpaginated happy path.
#[tokio::test]
async fn backfill_returns_chain_oldest_first_complete() {
    let harness = MultiInstanceHarness::new(4).await;
    // A receives the chain from B (the originator stand-in); D pulls
    // from A. A is the only instance whose DB we walk on the GET side.
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&a.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&a.state.db, "user-bob", "bob", &bob_pub).await;

    // Seed A with a chained history. Distinct ms-precision timestamps
    // keep the (created_at, canonical_hash) keyset pagination
    // unambiguous; the timestamps round to whole-second ISO strings on
    // store, so they only need to differ at the second level.
    let chain = sign_chain(
        &alice_key,
        &bob_pub,
        &[
            (TrustStance::Trust, 1_700_000_000_000),
            (TrustStance::Distrust, 1_700_000_001_000),
            (TrustStance::Trust, 1_700_000_002_000),
        ],
    );
    push_chain(&harness, "b", "a", &chain).await;

    // D joins late and peers with A.
    establish_active_peering(&harness, "a", "d").await;

    let alice_hex = to_hex(&alice_pub);
    let bob_hex = to_hex(&bob_pub);
    let (status, body) = get_backfill(&harness, "d", "a", &alice_hex, &bob_hex, None, None).await;
    assert_eq!(status, StatusCode::OK, "happy backfill must be 200");

    let parsed = parse_backfill_body(&body);
    assert!(parsed.complete, "single page must report complete=true");
    assert!(
        parsed.next_cursor.is_none(),
        "complete=true must omit next_cursor (§10.5.2)",
    );
    assert_eq!(parsed.objects.len(), 3, "all 3 chained edges returned");

    // Oldest-first: the order returned must thread by prior_edge_hash —
    // i.e. equal the order we seeded.
    for (i, signed) in chain.iter().enumerate() {
        let expected = encode_wire(&signed.payload, &signed.signature);
        assert_eq!(
            parsed.objects[i], expected,
            "object[{i}] must be the chained signed bytes verbatim",
        );
    }
}

/// Pagination round-trip: 4-mutation chain, page size 2. First GET
/// returns 2 objects + `next_cursor` + `complete: false`; the resume
/// GET with that cursor returns the final 2 with `complete: true`.
#[tokio::test]
async fn backfill_paginates_with_limit_and_next_cursor() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&a.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&a.state.db, "user-bob", "bob", &bob_pub).await;

    let chain = sign_chain(
        &alice_key,
        &bob_pub,
        &[
            (TrustStance::Trust, 1_700_000_000_000),
            (TrustStance::Distrust, 1_700_000_001_000),
            (TrustStance::Trust, 1_700_000_002_000),
            (TrustStance::Distrust, 1_700_000_003_000),
        ],
    );
    push_chain(&harness, "b", "a", &chain).await;

    establish_active_peering(&harness, "a", "d").await;

    let alice_hex = to_hex(&alice_pub);
    let bob_hex = to_hex(&bob_pub);

    // Page 1: limit=2 → first two objects + next_cursor.
    let (s1, b1) = get_backfill(&harness, "d", "a", &alice_hex, &bob_hex, Some(2), None).await;
    assert_eq!(s1, StatusCode::OK);
    let p1 = parse_backfill_body(&b1);
    assert_eq!(p1.objects.len(), 2);
    assert!(!p1.complete, "more rows remain — must be incomplete");
    let next_cursor = p1.next_cursor.expect("incomplete page must carry cursor");
    assert_eq!(
        p1.objects[0],
        encode_wire(&chain[0].payload, &chain[0].signature)
    );
    assert_eq!(
        p1.objects[1],
        encode_wire(&chain[1].payload, &chain[1].signature)
    );

    // Page 2: resume with the cursor → final two objects + complete:true.
    let cursor_b64 = URL_SAFE_NO_PAD.encode(&next_cursor);
    let (s2, b2) = get_backfill(
        &harness,
        "d",
        "a",
        &alice_hex,
        &bob_hex,
        Some(2),
        Some(&cursor_b64),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    let p2 = parse_backfill_body(&b2);
    assert_eq!(p2.objects.len(), 2, "remaining tail of the chain");
    assert!(p2.complete, "tail page completes the walk");
    assert!(p2.next_cursor.is_none(), "complete=true omits cursor");
    assert_eq!(
        p2.objects[0],
        encode_wire(&chain[2].payload, &chain[2].signature)
    );
    assert_eq!(
        p2.objects[1],
        encode_wire(&chain[3].payload, &chain[3].signature)
    );
}

/// Both endpoints unknown to A → `400 unknown_chain`. Distinguished
/// from `invalid_key` (which is a malformed hex string).
#[tokio::test]
async fn backfill_unknown_chain_returns_400() {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;

    // Random keys A has never seen — no users rows, no signed_objects.
    let stranger1 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let stranger2 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let (status, body) = get_backfill(
        &harness,
        "d",
        "a",
        &to_hex(&stranger1),
        &to_hex(&stranger2),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&body), "unknown_chain");
}

/// Garbage `since` cursor (right base64 alphabet, wrong length) →
/// `400 invalid_cursor`. The spec mandates this collapse so a client
/// retries without `since` rather than looping on a stale cursor.
#[tokio::test]
async fn backfill_invalid_cursor_returns_400() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;
    let a = harness.instance("a");

    // Need both endpoints to be known users so we get past the
    // `unknown_chain` check and reach the cursor parser. The chain
    // itself can be empty — invalid_cursor fires before the SQL walk.
    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&a.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&a.state.db, "user-bob", "bob", &bob_pub).await;

    // 10 bytes — not the 52-byte cursor layout the handler expects.
    let garbage = URL_SAFE_NO_PAD.encode([0u8; 10]);
    let (status, body) = get_backfill(
        &harness,
        "d",
        "a",
        &to_hex(&alice_pub),
        &to_hex(&bob_pub),
        None,
        Some(&garbage),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_error_body(&body), "invalid_cursor");
}

/// `limit=0` and `limit=MAX_EDGE_BACKFILL_PAGE + 1` both collapse to
/// `400 limit_out_of_range`. Pins the §9.6 cap.
#[tokio::test]
async fn backfill_limit_out_of_range_returns_400() {
    use prismoire_server::federation::backfill::MAX_EDGE_BACKFILL_PAGE;

    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;
    let a = harness.instance("a");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&a.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&a.state.db, "user-bob", "bob", &bob_pub).await;

    for bad_limit in [0u32, MAX_EDGE_BACKFILL_PAGE + 1] {
        let (status, body) = get_backfill(
            &harness,
            "d",
            "a",
            &to_hex(&alice_pub),
            &to_hex(&bob_pub),
            Some(bad_limit),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "limit={bad_limit}");
        assert_eq!(parse_error_body(&body), "limit_out_of_range");
    }
}

/// Done-when (Task #17): **end-to-end partition heal.** A holds a
/// 3-mutation chain. D joins late, walks `/edges/backfill` against A,
/// and replays each returned signed object into its own `/edges`
/// handler. After the replay, D's `current_trust_edges` view matches
/// A's latest stance — the exact convergence guarantee §9.3 sells.
#[tokio::test]
async fn partition_heal_via_backfill_and_replay() {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "b").await;
    let a = harness.instance("a");

    let alice_key = SigningKey::generate(&mut OsRng);
    let bob_key = SigningKey::generate(&mut OsRng);
    let alice_pub = alice_key.verifying_key().to_bytes();
    let bob_pub = bob_key.verifying_key().to_bytes();
    insert_user_with_pubkey(&a.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&a.state.db, "user-bob", "bob", &bob_pub).await;

    let chain = sign_chain(
        &alice_key,
        &bob_pub,
        &[
            // Each step flips the stance so the projection's final
            // value is non-trivial — if D drops any object in transit,
            // the convergence assert below catches it.
            (TrustStance::Trust, 1_700_000_000_000),
            (TrustStance::Distrust, 1_700_000_001_000),
            (TrustStance::Trust, 1_700_000_002_000),
        ],
    );
    push_chain(&harness, "b", "a", &chain).await;

    // D joins. D needs its own alice/bob rows so the §9.1 projection
    // lands on D's side too — Phase-5 only projects when both endpoints
    // are local users.
    let d = harness.instance("d");
    insert_user_with_pubkey(&d.state.db, "user-alice", "alice", &alice_pub).await;
    insert_user_with_pubkey(&d.state.db, "user-bob", "bob", &bob_pub).await;
    establish_active_peering(&harness, "a", "d").await;

    // D pulls the chain from A.
    let alice_hex = to_hex(&alice_pub);
    let bob_hex = to_hex(&bob_pub);
    let (status, body) = get_backfill(&harness, "d", "a", &alice_hex, &bob_hex, None, None).await;
    assert_eq!(status, StatusCode::OK);
    let parsed = parse_backfill_body(&body);
    assert!(parsed.complete);
    assert_eq!(parsed.objects.len(), 3);

    // D replays each backfilled object through its own `/edges` push
    // handler, with A as the upstream sender (A is the active peer D
    // knows, and `/edges` only cares that *some* active peer pushed
    // the bytes). After this round-trip, D's tables hold the same
    // chain A's do.
    let replay_body = encode_edges_body(&parsed.objects);
    let (replay_status, _) = send_envelope_signed(
        &harness,
        "a",
        "d",
        Method::POST,
        "/federation/v1/edges",
        &replay_body,
    )
    .await;
    assert_eq!(replay_status, StatusCode::OK, "replay must succeed");

    // Convergence: every signed object A has, D now has too.
    for signed in &chain {
        let hash_slice: &[u8] = signed.canonical_hash.as_slice();
        let present_on_d: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) AS \"c!: i64\" FROM signed_objects WHERE canonical_hash = ?",
            hash_slice,
        )
        .fetch_one(&d.state.db)
        .await
        .expect("count signed_objects on d");
        assert_eq!(
            present_on_d, 1,
            "d must hold every backfilled signed object verbatim",
        );
    }

    // Projection: the final stance on D's `current_trust_edges` view
    // matches A's — both `trust`, the last entry in the chain. The
    // view picks the latest non-neutral row per pair, so this single
    // assertion validates the full chain landed in the right order.
    let stance_on_a: String = sqlx::query_scalar!(
        "SELECT trust_type FROM current_trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&a.state.db)
    .await
    .expect("current stance on a");
    let stance_on_d: String = sqlx::query_scalar!(
        "SELECT trust_type FROM current_trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&d.state.db)
    .await
    .expect("current stance on d");
    assert_eq!(stance_on_a, "trust", "A's latest stance is trust");
    assert_eq!(
        stance_on_d, stance_on_a,
        "after backfill+replay, D converges on A's stance",
    );

    // Row counts match too — the projection table on D has the same
    // 3 historical entries as A. This guards against the "view picks
    // the right latest row, but the underlying log is missing entries"
    // failure mode.
    let count_on_a: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&a.state.db)
    .await
    .expect("count on a");
    let count_on_d: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"c!: i64\" FROM trust_edges \
         WHERE source_user = 'user-alice' AND target_user = 'user-bob'",
    )
    .fetch_one(&d.state.db)
    .await
    .expect("count on d");
    assert_eq!(count_on_a, 3);
    assert_eq!(count_on_d, count_on_a, "log lengths converge");
}
