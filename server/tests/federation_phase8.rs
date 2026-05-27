//! Phase-8 Layer-1 integration tests: §10.5 pull-backfill correctness
//! backstop.
//!
//! Pins the Phase-8 done-when criteria from
//! `docs/federation-impl-plan.md`:
//!
//! - `POST /federation/v1/backfill/by-hash` returns `200 OK` with the
//!   §6.3 WireFormat bytes when the hash is locally available.
//! - When the hash maps to an *erased* row, the response is `410 Gone`
//!   carrying the §10.5.2 `erased` array, where each entry's
//!   `authority` field is the WireFormat of the signed object that
//!   authorised the erasure (admin-rm, retract, deactivate, neutral).
//!   This is the partition-heal contract: a late-joining peer can
//!   recover the *fact* of erasure plus the cryptographic warrant for
//!   it from any active peer that has processed it.
//! - Unknown hashes (not in `signed_objects` at all) collapse to
//!   `200 OK` with an empty `objects` array and `complete: true` —
//!   distinct from "had it but erased". The sender treats this as
//!   "ask another peer".
//!
//! Layer-0 invariants (request body decode, gone-body shape, cursor
//! round-trips) live in the in-module `#[cfg(test)]` block in
//! `src/federation/backfill.rs`.

#![cfg(feature = "test-auth")]

mod common;

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use http::{Method, StatusCode};
use prismoire_server::signing::{
    SigningOutput, sign_post_revision_with_key, sign_retraction_with_key, store_signed_object,
};
use rand::rngs::OsRng;
use sqlx::SqlitePool;
use uuid::Uuid;

use common::federation::{MultiInstanceHarness, establish_active_peering, send_envelope_signed};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Seed a `signed_objects` row directly via the production helper,
/// returning the canonical_hash for later reference. The row lands
/// with `payload IS NOT NULL` and `erased_at IS NULL`.
async fn store_object(db: &SqlitePool, inner_class: &str, signed: &SigningOutput) {
    store_signed_object(
        db,
        inner_class,
        &signed.payload,
        &signed.signature,
        &signed.canonical_hash,
    )
    .await
    .expect("store_signed_object");
}

/// Stamp an existing `signed_objects` row as erased, linking it to
/// `authority_hash` so the by-hash handler can resolve the §10.5.2
/// `authority` WireFormat in O(1) via `erased_by`.
///
/// Mirrors what production erase helpers
/// (`erase_post_rev_payloads`, etc.) do, but bypasses the projection
/// JOINs so we can target a single row by canonical_hash without
/// having to thread it through `post_revisions` / `trust_edges`
/// fixtures first.
async fn mark_erased(db: &SqlitePool, canonical_hash: &[u8; 32], authority_hash: &[u8; 32]) {
    let hash_slice: &[u8] = canonical_hash.as_slice();
    let auth_slice: &[u8] = authority_hash.as_slice();
    sqlx::query!(
        "UPDATE signed_objects \
         SET payload = NULL, \
             erased_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
             erased_by = COALESCE(erased_by, ?) \
         WHERE canonical_hash = ?",
        auth_slice,
        hash_slice,
    )
    .execute(db)
    .await
    .expect("mark erased");
}

// ---------------------------------------------------------------------------
// CBOR encode / decode helpers (`{ "hashes": [bstr32, ...] }` request
// + 410-Gone / 200-OK response shapes)
// ---------------------------------------------------------------------------

/// `{ "p": bstr, "s": bstr }` (§6.3 WireFormat). Used here both to
/// pack a single signed object into the by-hash response shape and to
/// compare against `authority` entries the handler returns.
fn encode_wire(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let m = Value::Map(vec![
        (Value::Text("p".into()), Value::Bytes(payload.to_vec())),
        (Value::Text("s".into()), Value::Bytes(signature.to_vec())),
    ]);
    let mut buf = Vec::with_capacity(payload.len() + signature.len() + 16);
    ciborium::ser::into_writer(&m, &mut buf).expect("ser");
    buf
}

/// Build the §10.5.1 by-hash request body:
/// `{ "hashes": [bstr(32), ...] }`.
fn encode_by_hash_body(hashes: &[[u8; 32]]) -> Vec<u8> {
    let arr: Vec<Value> = hashes.iter().map(|h| Value::Bytes(h.to_vec())).collect();
    let body = Value::Map(vec![(Value::Text("hashes".into()), Value::Array(arr))]);
    let mut buf = Vec::with_capacity(64 + hashes.len() * 36);
    ciborium::ser::into_writer(&body, &mut buf).expect("ser");
    buf
}

/// Decoded shape of a `200 OK` body: `{ objects, [next_cursor], complete }`.
/// `objects` entries are raw §6.3 WireFormat blobs.
struct OkBody {
    objects: Vec<Vec<u8>>,
    complete: bool,
}

fn parse_ok_body(bytes: &[u8]) -> OkBody {
    let v: Value = ciborium::de::from_reader(bytes).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("ok body is not a map");
    };
    let mut objects: Option<Vec<Vec<u8>>> = None;
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
                ("complete", Value::Bool(b)) => complete = Some(b),
                _ => {}
            }
        }
    }
    OkBody {
        objects: objects.expect("missing `objects`"),
        complete: complete.expect("missing `complete`"),
    }
}

/// Decoded shape of a `410 Gone` body:
/// `{ erased: [{canonical_hash, [authority,] erased_at}], objects: [...] }`.
struct GoneBody {
    erased: Vec<ErasedEntry>,
    /// Same-batch hashes that *were* available (cross-batch carry-along
    /// per §10.5.2).
    objects: Vec<Vec<u8>>,
}

struct ErasedEntry {
    canonical_hash: Vec<u8>,
    authority: Option<Vec<u8>>,
    erased_at_ms: u64,
}

fn parse_gone_body(bytes: &[u8]) -> GoneBody {
    let v: Value = ciborium::de::from_reader(bytes).expect("cbor parse");
    let Value::Map(m) = v else {
        panic!("gone body is not a map");
    };
    let mut erased: Option<Vec<ErasedEntry>> = None;
    let mut objects: Option<Vec<Vec<u8>>> = None;
    for (k, v) in m {
        if let Value::Text(t) = &k {
            match (t.as_str(), v) {
                ("erased", Value::Array(arr)) => {
                    let mut out = Vec::with_capacity(arr.len());
                    for entry in arr {
                        out.push(parse_erased_entry(entry));
                    }
                    erased = Some(out);
                }
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
                _ => {}
            }
        }
    }
    GoneBody {
        erased: erased.expect("missing `erased`"),
        objects: objects.expect("missing `objects`"),
    }
}

fn parse_erased_entry(v: Value) -> ErasedEntry {
    let Value::Map(m) = v else {
        panic!("erased entry is not a map");
    };
    let mut canonical_hash: Option<Vec<u8>> = None;
    let mut authority: Option<Vec<u8>> = None;
    let mut erased_at_ms: Option<u64> = None;
    for (k, v) in m {
        if let Value::Text(t) = &k {
            match (t.as_str(), v) {
                ("canonical_hash", Value::Bytes(b)) => canonical_hash = Some(b),
                ("authority", Value::Bytes(b)) => authority = Some(b),
                ("erased_at", Value::Integer(i)) => {
                    let n: i128 = i.into();
                    erased_at_ms = Some(n.max(0) as u64);
                }
                _ => {}
            }
        }
    }
    ErasedEntry {
        canonical_hash: canonical_hash.expect("missing canonical_hash"),
        authority,
        erased_at_ms: erased_at_ms.expect("missing erased_at"),
    }
}

// ---------------------------------------------------------------------------
// Done-when scenarios
// ---------------------------------------------------------------------------

/// Available-row path: a peer that has the canonical bytes locally
/// answers a by-hash pull with `200 OK` + WireFormat. This is the
/// non-erased branch of the §10.5.2 three-way response.
#[tokio::test]
async fn by_hash_returns_200_with_wire_for_available_row() {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;
    let a = harness.instance("a");

    // Mint a real post-rev signed by a fresh user key. The handler
    // doesn't care that the user has no `users` row — it keys on
    // `signed_objects.canonical_hash` alone.
    let author_key = SigningKey::generate(&mut OsRng);
    let post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();
    let signed = sign_post_revision_with_key(
        &author_key,
        &post_id,
        &thread_id,
        None,
        1,
        "hello partition heal",
        1_700_000_000_000,
        vec![],
    );
    store_object(&a.state.db, "post-rev", &signed).await;

    let body = encode_by_hash_body(&[signed.canonical_hash]);
    let (status, resp) = send_envelope_signed(
        &harness,
        "d",
        "a",
        Method::POST,
        "/federation/v1/backfill/by-hash",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "available row must be 200");
    let parsed = parse_ok_body(&resp);
    assert!(parsed.complete, "by-hash is single-shot — always complete");
    assert_eq!(parsed.objects.len(), 1, "exactly one object");
    assert_eq!(
        parsed.objects[0],
        encode_wire(&signed.payload, &signed.signature),
        "object[0] must be the signed bytes wrapped as §6.3 WireFormat",
    );
}

/// Partition-heal contract (Phase 8 done-when): when A has erased a
/// post-rev under a retract, D can pull the canonical_hash and recover
/// (a) the fact of erasure, (b) the retract's WireFormat as the
/// cryptographic authority, and (c) the receiver-local erased_at
/// timestamp — without leaking the erased payload itself.
#[tokio::test]
async fn by_hash_returns_410_with_authority_for_erased_row() {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;
    let a = harness.instance("a");

    let author_key = SigningKey::generate(&mut OsRng);
    let post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();

    // 1. Seed the post-rev as the erasure *target*.
    let post_rev = sign_post_revision_with_key(
        &author_key,
        &post_id,
        &thread_id,
        None,
        1,
        "this revision will be erased",
        1_700_000_000_000,
        vec![],
    );
    store_object(&a.state.db, "post-rev", &post_rev).await;

    // 2. Seed the retract that authorises the erasure.
    let retract = sign_retraction_with_key(&author_key, &post_id, 1_700_000_001_000);
    store_object(&a.state.db, "retract", &retract).await;

    // 3. Stamp the post-rev row as erased, with `erased_by` pointing at
    //    the retract. This is exactly the state
    //    `erase_post_rev_payloads(_, _, Some(&retract.canonical_hash))`
    //    would leave after a real retract dispatch.
    mark_erased(
        &a.state.db,
        &post_rev.canonical_hash,
        &retract.canonical_hash,
    )
    .await;

    // 4. D asks A for the post-rev by hash. Expect 410 Gone with the
    //    retract's WireFormat as the authority.
    let body = encode_by_hash_body(&[post_rev.canonical_hash]);
    let (status, resp) = send_envelope_signed(
        &harness,
        "d",
        "a",
        Method::POST,
        "/federation/v1/backfill/by-hash",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::GONE, "erased row must be 410");

    let parsed = parse_gone_body(&resp);
    assert_eq!(parsed.erased.len(), 1, "exactly one erased entry");
    assert!(
        parsed.objects.is_empty(),
        "no same-batch available rows to carry along",
    );

    let entry = &parsed.erased[0];
    assert_eq!(
        entry.canonical_hash,
        post_rev.canonical_hash.to_vec(),
        "echoes back the canonical_hash that was asked about",
    );
    assert_eq!(
        entry.authority.as_deref(),
        Some(encode_wire(&retract.payload, &retract.signature).as_slice()),
        "authority must be the retract wrapped as §6.3 WireFormat",
    );
    assert!(
        entry.erased_at_ms > 0,
        "erased_at must be the receiver-local Unix-ms (got {})",
        entry.erased_at_ms,
    );
}

/// Hashes A has never seen at all collapse to `200 OK` + empty
/// `objects` + `complete: true` — distinct from "had it but erased".
/// Per §10.5.2 the sender treats this as "ask another peer".
#[tokio::test]
async fn by_hash_returns_200_empty_for_unknown_hash() {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;

    // Random 32 bytes — A has no signed_objects row keyed on this.
    let stranger: [u8; 32] = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

    let body = encode_by_hash_body(&[stranger]);
    let (status, resp) = send_envelope_signed(
        &harness,
        "d",
        "a",
        Method::POST,
        "/federation/v1/backfill/by-hash",
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "all-unknown collapses to 200");
    let parsed = parse_ok_body(&resp);
    assert!(
        parsed.objects.is_empty(),
        "no objects served for unknown hash"
    );
    assert!(
        parsed.complete,
        "complete must be true on an all-unknown response"
    );
}

/// §10.5.5 receiver-side rate-limit gate fires on the 101st request
/// from the same peer inside a rolling minute. The handler shortcuts
/// to `429 Too Many Requests` + `Retry-After: 60` *after* well-formed
/// pre-checks but *before* any DB work — a sender can't drive
/// arbitrary load even at the per-hash SELECT pattern the by-hash
/// handler uses internally.
#[tokio::test]
async fn by_hash_returns_429_when_per_peer_rpm_exhausted() {
    use prismoire_server::federation::backfill_rate_limit::BACKFILL_RPM_PER_PEER;

    let harness = MultiInstanceHarness::new(2).await;
    establish_active_peering(&harness, "a", "b").await;

    // Random bytes — every request will hit the "unknown hash" path
    // and 200 OK with empty `objects`. We don't care about content
    // here; we're driving the limiter's request counter past 100.
    let stranger: [u8; 32] = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let body = encode_by_hash_body(&[stranger]);

    // Saturate the per-peer minute budget.
    for i in 0..BACKFILL_RPM_PER_PEER {
        let (status, _resp) = send_envelope_signed(
            &harness,
            "b",
            "a",
            Method::POST,
            "/federation/v1/backfill/by-hash",
            &body,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "request {i} should still admit");
    }

    // 101st request from the same peer trips the limiter.
    let (status, _resp) = send_envelope_signed(
        &harness,
        "b",
        "a",
        Method::POST,
        "/federation/v1/backfill/by-hash",
        &body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "post-saturation request must be 429",
    );
}

/// Mixed batch: one hash is available, one is erased. §10.5.2 requires
/// the response to be `410 Gone` (any erasure dominates) with the
/// available row's bytes still carried in `objects` alongside the
/// erased entry — so the sender doesn't have to re-ask for the
/// non-erased ones.
#[tokio::test]
async fn by_hash_mixed_batch_returns_410_with_both_arrays() {
    let harness = MultiInstanceHarness::new(4).await;
    establish_active_peering(&harness, "a", "d").await;
    let a = harness.instance("a");

    let author_key = SigningKey::generate(&mut OsRng);
    let kept_post_id = Uuid::new_v4();
    let erased_post_id = Uuid::new_v4();
    let thread_id = Uuid::new_v4();

    // Kept post-rev — stays with payload.
    let kept = sign_post_revision_with_key(
        &author_key,
        &kept_post_id,
        &thread_id,
        None,
        1,
        "kept",
        1_700_000_000_000,
        vec![],
    );
    store_object(&a.state.db, "post-rev", &kept).await;

    // Erased post-rev plus its authorising retract.
    let doomed = sign_post_revision_with_key(
        &author_key,
        &erased_post_id,
        &thread_id,
        None,
        1,
        "doomed",
        1_700_000_002_000,
        vec![],
    );
    store_object(&a.state.db, "post-rev", &doomed).await;
    let retract = sign_retraction_with_key(&author_key, &erased_post_id, 1_700_000_003_000);
    store_object(&a.state.db, "retract", &retract).await;
    mark_erased(&a.state.db, &doomed.canonical_hash, &retract.canonical_hash).await;

    let body = encode_by_hash_body(&[kept.canonical_hash, doomed.canonical_hash]);
    let (status, resp) = send_envelope_signed(
        &harness,
        "d",
        "a",
        Method::POST,
        "/federation/v1/backfill/by-hash",
        &body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::GONE,
        "any erasure in the batch escalates the whole response to 410",
    );

    let parsed = parse_gone_body(&resp);
    assert_eq!(parsed.erased.len(), 1, "one erased entry");
    assert_eq!(
        parsed.erased[0].canonical_hash,
        doomed.canonical_hash.to_vec(),
    );
    assert_eq!(
        parsed.erased[0].authority.as_deref(),
        Some(encode_wire(&retract.payload, &retract.signature).as_slice()),
    );
    assert_eq!(
        parsed.objects.len(),
        1,
        "same-batch available row must still be carried in `objects`",
    );
    assert_eq!(
        parsed.objects[0],
        encode_wire(&kept.payload, &kept.signature),
    );
}
