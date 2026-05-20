//! Test-vector corpus for canonical signed-payload encoding.
//!
//! Fixtures live in `server/tests/fixtures/signed/`. Every positive
//! fixture (under `post-rev/`, `retract/`, `trust-edge/`) is a
//! `(.cbor, .sig, .key.pub, .key.sec)` quadruple: the canonical CBOR
//! payload bytes, its Ed25519 signature, and the public/private key
//! material that produced the signature. Test-only private keys are
//! committed alongside so the corpus can be regenerated; they MUST
//! NEVER be used for anything else.
//!
//! Every negative fixture (`negative/`) is a hand-crafted `.cbor`
//! file that fails one specific canonicalization or schema check.
//! The expected error class is hardcoded in [`NEGATIVE_FIXTURES`].
//!
//! ## Running
//!
//! - `cargo test --test signed_payload_fixtures` — verifies the
//!   committed corpus.
//! - `cargo test --test signed_payload_fixtures regen -- --ignored
//!   --nocapture` — regenerates `.cbor` / `.sig` / `.key.{pub,sec}`
//!   for the positive fixtures from pinned key seeds.
//!
//! Regeneration is the *only* path that produces new fixture bytes;
//! never edit a `.cbor` or `.sig` by hand. If a regen run changes any
//! committed byte, that's the canonicalization-ratchet alarm — review
//! the diff carefully (the format spec or encoder behavior changed).

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use prismoire_server::signed::{
    self, ParseError, PostRevision, ProfileRevision, Retraction, SignedPayload, TrustEdge,
    TrustStance,
};

// --- Pinned test keys (never use for anything real) ---

const KEY_ALICE_SEED: [u8; 32] = [0x11; 32];
const KEY_BOB_SEED: [u8; 32] = [0x22; 32];
const KEY_CAROL_SEED: [u8; 32] = [0x33; 32];

fn signing_key(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("signed")
}

// --- Positive fixture descriptors ---

struct PositiveFixture {
    /// Path under `fixtures/signed/` without extension. E.g.
    /// `"post-rev/v1-minimal"`. The harness expects `.cbor`, `.sig`,
    /// `.key.pub`, `.key.sec` to exist at this stem.
    stem: &'static str,
    /// Constructor returning the typed payload, signed with the
    /// returned signing key (the key seed is pinned per-fixture below).
    payload: fn() -> (SignedPayload, SigningKey),
}

fn positive_fixtures() -> Vec<PositiveFixture> {
    vec![
        PositiveFixture {
            stem: "post-rev/v1-minimal",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                let p = PostRevision {
                    post_id: [0x0a; 16],
                    author: *key.verifying_key().as_bytes(),
                    thread_id: [0x0b; 16],
                    parent_id: None,
                    revision: 0,
                    body: "Hello, world!".to_string(),
                    created_at: 1_700_000_000_000,
                };
                (SignedPayload::PostRevision(p), key)
            },
        },
        PositiveFixture {
            stem: "post-rev/v1-with-parent",
            payload: || {
                let key = signing_key(&KEY_BOB_SEED);
                let p = PostRevision {
                    post_id: [0x0c; 16],
                    author: *key.verifying_key().as_bytes(),
                    thread_id: [0x0b; 16],
                    parent_id: Some([0x0a; 16]),
                    revision: 0,
                    body: "Reply body.".to_string(),
                    created_at: 1_700_000_001_000,
                };
                (SignedPayload::PostRevision(p), key)
            },
        },
        // revision: 100 forces the multi-byte uint encoding (0x18 0x64)
        // rather than the immediate form used for 0..=23. Guards the
        // shortest-form integer path beyond the trivial range.
        PositiveFixture {
            stem: "post-rev/v1-large-revision",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                let p = PostRevision {
                    post_id: [0x0a; 16],
                    author: *key.verifying_key().as_bytes(),
                    thread_id: [0x0b; 16],
                    parent_id: None,
                    revision: 100,
                    body: "Hundred-and-first revision.".to_string(),
                    created_at: 1_700_000_006_000,
                };
                (SignedPayload::PostRevision(p), key)
            },
        },
        // Body containing multi-byte UTF-8: emoji, accented Latin, CJK.
        // Locks in byte-for-byte producer responsibility for NFC; if a
        // future change normalizes/transcodes on encode, the bytes here
        // will diverge from the committed fixture.
        PositiveFixture {
            stem: "post-rev/v1-non-ascii-body",
            payload: || {
                let key = signing_key(&KEY_BOB_SEED);
                let p = PostRevision {
                    post_id: [0x0d; 16],
                    author: *key.verifying_key().as_bytes(),
                    thread_id: [0x0b; 16],
                    parent_id: None,
                    revision: 0,
                    body: "héllo 🌍 世界".to_string(),
                    created_at: 1_700_000_007_000,
                };
                (SignedPayload::PostRevision(p), key)
            },
        },
        PositiveFixture {
            stem: "retract/v1-basic",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                let r = Retraction {
                    post_id: [0x0a; 16],
                    author: *key.verifying_key().as_bytes(),
                    created_at: 1_700_000_002_000,
                };
                (SignedPayload::Retraction(r), key)
            },
        },
        PositiveFixture {
            stem: "trust-edge/v1-trust",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                let to = signing_key(&KEY_BOB_SEED);
                let e = TrustEdge {
                    from_key: *key.verifying_key().as_bytes(),
                    to_key: *to.verifying_key().as_bytes(),
                    stance: TrustStance::Trust,
                    created_at: 1_700_000_003_000,
                    prior_edge_hash: None,
                };
                (SignedPayload::TrustEdge(e), key)
            },
        },
        PositiveFixture {
            stem: "trust-edge/v1-distrust",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                let to = signing_key(&KEY_CAROL_SEED);
                let e = TrustEdge {
                    from_key: *key.verifying_key().as_bytes(),
                    to_key: *to.verifying_key().as_bytes(),
                    stance: TrustStance::Distrust,
                    created_at: 1_700_000_004_000,
                    prior_edge_hash: None,
                };
                (SignedPayload::TrustEdge(e), key)
            },
        },
        PositiveFixture {
            stem: "trust-edge/v1-neutral-with-prior",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                let to = signing_key(&KEY_BOB_SEED);
                // A hand-fixed 32-byte "prior hash" — for the test we
                // just need the field to be present and round-trippable;
                // it doesn't need to be a real SHA-256 of anything.
                let e = TrustEdge {
                    from_key: *key.verifying_key().as_bytes(),
                    to_key: *to.verifying_key().as_bytes(),
                    stance: TrustStance::Neutral,
                    created_at: 1_700_000_005_000,
                    prior_edge_hash: Some([0xab; 32]),
                };
                (SignedPayload::TrustEdge(e), key)
            },
        },
        // First profile revision: required fields only (no avatar, no
        // prior). Locks in the absent-optional encoding for a six-key
        // map.
        PositiveFixture {
            stem: "profile/v1-minimal",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                let p = ProfileRevision {
                    user: *key.verifying_key().as_bytes(),
                    display_name: "Alice".to_string(),
                    bio: "first bio".to_string(),
                    avatar_attachment_hash: None,
                    created_at: 1_700_000_010_000,
                    prior_profile_hash: None,
                };
                (SignedPayload::ProfileRevision(p), key)
            },
        },
        // Profile revision with both optionals present: avatar hash and
        // prior_profile_hash. Locks in an eight-key map and the
        // canonical (length-prefixed) ordering of the longer keys.
        PositiveFixture {
            stem: "profile/v1-with-avatar-and-prior",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                let p = ProfileRevision {
                    user: *key.verifying_key().as_bytes(),
                    display_name: "Alice".to_string(),
                    bio: "second bio".to_string(),
                    avatar_attachment_hash: Some([0xcd; 32]),
                    created_at: 1_700_000_011_000,
                    prior_profile_hash: Some([0xab; 32]),
                };
                (SignedPayload::ProfileRevision(p), key)
            },
        },
        // Empty display_name and empty bio: spec §5.8 permits both.
        // Receivers render a pubkey-hex placeholder for empty
        // display_name; producers must still emit the empty string
        // (not omit the key).
        PositiveFixture {
            stem: "profile/v1-empty-strings",
            payload: || {
                let key = signing_key(&KEY_BOB_SEED);
                let p = ProfileRevision {
                    user: *key.verifying_key().as_bytes(),
                    display_name: String::new(),
                    bio: String::new(),
                    avatar_attachment_hash: None,
                    created_at: 1_700_000_012_000,
                    prior_profile_hash: None,
                };
                (SignedPayload::ProfileRevision(p), key)
            },
        },
        // Multi-byte UTF-8 in display_name and bio: same NFC
        // byte-faithfulness concern as `post-rev/v1-non-ascii-body`.
        PositiveFixture {
            stem: "profile/v1-non-ascii",
            payload: || {
                let key = signing_key(&KEY_CAROL_SEED);
                let p = ProfileRevision {
                    user: *key.verifying_key().as_bytes(),
                    display_name: "Káröl".to_string(),
                    bio: "héllo 🌍 世界".to_string(),
                    avatar_attachment_hash: None,
                    created_at: 1_700_000_013_000,
                    prior_profile_hash: None,
                };
                (SignedPayload::ProfileRevision(p), key)
            },
        },
    ]
}

// --- Negative fixture descriptors ---

/// Expected error class for a negative fixture. We match on the
/// discriminant only; specific message contents aren't part of the
/// contract.
#[derive(Debug)]
enum ExpectedError {
    NonCanonical,
    NonTextKey,
    KeysOutOfOrder,
    UnknownClass,
    UnsupportedVersion,
    BadByteLength,
}

fn error_matches(actual: &ParseError, expected: &ExpectedError) -> bool {
    matches!(
        (actual, expected),
        (ParseError::NonCanonical, ExpectedError::NonCanonical)
            | (ParseError::NonTextKey, ExpectedError::NonTextKey)
            | (ParseError::KeysOutOfOrder, ExpectedError::KeysOutOfOrder)
            | (ParseError::UnknownClass(_), ExpectedError::UnknownClass)
            | (
                ParseError::UnsupportedVersion { .. },
                ExpectedError::UnsupportedVersion
            )
            | (
                ParseError::BadByteLength { .. },
                ExpectedError::BadByteLength
            )
    )
}

const NEGATIVE_FIXTURES: &[(&str, ExpectedError)] = &[
    (
        "negative/retract-keys-misordered.cbor",
        ExpectedError::KeysOutOfOrder,
    ),
    (
        "negative/retract-non-shortest-uint.cbor",
        ExpectedError::NonCanonical,
    ),
    (
        "negative/retract-unknown-class.cbor",
        ExpectedError::UnknownClass,
    ),
    (
        "negative/retract-unsupported-version.cbor",
        ExpectedError::UnsupportedVersion,
    ),
    (
        "negative/retract-wrong-post-id-length.cbor",
        ExpectedError::BadByteLength,
    ),
    (
        "negative/retract-indefinite-length-string.cbor",
        ExpectedError::NonCanonical,
    ),
    (
        "negative/retract-non-text-key.cbor",
        ExpectedError::NonTextKey,
    ),
];

// --- Positive corpus: re-verify on every test run ---

#[test]
fn positive_corpus_verifies() {
    let root = fixtures_dir();
    for fx in positive_fixtures() {
        let stem = root.join(fx.stem);
        let payload_bytes = read_or_panic(&stem.with_extension("cbor"));
        let sig_bytes = read_or_panic(&stem.with_extension("sig"));
        let pub_bytes = read_or_panic(&PathBuf::from(format!("{}.key.pub", stem.display())));

        let pub_array: [u8; 32] = pub_bytes
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("{}: public key file is not 32 bytes", fx.stem));
        let verifying_key = VerifyingKey::from_bytes(&pub_array)
            .unwrap_or_else(|e| panic!("{}: invalid public key: {e}", fx.stem));

        // The canonical-form contract: the encoder must still produce
        // these exact bytes for the same logical input. If this fails,
        // either the encoder changed or the fixture is stale — and
        // either way the canonicalization ratchet has tripped.
        let (expected_payload, _key) = (fx.payload)();
        let regen_bytes = expected_payload.encode();
        assert_eq!(
            regen_bytes, payload_bytes,
            "{}: encoder no longer produces committed canonical bytes",
            fx.stem
        );

        // Verify the committed signature against the committed public
        // key. Validates the whole §6 procedure end-to-end.
        let typed = signed::verify(&payload_bytes, &sig_bytes, &verifying_key)
            .unwrap_or_else(|e| panic!("{}: verify failed: {e:?}", fx.stem));
        assert_eq!(typed, expected_payload, "{}: decoded mismatch", fx.stem);
    }
}

// --- Negative corpus: re-reject on every test run ---

#[test]
fn negative_corpus_rejects() {
    let root = fixtures_dir();
    for (path, expected) in NEGATIVE_FIXTURES {
        let bytes = read_or_panic(&root.join(path));
        match SignedPayload::parse(&bytes) {
            Ok(_) => panic!("{path}: expected rejection {expected:?}, got Ok"),
            Err(actual) => {
                assert!(
                    error_matches(&actual, expected),
                    "{path}: expected {expected:?}, got {actual:?}"
                );
            }
        }
    }
}

// --- Regenerator (ignored by default) ---

#[test]
#[ignore = "writes/overwrites fixture files; run explicitly when adding or rotating fixtures"]
fn regen_corpus() {
    let root = fixtures_dir();

    // Positive: derive bytes from pinned seeds and overwrite.
    for fx in positive_fixtures() {
        let (payload, key) = (fx.payload)();
        let payload_bytes = payload.encode();
        let signature = key.sign(&payload_bytes);
        let stem = root.join(fx.stem);
        if let Some(parent) = stem.parent() {
            fs::create_dir_all(parent).expect("mkdir fixture dir");
        }
        write_or_panic(&stem.with_extension("cbor"), &payload_bytes);
        write_or_panic(&stem.with_extension("sig"), &signature.to_bytes());
        write_or_panic(
            &PathBuf::from(format!("{}.key.pub", stem.display())),
            key.verifying_key().as_bytes(),
        );
        write_or_panic(
            &PathBuf::from(format!("{}.key.sec", stem.display())),
            &key.to_bytes(),
        );
        eprintln!("regen: wrote {}", fx.stem);
    }

    // Negative: rebuild each hand-crafted byte sequence.
    let neg_dir = root.join("negative");
    fs::create_dir_all(&neg_dir).expect("mkdir negative");
    write_or_panic(
        &neg_dir.join("retract-keys-misordered.cbor"),
        &build_retract_keys_misordered(),
    );
    write_or_panic(
        &neg_dir.join("retract-non-shortest-uint.cbor"),
        &build_retract_non_shortest_uint(),
    );
    write_or_panic(
        &neg_dir.join("retract-unknown-class.cbor"),
        &build_unknown_class(),
    );
    write_or_panic(
        &neg_dir.join("retract-unsupported-version.cbor"),
        &build_retract_unsupported_version(),
    );
    write_or_panic(
        &neg_dir.join("retract-wrong-post-id-length.cbor"),
        &build_retract_wrong_post_id_length(),
    );
    write_or_panic(
        &neg_dir.join("retract-indefinite-length-string.cbor"),
        &build_retract_indefinite_length_string(),
    );
    write_or_panic(
        &neg_dir.join("retract-non-text-key.cbor"),
        &build_retract_non_text_key(),
    );
    eprintln!("regen: wrote negative fixtures");
}

// --- Hand-crafted negative byte sequences ---
//
// Each helper builds a byte sequence that violates exactly one
// canonicalization or schema rule. Keeping these close to the
// regenerator lets reviewers see the construction at a glance.

fn build_retract_keys_misordered() -> Vec<u8> {
    // Valid retraction encoded with the "v" key BEFORE the "t" key.
    // Canonical order is t (len 1, "t") < v (len 1, "v").
    let mut out = Vec::new();
    out.push(0xa5); // map(5)
    // v -> 1
    out.extend_from_slice(&[0x61, b'v']);
    out.push(0x01);
    // t -> "retract"
    out.extend_from_slice(&[0x61, b't']);
    out.extend_from_slice(&[0x67, b'r', b'e', b't', b'r', b'a', b'c', b't']);
    // author -> 32 zeros
    out.extend_from_slice(&[0x66, b'a', b'u', b't', b'h', b'o', b'r']);
    out.extend_from_slice(&[0x58, 0x20]);
    out.extend_from_slice(&[0u8; 32]);
    // post_id -> 16 zeros
    out.extend_from_slice(&[0x67, b'p', b'o', b's', b't', b'_', b'i', b'd']);
    out.push(0x50);
    out.extend_from_slice(&[0u8; 16]);
    // created_at -> 0
    out.extend_from_slice(&[
        0x6a, b'c', b'r', b'e', b'a', b't', b'e', b'd', b'_', b'a', b't',
    ]);
    out.push(0x00);
    out
}

fn build_retract_non_shortest_uint() -> Vec<u8> {
    // Valid retraction layout, but the version field encodes "1" as
    // the 1-byte form (0x18 0x01) instead of immediate (0x01). This
    // parses to Value::Integer(1) but fails the re-encode check.
    let mut out = Vec::new();
    out.push(0xa5);
    out.extend_from_slice(&[0x61, b't']);
    out.extend_from_slice(&[0x67, b'r', b'e', b't', b'r', b'a', b'c', b't']);
    out.extend_from_slice(&[0x61, b'v']);
    out.extend_from_slice(&[0x18, 0x01]); // non-shortest uint 1
    out.extend_from_slice(&[0x66, b'a', b'u', b't', b'h', b'o', b'r']);
    out.extend_from_slice(&[0x58, 0x20]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0x67, b'p', b'o', b's', b't', b'_', b'i', b'd']);
    out.push(0x50);
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&[
        0x6a, b'c', b'r', b'e', b'a', b't', b'e', b'd', b'_', b'a', b't',
    ]);
    out.push(0x00);
    out
}

fn build_unknown_class() -> Vec<u8> {
    // Minimal map with t = "bogus", v = 1. Fails dispatch.
    let mut out = Vec::new();
    out.push(0xa2);
    out.extend_from_slice(&[0x61, b't']);
    out.extend_from_slice(&[0x65, b'b', b'o', b'g', b'u', b's']);
    out.extend_from_slice(&[0x61, b'v']);
    out.push(0x01);
    out
}

fn build_retract_unsupported_version() -> Vec<u8> {
    // Valid retraction layout but v = 2.
    let mut out = Vec::new();
    out.push(0xa5);
    out.extend_from_slice(&[0x61, b't']);
    out.extend_from_slice(&[0x67, b'r', b'e', b't', b'r', b'a', b'c', b't']);
    out.extend_from_slice(&[0x61, b'v']);
    out.push(0x02); // future version
    out.extend_from_slice(&[0x66, b'a', b'u', b't', b'h', b'o', b'r']);
    out.extend_from_slice(&[0x58, 0x20]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0x67, b'p', b'o', b's', b't', b'_', b'i', b'd']);
    out.push(0x50);
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&[
        0x6a, b'c', b'r', b'e', b'a', b't', b'e', b'd', b'_', b'a', b't',
    ]);
    out.push(0x00);
    out
}

fn build_retract_wrong_post_id_length() -> Vec<u8> {
    // Retraction with a 15-byte post_id instead of 16.
    let mut out = Vec::new();
    out.push(0xa5);
    out.extend_from_slice(&[0x61, b't']);
    out.extend_from_slice(&[0x67, b'r', b'e', b't', b'r', b'a', b'c', b't']);
    out.extend_from_slice(&[0x61, b'v']);
    out.push(0x01);
    out.extend_from_slice(&[0x66, b'a', b'u', b't', b'h', b'o', b'r']);
    out.extend_from_slice(&[0x58, 0x20]);
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&[0x67, b'p', b'o', b's', b't', b'_', b'i', b'd']);
    out.push(0x4f); // bstr(15)
    out.extend_from_slice(&[0u8; 15]);
    out.extend_from_slice(&[
        0x6a, b'c', b'r', b'e', b'a', b't', b'e', b'd', b'_', b'a', b't',
    ]);
    out.push(0x00);
    out
}

fn build_retract_indefinite_length_string() -> Vec<u8> {
    // Valid retraction layout, but the value of the `t` field is encoded
    // as an indefinite-length text string with two chunks ("ret" + "ract")
    // instead of a single definite-length text string. ciborium parses
    // this as Value::Text("retract"), but re-encodes it in definite-length
    // form, so the canonical-form re-encode comparison fails.
    let mut out = Vec::new();
    out.push(0xa5); // map(5)
    // t -> indefinite-length "retract" as ("ret" + "ract")
    out.extend_from_slice(&[0x61, b't']);
    out.push(0x7f); // indefinite text string start
    out.extend_from_slice(&[0x63, b'r', b'e', b't']); // chunk "ret"
    out.extend_from_slice(&[0x64, b'r', b'a', b'c', b't']); // chunk "ract"
    out.push(0xff); // break
    // v -> 1
    out.extend_from_slice(&[0x61, b'v']);
    out.push(0x01);
    // author -> 32 zeros
    out.extend_from_slice(&[0x66, b'a', b'u', b't', b'h', b'o', b'r']);
    out.extend_from_slice(&[0x58, 0x20]);
    out.extend_from_slice(&[0u8; 32]);
    // post_id -> 16 zeros
    out.extend_from_slice(&[0x67, b'p', b'o', b's', b't', b'_', b'i', b'd']);
    out.push(0x50);
    out.extend_from_slice(&[0u8; 16]);
    // created_at -> 0
    out.extend_from_slice(&[
        0x6a, b'c', b'r', b'e', b'a', b't', b'e', b'd', b'_', b'a', b't',
    ]);
    out.push(0x00);
    out
}

fn build_retract_non_text_key() -> Vec<u8> {
    // Single-entry map with an integer key (uint 0) and an integer value.
    // Round-trips through ciborium byte-for-byte (single entry, definite
    // length, shortest-form ints), so the re-encode check passes; the
    // parser then walks the entries and trips NonTextKey on the integer
    // key.
    vec![
        0xa1, // map(1)
        0x00, // uint 0 (key)
        0x00, // uint 0 (value)
    ]
}

// --- fs helpers ---

fn read_or_panic(path: &Path) -> Vec<u8> {
    fs::read(path)
        .unwrap_or_else(|e| panic!("read {}: {e}\n(run `cargo test --test signed_payload_fixtures regen -- --ignored` to populate)", path.display()))
}

fn write_or_panic(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}
