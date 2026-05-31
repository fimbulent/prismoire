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
    self, AdminRemoval, Deactivation, FedEnvelope, GenesisAttestation, Move, ParseError,
    PostRevision, PriorHomeChallenge, PriorHomeResponse, ProfileRevision, RegistrationChallenge,
    Report, ReportReason, Retraction, SignedPayload, ThreadCreate, ThreadStatus, ThreadStatusKind,
    TrustEdge, TrustStance, UserStatus, UserStatusKind,
};

// --- Pinned test keys (never use for anything real) ---

const KEY_ALICE_SEED: [u8; 32] = [0x11; 32];
const KEY_BOB_SEED: [u8; 32] = [0x22; 32];
const KEY_CAROL_SEED: [u8; 32] = [0x33; 32];
// Pinned instance signing-key seeds. Used for instance-signed
// classes (admin-rm, fed-envelope, prior-home-challenge,
// user-status, thread-status) so the (.key.pub, .key.sec) committed
// alongside an instance-signed fixture is a stable, distinct key
// not reused as a user identity.
const KEY_INSTANCE_A_SEED: [u8; 32] = [0xa1; 32];
const KEY_INSTANCE_B_SEED: [u8; 32] = [0xb2; 32];

fn signing_key(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Build a §5.1 [`GenesisAttestation`] for a move fixture: the birth
/// instance (`birth_seed`) counter-signs the `{key, genesis_at,
/// birth_instance_key}` triple. `key`/`genesis_at` mirror the outer
/// move so the parse-time inner==outer binding check passes.
fn genesis_attestation(
    user_key: &[u8; 32],
    genesis_at: u64,
    birth_seed: &[u8; 32],
) -> GenesisAttestation {
    let birth = signing_key(birth_seed);
    let birth_instance_key = birth.verifying_key().to_bytes();
    let bytes =
        signed::genesis_attestation_signing_bytes(user_key, genesis_at, &birth_instance_key);
    let sig = birth.sign(&bytes).to_bytes();
    GenesisAttestation {
        key: *user_key,
        genesis_at,
        birth_instance_key,
        sig,
    }
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
                    attachments: Vec::new(),
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
                    attachments: Vec::new(),
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
                    attachments: Vec::new(),
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
                    attachments: Vec::new(),
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
        // --- Federation-era classes (docs/signed-payload-format.md §5) ---
        //
        // For instance-signed classes (admin-rm, fed-envelope,
        // prior-home-challenge, user-status, thread-status) the committed
        // key.pub/key.sec is the instance signing key. The identity-binding
        // check in `verify()` returns `None` for these so the caller is
        // responsible for resolving the claimed domain → key.
        PositiveFixture {
            stem: "move/v1-first",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                // Source / destination `instance_pubkey` are pinned
                // to the test instance seeds — same anchors used by
                // instance-signed fixtures (admin-rm / fed-envelope),
                // so a downstream test wiring a Move into a
                // multi-instance harness can correlate the move's
                // declared homes with the harness's instance keys.
                let from_key = signing_key(&KEY_INSTANCE_A_SEED).verifying_key().to_bytes();
                let to_key = signing_key(&KEY_INSTANCE_B_SEED).verifying_key().to_bytes();
                let user_key = *key.verifying_key().as_bytes();
                let genesis_at = 1_700_000_000_000;
                let m = Move {
                    key: user_key,
                    from_instance_key: Some(from_key),
                    from_instance: Some("old.example".to_string()),
                    to_instance_key: to_key,
                    to_instance: "new.example".to_string(),
                    created_at: 1_700_000_020_000,
                    genesis_at,
                    genesis_attestation: genesis_attestation(
                        &user_key,
                        genesis_at,
                        &KEY_INSTANCE_A_SEED,
                    ),
                    prior_move_hash: None,
                };
                (SignedPayload::Move(m), key)
            },
        },
        // Subsequent move: prior_move_hash present. Locks in the
        // optional-present encoding for the §5.1 map.
        PositiveFixture {
            stem: "move/v1-with-prior",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                let from_key = signing_key(&KEY_INSTANCE_B_SEED).verifying_key().to_bytes();
                // Two-hop chain: third instance the user is moving
                // to. Distinct pubkey from the first-move fixture so
                // a producer test that emits both fixtures back-to-
                // back exercises a real key rotation across the move
                // chain.
                let to_key = signing_key(&[0xc3; 32]).verifying_key().to_bytes();
                let user_key = *key.verifying_key().as_bytes();
                // Same identity as v1-first, so the immutable birth time
                // and birth instance match — a downstream chain test can
                // treat the two fixtures as successive links for Alice.
                let genesis_at = 1_700_000_000_000;
                let m = Move {
                    key: user_key,
                    from_instance_key: Some(from_key),
                    from_instance: Some("new.example".to_string()),
                    to_instance_key: to_key,
                    to_instance: "newer.example".to_string(),
                    created_at: 1_700_000_021_000,
                    genesis_at,
                    genesis_attestation: genesis_attestation(
                        &user_key,
                        genesis_at,
                        &KEY_INSTANCE_A_SEED,
                    ),
                    prior_move_hash: Some([0x5a; 32]),
                };
                (SignedPayload::Move(m), key)
            },
        },
        PositiveFixture {
            stem: "admin-rm/v1-minimal",
            payload: || {
                let key = signing_key(&KEY_INSTANCE_A_SEED);
                let target = signing_key(&KEY_BOB_SEED);
                let r = AdminRemoval {
                    post_id: [0x0a; 16],
                    target_author: *target.verifying_key().as_bytes(),
                    signing_instance: "moderator.example".to_string(),
                    created_at: 1_700_000_030_000,
                    reason: None,
                };
                (SignedPayload::AdminRemoval(r), key)
            },
        },
        PositiveFixture {
            stem: "admin-rm/v1-with-reason",
            payload: || {
                let key = signing_key(&KEY_INSTANCE_A_SEED);
                let target = signing_key(&KEY_BOB_SEED);
                let r = AdminRemoval {
                    post_id: [0x0e; 16],
                    target_author: *target.verifying_key().as_bytes(),
                    signing_instance: "moderator.example".to_string(),
                    created_at: 1_700_000_031_000,
                    reason: Some("spam".to_string()),
                };
                (SignedPayload::AdminRemoval(r), key)
            },
        },
        // fed-envelope without body_hash: typical GET (no request body).
        PositiveFixture {
            stem: "fed-envelope/v1-no-body",
            payload: || {
                let key = signing_key(&KEY_INSTANCE_A_SEED);
                let receiver = signing_key(&KEY_INSTANCE_B_SEED);
                let e = FedEnvelope {
                    sender: *key.verifying_key().as_bytes(),
                    receiver: *receiver.verifying_key().as_bytes(),
                    method: "GET".to_string(),
                    path: "/fed/v1/peer-info".to_string(),
                    body_hash: None,
                    created_at: 1_700_000_040_000,
                    nonce: [0x11; 16],
                };
                (SignedPayload::FedEnvelope(e), key)
            },
        },
        // fed-envelope with body_hash: typical POST.
        PositiveFixture {
            stem: "fed-envelope/v1-with-body",
            payload: || {
                let key = signing_key(&KEY_INSTANCE_A_SEED);
                let receiver = signing_key(&KEY_INSTANCE_B_SEED);
                let e = FedEnvelope {
                    sender: *key.verifying_key().as_bytes(),
                    receiver: *receiver.verifying_key().as_bytes(),
                    method: "POST".to_string(),
                    path: "/fed/v1/deliver".to_string(),
                    body_hash: Some([0xbb; 32]),
                    created_at: 1_700_000_041_000,
                    nonce: [0x22; 16],
                };
                (SignedPayload::FedEnvelope(e), key)
            },
        },
        PositiveFixture {
            stem: "registration-challenge/v1",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                let dest = signing_key(&KEY_INSTANCE_B_SEED);
                let c = RegistrationChallenge {
                    user_key: *key.verifying_key().as_bytes(),
                    dest_instance_key: *dest.verifying_key().as_bytes(),
                    dest_domain: "newhome.example".to_string(),
                    nonce: [0x77; 32],
                    created_at: 1_700_000_060_000,
                };
                (SignedPayload::RegistrationChallenge(c), key)
            },
        },
        PositiveFixture {
            stem: "prior-home-challenge/v1",
            payload: || {
                let key = signing_key(&KEY_INSTANCE_A_SEED);
                let subject = signing_key(&KEY_BOB_SEED);
                let c = PriorHomeChallenge {
                    responder_instance_key: *key.verifying_key().as_bytes(),
                    subject_key: *subject.verifying_key().as_bytes(),
                    nonce: [0x88; 32],
                    created_at: 1_700_000_070_000,
                    expires_at: 1_700_000_070_300,
                };
                (SignedPayload::PriorHomeChallenge(c), key)
            },
        },
        PositiveFixture {
            stem: "prior-home-response/v1",
            payload: || {
                let key = signing_key(&KEY_BOB_SEED);
                let r = PriorHomeResponse {
                    subject_key: *key.verifying_key().as_bytes(),
                    challenge_hash: [0xc1; 32],
                    created_at: 1_700_000_072_000,
                };
                (SignedPayload::PriorHomeResponse(r), key)
            },
        },
        PositiveFixture {
            stem: "thread-create/v1-discussion",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                let t = ThreadCreate {
                    thread_id: [0xf1; 16],
                    author: *key.verifying_key().as_bytes(),
                    room_slug: "general".to_string(),
                    title: "Welcome to the room".to_string(),
                    link_url: None,
                    op_post_id: [0xf2; 16],
                    created_at: 1_700_000_080_000,
                };
                (SignedPayload::ThreadCreate(t), key)
            },
        },
        PositiveFixture {
            stem: "thread-create/v1-link",
            payload: || {
                let key = signing_key(&KEY_BOB_SEED);
                let t = ThreadCreate {
                    thread_id: [0xf3; 16],
                    author: *key.verifying_key().as_bytes(),
                    room_slug: "links".to_string(),
                    title: "Interesting article".to_string(),
                    link_url: Some("https://example.com/article".to_string()),
                    op_post_id: [0xf4; 16],
                    created_at: 1_700_000_081_000,
                };
                (SignedPayload::ThreadCreate(t), key)
            },
        },
        PositiveFixture {
            stem: "user-status/v1-active",
            payload: || {
                let key = signing_key(&KEY_INSTANCE_A_SEED);
                let subject = signing_key(&KEY_BOB_SEED);
                let s = UserStatus {
                    subject: *subject.verifying_key().as_bytes(),
                    status: UserStatusKind::Active,
                    suspended_until: None,
                    signing_instance: "mod.example".to_string(),
                    reason: None,
                    created_at: 1_700_000_090_000,
                    prior_status_hash: None,
                };
                (SignedPayload::UserStatus(s), key)
            },
        },
        // Indefinite suspension: status = Suspended but no suspended_until.
        // Spec §5.10 allows absent suspended_until for indefinite holds.
        PositiveFixture {
            stem: "user-status/v1-suspended-indefinite",
            payload: || {
                let key = signing_key(&KEY_INSTANCE_A_SEED);
                let subject = signing_key(&KEY_BOB_SEED);
                let s = UserStatus {
                    subject: *subject.verifying_key().as_bytes(),
                    status: UserStatusKind::Suspended,
                    suspended_until: None,
                    signing_instance: "mod.example".to_string(),
                    reason: Some("under review".to_string()),
                    created_at: 1_700_000_091_000,
                    prior_status_hash: Some([0xaa; 32]),
                };
                (SignedPayload::UserStatus(s), key)
            },
        },
        // Time-bound suspension: suspended_until present.
        PositiveFixture {
            stem: "user-status/v1-suspended-fixed",
            payload: || {
                let key = signing_key(&KEY_INSTANCE_A_SEED);
                let subject = signing_key(&KEY_CAROL_SEED);
                let s = UserStatus {
                    subject: *subject.verifying_key().as_bytes(),
                    status: UserStatusKind::Suspended,
                    suspended_until: Some(1_800_000_000_000),
                    signing_instance: "mod.example".to_string(),
                    reason: Some("rule violation".to_string()),
                    created_at: 1_700_000_092_000,
                    prior_status_hash: None,
                };
                (SignedPayload::UserStatus(s), key)
            },
        },
        PositiveFixture {
            stem: "user-status/v1-banned",
            payload: || {
                let key = signing_key(&KEY_INSTANCE_A_SEED);
                let subject = signing_key(&KEY_CAROL_SEED);
                let s = UserStatus {
                    subject: *subject.verifying_key().as_bytes(),
                    status: UserStatusKind::Banned,
                    suspended_until: None,
                    signing_instance: "mod.example".to_string(),
                    reason: Some("repeat offender".to_string()),
                    created_at: 1_700_000_093_000,
                    prior_status_hash: Some([0xbb; 32]),
                };
                (SignedPayload::UserStatus(s), key)
            },
        },
        PositiveFixture {
            stem: "deactivate/v1",
            payload: || {
                let key = signing_key(&KEY_ALICE_SEED);
                let d = Deactivation {
                    user: *key.verifying_key().as_bytes(),
                    created_at: 1_700_000_100_000,
                };
                (SignedPayload::Deactivation(d), key)
            },
        },
        PositiveFixture {
            stem: "thread-status/v1-locked",
            payload: || {
                let key = signing_key(&KEY_INSTANCE_A_SEED);
                let s = ThreadStatus {
                    thread_id: [0xf1; 16],
                    status: ThreadStatusKind::Locked,
                    signing_instance: "host.example".to_string(),
                    reason: Some("off-topic derail".to_string()),
                    created_at: 1_700_000_110_000,
                    prior_status_hash: None,
                };
                (SignedPayload::ThreadStatus(s), key)
            },
        },
        PositiveFixture {
            stem: "thread-status/v1-open-with-prior",
            payload: || {
                let key = signing_key(&KEY_INSTANCE_A_SEED);
                let s = ThreadStatus {
                    thread_id: [0xf1; 16],
                    status: ThreadStatusKind::Open,
                    signing_instance: "host.example".to_string(),
                    reason: None,
                    created_at: 1_700_000_111_000,
                    prior_status_hash: Some([0xcc; 32]),
                };
                (SignedPayload::ThreadStatus(s), key)
            },
        },
        PositiveFixture {
            stem: "report/v1-spam",
            payload: || {
                let key = signing_key(&KEY_CAROL_SEED);
                let target = signing_key(&KEY_BOB_SEED);
                let r = Report {
                    post_id: [0x0a; 16],
                    target_author: *target.verifying_key().as_bytes(),
                    reporter: *key.verifying_key().as_bytes(),
                    reason: ReportReason::Spam,
                    detail: None,
                    created_at: 1_700_000_120_000,
                };
                (SignedPayload::Report(r), key)
            },
        },
        PositiveFixture {
            stem: "report/v1-with-detail",
            payload: || {
                let key = signing_key(&KEY_CAROL_SEED);
                let target = signing_key(&KEY_BOB_SEED);
                let r = Report {
                    post_id: [0x0a; 16],
                    target_author: *target.verifying_key().as_bytes(),
                    reporter: *key.verifying_key().as_bytes(),
                    reason: ReportReason::RulesViolation,
                    detail: Some("repeated personal attacks across threads".to_string()),
                    created_at: 1_700_000_121_000,
                };
                (SignedPayload::Report(r), key)
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
