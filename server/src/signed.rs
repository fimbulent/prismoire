//! Canonical CBOR encoding and verification for signed payloads.
//!
//! This module is the authoritative encoder/decoder for V1 signed
//! payloads per [`docs/signed-payload-format.md`]. Every byte sequence
//! that gets an Ed25519 signature in Prismoire passes through here.
//!
//! ## Format invariants (RFC 8949 §4.2)
//!
//! - Definite-length items only.
//! - Shortest-form unsigned integer encoding.
//! - Map keys sorted bytewise-lex of their CBOR encoding.
//! - No semantic tags.
//! - UTF-8 text strings; NFC normalization is the *producer's*
//!   responsibility (this module is byte-faithful — it does not
//!   normalize body text on caller's behalf).
//!
//! ## Verification flow
//!
//! [`verify`] performs the full §6 procedure:
//!
//! 1. Parse the CBOR.
//! 2. Re-encode the parsed value and compare bytewise to the input;
//!    any difference means the payload was non-canonical.
//! 3. Check explicit canonicalization invariants the re-encode pass
//!    can't catch: map-key order, duplicate keys, text-typed map keys.
//! 4. Dispatch on `(t, v)` to the object class, validate field
//!    presence and types.
//! 5. Verify the Ed25519 signature against the canonical bytes, with
//!    the author / `from_key` identity field consistent with the
//!    `claimed_key`.
//!
//! The signing side ([`SignedPayload::encode`]) constructs the
//! canonical bytes from typed Rust values. Producers never hand-roll
//! CBOR.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use ciborium::Value;
use ciborium::value::Integer;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

// --- Class tags and current versions ---

/// Object-class tag for a post revision (`t = "post-rev"`).
pub const TAG_POST_REVISION: &str = "post-rev";
/// Object-class tag for a post retraction (`t = "retract"`).
pub const TAG_RETRACTION: &str = "retract";
/// Object-class tag for a trust-edge mutation (`t = "trust-edge"`).
pub const TAG_TRUST_EDGE: &str = "trust-edge";
/// Object-class tag for a user-profile revision (`t = "profile"`).
pub const TAG_PROFILE: &str = "profile";

// Federation-era classes per `docs/signed-payload-format.md` §5.
// These are the V1 wire-shape for every signed object that flows
// across instance boundaries (or, for the ephemeral classes, signs
// a single client ↔ server exchange).

/// Cross-instance move declaration (`t = "move"`). User-signed.
/// See `docs/signed-payload-format.md` §5.1.
pub const TAG_MOVE: &str = "move";
/// Admin-issued post removal (`t = "admin-rm"`). Instance-signed.
/// See `docs/signed-payload-format.md` §5.2.
pub const TAG_ADMIN_REMOVAL: &str = "admin-rm";
/// Per-request federation envelope (`t = "fed-envelope"`). Instance-
/// signed, ephemeral. See `docs/signed-payload-format.md` §5.3 and
/// `docs/federation-protocol.md` §6.
pub const TAG_FED_ENVELOPE: &str = "fed-envelope";
/// Cross-instance registration challenge (`t = "registration-challenge"`).
/// User-signed, ephemeral. See `docs/signed-payload-format.md` §5.5
/// and `docs/federation-protocol.md` §13.
pub const TAG_REGISTRATION_CHALLENGE: &str = "registration-challenge";
/// Prior-home challenge (`t = "prior-home-challenge"`). Instance-signed,
/// ephemeral. See `docs/signed-payload-format.md` §5.6.
pub const TAG_PRIOR_HOME_CHALLENGE: &str = "prior-home-challenge";
/// Prior-home response (`t = "prior-home-response"`). User-signed,
/// ephemeral. See `docs/signed-payload-format.md` §5.7.
pub const TAG_PRIOR_HOME_RESPONSE: &str = "prior-home-response";
/// Thread creation (`t = "thread-create"`). User-signed.
/// See `docs/signed-payload-format.md` §5.9.
pub const TAG_THREAD_CREATE: &str = "thread-create";
/// Instance-issued moderation user-status (`t = "user-status"`).
/// Instance-signed. See `docs/signed-payload-format.md` §5.10.
pub const TAG_USER_STATUS: &str = "user-status";
/// Account deactivation (`t = "deactivate"`). User-signed; terminal
/// erasure authority over the signing user's own objects. See
/// `docs/signed-payload-format.md` §5.11.
pub const TAG_DEACTIVATION: &str = "deactivate";
/// Instance-issued thread lock state (`t = "thread-status"`).
/// Instance-signed. See `docs/signed-payload-format.md` §5.12.
pub const TAG_THREAD_STATUS: &str = "thread-status";
/// User report against a post (`t = "report"`). User-signed.
/// See `docs/signed-payload-format.md` §5.13.
pub const TAG_REPORT: &str = "report";

/// V1 format version for all currently-defined object classes.
pub const V1: u64 = 1;

/// Maximum bio length in *characters* (Unicode scalar values) for a
/// V1 `profile` payload per spec §5.8. Producers are responsible for
/// enforcing this before signing; this module is byte-faithful and
/// does not truncate.
pub const MAX_PROFILE_BIO_LEN: usize = 4096;

/// Maximum thread title length in *bytes* (UTF-8) for a V1
/// `thread-create` payload per spec §5.9. Wire invariant: federation
/// peers reject any thread-create whose `title` exceeds this.
pub const MAX_THREAD_TITLE_LEN: usize = 300;

/// Maximum report-detail length in *bytes* (UTF-8) for a V1 `report`
/// payload per spec §5.13. Bound applies to `detail` only; `reason`
/// is an enum.
pub const MAX_REPORT_DETAIL_LEN: usize = 2000;

// --- Attachment protocol invariants (docs/attachments.md §10.1) ---
//
// These are part of the federation wire contract. Per-instance drift
// breaks interop or security; loosening on one instance forces every
// peer to choose between rejecting legitimate posts and accepting
// content that violates its own policy. Bumping any of these is a
// protocol revision, not a knob. They live here (next to the rest of
// the canonical-byte invariants) so every validation path — upload
// rejection, signed-payload verification, federation accept/reject —
// references the same values.

/// Maximum size of a single attachment blob, in bytes (`MAX_ATTACHMENT_SIZE`).
///
/// Appears in the signed canonical bytes (`attachments[].size`). Wire
/// invariant per `federation-protocol.md` §11.6.
pub const MAX_ATTACHMENT_SIZE: usize = 500 * 1024;

/// Maximum number of attachments bound to a single post revision
/// (`MAX_ATTACHMENTS_PER_OP`). Array length is signed, so this cannot
/// vary per instance.
pub const MAX_ATTACHMENTS_PER_OP: usize = 3;

/// Maximum length of a sanitized attachment filename, in UTF-8 bytes
/// (`MAX_ATTACHMENT_FILENAME_LEN`). The numeric form of the cap in
/// `FILENAME_RULES`; sized to match a `Content-Disposition`-friendly
/// indexable column length.
pub const MAX_ATTACHMENT_FILENAME_LEN: usize = 255;

/// Allowlist of attachment MIME types (`ALLOWED_MIMES`).
///
/// Both a wire contract and a security invariant. GIF, HTML, and SVG
/// are deliberately excluded — see `docs/attachments.md` §3 step 2 for
/// the rationale (animation pushes toward image-driven culture; HTML
/// and SVG are executable in a browser). The upload classifier and the
/// federation-receive MIME re-verification both gate on this exact
/// list.
pub const ALLOWED_MIMES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/webp",
    "text/plain",
    "application/pdf",
];

/// CBOR map-key constant: the optional outer key carrying the
/// attachment array on a `post-rev` payload. Empty arrays MUST omit
/// the key entirely (the no-attachments case has exactly one canonical
/// form). See `docs/attachments.md` §2.1.
pub const KEY_ATTACHMENTS: &str = "attachments";

/// CBOR map-key constant: inner attachment-map field — 32-byte SHA-256
/// of the stored blob bytes.
pub const KEY_ATTACHMENT_CONTENT_HASH: &str = "content_hash";

/// CBOR map-key constant: inner attachment-map field — sanitized
/// filename per §2.2.
pub const KEY_ATTACHMENT_FILENAME: &str = "filename";

/// CBOR map-key constant: inner attachment-map field — MIME, member of
/// [`ALLOWED_MIMES`].
pub const KEY_ATTACHMENT_MIME: &str = "mime";

/// CBOR map-key constant: inner attachment-map field — byte length of
/// the named blob.
pub const KEY_ATTACHMENT_SIZE: &str = "size";

/// One entry in a `post-rev`'s signed `attachments[]` array.
///
/// All four fields are signed: the hash binds the bytes, but `mime`,
/// `size`, and `filename` are signed too so a federation peer (or
/// local attacker) cannot rename or substitute MIME/size while leaving
/// the signature valid. Layout intent (inline vs chip) is *not*
/// signed — it's derived at render time from `![](filename)`
/// references in the post body (§2.1, §3 inline-rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRef {
    /// SHA-256 of the stored blob bytes.
    pub content_hash: [u8; 32],
    /// MIME type — must be a member of [`ALLOWED_MIMES`].
    pub mime: String,
    /// Byte length of the named blob; must equal the stored size and
    /// be ≤ [`MAX_ATTACHMENT_SIZE`].
    pub size: u64,
    /// Sanitized filename (§2.2): NFC, no path separators / NUL /
    /// control characters / leading dots, ≤ [`MAX_ATTACHMENT_FILENAME_LEN`]
    /// UTF-8 bytes, non-empty.
    pub filename: String,
}

/// Apply `FILENAME_RULES` (§2.2) to a candidate filename.
///
/// 1. NFC normalize.
/// 2. Strip path separators (`/`, `\`) and NUL.
/// 3. Strip ASCII control characters (`U+0001`..`U+001F`, `U+007F`).
/// 4. Strip Unicode bidi controls (`U+200E`, `U+200F`,
///    `U+202A`..`U+202E`, `U+2066`..`U+2069`). Without this, a signed
///    filename containing `U+202E` (RLO) renders deceptively in
///    `Content-Disposition` — e.g. `evil\u{202E}gpj.exe` displays as
///    `evilexe.gpj` to the reader.
/// 5. Strip zero-width / invisible code points (`U+200B`..`U+200D`,
///    `U+2060`, `U+FEFF`). These are unobservable in a download UI
///    yet survive into the served filename, so they let two
///    distinct signed filenames render identically.
/// 6. Strip Windows-reserved characters (`<`, `>`, `:`, `"`, `|`,
///    `?`, `*`). The serve path emits the signed filename verbatim
///    in `Content-Disposition`; without this, a Windows reader
///    cannot save the file and the ZIP-export sanitizer would
///    silently rename it later.
/// 7. Strip leading dots so the entry is not a hidden file on Unix
///    extraction.
/// 8. Truncate to [`MAX_ATTACHMENT_FILENAME_LEN`] UTF-8 bytes, never
///    splitting a code point.
/// 9. Reject (return `None`) if the result is empty.
///
/// This is the *wire-canonical* rule — verifiers MUST reject any
/// signed body whose `filename` does not survive a fresh pass
/// byte-identically (`docs/attachments.md` §2.2 / §10.1,
/// `docs/federation-protocol.md` §11.6).
pub fn sanitize_attachment_filename(raw: &str) -> Option<String> {
    use unicode_normalization::UnicodeNormalization;

    // NFC normalize, then drop forbidden code points in a single pass.
    let normalized: String = raw
        .nfc()
        .filter(|c| {
            let cu = *c as u32;
            // Strip path separators and NUL.
            if *c == '/' || *c == '\\' || *c == '\0' {
                return false;
            }
            // Strip ASCII control characters (C0 controls + DEL).
            // U+0000 is already excluded above; we keep the inclusive
            // range here for clarity.
            if (0x01..=0x1F).contains(&cu) || cu == 0x7F {
                return false;
            }
            // Strip Unicode bidirectional formatting controls.
            // LRM/RLM are direction marks; LRE/RLE/PDF/LRO/RLO are
            // embedding/override controls; LRI/RLI/FSI/PDI are the
            // isolate controls. Any of these in a signed filename
            // lets the rendered Content-Disposition string lie about
            // its true left-to-right byte order.
            if cu == 0x200E
                || cu == 0x200F
                || (0x202A..=0x202E).contains(&cu)
                || (0x2066..=0x2069).contains(&cu)
            {
                return false;
            }
            // Strip zero-width / invisible code points. ZWSP/ZWNJ/ZWJ
            // (U+200B..U+200D), word-joiner (U+2060), and the BOM /
            // ZWNBSP (U+FEFF) all render as nothing yet remain
            // distinct on the wire — perfect for spoofing visually
            // identical filenames that resolve to different signed
            // bytes.
            if (0x200B..=0x200D).contains(&cu) || cu == 0x2060 || cu == 0xFEFF {
                return false;
            }
            // Strip Windows-reserved filename characters. The serve
            // path puts the signed filename verbatim into
            // Content-Disposition; on Windows these characters are
            // illegal in filenames and cause save dialogs to fail or
            // silently rewrite. Matches `sanitize_zip_entry_name` in
            // `privacy.rs` so the JSON metadata, the ZIP entry, and
            // the served filename all agree.
            if matches!(*c, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                return false;
            }
            true
        })
        .collect();

    // Strip leading dots (rule 4). `trim_start_matches` is byte-safe
    // here because `.` is single-byte ASCII.
    let stripped = normalized.trim_start_matches('.');

    // Truncate to MAX_ATTACHMENT_FILENAME_LEN UTF-8 bytes without
    // splitting a code point. Walk char boundaries from the start and
    // stop at the last boundary that fits.
    let truncated: &str = if stripped.len() <= MAX_ATTACHMENT_FILENAME_LEN {
        stripped
    } else {
        let mut end = MAX_ATTACHMENT_FILENAME_LEN;
        while end > 0 && !stripped.is_char_boundary(end) {
            end -= 1;
        }
        &stripped[..end]
    };

    if truncated.is_empty() {
        None
    } else {
        Some(truncated.to_string())
    }
}

// --- Typed payloads ---

/// A typed signed payload, decoded from canonical CBOR.
///
/// Variants correspond to the V1 object classes in
/// [`docs/signed-payload-format.md`] §4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedPayload {
    PostRevision(PostRevision),
    Retraction(Retraction),
    TrustEdge(TrustEdge),
    ProfileRevision(ProfileRevision),
    Move(Move),
    AdminRemoval(AdminRemoval),
    FedEnvelope(FedEnvelope),
    RegistrationChallenge(RegistrationChallenge),
    PriorHomeChallenge(PriorHomeChallenge),
    PriorHomeResponse(PriorHomeResponse),
    ThreadCreate(ThreadCreate),
    UserStatus(UserStatus),
    Deactivation(Deactivation),
    ThreadStatus(ThreadStatus),
    Report(Report),
}

/// Post revision (initial creation or subsequent edit).
///
/// See [`docs/signed-payload-format.md`] §4.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostRevision {
    /// Post UUID (raw 16 bytes). Same across all revisions.
    pub post_id: [u8; 16],
    /// Ed25519 public key of the author.
    pub author: [u8; 32],
    /// Thread UUID this post belongs to.
    pub thread_id: [u8; 16],
    /// Parent post UUID. `None` for thread OPs; `Some` for replies.
    pub parent_id: Option<[u8; 16]>,
    /// Zero-indexed revision number.
    pub revision: u64,
    /// Post body, assumed to be in Unicode NFC by the producer.
    pub body: String,
    /// Unix milliseconds since epoch, UTC.
    pub created_at: u64,
    /// Optional attachments bound to this revision
    /// (`docs/attachments.md` §2.1). Empty vec encodes as "key absent"
    /// on the wire so existing signed posts remain bit-identical.
    /// Wire-invariant: when present, 1..=[`MAX_ATTACHMENTS_PER_OP`].
    pub attachments: Vec<AttachmentRef>,
}

/// Post retraction.
///
/// See [`docs/signed-payload-format.md`] §4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retraction {
    /// Post UUID being retracted.
    pub post_id: [u8; 16],
    /// Ed25519 public key of the retractor; must match revision 0's author.
    pub author: [u8; 32],
    /// Retraction time in Unix milliseconds, UTC.
    pub created_at: u64,
}

/// Stance value of a trust-edge mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStance {
    Trust,
    Distrust,
    Neutral,
}

impl TrustStance {
    /// Canonical lowercase string form used in the CBOR payload.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trust => "trust",
            Self::Distrust => "distrust",
            Self::Neutral => "neutral",
        }
    }

    /// Parse the canonical string form. Returns `None` for any other input.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "trust" => Some(Self::Trust),
            "distrust" => Some(Self::Distrust),
            "neutral" => Some(Self::Neutral),
            _ => None,
        }
    }
}

/// Trust-edge mutation (set / clear trust or distrust between two keys).
///
/// See [`docs/signed-payload-format.md`] §4.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEdge {
    /// Ed25519 public key of the user setting the stance (the signer).
    pub from_key: [u8; 32],
    /// Ed25519 public key of the target.
    pub to_key: [u8; 32],
    /// `trust` / `distrust` / `neutral`.
    pub stance: TrustStance,
    /// Mutation time, Unix milliseconds, UTC.
    pub created_at: u64,
    /// SHA-256 of the canonical payload bytes of the prior trust-edge
    /// object for the same `(from_key, to_key)` pair. `None` for the
    /// first mutation.
    pub prior_edge_hash: Option<[u8; 32]>,
}

/// User profile revision (display-name / bio / avatar change).
///
/// Chains form per-user  history with the same `latest-wins by created_at`
/// semantics as [`TrustEdge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRevision {
    /// Ed25519 public key of the user (the signer). Bound into the
    /// canonical payload as the `user` field — matches the
    /// `identity_key` arm in [`verify`].
    pub user: [u8; 32],
    /// Display name in Unicode NFC. Empty string permitted (receivers
    /// render a truncated pubkey hex in that case).
    pub display_name: String,
    /// Bio in Unicode NFC. Empty string permitted. Producers must
    /// enforce length ≤ [`MAX_PROFILE_BIO_LEN`] before signing.
    pub bio: String,
    /// SHA-256 of an attachment carrying the avatar image, or `None`
    /// if the user has no avatar.
    pub avatar_attachment_hash: Option<[u8; 32]>,
    /// Revision time, Unix milliseconds, UTC.
    pub created_at: u64,
    /// SHA-256 of the canonical payload bytes of the prior `profile`
    /// object for `user`. `None` for the user's first revision.
    pub prior_profile_hash: Option<[u8; 32]>,
}

// --- Federation-era classes (`docs/signed-payload-format.md` §5) ---

/// Cross-instance move declaration. User-signed.
///
/// See `docs/signed-payload-format.md` §5.1 and
/// `docs/federation-protocol.md` §12.
///
/// **Joint binding of pubkey and domain.** Per `federation-protocol.md`
/// §3 the instance trust anchor is its `instance_pubkey`; the domain
/// is mutable metadata. Both `from_instance_key` and `to_instance_key`
/// (and their `_instance` domain counterparts) are bound into the
/// canonical payload so the move chain stays consistent with §3's
/// "peer records are authoritative on key; everything else stored
/// alongside is mutable metadata." Receivers resolving "is sender S
/// authoritative for K?" check both fields per the §5.1 verification
/// rule; pubkey wins on conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Move {
    /// Ed25519 public key of the moving identity (the signer).
    pub key: [u8; 32],
    /// Ed25519 `instance_pubkey` of the source instance, as
    /// observed at signing time. The trust anchor for "where K was
    /// hosted before this move." **`None` ⇒ genesis declaration** (the
    /// key was born at `to_instance`, no predecessor); coupled with
    /// `from_instance` — both present or both absent (§5.1).
    pub from_instance_key: Option<[u8; 32]>,
    /// Bare canonical domain of the source instance. `None` iff
    /// `from_instance_key` is `None` (genesis declaration).
    pub from_instance: Option<String>,
    /// Ed25519 `instance_pubkey` of the destination instance, as
    /// observed at signing time. For moves originating from a §13
    /// registration ceremony this MUST equal the `dest_instance_key`
    /// of the redeemed `registration-challenge`.
    pub to_instance_key: [u8; 32],
    /// Bare canonical domain of the destination instance.
    pub to_instance: String,
    /// Move time, Unix milliseconds, UTC. *Not* account age — see
    /// `genesis_at`.
    pub created_at: u64,
    /// Immutable account **birth** time, Unix milliseconds, UTC.
    /// Re-stated and re-signed in every declaration in the chain
    /// (genesis and moves alike); MUST be identical across the chain
    /// (§5.1, §12.8). Forward-carried so one flooded declaration
    /// conveys the key's age without walking the chain to genesis.
    pub genesis_at: u64,
    /// Birth-instance counter-signature over the birth fact. Anchors
    /// `genesis_at` against self-attestation (§5.1, §12.8).
    pub genesis_attestation: GenesisAttestation,
    /// SHA-256 of the canonical bytes of the previous `move` for
    /// `key`. `None` for the user's first (genesis) declaration.
    pub prior_move_hash: Option<[u8; 32]>,
}

/// Birth-instance counter-signature embedded in every move/genesis
/// declaration (`docs/signed-payload-format.md` §5.1). Converts the
/// user-signed `genesis_at` into an instance-vouched account age so an
/// age-ceiling forwarder (`federation-protocol.md` §8.10) can honour it
/// without trusting a pure self-attestation — closing the tail-spam
/// vector. The user signs the **outer** move declaration; the birth
/// instance signs this **inner** birth fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisAttestation {
    /// MUST equal the enclosing declaration's `key`.
    pub key: [u8; 32],
    /// MUST equal the enclosing declaration's `genesis_at`.
    pub genesis_at: u64,
    /// The birth instance's `instance_pubkey` — the instance that
    /// hosted `key` at account creation.
    pub birth_instance_key: [u8; 32],
    /// Ed25519 signature by `birth_instance_key`'s admin key over the
    /// canonical CBOR of `{key, genesis_at, birth_instance_key}` (see
    /// [`genesis_attestation_signing_bytes`]).
    pub sig: [u8; 64],
}

/// Admin-issued post removal. Instance-signed (signed by the
/// admin's instance signing key, not by the admin's personal key).
///
/// See `docs/signed-payload-format.md` §5.2 and
/// `docs/federation-protocol.md` §10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRemoval {
    /// Target post UUID (raw 16 bytes).
    pub post_id: [u8; 16],
    /// Target post's author pubkey. Disambiguates the home-scoped
    /// `post_id`.
    pub target_author: [u8; 32],
    /// Bare canonical domain of the issuing instance. MUST equal
    /// the domain whose signing key signs this object.
    pub signing_instance: String,
    /// Removal time, Unix milliseconds, UTC.
    pub created_at: u64,
    /// Optional human-readable reason. Stored verbatim; not
    /// interpreted by the protocol.
    pub reason: Option<String>,
}

/// Per-request federation envelope. Instance-signed, ephemeral.
///
/// Rides as an HTTP header per `docs/federation-protocol.md` §6;
/// never enters any storage tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FedEnvelope {
    /// Sender instance's signing pubkey (the signer).
    pub sender: [u8; 32],
    /// Receiver instance's signing pubkey, as currently recorded
    /// by the sender.
    pub receiver: [u8; 32],
    /// HTTP method, uppercase ASCII (e.g. `"GET"`, `"POST"`).
    /// Casing is producer-enforced; this module is byte-faithful.
    pub method: String,
    /// Request path including query string, percent-encoded as on
    /// the wire.
    pub path: String,
    /// SHA-256 of the request body. `None` iff the request has no
    /// body (typical for GET / HEAD). The parser enforces presence
    /// matches `body_hash`'s semantic meaning per spec §5.3.
    pub body_hash: Option<[u8; 32]>,
    /// Envelope mint time, Unix milliseconds, UTC.
    pub created_at: u64,
    /// 16 cryptographically-random bytes, single-use per
    /// (sender, receiver) pair.
    pub nonce: [u8; 16],
}

/// Cross-instance registration challenge. User-signed, ephemeral.
///
/// See `docs/signed-payload-format.md` §5.5 and
/// `docs/federation-protocol.md` §13.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationChallenge {
    /// Ed25519 public key being registered (the signer).
    pub user_key: [u8; 32],
    /// Destination instance's signing pubkey at issuance time.
    pub dest_instance_key: [u8; 32],
    /// Destination's bare canonical domain at issuance time.
    pub dest_domain: String,
    /// Server-issued, CSPRNG-generated, single-use 32-byte nonce.
    pub nonce: [u8; 32],
    /// Server's issuance time, Unix milliseconds, UTC.
    pub created_at: u64,
}

/// Prior-home challenge. Instance-signed, ephemeral.
///
/// See `docs/signed-payload-format.md` §5.6 and
/// `docs/federation-protocol.md` §14.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorHomeChallenge {
    /// Issuing instance's signing pubkey (the signer). The
    /// challenge is bound to this instance — captures cannot
    /// redirect to a different peer.
    pub responder_instance_key: [u8; 32],
    /// Ed25519 public key K whose prior-home probe is being
    /// authenticated.
    pub subject_key: [u8; 32],
    /// CSPRNG-generated, single-use 32-byte nonce.
    pub nonce: [u8; 32],
    /// Issuance time, Unix milliseconds, UTC.
    pub created_at: u64,
    /// Hard expiry, Unix milliseconds, UTC.
    pub expires_at: u64,
}

/// Prior-home response. User-signed, ephemeral.
///
/// See `docs/signed-payload-format.md` §5.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorHomeResponse {
    /// Ed25519 public key K (the signer). Must equal the
    /// `subject_key` of the referenced challenge.
    pub subject_key: [u8; 32],
    /// Canonical hash (SHA-256 of canonical bytes) of the §5.6
    /// challenge being redeemed.
    pub challenge_hash: [u8; 32],
    /// Response signing time, Unix milliseconds, UTC.
    pub created_at: u64,
}

/// Thread creation. User-signed (by the OP author).
///
/// See `docs/signed-payload-format.md` §5.9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadCreate {
    /// Thread UUID (raw 16 bytes).
    pub thread_id: [u8; 16],
    /// Ed25519 public key of the thread creator / OP author (the
    /// signer).
    pub author: [u8; 32],
    /// Room slug in canonical form. Globally shared namespace.
    pub room_slug: String,
    /// Thread title in Unicode NFC. Length bounded by
    /// [`MAX_THREAD_TITLE_LEN`].
    pub title: String,
    /// Normalized link URL for link-post threads. `None` for
    /// discussion-only threads.
    pub link_url: Option<String>,
    /// UUID of the OP `post-rev` (revision 0). Receivers REQUIRE
    /// this `post-rev` to be stored before applying the
    /// thread-create.
    pub op_post_id: [u8; 16],
    /// Thread creation time, Unix milliseconds, UTC.
    pub created_at: u64,
}

/// Status kind for [`UserStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatusKind {
    Active,
    Suspended,
    Banned,
}

impl UserStatusKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Banned => "banned",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "banned" => Some(Self::Banned),
            _ => None,
        }
    }
}

/// Instance-issued moderation user-status. Instance-signed.
///
/// See `docs/signed-payload-format.md` §5.10 and
/// `docs/federation-protocol.md` §16.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserStatus {
    /// Ed25519 public key of the user the status applies to.
    pub subject: [u8; 32],
    /// Status kind.
    pub status: UserStatusKind,
    /// Unix milliseconds, UTC. Present iff `status == Suspended`
    /// AND the suspension has a fixed end time. Absent for
    /// indefinite suspensions and for all non-suspended statuses.
    /// Wire-invariant per §5.10; enforced by the parser.
    pub suspended_until: Option<u64>,
    /// Bare canonical domain of the issuing instance. MUST equal
    /// the domain whose signing key signs this object.
    pub signing_instance: String,
    /// Optional human-readable reason.
    pub reason: Option<String>,
    /// Issuance time, Unix milliseconds, UTC.
    pub created_at: u64,
    /// SHA-256 of the canonical payload bytes of the prior
    /// `user-status` object for `subject`. `None` for the user's
    /// first status object.
    pub prior_status_hash: Option<[u8; 32]>,
}

/// Account deactivation. User-signed; terminal. Acts as an
/// erasure authority over every signed object whose inner author
/// key is `user`.
///
/// See `docs/signed-payload-format.md` §5.11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deactivation {
    /// Ed25519 public key of the user (the signer).
    pub user: [u8; 32],
    /// Deactivation time, Unix milliseconds, UTC.
    pub created_at: u64,
}

/// Status kind for [`ThreadStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadStatusKind {
    Open,
    Locked,
}

impl ThreadStatusKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Self::Open),
            "locked" => Some(Self::Locked),
            _ => None,
        }
    }
}

/// Instance-issued thread lock state. Instance-signed.
///
/// See `docs/signed-payload-format.md` §5.12 and
/// `docs/federation-protocol.md` §17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadStatus {
    /// Target thread UUID.
    pub thread_id: [u8; 16],
    /// Status kind.
    pub status: ThreadStatusKind,
    /// Bare canonical domain of the issuing instance. MUST equal
    /// the domain whose signing key signs this object AND be the
    /// thread's home per §5.12's authority rule.
    pub signing_instance: String,
    /// Optional human-readable reason.
    pub reason: Option<String>,
    /// Issuance time, Unix milliseconds, UTC.
    pub created_at: u64,
    /// SHA-256 of the canonical payload bytes of the prior
    /// `thread-status` object for `thread_id`. `None` for the
    /// thread's first status object.
    pub prior_status_hash: Option<[u8; 32]>,
}

/// Reason enum for [`Report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportReason {
    Spam,
    RulesViolation,
    IllegalContent,
    Other,
}

impl ReportReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Spam => "spam",
            Self::RulesViolation => "rules_violation",
            Self::IllegalContent => "illegal_content",
            Self::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "spam" => Some(Self::Spam),
            "rules_violation" => Some(Self::RulesViolation),
            "illegal_content" => Some(Self::IllegalContent),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

/// User report against a post. User-signed; routed only to the
/// target post's home (and locally to the reporter's home by
/// policy). Never gossip-forwarded.
///
/// See `docs/signed-payload-format.md` §5.13 and
/// `docs/federation-protocol.md` §18.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Target post UUID.
    pub post_id: [u8; 16],
    /// Target post's author pubkey.
    pub target_author: [u8; 32],
    /// Reporter's Ed25519 public key (the signer).
    pub reporter: [u8; 32],
    /// Bounded reason enum.
    pub reason: ReportReason,
    /// Optional reporter-supplied detail. Length bounded by
    /// [`MAX_REPORT_DETAIL_LEN`].
    pub detail: Option<String>,
    /// Report time, Unix milliseconds, UTC.
    pub created_at: u64,
}

// --- Errors ---

/// A canonical-form or schema violation when parsing a signed payload.
#[derive(Debug)]
pub enum ParseError {
    /// The bytes are not valid CBOR.
    InvalidCbor,
    /// The bytes parse as CBOR but are not in canonical form (indefinite
    /// length, non-shortest integer, etc.).
    NonCanonical,
    /// A map key was not a text string, or the top-level CBOR item was
    /// not a map.
    NonTextKey,
    /// Map keys are not in canonical (length, bytewise) order.
    KeysOutOfOrder,
    /// A key appears more than once in the map.
    DuplicateKey(String),
    /// Unknown object class (unrecognized `t` value).
    UnknownClass(String),
    /// `v` value not supported for this class.
    UnsupportedVersion { class: &'static str, got: u64 },
    /// A required field is missing from the payload.
    MissingField(&'static str),
    /// A field is present but of the wrong CBOR type.
    WrongType(&'static str),
    /// A fixed-length byte string field has the wrong length.
    BadByteLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    /// `stance` text was not one of `trust` / `distrust` / `neutral`.
    InvalidStance(String),
    /// An integer field would not fit in `u64`.
    IntegerOutOfRange(&'static str),
    /// A bounded text field exceeds its maximum byte length.
    TextTooLong {
        field: &'static str,
        max: usize,
        got: usize,
    },
    /// `attachments` key was present but its array was empty
    /// (the canonical no-attachments form is the omitted key).
    AttachmentsEmpty,
    /// `attachments` array length exceeds [`MAX_ATTACHMENTS_PER_OP`].
    AttachmentsTooMany { max: usize, got: usize },
    /// A signed `filename` did not survive a fresh
    /// [`sanitize_attachment_filename`] pass byte-identically.
    /// This is the §2.2 wire-canonical check.
    NonCanonicalFilename,
    /// A signed `mime` is not a member of [`ALLOWED_MIMES`].
    DisallowedMime(String),
    /// A signed `attachments[].size` exceeds [`MAX_ATTACHMENT_SIZE`].
    AttachmentTooLarge { max: u64, got: u64 },
    /// `status` text was not one of the spec-defined values for the
    /// containing class (`user-status` or `thread-status`).
    InvalidStatus(String),
    /// `reason` text on a `report` was not one of the spec-defined
    /// values. (For free-text `reason` fields on `admin-rm` /
    /// `user-status` / `thread-status` this error is not produced.)
    InvalidReportReason(String),
    /// `suspended_until` was present on a `user-status` whose status
    /// was not `suspended`. Per spec §5.10 the field MUST be absent
    /// for non-suspended statuses.
    IllegalSuspendedUntil,
    /// A `move` violated §5.1 presence coupling: `from_instance_key`
    /// and `from_instance` must both be present (move) or both absent
    /// (genesis declaration), and a genesis declaration (both absent)
    /// must carry no `prior_move_hash`.
    MovePresenceCoupling,
    /// A `move`'s embedded `genesis_attestation` had an inner `key` or
    /// `genesis_at` that did not equal the outer declaration's
    /// fields (§5.1 verification step 4, structural half).
    GenesisAttestationMismatch,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCbor => f.write_str("invalid CBOR"),
            Self::NonCanonical => f.write_str("CBOR is not in canonical form"),
            Self::NonTextKey => f.write_str("map key is not a text string"),
            Self::KeysOutOfOrder => f.write_str("map keys are not in canonical order"),
            Self::DuplicateKey(k) => write!(f, "duplicate map key: {k}"),
            Self::UnknownClass(t) => write!(f, "unknown object class: {t}"),
            Self::UnsupportedVersion { class, got } => {
                write!(f, "unsupported version {got} for class {class}")
            }
            Self::MissingField(name) => write!(f, "missing field: {name}"),
            Self::WrongType(name) => write!(f, "wrong CBOR type for field: {name}"),
            Self::BadByteLength {
                field,
                expected,
                got,
            } => {
                write!(f, "field {field}: expected {expected} bytes, got {got}")
            }
            Self::InvalidStance(s) => write!(f, "invalid trust stance: {s}"),
            Self::IntegerOutOfRange(name) => write!(f, "integer field out of u64 range: {name}"),
            Self::TextTooLong { field, max, got } => {
                write!(f, "field {field}: max {max} bytes, got {got}")
            }
            Self::AttachmentsEmpty => f.write_str(
                "attachments array is empty; the canonical no-attachments form omits the key",
            ),
            Self::AttachmentsTooMany { max, got } => {
                write!(f, "attachments array length {got} exceeds maximum {max}")
            }
            Self::NonCanonicalFilename => {
                f.write_str("signed attachment filename is not canonical per FILENAME_RULES")
            }
            Self::DisallowedMime(s) => write!(f, "attachment mime not in ALLOWED_MIMES: {s}"),
            Self::AttachmentTooLarge { max, got } => {
                write!(f, "attachment size {got} exceeds maximum {max}")
            }
            Self::InvalidStatus(s) => write!(f, "invalid status: {s}"),
            Self::InvalidReportReason(s) => write!(f, "invalid report reason: {s}"),
            Self::IllegalSuspendedUntil => f.write_str(
                "suspended_until present on user-status whose status is not 'suspended'",
            ),
            Self::MovePresenceCoupling => f.write_str(
                "move violates §5.1 from_* presence coupling / genesis prior_move_hash rule",
            ),
            Self::GenesisAttestationMismatch => f.write_str(
                "genesis_attestation inner key/genesis_at does not match outer declaration",
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// A verification failure.
#[derive(Debug)]
pub enum VerifyError {
    /// The payload bytes were not canonical or did not match the schema.
    Parse(ParseError),
    /// The signature was not 64 bytes.
    BadSignatureLength,
    /// The `claimed_key` did not match the payload's identity field
    /// (`author` for posts/retractions, `from_key` for trust edges).
    AuthorMismatch,
    /// Ed25519 verification failed.
    SignatureFailed,
}

impl From<ParseError> for VerifyError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "parse error: {e}"),
            Self::BadSignatureLength => f.write_str("signature is not 64 bytes"),
            Self::AuthorMismatch => f.write_str("claimed key does not match payload identity"),
            Self::SignatureFailed => f.write_str("Ed25519 verification failed"),
        }
    }
}

impl std::error::Error for VerifyError {}

// --- Encoder ---

impl SignedPayload {
    /// Serialize this payload to canonical CBOR bytes.
    ///
    /// The output is what the signer signs and what verifiers re-encode
    /// for the byte-equality canonicalization check.
    pub fn encode(&self) -> Vec<u8> {
        let value = self.to_cbor_value();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf)
            .expect("ciborium serialization of well-formed Value is infallible");
        buf
    }

    fn to_cbor_value(&self) -> Value {
        match self {
            Self::PostRevision(p) => post_revision_to_cbor(p),
            Self::Retraction(r) => retraction_to_cbor(r),
            Self::TrustEdge(e) => trust_edge_to_cbor(e),
            Self::ProfileRevision(p) => profile_revision_to_cbor(p),
            Self::Move(m) => move_to_cbor(m),
            Self::AdminRemoval(a) => admin_removal_to_cbor(a),
            Self::FedEnvelope(e) => fed_envelope_to_cbor(e),
            Self::RegistrationChallenge(c) => registration_challenge_to_cbor(c),
            Self::PriorHomeChallenge(c) => prior_home_challenge_to_cbor(c),
            Self::PriorHomeResponse(r) => prior_home_response_to_cbor(r),
            Self::ThreadCreate(t) => thread_create_to_cbor(t),
            Self::UserStatus(s) => user_status_to_cbor(s),
            Self::Deactivation(d) => deactivation_to_cbor(d),
            Self::ThreadStatus(s) => thread_status_to_cbor(s),
            Self::Report(r) => report_to_cbor(r),
        }
    }
}

/// Build a canonical CBOR map from a list of entries.
///
/// Entries may be provided in any order; this function sorts them by
/// the canonical (length, bytewise) order of their text-string keys.
fn build_map(mut entries: Vec<(&'static str, Value)>) -> Value {
    entries.sort_by(|a, b| cbor_text_key_cmp(a.0, b.0));
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Text(k.to_string()), v))
            .collect(),
    )
}

/// Canonical ordering of two short text-string CBOR map keys.
///
/// For text strings under 24 bytes, the CBOR encoding is
/// `(0x60 | len) || utf8_bytes`. Bytewise comparison of the encodings
/// is equivalent to lexicographic comparison of `(len, bytes)`. All
/// signed-payload field keys in V1 are short ASCII, well under 24 bytes.
fn cbor_text_key_cmp(a: &str, b: &str) -> Ordering {
    debug_assert!(
        a.len() < 24 && b.len() < 24,
        "signed-payload keys are assumed under 24 bytes"
    );
    a.len()
        .cmp(&b.len())
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

fn uint(n: u64) -> Value {
    Value::Integer(Integer::from(n))
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn post_revision_to_cbor(p: &PostRevision) -> Value {
    let mut entries: Vec<(&'static str, Value)> = vec![
        ("v", uint(V1)),
        ("t", text(TAG_POST_REVISION)),
        ("post_id", bytes(&p.post_id)),
        ("author", bytes(&p.author)),
        ("thread_id", bytes(&p.thread_id)),
        ("revision", uint(p.revision)),
        ("body", text(&p.body)),
        ("created_at", uint(p.created_at)),
    ];
    if let Some(parent_id) = p.parent_id {
        entries.push(("parent_id", bytes(&parent_id)));
    }
    // Attachments key is omitted entirely when the vec is empty
    // (`docs/attachments.md` §2.1 wire invariant) so existing signed
    // posts in the wild remain bit-identical.
    if !p.attachments.is_empty() {
        entries.push((KEY_ATTACHMENTS, attachments_to_cbor(&p.attachments)));
    }
    build_map(entries)
}

/// Encode an `AttachmentRef` array to a canonical CBOR array.
///
/// Each inner map is built via [`build_map`] so its keys are sorted
/// canonically. The array preserves caller order — array index *is*
/// the on-screen position (§2.1), so the encoder MUST NOT sort.
fn attachments_to_cbor(refs: &[AttachmentRef]) -> Value {
    Value::Array(refs.iter().map(attachment_ref_to_cbor).collect())
}

fn attachment_ref_to_cbor(r: &AttachmentRef) -> Value {
    build_map(vec![
        (KEY_ATTACHMENT_CONTENT_HASH, bytes(&r.content_hash)),
        (KEY_ATTACHMENT_FILENAME, text(&r.filename)),
        (KEY_ATTACHMENT_MIME, text(&r.mime)),
        (KEY_ATTACHMENT_SIZE, uint(r.size)),
    ])
}

fn retraction_to_cbor(r: &Retraction) -> Value {
    build_map(vec![
        ("v", uint(V1)),
        ("t", text(TAG_RETRACTION)),
        ("post_id", bytes(&r.post_id)),
        ("author", bytes(&r.author)),
        ("created_at", uint(r.created_at)),
    ])
}

fn trust_edge_to_cbor(e: &TrustEdge) -> Value {
    let mut entries: Vec<(&'static str, Value)> = vec![
        ("v", uint(V1)),
        ("t", text(TAG_TRUST_EDGE)),
        ("from_key", bytes(&e.from_key)),
        ("to_key", bytes(&e.to_key)),
        ("stance", text(e.stance.as_str())),
        ("created_at", uint(e.created_at)),
    ];
    if let Some(prior) = e.prior_edge_hash {
        entries.push(("prior_edge_hash", bytes(&prior)));
    }
    build_map(entries)
}

fn profile_revision_to_cbor(p: &ProfileRevision) -> Value {
    // Required fields per spec §5.8. Optional `avatar_attachment_hash`
    // and `prior_profile_hash` are appended below — absence is signalled
    // by omitting the key (not by encoding a CBOR null), matching the
    // post-revision / trust-edge optional-field convention.
    let mut entries: Vec<(&'static str, Value)> = vec![
        ("v", uint(V1)),
        ("t", text(TAG_PROFILE)),
        ("user", bytes(&p.user)),
        ("display_name", text(&p.display_name)),
        ("bio", text(&p.bio)),
        ("created_at", uint(p.created_at)),
    ];
    if let Some(avatar) = p.avatar_attachment_hash {
        entries.push(("avatar_attachment_hash", bytes(&avatar)));
    }
    if let Some(prior) = p.prior_profile_hash {
        entries.push(("prior_profile_hash", bytes(&prior)));
    }
    build_map(entries)
}

// --- Federation-era encoders (`docs/signed-payload-format.md` §5) ---

fn move_to_cbor(m: &Move) -> Value {
    // Field order matters: canonical CBOR sorts by key bytes, and
    // `build_map` re-sorts before emitting, so the literal order here
    // is for readability only. The set of keys, however, must match
    // the §5.1 schema exactly: any added/removed key changes the
    // canonical_hash and therefore the chain identity.
    let mut entries: Vec<(&'static str, Value)> = vec![
        ("v", uint(V1)),
        ("t", text(TAG_MOVE)),
        ("key", bytes(&m.key)),
        ("to_instance_key", bytes(&m.to_instance_key)),
        ("to_instance", text(&m.to_instance)),
        ("created_at", uint(m.created_at)),
        ("genesis_at", uint(m.genesis_at)),
        (
            "genesis_attestation",
            genesis_attestation_to_cbor(&m.genesis_attestation),
        ),
    ];
    // §5.1 presence coupling: `from_*` are emitted together for a move
    // and omitted together for a genesis declaration. The struct keeps
    // them as a coupled `Option` pair, so a desynchronised half-set
    // (only one `Some`) silently drops both rather than emitting a
    // non-canonical half — but construction always sets them together.
    if let (Some(from_key), Some(from_domain)) = (&m.from_instance_key, &m.from_instance) {
        entries.push(("from_instance_key", bytes(from_key)));
        entries.push(("from_instance", text(from_domain)));
    }
    if let Some(prior) = m.prior_move_hash {
        entries.push(("prior_move_hash", bytes(&prior)));
    }
    build_map(entries)
}

/// Encode an embedded [`GenesisAttestation`] to a canonical CBOR map.
/// Keys are sorted by [`build_map`]; this same key set (minus `sig`)
/// is what [`genesis_attestation_signing_bytes`] signs.
fn genesis_attestation_to_cbor(a: &GenesisAttestation) -> Value {
    build_map(vec![
        ("key", bytes(&a.key)),
        ("genesis_at", uint(a.genesis_at)),
        ("birth_instance_key", bytes(&a.birth_instance_key)),
        ("sig", bytes(&a.sig)),
    ])
}

/// Canonical CBOR of the genesis-attestation **signing input**: the
/// `{key, genesis_at, birth_instance_key}` triple a birth instance
/// signs (`docs/signed-payload-format.md` §5.1). Both the signer (the
/// birth instance's admin key) and every verifier reconstruct these
/// exact bytes; the embedded `sig` is an Ed25519 signature over them.
/// Excludes `sig` itself — the signature can't cover its own bytes.
pub fn genesis_attestation_signing_bytes(
    key: &[u8; 32],
    genesis_at: u64,
    birth_instance_key: &[u8; 32],
) -> Vec<u8> {
    let value = build_map(vec![
        ("key", bytes(key)),
        ("genesis_at", uint(genesis_at)),
        ("birth_instance_key", bytes(birth_instance_key)),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&value, &mut buf).expect("ciborium ser of well-formed Value");
    buf
}

fn admin_removal_to_cbor(a: &AdminRemoval) -> Value {
    let mut entries: Vec<(&'static str, Value)> = vec![
        ("v", uint(V1)),
        ("t", text(TAG_ADMIN_REMOVAL)),
        ("post_id", bytes(&a.post_id)),
        ("target_author", bytes(&a.target_author)),
        ("signing_instance", text(&a.signing_instance)),
        ("created_at", uint(a.created_at)),
    ];
    if let Some(reason) = &a.reason {
        entries.push(("reason", text(reason)));
    }
    build_map(entries)
}

fn fed_envelope_to_cbor(e: &FedEnvelope) -> Value {
    let mut entries: Vec<(&'static str, Value)> = vec![
        ("v", uint(V1)),
        ("t", text(TAG_FED_ENVELOPE)),
        ("sender", bytes(&e.sender)),
        ("receiver", bytes(&e.receiver)),
        ("method", text(&e.method)),
        ("path", text(&e.path)),
        ("created_at", uint(e.created_at)),
        ("nonce", bytes(&e.nonce)),
    ];
    if let Some(body_hash) = e.body_hash {
        entries.push(("body_hash", bytes(&body_hash)));
    }
    build_map(entries)
}

fn registration_challenge_to_cbor(c: &RegistrationChallenge) -> Value {
    build_map(vec![
        ("v", uint(V1)),
        ("t", text(TAG_REGISTRATION_CHALLENGE)),
        ("user_key", bytes(&c.user_key)),
        ("dest_instance_key", bytes(&c.dest_instance_key)),
        ("dest_domain", text(&c.dest_domain)),
        ("nonce", bytes(&c.nonce)),
        ("created_at", uint(c.created_at)),
    ])
}

fn prior_home_challenge_to_cbor(c: &PriorHomeChallenge) -> Value {
    build_map(vec![
        ("v", uint(V1)),
        ("t", text(TAG_PRIOR_HOME_CHALLENGE)),
        ("responder_instance_key", bytes(&c.responder_instance_key)),
        ("subject_key", bytes(&c.subject_key)),
        ("nonce", bytes(&c.nonce)),
        ("created_at", uint(c.created_at)),
        ("expires_at", uint(c.expires_at)),
    ])
}

fn prior_home_response_to_cbor(r: &PriorHomeResponse) -> Value {
    build_map(vec![
        ("v", uint(V1)),
        ("t", text(TAG_PRIOR_HOME_RESPONSE)),
        ("subject_key", bytes(&r.subject_key)),
        ("challenge_hash", bytes(&r.challenge_hash)),
        ("created_at", uint(r.created_at)),
    ])
}

fn thread_create_to_cbor(t: &ThreadCreate) -> Value {
    let mut entries: Vec<(&'static str, Value)> = vec![
        ("v", uint(V1)),
        ("t", text(TAG_THREAD_CREATE)),
        ("thread_id", bytes(&t.thread_id)),
        ("author", bytes(&t.author)),
        ("room_slug", text(&t.room_slug)),
        ("title", text(&t.title)),
        ("op_post_id", bytes(&t.op_post_id)),
        ("created_at", uint(t.created_at)),
    ];
    if let Some(url) = &t.link_url {
        entries.push(("link_url", text(url)));
    }
    build_map(entries)
}

fn user_status_to_cbor(s: &UserStatus) -> Value {
    let mut entries: Vec<(&'static str, Value)> = vec![
        ("v", uint(V1)),
        ("t", text(TAG_USER_STATUS)),
        ("subject", bytes(&s.subject)),
        ("status", text(s.status.as_str())),
        ("signing_instance", text(&s.signing_instance)),
        ("created_at", uint(s.created_at)),
    ];
    if let Some(until) = s.suspended_until {
        entries.push(("suspended_until", uint(until)));
    }
    if let Some(reason) = &s.reason {
        entries.push(("reason", text(reason)));
    }
    if let Some(prior) = s.prior_status_hash {
        entries.push(("prior_status_hash", bytes(&prior)));
    }
    build_map(entries)
}

fn deactivation_to_cbor(d: &Deactivation) -> Value {
    build_map(vec![
        ("v", uint(V1)),
        ("t", text(TAG_DEACTIVATION)),
        ("user", bytes(&d.user)),
        ("created_at", uint(d.created_at)),
    ])
}

fn thread_status_to_cbor(s: &ThreadStatus) -> Value {
    let mut entries: Vec<(&'static str, Value)> = vec![
        ("v", uint(V1)),
        ("t", text(TAG_THREAD_STATUS)),
        ("thread_id", bytes(&s.thread_id)),
        ("status", text(s.status.as_str())),
        ("signing_instance", text(&s.signing_instance)),
        ("created_at", uint(s.created_at)),
    ];
    if let Some(reason) = &s.reason {
        entries.push(("reason", text(reason)));
    }
    if let Some(prior) = s.prior_status_hash {
        entries.push(("prior_status_hash", bytes(&prior)));
    }
    build_map(entries)
}

fn report_to_cbor(r: &Report) -> Value {
    let mut entries: Vec<(&'static str, Value)> = vec![
        ("v", uint(V1)),
        ("t", text(TAG_REPORT)),
        ("post_id", bytes(&r.post_id)),
        ("target_author", bytes(&r.target_author)),
        ("reporter", bytes(&r.reporter)),
        ("reason", text(r.reason.as_str())),
        ("created_at", uint(r.created_at)),
    ];
    if let Some(d) = &r.detail {
        entries.push(("detail", text(d)));
    }
    build_map(entries)
}

// --- Parser ---

impl SignedPayload {
    /// Parse canonical CBOR bytes into a typed payload.
    ///
    /// Performs the full §6 canonicalization check: parse, re-encode,
    /// bytewise compare, plus explicit key-order and duplicate-key
    /// checks. The output is byte-identical to what [`Self::encode`]
    /// would produce for the returned value.
    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        // Parse via ciborium.
        let value: Value = ciborium::de::from_reader(input).map_err(|_| ParseError::InvalidCbor)?;

        // Re-encode and compare. Catches non-canonical integer encodings,
        // indefinite-length items, and any other byte-level deviation.
        let mut re_encoded = Vec::with_capacity(input.len());
        ciborium::ser::into_writer(&value, &mut re_encoded).map_err(|_| ParseError::InvalidCbor)?;
        if re_encoded.as_slice() != input {
            return Err(ParseError::NonCanonical);
        }

        // Extract the top-level map.
        let map_entries = match value {
            Value::Map(m) => m,
            _ => return Err(ParseError::WrongType("payload")),
        };

        // Walk the entries, enforce canonical key order, reject
        // duplicates and non-text keys. Re-encode comparison won't
        // catch key-order violations because ciborium preserves
        // Value::Map insertion order on both parse and serialize.
        let mut fields: BTreeMap<String, Value> = BTreeMap::new();
        let mut last_key: Option<String> = None;
        for (k, v) in map_entries {
            let key_str = match k {
                Value::Text(s) => s,
                _ => return Err(ParseError::NonTextKey),
            };
            if let Some(prev) = &last_key
                && cbor_text_key_cmp(prev, &key_str) != Ordering::Less
            {
                return Err(ParseError::KeysOutOfOrder);
            }
            if fields.contains_key(&key_str) {
                return Err(ParseError::DuplicateKey(key_str));
            }
            last_key = Some(key_str.clone());
            fields.insert(key_str, v);
        }

        // Dispatch on (t, v).
        let t = field_text(&fields, "t")?;
        let version = field_uint(&fields, "v")?;

        match t.as_str() {
            TAG_POST_REVISION => {
                require_version(TAG_POST_REVISION, version)?;
                parse_post_revision(&fields).map(SignedPayload::PostRevision)
            }
            TAG_RETRACTION => {
                require_version(TAG_RETRACTION, version)?;
                parse_retraction(&fields).map(SignedPayload::Retraction)
            }
            TAG_TRUST_EDGE => {
                require_version(TAG_TRUST_EDGE, version)?;
                parse_trust_edge(&fields).map(SignedPayload::TrustEdge)
            }
            TAG_PROFILE => {
                require_version(TAG_PROFILE, version)?;
                parse_profile_revision(&fields).map(SignedPayload::ProfileRevision)
            }
            TAG_MOVE => {
                require_version(TAG_MOVE, version)?;
                parse_move(&fields).map(SignedPayload::Move)
            }
            TAG_ADMIN_REMOVAL => {
                require_version(TAG_ADMIN_REMOVAL, version)?;
                parse_admin_removal(&fields).map(SignedPayload::AdminRemoval)
            }
            TAG_FED_ENVELOPE => {
                require_version(TAG_FED_ENVELOPE, version)?;
                parse_fed_envelope(&fields).map(SignedPayload::FedEnvelope)
            }
            TAG_REGISTRATION_CHALLENGE => {
                require_version(TAG_REGISTRATION_CHALLENGE, version)?;
                parse_registration_challenge(&fields).map(SignedPayload::RegistrationChallenge)
            }
            TAG_PRIOR_HOME_CHALLENGE => {
                require_version(TAG_PRIOR_HOME_CHALLENGE, version)?;
                parse_prior_home_challenge(&fields).map(SignedPayload::PriorHomeChallenge)
            }
            TAG_PRIOR_HOME_RESPONSE => {
                require_version(TAG_PRIOR_HOME_RESPONSE, version)?;
                parse_prior_home_response(&fields).map(SignedPayload::PriorHomeResponse)
            }
            TAG_THREAD_CREATE => {
                require_version(TAG_THREAD_CREATE, version)?;
                parse_thread_create(&fields).map(SignedPayload::ThreadCreate)
            }
            TAG_USER_STATUS => {
                require_version(TAG_USER_STATUS, version)?;
                parse_user_status(&fields).map(SignedPayload::UserStatus)
            }
            TAG_DEACTIVATION => {
                require_version(TAG_DEACTIVATION, version)?;
                parse_deactivation(&fields).map(SignedPayload::Deactivation)
            }
            TAG_THREAD_STATUS => {
                require_version(TAG_THREAD_STATUS, version)?;
                parse_thread_status(&fields).map(SignedPayload::ThreadStatus)
            }
            TAG_REPORT => {
                require_version(TAG_REPORT, version)?;
                parse_report(&fields).map(SignedPayload::Report)
            }
            _ => Err(ParseError::UnknownClass(t)),
        }
    }
}

fn require_version(class: &'static str, got: u64) -> Result<(), ParseError> {
    if got == V1 {
        Ok(())
    } else {
        Err(ParseError::UnsupportedVersion { class, got })
    }
}

fn field_text(fields: &BTreeMap<String, Value>, name: &'static str) -> Result<String, ParseError> {
    let v = fields.get(name).ok_or(ParseError::MissingField(name))?;
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(ParseError::WrongType(name)),
    }
}

fn field_uint(fields: &BTreeMap<String, Value>, name: &'static str) -> Result<u64, ParseError> {
    let v = fields.get(name).ok_or(ParseError::MissingField(name))?;
    match v {
        Value::Integer(i) => u64::try_from(*i).map_err(|_| ParseError::IntegerOutOfRange(name)),
        _ => Err(ParseError::WrongType(name)),
    }
}

fn field_bytes_fixed<const N: usize>(
    fields: &BTreeMap<String, Value>,
    name: &'static str,
) -> Result<[u8; N], ParseError> {
    let v = fields.get(name).ok_or(ParseError::MissingField(name))?;
    match v {
        Value::Bytes(b) => {
            <[u8; N]>::try_from(b.as_slice()).map_err(|_| ParseError::BadByteLength {
                field: name,
                expected: N,
                got: b.len(),
            })
        }
        _ => Err(ParseError::WrongType(name)),
    }
}

fn parse_post_revision(fields: &BTreeMap<String, Value>) -> Result<PostRevision, ParseError> {
    let post_id = field_bytes_fixed::<16>(fields, "post_id")?;
    let author = field_bytes_fixed::<32>(fields, "author")?;
    let thread_id = field_bytes_fixed::<16>(fields, "thread_id")?;
    let parent_id = if fields.contains_key("parent_id") {
        Some(field_bytes_fixed::<16>(fields, "parent_id")?)
    } else {
        None
    };
    let revision = field_uint(fields, "revision")?;
    let body = field_text(fields, "body")?;
    let created_at = field_uint(fields, "created_at")?;
    let attachments = if fields.contains_key(KEY_ATTACHMENTS) {
        parse_attachments(fields)?
    } else {
        Vec::new()
    };
    Ok(PostRevision {
        post_id,
        author,
        thread_id,
        parent_id,
        revision,
        body,
        created_at,
        attachments,
    })
}

/// Parse the optional `attachments` array on a `post-rev`.
///
/// Caller has already established that the key is present; an empty
/// array here is a wire violation per `docs/attachments.md` §2.1
/// (the no-attachments case must omit the key entirely).
fn parse_attachments(fields: &BTreeMap<String, Value>) -> Result<Vec<AttachmentRef>, ParseError> {
    let v = fields
        .get(KEY_ATTACHMENTS)
        .ok_or(ParseError::MissingField(KEY_ATTACHMENTS))?;
    let items = match v {
        Value::Array(items) => items,
        _ => return Err(ParseError::WrongType(KEY_ATTACHMENTS)),
    };
    // Per §2.1: 1..=MAX_ATTACHMENTS_PER_OP when present. Empty arrays
    // are non-canonical (the omitted form is the canonical
    // no-attachments encoding).
    if items.is_empty() {
        return Err(ParseError::AttachmentsEmpty);
    }
    if items.len() > MAX_ATTACHMENTS_PER_OP {
        return Err(ParseError::AttachmentsTooMany {
            max: MAX_ATTACHMENTS_PER_OP,
            got: items.len(),
        });
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(parse_attachment_ref(item)?);
    }
    Ok(out)
}

fn parse_attachment_ref(v: &Value) -> Result<AttachmentRef, ParseError> {
    let map_entries = match v {
        Value::Map(m) => m,
        _ => return Err(ParseError::WrongType("attachments[]")),
    };
    // Walk inner-map entries with the same canonical-order + duplicate
    // checks the top-level parser applies. Re-encode comparison
    // already caught indefinite-length / non-canonical-integer issues
    // at the outer level; the inner key-order check below is the
    // load-bearing canonicalization for the inner maps (ciborium
    // preserves Value::Map insertion order on parse + serialize).
    let mut fields: BTreeMap<String, Value> = BTreeMap::new();
    let mut last_key: Option<String> = None;
    for (k, v) in map_entries {
        let key_str = match k {
            Value::Text(s) => s.clone(),
            _ => return Err(ParseError::NonTextKey),
        };
        if let Some(prev) = &last_key
            && cbor_text_key_cmp(prev, &key_str) != Ordering::Less
        {
            return Err(ParseError::KeysOutOfOrder);
        }
        if fields.contains_key(&key_str) {
            return Err(ParseError::DuplicateKey(key_str));
        }
        last_key = Some(key_str.clone());
        fields.insert(key_str, v.clone());
    }

    let content_hash = field_bytes_fixed::<32>(&fields, KEY_ATTACHMENT_CONTENT_HASH)?;
    let filename = field_text(&fields, KEY_ATTACHMENT_FILENAME)?;
    // Wire-invariant: the signed filename MUST be the byte-identical
    // output of FILENAME_RULES (§2.2 step 6). Re-run the sanitizer
    // and reject any drift — this is what stops a malicious origin
    // from signing `"../../etc/passwd"` and forcing a permissive
    // peer to accept it.
    match sanitize_attachment_filename(&filename) {
        Some(canonical) if canonical == filename => {}
        _ => return Err(ParseError::NonCanonicalFilename),
    }
    let mime = field_text(&fields, KEY_ATTACHMENT_MIME)?;
    if !ALLOWED_MIMES.contains(&mime.as_str()) {
        return Err(ParseError::DisallowedMime(mime));
    }
    let size = field_uint(&fields, KEY_ATTACHMENT_SIZE)?;
    if size as usize > MAX_ATTACHMENT_SIZE {
        return Err(ParseError::AttachmentTooLarge {
            max: MAX_ATTACHMENT_SIZE as u64,
            got: size,
        });
    }
    Ok(AttachmentRef {
        content_hash,
        mime,
        size,
        filename,
    })
}

fn parse_retraction(fields: &BTreeMap<String, Value>) -> Result<Retraction, ParseError> {
    let post_id = field_bytes_fixed::<16>(fields, "post_id")?;
    let author = field_bytes_fixed::<32>(fields, "author")?;
    let created_at = field_uint(fields, "created_at")?;
    Ok(Retraction {
        post_id,
        author,
        created_at,
    })
}

fn parse_profile_revision(fields: &BTreeMap<String, Value>) -> Result<ProfileRevision, ParseError> {
    let user = field_bytes_fixed::<32>(fields, "user")?;
    let display_name = field_text(fields, "display_name")?;
    let bio = field_text(fields, "bio")?;
    // Defense-in-depth bound on inbound bio length. The local sign path
    // already gates writes at MAX_BIO_LEN (500 bytes, in users.rs);
    // this check protects the verifier against federation peers
    // attempting to ship outsized bios.
    if bio.len() > MAX_PROFILE_BIO_LEN {
        return Err(ParseError::TextTooLong {
            field: "bio",
            max: MAX_PROFILE_BIO_LEN,
            got: bio.len(),
        });
    }
    let created_at = field_uint(fields, "created_at")?;
    let avatar_attachment_hash = if fields.contains_key("avatar_attachment_hash") {
        Some(field_bytes_fixed::<32>(fields, "avatar_attachment_hash")?)
    } else {
        None
    };
    let prior_profile_hash = if fields.contains_key("prior_profile_hash") {
        Some(field_bytes_fixed::<32>(fields, "prior_profile_hash")?)
    } else {
        None
    };
    Ok(ProfileRevision {
        user,
        display_name,
        bio,
        avatar_attachment_hash,
        created_at,
        prior_profile_hash,
    })
}

fn parse_trust_edge(fields: &BTreeMap<String, Value>) -> Result<TrustEdge, ParseError> {
    let from_key = field_bytes_fixed::<32>(fields, "from_key")?;
    let to_key = field_bytes_fixed::<32>(fields, "to_key")?;
    let stance_str = field_text(fields, "stance")?;
    let stance = TrustStance::parse(&stance_str).ok_or(ParseError::InvalidStance(stance_str))?;
    let created_at = field_uint(fields, "created_at")?;
    let prior_edge_hash = if fields.contains_key("prior_edge_hash") {
        Some(field_bytes_fixed::<32>(fields, "prior_edge_hash")?)
    } else {
        None
    };
    Ok(TrustEdge {
        from_key,
        to_key,
        stance,
        created_at,
        prior_edge_hash,
    })
}

// --- Federation-era parsers (`docs/signed-payload-format.md` §5) ---

fn parse_move(fields: &BTreeMap<String, Value>) -> Result<Move, ParseError> {
    let key = field_bytes_fixed::<32>(fields, "key")?;

    // §5.1 presence coupling: `from_instance_key` and `from_instance`
    // MUST both be present (a move) or both absent (a genesis
    // declaration). A half-set is `schema_invalid`.
    let has_from_key = fields.contains_key("from_instance_key");
    let has_from_domain = fields.contains_key("from_instance");
    if has_from_key != has_from_domain {
        return Err(ParseError::MovePresenceCoupling);
    }
    let (from_instance_key, from_instance) = if has_from_key {
        (
            Some(field_bytes_fixed::<32>(fields, "from_instance_key")?),
            Some(field_text(fields, "from_instance")?),
        )
    } else {
        (None, None)
    };

    let to_instance_key = field_bytes_fixed::<32>(fields, "to_instance_key")?;
    let to_instance = field_text(fields, "to_instance")?;
    let created_at = field_uint(fields, "created_at")?;
    let genesis_at = field_uint(fields, "genesis_at")?;
    let genesis_attestation = parse_genesis_attestation(fields, &key, genesis_at)?;
    let prior_move_hash = if fields.contains_key("prior_move_hash") {
        Some(field_bytes_fixed::<32>(fields, "prior_move_hash")?)
    } else {
        None
    };

    // §5.1 step 5: a genesis declaration (from_* absent) requires
    // `prior_move_hash` absent — it has no predecessor by definition.
    if from_instance_key.is_none() && prior_move_hash.is_some() {
        return Err(ParseError::MovePresenceCoupling);
    }

    Ok(Move {
        key,
        from_instance_key,
        from_instance,
        to_instance_key,
        to_instance,
        created_at,
        genesis_at,
        genesis_attestation,
        prior_move_hash,
    })
}

/// Parse the embedded `genesis_attestation` sub-map (§5.1). Walks the
/// inner map with the same canonical-order + duplicate-key checks the
/// top-level parser applies (the outer re-encode comparison does not
/// catch inner key-order violations — ciborium preserves `Value::Map`
/// insertion order). Enforces the §5.1-step-4 *structural* binding:
/// inner `key` / `genesis_at` MUST equal the outer declaration's
/// fields. The `sig` cryptographic check is deferred to the receive
/// path (`federation::moves`), which holds `birth_instance_key` as a
/// verifying key — mirroring how the outer move signature is verified
/// there, not at parse time.
fn parse_genesis_attestation(
    fields: &BTreeMap<String, Value>,
    outer_key: &[u8; 32],
    outer_genesis_at: u64,
) -> Result<GenesisAttestation, ParseError> {
    let v = fields
        .get("genesis_attestation")
        .ok_or(ParseError::MissingField("genesis_attestation"))?;
    let map_entries = match v {
        Value::Map(m) => m,
        _ => return Err(ParseError::WrongType("genesis_attestation")),
    };

    let mut inner: BTreeMap<String, Value> = BTreeMap::new();
    let mut last_key: Option<String> = None;
    for (k, v) in map_entries {
        let key_str = match k {
            Value::Text(s) => s.clone(),
            _ => return Err(ParseError::NonTextKey),
        };
        if let Some(prev) = &last_key
            && cbor_text_key_cmp(prev, &key_str) != Ordering::Less
        {
            return Err(ParseError::KeysOutOfOrder);
        }
        if inner.contains_key(&key_str) {
            return Err(ParseError::DuplicateKey(key_str));
        }
        last_key = Some(key_str.clone());
        inner.insert(key_str, v.clone());
    }

    let key = field_bytes_fixed::<32>(&inner, "key")?;
    let genesis_at = field_uint(&inner, "genesis_at")?;
    let birth_instance_key = field_bytes_fixed::<32>(&inner, "birth_instance_key")?;
    let sig = field_bytes_fixed::<64>(&inner, "sig")?;

    if &key != outer_key || genesis_at != outer_genesis_at {
        return Err(ParseError::GenesisAttestationMismatch);
    }

    Ok(GenesisAttestation {
        key,
        genesis_at,
        birth_instance_key,
        sig,
    })
}

fn parse_admin_removal(fields: &BTreeMap<String, Value>) -> Result<AdminRemoval, ParseError> {
    let post_id = field_bytes_fixed::<16>(fields, "post_id")?;
    let target_author = field_bytes_fixed::<32>(fields, "target_author")?;
    let signing_instance = field_text(fields, "signing_instance")?;
    let created_at = field_uint(fields, "created_at")?;
    let reason = if fields.contains_key("reason") {
        Some(field_text(fields, "reason")?)
    } else {
        None
    };
    Ok(AdminRemoval {
        post_id,
        target_author,
        signing_instance,
        created_at,
        reason,
    })
}

fn parse_fed_envelope(fields: &BTreeMap<String, Value>) -> Result<FedEnvelope, ParseError> {
    let sender = field_bytes_fixed::<32>(fields, "sender")?;
    let receiver = field_bytes_fixed::<32>(fields, "receiver")?;
    let method = field_text(fields, "method")?;
    let path = field_text(fields, "path")?;
    let created_at = field_uint(fields, "created_at")?;
    let nonce = field_bytes_fixed::<16>(fields, "nonce")?;
    let body_hash = if fields.contains_key("body_hash") {
        Some(field_bytes_fixed::<32>(fields, "body_hash")?)
    } else {
        None
    };
    Ok(FedEnvelope {
        sender,
        receiver,
        method,
        path,
        body_hash,
        created_at,
        nonce,
    })
}

fn parse_registration_challenge(
    fields: &BTreeMap<String, Value>,
) -> Result<RegistrationChallenge, ParseError> {
    let user_key = field_bytes_fixed::<32>(fields, "user_key")?;
    let dest_instance_key = field_bytes_fixed::<32>(fields, "dest_instance_key")?;
    let dest_domain = field_text(fields, "dest_domain")?;
    let nonce = field_bytes_fixed::<32>(fields, "nonce")?;
    let created_at = field_uint(fields, "created_at")?;
    Ok(RegistrationChallenge {
        user_key,
        dest_instance_key,
        dest_domain,
        nonce,
        created_at,
    })
}

fn parse_prior_home_challenge(
    fields: &BTreeMap<String, Value>,
) -> Result<PriorHomeChallenge, ParseError> {
    let responder_instance_key = field_bytes_fixed::<32>(fields, "responder_instance_key")?;
    let subject_key = field_bytes_fixed::<32>(fields, "subject_key")?;
    let nonce = field_bytes_fixed::<32>(fields, "nonce")?;
    let created_at = field_uint(fields, "created_at")?;
    let expires_at = field_uint(fields, "expires_at")?;
    Ok(PriorHomeChallenge {
        responder_instance_key,
        subject_key,
        nonce,
        created_at,
        expires_at,
    })
}

fn parse_prior_home_response(
    fields: &BTreeMap<String, Value>,
) -> Result<PriorHomeResponse, ParseError> {
    let subject_key = field_bytes_fixed::<32>(fields, "subject_key")?;
    let challenge_hash = field_bytes_fixed::<32>(fields, "challenge_hash")?;
    let created_at = field_uint(fields, "created_at")?;
    Ok(PriorHomeResponse {
        subject_key,
        challenge_hash,
        created_at,
    })
}

fn parse_thread_create(fields: &BTreeMap<String, Value>) -> Result<ThreadCreate, ParseError> {
    let thread_id = field_bytes_fixed::<16>(fields, "thread_id")?;
    let author = field_bytes_fixed::<32>(fields, "author")?;
    let room_slug = field_text(fields, "room_slug")?;
    let title = field_text(fields, "title")?;
    if title.len() > MAX_THREAD_TITLE_LEN {
        return Err(ParseError::TextTooLong {
            field: "title",
            max: MAX_THREAD_TITLE_LEN,
            got: title.len(),
        });
    }
    let op_post_id = field_bytes_fixed::<16>(fields, "op_post_id")?;
    let created_at = field_uint(fields, "created_at")?;
    let link_url = if fields.contains_key("link_url") {
        Some(field_text(fields, "link_url")?)
    } else {
        None
    };
    Ok(ThreadCreate {
        thread_id,
        author,
        room_slug,
        title,
        link_url,
        op_post_id,
        created_at,
    })
}

fn parse_user_status(fields: &BTreeMap<String, Value>) -> Result<UserStatus, ParseError> {
    let subject = field_bytes_fixed::<32>(fields, "subject")?;
    let status_str = field_text(fields, "status")?;
    let status = UserStatusKind::parse(&status_str).ok_or(ParseError::InvalidStatus(status_str))?;
    let signing_instance = field_text(fields, "signing_instance")?;
    let created_at = field_uint(fields, "created_at")?;
    let suspended_until = if fields.contains_key("suspended_until") {
        Some(field_uint(fields, "suspended_until")?)
    } else {
        None
    };
    // Wire invariant per spec §5.10: `suspended_until` only valid
    // when status == suspended. (Suspended + None still permitted
    // for indefinite suspensions.)
    if suspended_until.is_some() && status != UserStatusKind::Suspended {
        return Err(ParseError::IllegalSuspendedUntil);
    }
    let reason = if fields.contains_key("reason") {
        Some(field_text(fields, "reason")?)
    } else {
        None
    };
    let prior_status_hash = if fields.contains_key("prior_status_hash") {
        Some(field_bytes_fixed::<32>(fields, "prior_status_hash")?)
    } else {
        None
    };
    Ok(UserStatus {
        subject,
        status,
        suspended_until,
        signing_instance,
        reason,
        created_at,
        prior_status_hash,
    })
}

fn parse_deactivation(fields: &BTreeMap<String, Value>) -> Result<Deactivation, ParseError> {
    let user = field_bytes_fixed::<32>(fields, "user")?;
    let created_at = field_uint(fields, "created_at")?;
    Ok(Deactivation { user, created_at })
}

fn parse_thread_status(fields: &BTreeMap<String, Value>) -> Result<ThreadStatus, ParseError> {
    let thread_id = field_bytes_fixed::<16>(fields, "thread_id")?;
    let status_str = field_text(fields, "status")?;
    let status =
        ThreadStatusKind::parse(&status_str).ok_or(ParseError::InvalidStatus(status_str))?;
    let signing_instance = field_text(fields, "signing_instance")?;
    let created_at = field_uint(fields, "created_at")?;
    let reason = if fields.contains_key("reason") {
        Some(field_text(fields, "reason")?)
    } else {
        None
    };
    let prior_status_hash = if fields.contains_key("prior_status_hash") {
        Some(field_bytes_fixed::<32>(fields, "prior_status_hash")?)
    } else {
        None
    };
    Ok(ThreadStatus {
        thread_id,
        status,
        signing_instance,
        reason,
        created_at,
        prior_status_hash,
    })
}

fn parse_report(fields: &BTreeMap<String, Value>) -> Result<Report, ParseError> {
    let post_id = field_bytes_fixed::<16>(fields, "post_id")?;
    let target_author = field_bytes_fixed::<32>(fields, "target_author")?;
    let reporter = field_bytes_fixed::<32>(fields, "reporter")?;
    let reason_str = field_text(fields, "reason")?;
    let reason =
        ReportReason::parse(&reason_str).ok_or(ParseError::InvalidReportReason(reason_str))?;
    let created_at = field_uint(fields, "created_at")?;
    let detail = if fields.contains_key("detail") {
        let d = field_text(fields, "detail")?;
        if d.len() > MAX_REPORT_DETAIL_LEN {
            return Err(ParseError::TextTooLong {
                field: "detail",
                max: MAX_REPORT_DETAIL_LEN,
                got: d.len(),
            });
        }
        Some(d)
    } else {
        None
    };
    Ok(Report {
        post_id,
        target_author,
        reporter,
        reason,
        detail,
        created_at,
    })
}

// --- Verifier ---

/// Full §6 verification: parse, canonical-form check, dispatch,
/// author-key consistency, Ed25519 verify.
///
/// On success, returns the typed payload. On any failure, returns the
/// specific [`VerifyError`] that describes which check failed — useful
/// for diagnostic logging and for negative-corpus tests.
pub fn verify(
    payload_bytes: &[u8],
    signature_bytes: &[u8],
    claimed_key: &VerifyingKey,
) -> Result<SignedPayload, VerifyError> {
    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| VerifyError::BadSignatureLength)?;
    let signature = Signature::from_bytes(&sig_array);

    let payload = SignedPayload::parse(payload_bytes)?;

    // Per-class identity binding. For classes that carry the signing
    // key as a payload field, we cross-check it against `claimed_key`
    // so a caller can't be tricked into verifying with the wrong key.
    // For instance-signed classes whose authority is named by *domain*
    // rather than by key inside the payload (`admin-rm`,
    // `user-status`, `thread-status`), the caller is
    // responsible for resolving signing_instance → key via the peers
    // table and supplying it as `claimed_key`; no inner-field check
    // is meaningful here and the dispatch returns `None`.
    if let Some(identity_key) = identity_binding(&payload)
        && identity_key != claimed_key.as_bytes()
    {
        return Err(VerifyError::AuthorMismatch);
    }

    claimed_key
        .verify(payload_bytes, &signature)
        .map_err(|_| VerifyError::SignatureFailed)?;

    Ok(payload)
}

/// Identity-binding dispatch: for each class, return the 32-byte
/// identity field that MUST equal the verifier's `claimed_key`, or
/// `None` if the class doesn't bind its signing identity in the
/// payload (in which case the caller's `claimed_key` is the sole
/// authority — instance-signed classes whose authority is named by
/// domain).
fn identity_binding(payload: &SignedPayload) -> Option<&[u8; 32]> {
    match payload {
        // User-signed: identity field is the inner author / user key.
        SignedPayload::PostRevision(p) => Some(&p.author),
        SignedPayload::Retraction(r) => Some(&r.author),
        SignedPayload::TrustEdge(e) => Some(&e.from_key),
        SignedPayload::ProfileRevision(p) => Some(&p.user),
        SignedPayload::Move(m) => Some(&m.key),
        SignedPayload::Deactivation(d) => Some(&d.user),
        SignedPayload::ThreadCreate(t) => Some(&t.author),
        SignedPayload::Report(r) => Some(&r.reporter),
        SignedPayload::RegistrationChallenge(c) => Some(&c.user_key),
        SignedPayload::PriorHomeResponse(r) => Some(&r.subject_key),
        // Instance-signed with the signing key as a payload field
        // (rather than only a domain name): bind to the key.
        SignedPayload::FedEnvelope(e) => Some(&e.sender),
        SignedPayload::PriorHomeChallenge(c) => Some(&c.responder_instance_key),
        // Instance-signed by domain: no inner-field binding. The
        // caller resolves `signing_instance` / `issuer` → key via the
        // peers table and passes the resolved key as `claimed_key`.
        SignedPayload::AdminRemoval(_) => None,
        SignedPayload::UserStatus(_) => None,
        SignedPayload::ThreadStatus(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    /// Every map key the encoder emits, across all V1 object classes.
    /// `cbor_text_key_cmp` is only correct for keys whose CBOR encoding
    /// uses the immediate text-string prefix (i.e. length < 24 bytes).
    /// This list is the load-bearing invariant for that comparator —
    /// adding a new field to any V1 class means adding its key here
    /// (and confirming it's still under 24 bytes).
    const ALL_V1_KEYS: &[&str] = &[
        // Envelope (every class).
        "v",
        "t",
        // post-rev fields.
        "post_id",
        "author",
        "thread_id",
        "parent_id",
        "revision",
        "body",
        "created_at",
        // retract fields — overlap with post-rev for post_id/author/created_at.
        // trust-edge fields.
        "from_key",
        "to_key",
        "stance",
        "prior_edge_hash",
        // profile fields — `created_at` overlaps post-rev / retract /
        // trust-edge.
        "user",
        "display_name",
        "bio",
        "avatar_attachment_hash",
        "prior_profile_hash",
        // post-rev attachment fields (§10.1, §2.1). Outer key on
        // post-rev plus the four inner-map keys per AttachmentRef.
        "attachments",
        "content_hash",
        "filename",
        "mime",
        "size",
        // move fields — `created_at` overlaps everywhere; `key` is also
        // distinct from `from_key`/`to_key`/`user_key`/`subject_key`.
        "key",
        "from_instance_key",
        "from_instance",
        "to_instance_key",
        "to_instance",
        "genesis_at",
        "prior_move_hash",
        // genesis_attestation: the outer key plus its inner sub-map keys
        // (`key`/`genesis_at` overlap the outer move; `sig` is distinct).
        "genesis_attestation",
        "birth_instance_key",
        "sig",
        // admin-rm fields — `post_id`/`created_at` overlap.
        "target_author",
        "signing_instance",
        "reason",
        // fed-envelope fields.
        "sender",
        "receiver",
        "method",
        "path",
        "body_hash",
        "nonce",
        // user-status `subject` (`status`/`signing_instance`/`created_at`
        // overlap); `expires_at` also appears on prior-home-challenge.
        "subject",
        "expires_at",
        // registration-challenge fields (`nonce`/`created_at` overlap).
        "user_key",
        "dest_instance_key",
        "dest_domain",
        // prior-home-challenge fields (`nonce`/`subject_key`/`expires_at`
        // overlap).
        "responder_instance_key",
        "subject_key",
        "operation",
        // prior-home-response fields (`subject_key`/`created_at` overlap).
        "challenge_hash",
        // thread-create fields (`thread_id`/`author`/`created_at` overlap).
        "room_slug",
        "title",
        "link_url",
        "op_post_id",
        // user-status fields (`subject`/`signing_instance`/`reason`/
        // `created_at` overlap).
        "status",
        "suspended_until",
        "prior_status_hash",
        // deactivate fields (all overlap).
        // thread-status fields (all overlap).
        // report fields (most overlap; new field below).
        "reporter",
        "detail",
    ];

    #[test]
    fn all_v1_keys_fit_immediate_text_string_encoding() {
        // `cbor_text_key_cmp`'s correctness contract: every key must be
        // under 24 bytes so its CBOR encoding is `(0x60 | len) || bytes`
        // and bytewise comparison of encodings equals (len, bytes) lex.
        // Debug-asserts inside the comparator skip release builds, so a
        // test here is the real backstop.
        for k in ALL_V1_KEYS {
            assert!(
                k.len() < 24,
                "key {k:?} is {} bytes, must be under 24 for the comparator's short-form assumption",
                k.len()
            );
        }
    }

    fn sample_post_revision() -> PostRevision {
        PostRevision {
            post_id: [0x01; 16],
            author: [0x02; 32],
            thread_id: [0x03; 16],
            parent_id: None,
            revision: 0,
            body: "Hello, world!".to_string(),
            created_at: 1_700_000_000_000,
            attachments: Vec::new(),
        }
    }

    fn sample_attachment_ref() -> AttachmentRef {
        AttachmentRef {
            content_hash: [0xAA; 32],
            mime: "image/png".to_string(),
            size: 12345,
            filename: "photo.png".to_string(),
        }
    }

    fn sample_post_revision_with_attachments() -> PostRevision {
        PostRevision {
            post_id: [0x01; 16],
            author: [0x02; 32],
            thread_id: [0x03; 16],
            parent_id: None,
            revision: 0,
            body: "Look at this!".to_string(),
            created_at: 1_700_000_000_000,
            attachments: vec![sample_attachment_ref()],
        }
    }

    fn sample_retraction() -> Retraction {
        Retraction {
            post_id: [0x11; 16],
            author: [0x22; 32],
            created_at: 1_700_000_001_000,
        }
    }

    fn sample_trust_edge(stance: TrustStance, with_prior: bool) -> TrustEdge {
        TrustEdge {
            from_key: [0x55; 32],
            to_key: [0x66; 32],
            stance,
            created_at: 1_700_000_002_000,
            prior_edge_hash: if with_prior { Some([0x77; 32]) } else { None },
        }
    }

    fn sample_profile_revision(with_avatar: bool, with_prior: bool) -> ProfileRevision {
        ProfileRevision {
            user: [0x88; 32],
            display_name: "Alice".to_string(),
            bio: "hello, world".to_string(),
            avatar_attachment_hash: if with_avatar { Some([0x99; 32]) } else { None },
            created_at: 1_700_000_003_000,
            prior_profile_hash: if with_prior { Some([0xaa; 32]) } else { None },
        }
    }

    // --- AttachmentRef / attachments[] round-trip and canonicalization ---

    #[test]
    fn post_revision_round_trip_with_attachment() {
        let p = sample_post_revision_with_attachments();
        let bytes = SignedPayload::PostRevision(p.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::PostRevision(p));
    }

    #[test]
    fn post_revision_attachments_absent_vs_present_bytes_differ() {
        // The empty-vec case omits the `attachments` key entirely so
        // legacy posts (signed before the feature) remain bit-identical.
        // This test pins that invariant.
        let p_no = sample_post_revision();
        let p_yes = sample_post_revision_with_attachments();
        let b_no = SignedPayload::PostRevision(p_no).encode();
        let b_yes = SignedPayload::PostRevision(p_yes).encode();
        assert_ne!(b_no, b_yes);
    }

    #[test]
    fn post_revision_round_trip_three_attachments() {
        // Exercise the §10.1 MAX_ATTACHMENTS_PER_OP boundary plus the
        // mixed-MIME shape. Three entries means the inner-array length
        // still fits the immediate CBOR length prefix (`0x83`).
        let refs = vec![
            AttachmentRef {
                content_hash: [0xAA; 32],
                mime: "image/png".to_string(),
                size: 1024,
                filename: "a.png".to_string(),
            },
            AttachmentRef {
                content_hash: [0xBB; 32],
                mime: "application/pdf".to_string(),
                size: 4096,
                filename: "b.pdf".to_string(),
            },
            AttachmentRef {
                content_hash: [0xCC; 32],
                mime: "text/plain".to_string(),
                size: 16,
                filename: "c.txt".to_string(),
            },
        ];
        let mut p = sample_post_revision();
        p.attachments = refs;
        let bytes = SignedPayload::PostRevision(p.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::PostRevision(p));
    }

    #[test]
    fn post_revision_rejects_oversized_attachments_array_on_parse() {
        // Hand-forge a CBOR payload whose `attachments` array length
        // exceeds MAX_ATTACHMENTS_PER_OP by one and confirm the
        // parser rejects it. We build via the encoder for everything
        // *except* the attachments array length, then patch — the
        // encoder declines to construct a vec of 4 because the type
        // is unbounded but the spec is 1..=3, so we route around it
        // by replacing the attachments value at the Value layer.
        use ciborium::Value;
        let mut p = sample_post_revision();
        // Push 4 entries through the same path the encoder would —
        // we don't validate cardinality on encode (canonicalization
        // checks the bytes a producer signs are well-formed; the
        // length-bound is parser-side).
        for i in 0..(MAX_ATTACHMENTS_PER_OP + 1) {
            p.attachments.push(AttachmentRef {
                content_hash: [i as u8; 32],
                mime: "image/png".to_string(),
                size: 1,
                filename: format!("x{i}.png"),
            });
        }
        let bytes = SignedPayload::PostRevision(p).encode();
        // Sanity-check the array length the encoder produced.
        let val: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        match &val {
            Value::Map(entries) => {
                let attachments_entry = entries
                    .iter()
                    .find(|(k, _)| matches!(k, Value::Text(s) if s == "attachments"));
                let arr = match attachments_entry {
                    Some((_, Value::Array(a))) => a,
                    _ => panic!("expected attachments array"),
                };
                assert_eq!(arr.len(), MAX_ATTACHMENTS_PER_OP + 1);
            }
            _ => panic!("expected map"),
        }
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(
            result,
            Err(ParseError::AttachmentsTooMany { max, got })
            if max == MAX_ATTACHMENTS_PER_OP && got == MAX_ATTACHMENTS_PER_OP + 1
        ));
    }

    #[test]
    fn post_revision_rejects_non_canonical_filename_on_parse() {
        // A signed body whose filename does not survive a fresh
        // FILENAME_RULES pass byte-identically MUST be rejected
        // (§2.2 step 6). The encoder is byte-faithful, so we have
        // to construct a payload whose `filename` field contains a
        // forbidden code point and confirm the parser catches it.
        let mut p = sample_post_revision();
        p.attachments.push(AttachmentRef {
            content_hash: [0xAB; 32],
            mime: "image/png".to_string(),
            size: 1,
            // Embedded slash should never survive sanitization.
            filename: "evil/../path.png".to_string(),
        });
        let bytes = SignedPayload::PostRevision(p).encode();
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(result, Err(ParseError::NonCanonicalFilename)));
    }

    #[test]
    fn post_revision_rejects_disallowed_mime_on_parse() {
        let mut p = sample_post_revision();
        p.attachments.push(AttachmentRef {
            content_hash: [0xAB; 32],
            // text/html is excluded by ALLOWED_MIMES — a permissive
            // peer cannot accept it.
            mime: "text/html".to_string(),
            size: 1,
            filename: "evil.html".to_string(),
        });
        let bytes = SignedPayload::PostRevision(p).encode();
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(
            result,
            Err(ParseError::DisallowedMime(s)) if s == "text/html"
        ));
    }

    #[test]
    fn post_revision_rejects_oversized_attachment_size_on_parse() {
        let mut p = sample_post_revision();
        p.attachments.push(AttachmentRef {
            content_hash: [0xAB; 32],
            mime: "image/png".to_string(),
            size: MAX_ATTACHMENT_SIZE as u64 + 1,
            filename: "huge.png".to_string(),
        });
        let bytes = SignedPayload::PostRevision(p).encode();
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(
            result,
            Err(ParseError::AttachmentTooLarge { max, got })
            if max == MAX_ATTACHMENT_SIZE as u64 && got == MAX_ATTACHMENT_SIZE as u64 + 1
        ));
    }

    #[test]
    fn sanitize_attachment_filename_basic() {
        // Plain ASCII filename round-trips.
        assert_eq!(
            sanitize_attachment_filename("photo.png").as_deref(),
            Some("photo.png")
        );
        // Path separators stripped.
        assert_eq!(
            sanitize_attachment_filename("../etc/passwd").as_deref(),
            Some("etcpasswd")
        );
        // NUL stripped.
        assert_eq!(
            sanitize_attachment_filename("safe\0name.txt").as_deref(),
            Some("safename.txt")
        );
        // ASCII control characters stripped.
        assert_eq!(
            sanitize_attachment_filename("a\x01b\x1Fc\x7Fd.txt").as_deref(),
            Some("abcd.txt")
        );
        // Leading dots stripped.
        assert_eq!(
            sanitize_attachment_filename("...hidden.txt").as_deref(),
            Some("hidden.txt")
        );
        // All-dots reduces to empty → None.
        assert_eq!(sanitize_attachment_filename(".....").as_deref(), None);
        // Empty input → None.
        assert_eq!(sanitize_attachment_filename("").as_deref(), None);
    }

    #[test]
    fn sanitize_attachment_filename_strips_bidi_controls() {
        // The classic RLO (U+202E) spoof: "evil\u{202E}gpj.exe" would
        // render as "evilexe.gpj" in a Content-Disposition filename.
        // After sanitization the RLO is gone and the bytes match what
        // the reader sees.
        assert_eq!(
            sanitize_attachment_filename("evil\u{202E}gpj.exe").as_deref(),
            Some("evilgpj.exe")
        );
        // All other bidi formatting characters strip too.
        let with_all_bidi = "a\u{200E}b\u{200F}c\u{202A}d\u{202B}e\u{202C}f\u{202D}g\
                             h\u{2066}i\u{2067}j\u{2068}k\u{2069}l.txt";
        assert_eq!(
            sanitize_attachment_filename(with_all_bidi).as_deref(),
            Some("abcdefghijkl.txt")
        );
    }

    #[test]
    fn sanitize_attachment_filename_strips_zero_width() {
        // ZWSP/ZWNJ/ZWJ, word-joiner, BOM/ZWNBSP — all invisible,
        // all stripped, so two filenames that look identical can't
        // diverge on the wire.
        assert_eq!(
            sanitize_attachment_filename("photo\u{200B}.png").as_deref(),
            Some("photo.png")
        );
        let with_all_zw = "a\u{200B}b\u{200C}c\u{200D}d\u{2060}e\u{FEFF}f.txt";
        assert_eq!(
            sanitize_attachment_filename(with_all_zw).as_deref(),
            Some("abcdef.txt")
        );
    }

    #[test]
    fn sanitize_attachment_filename_strips_windows_reserved() {
        // < > : " | ? * are illegal in Windows filenames and would
        // break save-as on the serve path.
        assert_eq!(
            sanitize_attachment_filename(r#"a<b>c:d"e|f?g*h.txt"#).as_deref(),
            Some("abcdefgh.txt")
        );
    }

    #[test]
    fn sanitize_attachment_filename_truncates_safely() {
        // A 256-byte all-ASCII name must truncate to 255.
        let long = "a".repeat(MAX_ATTACHMENT_FILENAME_LEN + 1);
        let out = sanitize_attachment_filename(&long).unwrap();
        assert_eq!(out.len(), MAX_ATTACHMENT_FILENAME_LEN);
        // Multi-byte code points at the truncation boundary must not
        // split. Build a string whose byte 255 lands in the middle
        // of a 3-byte code point (CJK char `世` = 3 bytes), and check
        // the result ends on a code-point boundary < 255 bytes.
        let mut s = "a".repeat(MAX_ATTACHMENT_FILENAME_LEN - 1);
        s.push('世'); // pushes byte 254..=256
        let out = sanitize_attachment_filename(&s).unwrap();
        // The boundary walk-back means we keep the leading 'a' run
        // but drop the partial `世`.
        assert!(out.len() < MAX_ATTACHMENT_FILENAME_LEN);
        assert!(out.is_char_boundary(out.len()));
    }

    #[test]
    fn profile_revision_round_trip_minimal() {
        let p = sample_profile_revision(false, false);
        let bytes = SignedPayload::ProfileRevision(p.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::ProfileRevision(p));
    }

    #[test]
    fn profile_revision_round_trip_full() {
        let p = sample_profile_revision(true, true);
        let bytes = SignedPayload::ProfileRevision(p.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::ProfileRevision(p));
    }

    #[test]
    fn profile_revision_empty_strings_round_trip() {
        // Spec §5.8 explicitly permits empty display_name and bio.
        // Receivers render a pubkey-hex placeholder for empty
        // display_name and treat empty bio as absent. Both must
        // round-trip identically — empty string and missing key are
        // distinct (only display_name and bio are required; the
        // optional avatar / prior fields are omitted when absent).
        let p = ProfileRevision {
            user: [0; 32],
            display_name: String::new(),
            bio: String::new(),
            avatar_attachment_hash: None,
            created_at: 0,
            prior_profile_hash: None,
        };
        let bytes = SignedPayload::ProfileRevision(p.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::ProfileRevision(p));
    }

    #[test]
    fn profile_revision_rejects_oversized_bio_on_parse() {
        // Forge a profile-revision payload whose `bio` is one byte over
        // the MAX_PROFILE_BIO_LEN ceiling and confirm the parser
        // rejects it. This is the inbound-federation defense: local
        // writers gate at 500 bytes (users.rs), but a peer could
        // publish a 1MB bio — the verifier must reject it before any
        // hash-chain bookkeeping runs.
        let mut p = sample_profile_revision(false, false);
        p.bio = "a".repeat(MAX_PROFILE_BIO_LEN + 1);
        let bytes = SignedPayload::ProfileRevision(p).encode();
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(
            result,
            Err(ParseError::TextTooLong {
                field: "bio",
                max: MAX_PROFILE_BIO_LEN,
                got,
            }) if got == MAX_PROFILE_BIO_LEN + 1
        ));
    }

    #[test]
    fn profile_revision_avatar_present_vs_absent_differ() {
        let p_no = sample_profile_revision(false, false);
        let p_yes = sample_profile_revision(true, false);
        let b_no = SignedPayload::ProfileRevision(p_no).encode();
        let b_yes = SignedPayload::ProfileRevision(p_yes).encode();
        assert_ne!(b_no, b_yes);
    }

    #[test]
    fn sign_and_verify_profile_revision() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let mut p = sample_profile_revision(false, false);
        p.user = *verifying_key.as_bytes();
        let bytes = SignedPayload::ProfileRevision(p).encode();
        let sig = signing_key.sign(&bytes);
        let result = verify(&bytes, &sig.to_bytes(), &verifying_key).expect("verify");
        assert!(matches!(result, SignedPayload::ProfileRevision(_)));
    }

    #[test]
    fn verify_rejects_profile_revision_user_mismatch() {
        // Payload says user = key_a; we present key_b as the claimed key.
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);
        let mut p = sample_profile_revision(false, false);
        p.user = *key_a.verifying_key().as_bytes();
        let bytes = SignedPayload::ProfileRevision(p).encode();
        let sig = key_a.sign(&bytes);
        let result = verify(&bytes, &sig.to_bytes(), &key_b.verifying_key());
        assert!(matches!(result, Err(VerifyError::AuthorMismatch)));
    }

    #[test]
    fn profile_revision_canonical_bytes_match_hand_computed() {
        // Minimal all-zero profile revision: empty display_name, empty
        // bio, no avatar, created_at = 0, no prior.
        let p = ProfileRevision {
            user: [0; 32],
            display_name: String::new(),
            bio: String::new(),
            avatar_attachment_hash: None,
            created_at: 0,
            prior_profile_hash: None,
        };
        let bytes = SignedPayload::ProfileRevision(p).encode();
        let mut expected: Vec<u8> = Vec::new();
        // Map header: 6 entries -> 0xa6
        expected.push(0xa6);
        // "t" -> "profile"
        expected.extend_from_slice(&[0x61, b't']);
        expected.extend_from_slice(&[0x67, b'p', b'r', b'o', b'f', b'i', b'l', b'e']);
        // "v" -> 1
        expected.extend_from_slice(&[0x61, b'v']);
        expected.push(0x01);
        // "bio" -> "" (text-0)
        expected.extend_from_slice(&[0x63, b'b', b'i', b'o']);
        expected.push(0x60);
        // "user" -> 32 zero bytes
        expected.extend_from_slice(&[0x64, b'u', b's', b'e', b'r']);
        expected.extend_from_slice(&[0x58, 0x20]);
        expected.extend_from_slice(&[0u8; 32]);
        // "created_at" -> 0
        expected.extend_from_slice(&[
            0x6a, b'c', b'r', b'e', b'a', b't', b'e', b'd', b'_', b'a', b't',
        ]);
        expected.push(0x00);
        // "display_name" -> "" (text-0)
        expected.extend_from_slice(&[
            0x6c, b'd', b'i', b's', b'p', b'l', b'a', b'y', b'_', b'n', b'a', b'm', b'e',
        ]);
        expected.push(0x60);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn post_revision_round_trip() {
        let p = sample_post_revision();
        let bytes = SignedPayload::PostRevision(p.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).expect("parse");
        assert_eq!(decoded, SignedPayload::PostRevision(p));
    }

    #[test]
    fn encode_is_deterministic() {
        let p = sample_post_revision();
        let b1 = SignedPayload::PostRevision(p.clone()).encode();
        let b2 = SignedPayload::PostRevision(p).encode();
        assert_eq!(b1, b2);
    }

    #[test]
    fn retraction_round_trip() {
        let r = sample_retraction();
        let bytes = SignedPayload::Retraction(r.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::Retraction(r));
    }

    #[test]
    fn retraction_canonical_bytes_match_hand_computed() {
        // All-zeros retraction. Hand-computed canonical CBOR per
        // signed-payload-format.md §4.2. Key order (by (len, bytes)
        // of the text keys):
        //   t (1, "t"), v (1, "v"), author (6), post_id (7), created_at (10)
        let r = Retraction {
            post_id: [0; 16],
            author: [0; 32],
            created_at: 0,
        };
        let bytes = SignedPayload::Retraction(r).encode();
        let mut expected: Vec<u8> = Vec::new();
        // Map header: 5 entries -> 0xa5
        expected.push(0xa5);
        // "t" -> "retract"
        expected.extend_from_slice(&[0x61, b't']);
        expected.extend_from_slice(&[0x67, b'r', b'e', b't', b'r', b'a', b'c', b't']);
        // "v" -> 1
        expected.extend_from_slice(&[0x61, b'v']);
        expected.push(0x01);
        // "author" -> 32 zero bytes
        expected.extend_from_slice(&[0x66, b'a', b'u', b't', b'h', b'o', b'r']);
        expected.extend_from_slice(&[0x58, 0x20]);
        expected.extend_from_slice(&[0u8; 32]);
        // "post_id" -> 16 zero bytes
        expected.extend_from_slice(&[0x67, b'p', b'o', b's', b't', b'_', b'i', b'd']);
        expected.push(0x50); // bstr length 16, immediate
        expected.extend_from_slice(&[0u8; 16]);
        // "created_at" -> 0
        expected.extend_from_slice(&[
            0x6a, b'c', b'r', b'e', b'a', b't', b'e', b'd', b'_', b'a', b't',
        ]);
        expected.push(0x00);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn trust_edge_all_stances_round_trip() {
        for stance in [
            TrustStance::Trust,
            TrustStance::Distrust,
            TrustStance::Neutral,
        ] {
            let e = sample_trust_edge(stance, false);
            let bytes = SignedPayload::TrustEdge(e.clone()).encode();
            let decoded = SignedPayload::parse(&bytes).unwrap();
            assert_eq!(decoded, SignedPayload::TrustEdge(e));
        }
    }

    #[test]
    fn trust_edge_with_prior_hash_round_trips() {
        let e = sample_trust_edge(TrustStance::Trust, true);
        let bytes = SignedPayload::TrustEdge(e.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::TrustEdge(e));
    }

    #[test]
    fn parent_id_present_vs_absent_differ() {
        let p_no = sample_post_revision();
        let mut p_yes = p_no.clone();
        p_yes.parent_id = Some([0x09; 16]);
        let b_no = SignedPayload::PostRevision(p_no).encode();
        let b_yes = SignedPayload::PostRevision(p_yes).encode();
        assert_ne!(b_no, b_yes);
    }

    #[test]
    fn sign_and_verify_post_revision() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let mut p = sample_post_revision();
        p.author = *verifying_key.as_bytes();
        let bytes = SignedPayload::PostRevision(p).encode();
        let sig = signing_key.sign(&bytes);
        let result = verify(&bytes, &sig.to_bytes(), &verifying_key).expect("verify");
        assert!(matches!(result, SignedPayload::PostRevision(_)));
    }

    #[test]
    fn sign_and_verify_trust_edge_distrust() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let mut e = sample_trust_edge(TrustStance::Distrust, false);
        e.from_key = *verifying_key.as_bytes();
        let bytes = SignedPayload::TrustEdge(e).encode();
        let sig = signing_key.sign(&bytes);
        let result = verify(&bytes, &sig.to_bytes(), &verifying_key).expect("verify");
        match result {
            SignedPayload::TrustEdge(e) => assert_eq!(e.stance, TrustStance::Distrust),
            _ => panic!("wrong class"),
        }
    }

    #[test]
    fn verify_rejects_author_mismatch() {
        // Payload says author = key_a; we present key_b as the claimed key.
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);
        let mut p = sample_post_revision();
        p.author = *key_a.verifying_key().as_bytes();
        let bytes = SignedPayload::PostRevision(p).encode();
        let sig = key_a.sign(&bytes);
        let result = verify(&bytes, &sig.to_bytes(), &key_b.verifying_key());
        assert!(matches!(result, Err(VerifyError::AuthorMismatch)));
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut p = sample_post_revision();
        p.author = *signing_key.verifying_key().as_bytes();
        let mut bytes = SignedPayload::PostRevision(p).encode();
        let sig = signing_key.sign(&bytes);
        // Flip the 'H' in "Hello, world!" — survives parse (still
        // canonical CBOR with a single-character difference) but the
        // Ed25519 signature no longer matches.
        let offset = bytes.iter().position(|&b| b == b'H').expect("H in body");
        bytes[offset] = b'X';
        let result = verify(&bytes, &sig.to_bytes(), &signing_key.verifying_key());
        assert!(matches!(result, Err(VerifyError::SignatureFailed)));
    }

    #[test]
    fn verify_rejects_short_signature() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut p = sample_post_revision();
        p.author = *signing_key.verifying_key().as_bytes();
        let bytes = SignedPayload::PostRevision(p).encode();
        let result = verify(&bytes, &[0u8; 63], &signing_key.verifying_key());
        assert!(matches!(result, Err(VerifyError::BadSignatureLength)));
    }

    #[test]
    fn parse_rejects_misordered_keys() {
        // Construct a 2-entry map with keys in the wrong order: "v" then "t".
        // Canonical order is "t" then "v" (both 1 char, "t" < "v" bytewise).
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(0xa2); // map(2)
        bytes.extend_from_slice(&[0x61, b'v']); // "v"
        bytes.push(0x01); // 1
        bytes.extend_from_slice(&[0x61, b't']); // "t"
        bytes.extend_from_slice(&[0x67, b'r', b'e', b't', b'r', b'a', b'c', b't']); // "retract"
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(result, Err(ParseError::KeysOutOfOrder)));
    }

    #[test]
    fn parse_rejects_duplicate_keys() {
        // Map with two entries both keyed "v". Canonicalization keeps
        // sort order monotonic and bans equality, so the duplicate
        // trips KeysOutOfOrder before DuplicateKey. Either rejection
        // is acceptable — the input is invalid.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(0xa2); // map(2)
        bytes.extend_from_slice(&[0x61, b'v']); // "v"
        bytes.push(0x01);
        bytes.extend_from_slice(&[0x61, b'v']); // "v" again
        bytes.push(0x02);
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(
            result,
            Err(ParseError::KeysOutOfOrder) | Err(ParseError::DuplicateKey(_))
        ));
    }

    #[test]
    fn parse_rejects_non_shortest_integer() {
        // Encode the integer 1 in the 1-byte form (0x18 0x01) instead
        // of the immediate form (0x01). Should round-trip through
        // ciborium as Value::Integer(1), but re-encode produces 0x01,
        // so the canonical-form check fails.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(0xa2); // map(2)
        bytes.extend_from_slice(&[0x61, b't']);
        bytes.extend_from_slice(&[0x67, b'r', b'e', b't', b'r', b'a', b'c', b't']);
        bytes.extend_from_slice(&[0x61, b'v']);
        bytes.extend_from_slice(&[0x18, 0x01]); // non-shortest 1
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(result, Err(ParseError::NonCanonical)));
    }

    #[test]
    fn parse_rejects_unknown_class() {
        // Build a payload with t = "bogus", v = 1 (no required fields).
        // Should reject on dispatch before reaching field validation.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(0xa2);
        bytes.extend_from_slice(&[0x61, b't']);
        bytes.extend_from_slice(&[0x65, b'b', b'o', b'g', b'u', b's']);
        bytes.extend_from_slice(&[0x61, b'v']);
        bytes.push(0x01);
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(result, Err(ParseError::UnknownClass(s)) if s == "bogus"));
    }

    #[test]
    fn parse_rejects_unsupported_version() {
        // Encode a valid retraction structure but with v = 2.
        let r = sample_retraction();
        let bytes_v1 = SignedPayload::Retraction(r).encode();
        // Find the byte that encodes the "v" value: the byte
        // immediately after the "v" key encoding [0x61, b'v'].
        let mut bytes = bytes_v1.clone();
        let v_key_pos = bytes
            .windows(2)
            .position(|w| w == [0x61, b'v'])
            .expect("v key in retraction");
        bytes[v_key_pos + 2] = 0x02; // change uint 1 -> uint 2
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(
            result,
            Err(ParseError::UnsupportedVersion {
                class: TAG_RETRACTION,
                got: 2,
            })
        ));
    }

    #[test]
    fn parse_rejects_wrong_byte_length() {
        // Construct a retraction with a 15-byte post_id instead of 16.
        // We do this by building canonical bytes for a retraction with
        // a hand-crafted short post_id field.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(0xa5); // map(5)
        // t -> "retract"
        bytes.extend_from_slice(&[0x61, b't']);
        bytes.extend_from_slice(&[0x67, b'r', b'e', b't', b'r', b'a', b'c', b't']);
        // v -> 1
        bytes.extend_from_slice(&[0x61, b'v']);
        bytes.push(0x01);
        // author -> 32 zeros
        bytes.extend_from_slice(&[0x66, b'a', b'u', b't', b'h', b'o', b'r']);
        bytes.extend_from_slice(&[0x58, 0x20]);
        bytes.extend_from_slice(&[0u8; 32]);
        // post_id -> 15 zeros (wrong length, should be 16). bstr len 15 is immediate: 0x4f.
        bytes.extend_from_slice(&[0x67, b'p', b'o', b's', b't', b'_', b'i', b'd']);
        bytes.push(0x4f);
        bytes.extend_from_slice(&[0u8; 15]);
        // created_at -> 0
        bytes.extend_from_slice(&[
            0x6a, b'c', b'r', b'e', b'a', b't', b'e', b'd', b'_', b'a', b't',
        ]);
        bytes.push(0x00);
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(
            result,
            Err(ParseError::BadByteLength {
                field: "post_id",
                expected: 16,
                got: 15,
            })
        ));
    }

    #[test]
    fn parse_rejects_invalid_stance() {
        let mut e = sample_trust_edge(TrustStance::Trust, false);
        e.from_key = [0; 32];
        e.to_key = [0; 32];
        e.created_at = 0;
        let bytes_ok = SignedPayload::TrustEdge(e).encode();
        // Replace the stance value "trust" (text-5: 0x65 + 5 bytes) with
        // "weird" (also text-5 so byte length doesn't change).
        let mut bytes = bytes_ok.clone();
        let pos = bytes
            .windows(7)
            .position(|w| w == [0x65, b't', b'r', b'u', b's', b't', 0x1b])
            .or_else(|| {
                bytes
                    .windows(6)
                    .position(|w| w == [0x65, b't', b'r', b'u', b's', b't'])
            })
            .expect("stance value");
        bytes[pos..pos + 6].copy_from_slice(&[0x65, b'w', b'e', b'i', b'r', b'd']);
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(result, Err(ParseError::InvalidStance(s)) if s == "weird"));
    }

    // --- Federation-era classes: round-trip + bounded-field tests ---
    //
    // Each new class gets at least one round-trip (and a variant
    // covering its optional fields) plus one targeted negative
    // covering whichever bounded invariant matters most for that
    // class. Broader cross-class coverage (e.g. dispatch exhaustion,
    // unknown-class rejection) is already exercised against `retract`
    // earlier in this module — those tests apply to every class
    // because dispatch lives in `SignedPayload::parse`.

    /// Build a sample attestation whose inner `key` / `genesis_at`
    /// match the enclosing declaration (the §5.1 structural binding the
    /// parser enforces). The `sig` is filler — these unit tests only
    /// exercise the wire round-trip and the *outer* user signature, not
    /// the birth-instance counter-signature (that lives in the
    /// receive-path integration tests).
    fn sample_attestation(key: [u8; 32], genesis_at: u64) -> GenesisAttestation {
        GenesisAttestation {
            key,
            genesis_at,
            birth_instance_key: [0xb4; 32],
            sig: [0xb5; 64],
        }
    }

    /// A move declaration (from_* present). `with_prior` toggles the
    /// optional `prior_move_hash`.
    fn sample_move(with_prior: bool) -> Move {
        let key = [0xb0; 32];
        let genesis_at = 1_699_999_000_000;
        Move {
            key,
            from_instance_key: Some([0xb2; 32]),
            from_instance: Some("old.example".to_string()),
            to_instance_key: [0xb3; 32],
            to_instance: "new.example".to_string(),
            created_at: 1_700_000_100_000,
            genesis_at,
            genesis_attestation: sample_attestation(key, genesis_at),
            prior_move_hash: if with_prior { Some([0xb1; 32]) } else { None },
        }
    }

    /// A genesis declaration (from_* absent, no predecessor).
    fn sample_genesis() -> Move {
        let key = [0xc0; 32];
        let genesis_at = 1_700_000_100_000;
        Move {
            key,
            from_instance_key: None,
            from_instance: None,
            to_instance_key: [0xc3; 32],
            to_instance: "birth.example".to_string(),
            created_at: genesis_at,
            genesis_at,
            genesis_attestation: sample_attestation(key, genesis_at),
            prior_move_hash: None,
        }
    }

    #[test]
    fn move_round_trip_minimal_and_with_prior() {
        for with_prior in [false, true] {
            let m = sample_move(with_prior);
            let bytes = SignedPayload::Move(m.clone()).encode();
            let decoded = SignedPayload::parse(&bytes).unwrap();
            assert_eq!(decoded, SignedPayload::Move(m));
        }
    }

    #[test]
    fn genesis_declaration_round_trips() {
        let m = sample_genesis();
        let bytes = SignedPayload::Move(m.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::Move(m));
    }

    #[test]
    fn parse_rejects_genesis_with_prior_move_hash() {
        let mut m = sample_genesis();
        m.prior_move_hash = Some([0x07; 32]);
        let bytes = SignedPayload::Move(m).encode();
        assert!(matches!(
            SignedPayload::parse(&bytes),
            Err(ParseError::MovePresenceCoupling)
        ));
    }

    #[test]
    fn parse_rejects_half_set_from_fields() {
        // Encode a move with only `from_instance` present (the encoder
        // couples them, so build the CBOR map by hand to desync).
        let key = [0xd0; 32];
        let genesis_at = 1_700_000_000_000;
        let att = genesis_attestation_to_cbor(&sample_attestation(key, genesis_at));
        let value = build_map(vec![
            ("v", uint(V1)),
            ("t", text(TAG_MOVE)),
            ("key", bytes(&key)),
            ("from_instance", text("orphan.example")),
            ("to_instance_key", bytes(&[0xd3; 32])),
            ("to_instance", text("dest.example")),
            ("created_at", uint(genesis_at)),
            ("genesis_at", uint(genesis_at)),
            ("genesis_attestation", att),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&value, &mut bytes).unwrap();
        assert!(matches!(
            SignedPayload::parse(&bytes),
            Err(ParseError::MovePresenceCoupling)
        ));
    }

    #[test]
    fn parse_rejects_attestation_outer_inner_mismatch() {
        let mut m = sample_move(false);
        // Desync the inner attestation genesis_at from the outer.
        m.genesis_attestation.genesis_at = m.genesis_at + 1;
        let bytes = SignedPayload::Move(m).encode();
        assert!(matches!(
            SignedPayload::parse(&bytes),
            Err(ParseError::GenesisAttestationMismatch)
        ));
    }

    #[test]
    fn sign_and_verify_move_binds_to_key_field() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut m = sample_move(false);
        m.key = *signing_key.verifying_key().as_bytes();
        m.genesis_attestation.key = m.key;
        let bytes = SignedPayload::Move(m).encode();
        let sig = signing_key.sign(&bytes);
        let result = verify(&bytes, &sig.to_bytes(), &signing_key.verifying_key()).expect("verify");
        assert!(matches!(result, SignedPayload::Move(_)));
    }

    #[test]
    fn verify_rejects_move_key_mismatch() {
        let signer = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let mut m = sample_move(false);
        m.key = *signer.verifying_key().as_bytes();
        m.genesis_attestation.key = m.key;
        let bytes = SignedPayload::Move(m).encode();
        let sig = signer.sign(&bytes);
        let result = verify(&bytes, &sig.to_bytes(), &other.verifying_key());
        assert!(matches!(result, Err(VerifyError::AuthorMismatch)));
    }

    fn sample_admin_removal(with_reason: bool) -> AdminRemoval {
        AdminRemoval {
            post_id: [0xa0; 16],
            target_author: [0xa1; 32],
            signing_instance: "instance-a.example".to_string(),
            created_at: 1_700_000_200_000,
            reason: if with_reason {
                Some("spam".to_string())
            } else {
                None
            },
        }
    }

    #[test]
    fn admin_removal_round_trip_minimal_and_with_reason() {
        for with_reason in [false, true] {
            let a = sample_admin_removal(with_reason);
            let bytes = SignedPayload::AdminRemoval(a.clone()).encode();
            let decoded = SignedPayload::parse(&bytes).unwrap();
            assert_eq!(decoded, SignedPayload::AdminRemoval(a));
        }
    }

    #[test]
    fn verify_admin_removal_accepts_any_claimed_key() {
        // admin-rm has no inner key field; the caller supplies the
        // instance signing key as `claimed_key`. So verify() must
        // never raise AuthorMismatch for this class — only signature
        // validity matters.
        let signing_key = SigningKey::generate(&mut OsRng);
        let a = sample_admin_removal(false);
        let bytes = SignedPayload::AdminRemoval(a).encode();
        let sig = signing_key.sign(&bytes);
        let result = verify(&bytes, &sig.to_bytes(), &signing_key.verifying_key()).expect("verify");
        assert!(matches!(result, SignedPayload::AdminRemoval(_)));
    }

    fn sample_fed_envelope(with_body: bool) -> FedEnvelope {
        FedEnvelope {
            sender: [0xc0; 32],
            receiver: [0xc1; 32],
            method: "POST".to_string(),
            path: "/federation/v1/content".to_string(),
            body_hash: if with_body { Some([0xc2; 32]) } else { None },
            created_at: 1_700_000_300_000,
            nonce: [0xc3; 16],
        }
    }

    #[test]
    fn fed_envelope_round_trip_with_and_without_body() {
        for with_body in [false, true] {
            let e = sample_fed_envelope(with_body);
            let bytes = SignedPayload::FedEnvelope(e.clone()).encode();
            let decoded = SignedPayload::parse(&bytes).unwrap();
            assert_eq!(decoded, SignedPayload::FedEnvelope(e));
        }
    }

    #[test]
    fn sign_and_verify_fed_envelope_binds_to_sender() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut e = sample_fed_envelope(false);
        e.sender = *signing_key.verifying_key().as_bytes();
        let bytes = SignedPayload::FedEnvelope(e).encode();
        let sig = signing_key.sign(&bytes);
        let result = verify(&bytes, &sig.to_bytes(), &signing_key.verifying_key()).expect("verify");
        assert!(matches!(result, SignedPayload::FedEnvelope(_)));
    }

    fn sample_registration_challenge() -> RegistrationChallenge {
        RegistrationChallenge {
            user_key: [0xe0; 32],
            dest_instance_key: [0xe1; 32],
            dest_domain: "dest.example".to_string(),
            nonce: [0xe2; 32],
            created_at: 1_700_000_600_000,
        }
    }

    #[test]
    fn registration_challenge_round_trip() {
        let c = sample_registration_challenge();
        let bytes = SignedPayload::RegistrationChallenge(c.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::RegistrationChallenge(c));
    }

    fn sample_prior_home_challenge() -> PriorHomeChallenge {
        PriorHomeChallenge {
            responder_instance_key: [0xf0; 32],
            subject_key: [0xf1; 32],
            nonce: [0xf2; 32],
            created_at: 1_700_000_700_000,
            expires_at: 1_700_000_760_000,
        }
    }

    #[test]
    fn prior_home_challenge_round_trip() {
        let c = sample_prior_home_challenge();
        let bytes = SignedPayload::PriorHomeChallenge(c.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::PriorHomeChallenge(c));
    }

    fn sample_prior_home_response() -> PriorHomeResponse {
        PriorHomeResponse {
            subject_key: [0xf1; 32],
            challenge_hash: [0xf3; 32],
            created_at: 1_700_000_710_000,
        }
    }

    #[test]
    fn prior_home_response_round_trip() {
        let r = sample_prior_home_response();
        let bytes = SignedPayload::PriorHomeResponse(r.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::PriorHomeResponse(r));
    }

    fn sample_thread_create(with_link: bool) -> ThreadCreate {
        ThreadCreate {
            thread_id: [0x10; 16],
            author: [0x11; 32],
            room_slug: "politics".to_string(),
            title: "What about this?".to_string(),
            link_url: if with_link {
                Some("https://example.com/article".to_string())
            } else {
                None
            },
            op_post_id: [0x12; 16],
            created_at: 1_700_000_800_000,
        }
    }

    #[test]
    fn thread_create_round_trip_with_and_without_link() {
        for with_link in [false, true] {
            let t = sample_thread_create(with_link);
            let bytes = SignedPayload::ThreadCreate(t.clone()).encode();
            let decoded = SignedPayload::parse(&bytes).unwrap();
            assert_eq!(decoded, SignedPayload::ThreadCreate(t));
        }
    }

    #[test]
    fn thread_create_rejects_oversized_title() {
        let mut t = sample_thread_create(false);
        t.title = "a".repeat(MAX_THREAD_TITLE_LEN + 1);
        let bytes = SignedPayload::ThreadCreate(t).encode();
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(
            result,
            Err(ParseError::TextTooLong {
                field: "title",
                max: MAX_THREAD_TITLE_LEN,
                got,
            }) if got == MAX_THREAD_TITLE_LEN + 1
        ));
    }

    fn sample_user_status(
        status: UserStatusKind,
        with_until: bool,
        with_prior: bool,
    ) -> UserStatus {
        UserStatus {
            subject: [0x20; 32],
            status,
            suspended_until: if with_until {
                Some(1_700_000_900_000)
            } else {
                None
            },
            signing_instance: "instance-a.example".to_string(),
            reason: Some("spamming threads".to_string()),
            created_at: 1_700_000_850_000,
            prior_status_hash: if with_prior { Some([0x21; 32]) } else { None },
        }
    }

    #[test]
    fn user_status_round_trip_each_kind() {
        for kind in [
            UserStatusKind::Active,
            UserStatusKind::Suspended,
            UserStatusKind::Banned,
        ] {
            // No suspended_until except when allowed; with prior to
            // exercise both optional fields.
            let with_until = kind == UserStatusKind::Suspended;
            let s = sample_user_status(kind, with_until, true);
            let bytes = SignedPayload::UserStatus(s.clone()).encode();
            let decoded = SignedPayload::parse(&bytes).unwrap();
            assert_eq!(decoded, SignedPayload::UserStatus(s));
        }
    }

    #[test]
    fn user_status_suspended_without_until_is_indefinite() {
        // Suspended + None suspended_until is the indefinite-suspension
        // case per spec §5.10. Must round-trip cleanly.
        let s = sample_user_status(UserStatusKind::Suspended, false, false);
        let bytes = SignedPayload::UserStatus(s.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::UserStatus(s));
    }

    #[test]
    fn user_status_rejects_suspended_until_on_non_suspended() {
        // Spec §5.10: suspended_until MUST be absent unless status ==
        // suspended. Sneak it in on a Banned status and confirm the
        // parser trips IllegalSuspendedUntil.
        let s = sample_user_status(UserStatusKind::Banned, true, false);
        let bytes = SignedPayload::UserStatus(s).encode();
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(result, Err(ParseError::IllegalSuspendedUntil)));
    }

    fn sample_deactivation() -> Deactivation {
        Deactivation {
            user: [0x30; 32],
            created_at: 1_700_001_000_000,
        }
    }

    #[test]
    fn deactivation_round_trip() {
        let d = sample_deactivation();
        let bytes = SignedPayload::Deactivation(d.clone()).encode();
        let decoded = SignedPayload::parse(&bytes).unwrap();
        assert_eq!(decoded, SignedPayload::Deactivation(d));
    }

    fn sample_thread_status(status: ThreadStatusKind, with_prior: bool) -> ThreadStatus {
        ThreadStatus {
            thread_id: [0x40; 16],
            status,
            signing_instance: "instance-a.example".to_string(),
            reason: if status == ThreadStatusKind::Locked {
                Some("off-topic".to_string())
            } else {
                None
            },
            created_at: 1_700_001_100_000,
            prior_status_hash: if with_prior { Some([0x41; 32]) } else { None },
        }
    }

    #[test]
    fn thread_status_round_trip_each_kind() {
        for kind in [ThreadStatusKind::Open, ThreadStatusKind::Locked] {
            let s = sample_thread_status(kind, true);
            let bytes = SignedPayload::ThreadStatus(s.clone()).encode();
            let decoded = SignedPayload::parse(&bytes).unwrap();
            assert_eq!(decoded, SignedPayload::ThreadStatus(s));
        }
    }

    fn sample_report(reason: ReportReason, with_detail: bool) -> Report {
        Report {
            post_id: [0x50; 16],
            target_author: [0x51; 32],
            reporter: [0x52; 32],
            reason,
            detail: if with_detail {
                Some("witnessed in #general".to_string())
            } else {
                None
            },
            created_at: 1_700_001_200_000,
        }
    }

    #[test]
    fn report_round_trip_each_reason() {
        for reason in [
            ReportReason::Spam,
            ReportReason::RulesViolation,
            ReportReason::IllegalContent,
            ReportReason::Other,
        ] {
            let r = sample_report(reason, true);
            let bytes = SignedPayload::Report(r.clone()).encode();
            let decoded = SignedPayload::parse(&bytes).unwrap();
            assert_eq!(decoded, SignedPayload::Report(r));
        }
    }

    #[test]
    fn report_rejects_oversized_detail() {
        let mut r = sample_report(ReportReason::Spam, false);
        r.detail = Some("a".repeat(MAX_REPORT_DETAIL_LEN + 1));
        let bytes = SignedPayload::Report(r).encode();
        let result = SignedPayload::parse(&bytes);
        assert!(matches!(
            result,
            Err(ParseError::TextTooLong {
                field: "detail",
                max: MAX_REPORT_DETAIL_LEN,
                got,
            }) if got == MAX_REPORT_DETAIL_LEN + 1
        ));
    }
}
