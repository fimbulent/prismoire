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

/// V1 format version for all currently-defined object classes.
pub const V1: u64 = 1;

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
    build_map(entries)
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
    Ok(PostRevision {
        post_id,
        author,
        thread_id,
        parent_id,
        revision,
        body,
        created_at,
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

    let identity_key: &[u8; 32] = match &payload {
        SignedPayload::PostRevision(p) => &p.author,
        SignedPayload::Retraction(r) => &r.author,
        SignedPayload::TrustEdge(e) => &e.from_key,
    };
    if identity_key != claimed_key.as_bytes() {
        return Err(VerifyError::AuthorMismatch);
    }

    claimed_key
        .verify(payload_bytes, &signature)
        .map_err(|_| VerifyError::SignatureFailed)?;

    Ok(payload)
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
}
