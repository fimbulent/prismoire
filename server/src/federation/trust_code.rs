//! Trust codes — the §11.9.5 cross-instance trust bootstrap primitive.
//!
//! A trust code is a self-contained, copy-pasteable string that carries
//! a user's federated identity so a user on another instance can form
//! the *first* cross-instance trust edge by hand, breaking the bootstrap
//! deadlock where "no edge → no content → no local row → no edge".
//!
//! Wire shape (human-readable on purpose):
//!
//! ```text
//! :trust:<display_name>@<home_domain>:<user_pubkey_hex>@<instance_pubkey_hex>
//! ```
//!
//! - `:trust:` — paste-detection prefix + a cheap version anchor (bump
//!   to `:trust2:` if the shape ever changes).
//! - `<display_name>` — UX-only; lets the recipient eyeball whose code
//!   this is. **Never** used as identity. `validate_display_name`
//!   forbids both `@` and `:`, so a minted name can't collide with the
//!   delimiters.
//! - `<home_domain>` — the home-instance dialing address (`host` or
//!   `host:port`, possibly a bracketed IPv6 literal). Mutable metadata,
//!   not identity.
//! - `<user_pubkey_hex>` — 64 lowercase hex: the user's Ed25519
//!   credential pubkey, the identity + `users.public_key` lookup key.
//! - `<instance_pubkey_hex>` — 64 lowercase hex: the home instance's
//!   Ed25519 `instance_pubkey`, written to `users.home_instance` and the
//!   §3 trust anchor.
//!
//! **Parsing is right-to-left.** The two 64-hex fields are fixed width,
//! so we peel `@<instancepk>` then `:<userpk>` off the right; whatever
//! remains is `<display_name>@<home_domain>`, split on the *first* `@`.
//! Because `home_domain` may legitimately contain `:` (a port) and `[`
//! `]` (IPv6) but never `@` (userinfo is rejected by
//! [`parse_instance_domain`]), peeling the hex tail first makes the
//! grammar unambiguous.
//!
//! **Not signed, by design.** Anyone can fabricate a code asserting
//! `(user_pubkey P, home_instance Q)`. The blast radius is a harmless
//! dangling stub plus a *unilateral* edge to a pubkey nobody can
//! impersonate: all content is signed by `P`, so a wrong home `Q` can
//! never produce content that validates as `P`.

use crate::federation::domain::parse_instance_domain;

/// The version prefix + paste-detection anchor.
const PREFIX: &str = ":trust:";

/// Hard cap on the embedded display-name length. The name is UX-only and
/// remote, so it bypasses `validate_display_name`; this bound just keeps
/// an adversarial code from seeding an unbounded stub name.
const MAX_DISPLAY_NAME_LEN: usize = 128;

/// A parsed trust code. Field names mirror the wire grammar; none of the
/// metadata fields (`display_name`, `home_domain`) are identity — only
/// the two pubkeys are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustCode {
    /// UX-only label. Validated to be non-empty, control-char-free, and
    /// within [`MAX_DISPLAY_NAME_LEN`]; never used for lookup.
    pub display_name: String,
    /// Home-instance dialing address (`host[:port]`), already run
    /// through [`parse_instance_domain`] so it is a clean authority.
    pub home_domain: String,
    /// The user's Ed25519 credential pubkey — the identity.
    pub user_pubkey: [u8; 32],
    /// The home instance's Ed25519 `instance_pubkey` — the §3 anchor.
    pub instance_pubkey: [u8; 32],
}

/// Why a trust code failed to parse. All variants are caller-facing
/// "this paste is malformed", not internal errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustCodeError {
    /// Missing the `:trust:` prefix — not a trust code at all.
    MissingPrefix,
    /// Structurally truncated: too short to hold both hex tails, or a
    /// tail delimiter (`@` / `:`) was absent where required.
    Malformed,
    /// A 64-hex field was not exactly 64 lowercase-hex characters.
    BadHex,
    /// The embedded display name was empty, over-long, or contained a
    /// control character.
    BadName,
    /// The embedded home domain failed [`parse_instance_domain`].
    BadDomain,
}

impl std::fmt::Display for TrustCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TrustCodeError::MissingPrefix => "trust code missing ':trust:' prefix",
            TrustCodeError::Malformed => "trust code is malformed or truncated",
            TrustCodeError::BadHex => "trust code pubkey field is not 64 lowercase hex chars",
            TrustCodeError::BadName => "trust code display name is empty, too long, or invalid",
            TrustCodeError::BadDomain => "trust code home domain is invalid",
        };
        f.write_str(s)
    }
}

impl std::error::Error for TrustCodeError {}

/// Decode exactly 64 lowercase-hex chars into a 32-byte key. Mirrors the
/// strict lowercase rule used by `resolve_user_by_pubkey_hex` so the
/// canonical wire form is the only one that round-trips.
pub(crate) fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Lowercase-hex-encode a 32-byte key for embedding in a trust code.
fn encode_hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Mint a trust code for `(display_name, home_domain, user_pubkey,
/// instance_pubkey)`.
///
/// Callers pass an already-validated `display_name` (the minting user's
/// own, which went through `validate_display_name`) and the instance's
/// own `instance_domain`, so this is pure assembly — it does not
/// re-validate. The result round-trips through [`parse`].
pub fn mint(
    display_name: &str,
    home_domain: &str,
    user_pubkey: &[u8; 32],
    instance_pubkey: &[u8; 32],
) -> String {
    format!(
        "{PREFIX}{display_name}@{home_domain}:{user}@{instance}",
        user = encode_hex32(user_pubkey),
        instance = encode_hex32(instance_pubkey),
    )
}

/// Parse and validate a trust code from untrusted input.
///
/// Fails loudly on any structural defect (see [`TrustCodeError`]) so a
/// truncated or hand-corrupted paste never silently resolves to the
/// wrong identity. Whitespace around the whole code is tolerated (paste
/// noise); interior structure is strict.
pub fn parse(input: &str) -> Result<TrustCode, TrustCodeError> {
    let body = input
        .trim()
        .strip_prefix(PREFIX)
        .ok_or(TrustCodeError::MissingPrefix)?;

    // Peel `@<instancepk>` off the right. The last 64 bytes are ASCII
    // hex, so the split index is on a char boundary even when the
    // display name (leftmost) is multibyte UTF-8.
    if body.len() < 64 {
        return Err(TrustCodeError::Malformed);
    }
    let (rest, instance_hex) = body.split_at(body.len() - 64);
    let rest = rest.strip_suffix('@').ok_or(TrustCodeError::Malformed)?;
    let instance_pubkey = decode_hex32(instance_hex).ok_or(TrustCodeError::BadHex)?;

    // Peel `:<userpk>` off the right of what remains.
    if rest.len() < 64 {
        return Err(TrustCodeError::Malformed);
    }
    let (head, user_hex) = rest.split_at(rest.len() - 64);
    let head = head.strip_suffix(':').ok_or(TrustCodeError::Malformed)?;
    let user_pubkey = decode_hex32(user_hex).ok_or(TrustCodeError::BadHex)?;

    // The remainder is `<display_name>@<home_domain>`. The name forbids
    // `@`, so the *first* `@` is the delimiter; the domain may carry its
    // own `:`/`[]` but no `@`.
    let (display_name, home_domain) = head.split_once('@').ok_or(TrustCodeError::Malformed)?;

    if display_name.is_empty()
        || display_name.len() > MAX_DISPLAY_NAME_LEN
        || display_name.chars().any(|c| c.is_control())
    {
        return Err(TrustCodeError::BadName);
    }

    // Validate (but keep the original string form — callers store the
    // bare `host[:port]`, mirroring `user_homes.current_home_domain`).
    parse_instance_domain(home_domain).map_err(|_| TrustCodeError::BadDomain)?;

    Ok(TrustCode {
        display_name: display_name.to_string(),
        home_domain: home_domain.to_string(),
        user_pubkey,
        instance_pubkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn round_trips() {
        let code = mint("alice", "example.com", &key(0xab), &key(0xcd));
        let parsed = parse(&code).expect("round-trips");
        assert_eq!(parsed.display_name, "alice");
        assert_eq!(parsed.home_domain, "example.com");
        assert_eq!(parsed.user_pubkey, key(0xab));
        assert_eq!(parsed.instance_pubkey, key(0xcd));
    }

    #[test]
    fn round_trips_with_port() {
        // The `:port` in the domain must not confuse the right-to-left
        // hex peel — this is the whole reason for parsing the tail first.
        let code = mint("bob", "host.local:8443", &key(1), &key(2));
        let parsed = parse(&code).expect("port domain round-trips");
        assert_eq!(parsed.home_domain, "host.local:8443");
        assert_eq!(parsed.user_pubkey, key(1));
        assert_eq!(parsed.instance_pubkey, key(2));
    }

    #[test]
    fn round_trips_bracketed_ipv6() {
        let code = mint("carol", "[2001:db8::1]:443", &key(3), &key(4));
        let parsed = parse(&code).expect("ipv6 domain round-trips");
        assert_eq!(parsed.home_domain, "[2001:db8::1]:443");
    }

    #[test]
    fn tolerates_surrounding_whitespace() {
        let code = mint("dave", "example.com", &key(5), &key(6));
        let padded = format!("  \n{code}\t ");
        assert_eq!(parse(&padded).unwrap().display_name, "dave");
    }

    #[test]
    fn rejects_missing_prefix() {
        let code = mint("erin", "example.com", &key(7), &key(8));
        let no_prefix = code.strip_prefix(PREFIX).unwrap();
        assert_eq!(parse(no_prefix), Err(TrustCodeError::MissingPrefix));
    }

    #[test]
    fn rejects_truncated_tail() {
        let code = mint("frank", "example.com", &key(9), &key(10));
        // Lop off the last 5 chars of the instance pubkey.
        let truncated = &code[..code.len() - 5];
        assert!(matches!(
            parse(truncated),
            Err(TrustCodeError::BadHex | TrustCodeError::Malformed)
        ));
    }

    #[test]
    fn rejects_uppercase_hex() {
        let mut code = mint("grace", "example.com", &key(0x0a), &key(0x0b));
        code = code.to_uppercase(); // also uppercases the prefix
        // Even fixing the prefix, the hex is now uppercase → BadHex.
        let fixed = format!("{PREFIX}{}", &code[PREFIX.len()..]);
        assert_eq!(parse(&fixed), Err(TrustCodeError::BadHex));
    }

    #[test]
    fn rejects_non_hex_in_key() {
        let user = encode_hex32(&key(1));
        let bad = format!(
            "{PREFIX}heidi@example.com:{}@{}",
            &user[..63],
            "zz".repeat(32)
        );
        assert_eq!(parse(&bad), Err(TrustCodeError::BadHex));
    }

    #[test]
    fn rejects_empty_name() {
        let code = mint("", "example.com", &key(1), &key(2));
        assert_eq!(parse(&code), Err(TrustCodeError::BadName));
    }

    #[test]
    fn rejects_control_char_in_name() {
        let code = mint("ev\u{7}il", "example.com", &key(1), &key(2));
        assert_eq!(parse(&code), Err(TrustCodeError::BadName));
    }

    #[test]
    fn rejects_overlong_name() {
        let long = "a".repeat(MAX_DISPLAY_NAME_LEN + 1);
        let code = mint(&long, "example.com", &key(1), &key(2));
        assert_eq!(parse(&code), Err(TrustCodeError::BadName));
    }

    #[test]
    fn rejects_bad_domain() {
        // A path component is rejected by parse_instance_domain.
        let code = mint("ivan", "example.com/evil", &key(1), &key(2));
        assert_eq!(parse(&code), Err(TrustCodeError::BadDomain));
    }

    #[test]
    fn rejects_missing_domain() {
        // No `@` separating name from domain in the head remainder.
        let user = encode_hex32(&key(1));
        let inst = encode_hex32(&key(2));
        let bad = format!("{PREFIX}justname:{user}@{inst}");
        assert_eq!(parse(&bad), Err(TrustCodeError::Malformed));
    }

    #[test]
    fn name_with_unicode_letters_ok() {
        // Remote display names may carry non-ASCII letters; only the
        // delimiters and control chars are off-limits.
        let code = mint("José", "example.com", &key(1), &key(2));
        assert_eq!(parse(&code).unwrap().display_name, "José");
    }
}
