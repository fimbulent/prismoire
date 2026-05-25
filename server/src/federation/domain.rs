//! Federation `instance_domain` validation.
//!
//! `peers.instance_domain` is wire-supplied data — populated either by
//! the operator at peer-request time or by a remote signer's
//! `initiator_domain` field on inbound `/peer-request` (§5.4). Either
//! way it ends up on the outbound URL for every federation call:
//! `https://{instance_domain}{path}`. Without validation, a hostile
//! signer can register values like `127.0.0.1:8080/admin`,
//! `169.254.169.254` (cloud metadata IP), `evil.com#@victim.com`
//! (URL-parser confusion), or anything else that bends the URL into a
//! request the operator did not intend. The result is server-side
//! request forgery (SSRF) with the operator's own credentials.
//!
//! The defence is two-layer:
//!
//! 1. **Format gate** at every inbound boundary that writes
//!    `instance_domain` (handlers in `peering.rs`, the operator-side
//!    helpers) — strict `host[:port]` with no other syntax. See
//!    [`parse_instance_domain`].
//! 2. **IP-literal denylist** in the transport just before dispatch,
//!    catching hosts that *are* IPs in private / loopback / link-local
//!    ranges. See [`is_blocked_ip_literal`]. The check defaults to
//!    deny in production; the
//!    `PRISMOIRE_FEDERATION_ALLOW_PRIVATE_TARGETS` env var disables it
//!    for the loopback Layer-2 smoke test (`federation-impl-plan.md`
//!    §Phase 5). Hostname-based SSRF (DNS rebinding to a private IP)
//!    is *not* closed by this; that needs the operational-hardening
//!    pass (§6 follow-ups in the impl plan).

use std::net::{Ipv4Addr, Ipv6Addr};

/// Parsed `host[:port]` from an `instance_domain` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceDomain {
    /// Bare host — either an IPv4 literal, an IPv6 literal (without
    /// the bracket-pair the URL form requires), or an LDH hostname.
    pub host: String,
    /// Optional port. `None` means "default 443 for https" at the
    /// transport layer.
    pub port: Option<u16>,
}

/// Failure modes [`parse_instance_domain`] can surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainValidationError {
    /// String is empty or only whitespace.
    Empty,
    /// String exceeds the 253-character cap on DNS hostnames (or the
    /// equivalent IP-literal length plus optional port). Anything
    /// longer is almost certainly an attempted overflow / parser-
    /// confusion.
    TooLong,
    /// String contains a character outside the LDH + dot + colon +
    /// bracket alphabet allowed for `host[:port]`. Catches paths,
    /// query strings, userinfo (`@`), control chars, whitespace,
    /// CR/LF (header smuggling), unicode (IDN should be punycoded
    /// before reaching us).
    InvalidCharacter,
    /// Host segment failed structural validation (empty label,
    /// leading/trailing dot, label > 63 chars, etc.).
    InvalidHost,
    /// Port segment was present but not parseable as a `u16` > 0.
    InvalidPort,
}

impl std::fmt::Display for DomainValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DomainValidationError::Empty => f.write_str("empty instance_domain"),
            DomainValidationError::TooLong => f.write_str("instance_domain exceeds 253 chars"),
            DomainValidationError::InvalidCharacter => {
                f.write_str("instance_domain contains a disallowed character")
            }
            DomainValidationError::InvalidHost => f.write_str("instance_domain host is malformed"),
            DomainValidationError::InvalidPort => f.write_str("instance_domain port is invalid"),
        }
    }
}

impl std::error::Error for DomainValidationError {}

/// Parse an `instance_domain` string into a validated
/// [`InstanceDomain`].
///
/// The accepted grammar is intentionally narrower than a generic URL
/// authority:
///
/// - Either `host` or `host:port`.
/// - `host` is an IPv4 literal, a bracketed IPv6 literal
///   (`[::1]:443`), or an LDH hostname (letters, digits, `-`, `.`).
/// - `port` is a decimal `u16` greater than 0.
/// - No scheme, no userinfo (`@`), no path/query/fragment, no
///   whitespace, no control chars, no CR/LF (header smuggling),
///   no Unicode (callers MUST punycode IDN before reaching the wire).
pub fn parse_instance_domain(s: &str) -> Result<InstanceDomain, DomainValidationError> {
    // Run the character-validity check against the *raw* input — no
    // `.trim()` — so CR/LF (header smuggling) and other whitespace
    // are rejected outright rather than silently stripped.
    if s.is_empty() {
        return Err(DomainValidationError::Empty);
    }
    if s.chars().all(|c| c.is_ascii_whitespace()) {
        return Err(DomainValidationError::Empty);
    }
    if s.len() > 253 + 6 {
        // 253 max hostname + 1 ':' + 5 digits of port leaves room
        // for [host]:port bracketed IPv6 forms too.
        return Err(DomainValidationError::TooLong);
    }
    // Reject any disallowed character outright. Note: scheme prefix
    // (`http://`), userinfo (`@`), path (`/`), query (`?`), fragment
    // (`#`), and whitespace are all rejected at this stage, so the
    // splits below see a clean `host[:port]`.
    for c in s.chars() {
        let allowed = c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':' | '[' | ']');
        if !allowed {
            return Err(DomainValidationError::InvalidCharacter);
        }
    }

    // Bracketed IPv6 form: `[ipv6]:port` or `[ipv6]`.
    if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']').ok_or(DomainValidationError::InvalidHost)?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        host.parse::<Ipv6Addr>()
            .map_err(|_| DomainValidationError::InvalidHost)?;
        let port = match after {
            "" => None,
            rest_after => {
                let port_str = rest_after
                    .strip_prefix(':')
                    .ok_or(DomainValidationError::InvalidPort)?;
                Some(parse_port(port_str)?)
            }
        };
        return Ok(InstanceDomain {
            host: host.to_string(),
            port,
        });
    }

    // Everything else: `host[:port]`. Find the last `:` for the
    // port split — IPv6 has multiple colons but it's always
    // bracketed and handled above.
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) => (h, Some(parse_port(p)?)),
        None => (s, None),
    };
    if host.is_empty() {
        return Err(DomainValidationError::InvalidHost);
    }
    // IPv4 literal?
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(InstanceDomain {
            host: host.to_string(),
            port,
        });
    }
    // Else: LDH hostname. Validate label structure.
    validate_ldh_hostname(host)?;
    Ok(InstanceDomain {
        host: host.to_string(),
        port,
    })
}

fn parse_port(s: &str) -> Result<u16, DomainValidationError> {
    let p: u16 = s.parse().map_err(|_| DomainValidationError::InvalidPort)?;
    if p == 0 {
        return Err(DomainValidationError::InvalidPort);
    }
    Ok(p)
}

fn validate_ldh_hostname(host: &str) -> Result<(), DomainValidationError> {
    if host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return Err(DomainValidationError::InvalidHost);
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DomainValidationError::InvalidHost);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DomainValidationError::InvalidHost);
        }
        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' {
                return Err(DomainValidationError::InvalidHost);
            }
        }
    }
    Ok(())
}

/// Returns `true` if the host segment is an IP literal that lands in
/// a private / loopback / link-local / multicast / unspecified range
/// and so MUST NOT be the target of an outbound federation request
/// in a production deployment.
///
/// Hostnames (anything not a parseable IP literal) return `false` —
/// closing that hole requires resolving the hostname and filtering
/// the returned IPs, which is the operational-hardening pass's job
/// (DNS rebinding still escapes a one-shot lookup).
pub fn is_blocked_ip_literal(host: &str) -> bool {
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return is_blocked_v4(v4);
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return is_blocked_v6(v6);
    }
    false
}

fn is_blocked_v4(a: Ipv4Addr) -> bool {
    a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_unspecified()
        // Carrier-grade NAT (RFC 6598). `is_shared` is unstable as
        // of 1.91, so check manually.
        || (a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 64)
}

fn is_blocked_v6(a: Ipv6Addr) -> bool {
    if a.is_loopback() || a.is_multicast() || a.is_unspecified() {
        return true;
    }
    let seg = a.segments()[0];
    // fe80::/10 link-local.
    if (seg & 0xffc0) == 0xfe80 {
        return true;
    }
    // fc00::/7 unique local (RFC 4193).
    if (seg & 0xfe00) == 0xfc00 {
        return true;
    }
    // 4-in-6 embedded: if the v6 maps a v4 (::ffff:x.y.z.w or
    // ::x.y.z.w), recurse into the v4 rules so an attacker can't
    // smuggle 127.0.0.1 as ::ffff:127.0.0.1.
    if let Some(v4) = a.to_ipv4() {
        return is_blocked_v4(v4);
    }
    false
}

/// Read the `PRISMOIRE_FEDERATION_ALLOW_PRIVATE_TARGETS` env var.
///
/// Set to `1`/`true` in the Layer-2 smoke test (which dials a
/// loopback self-signed cert) and unset everywhere else. Reading at
/// transport-construction time is intentional: the policy can't be
/// flipped at runtime without restarting, which matches the
/// security posture we want for a kill-switch.
pub fn allow_private_targets_from_env() -> bool {
    matches!(
        std::env::var("PRISMOIRE_FEDERATION_ALLOW_PRIVATE_TARGETS")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_hostname() {
        let d = parse_instance_domain("example.com").unwrap();
        assert_eq!(d.host, "example.com");
        assert_eq!(d.port, None);
    }

    #[test]
    fn parses_hostname_with_port() {
        let d = parse_instance_domain("example.com:8443").unwrap();
        assert_eq!(d.host, "example.com");
        assert_eq!(d.port, Some(8443));
    }

    #[test]
    fn parses_ipv4_literal() {
        let d = parse_instance_domain("127.0.0.1:8080").unwrap();
        assert_eq!(d.host, "127.0.0.1");
        assert_eq!(d.port, Some(8080));
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        let d = parse_instance_domain("[::1]:8443").unwrap();
        assert_eq!(d.host, "::1");
        assert_eq!(d.port, Some(8443));
    }

    #[test]
    fn parses_bracketed_ipv6_without_port() {
        let d = parse_instance_domain("[::1]").unwrap();
        assert_eq!(d.host, "::1");
        assert_eq!(d.port, None);
    }

    #[test]
    fn rejects_path_segment() {
        assert!(matches!(
            parse_instance_domain("127.0.0.1:8080/admin"),
            Err(DomainValidationError::InvalidCharacter),
        ));
    }

    #[test]
    fn rejects_userinfo() {
        assert!(matches!(
            parse_instance_domain("evil.com#@victim.com"),
            Err(DomainValidationError::InvalidCharacter),
        ));
        assert!(matches!(
            parse_instance_domain("user@host.com"),
            Err(DomainValidationError::InvalidCharacter),
        ));
    }

    #[test]
    fn rejects_scheme_prefix() {
        assert!(matches!(
            parse_instance_domain("http://example.com"),
            Err(DomainValidationError::InvalidCharacter),
        ));
    }

    #[test]
    fn rejects_control_chars_and_whitespace() {
        assert!(parse_instance_domain("example.com\r\n").is_err());
        assert!(parse_instance_domain("exa mple.com").is_err());
        assert!(parse_instance_domain("example.com\0").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            parse_instance_domain(""),
            Err(DomainValidationError::Empty),
        ));
        assert!(matches!(
            parse_instance_domain("   "),
            Err(DomainValidationError::Empty),
        ));
    }

    #[test]
    fn rejects_zero_or_oversize_port() {
        assert!(parse_instance_domain("example.com:0").is_err());
        assert!(parse_instance_domain("example.com:65536").is_err());
        assert!(parse_instance_domain("example.com:99999").is_err());
    }

    #[test]
    fn rejects_malformed_labels() {
        assert!(parse_instance_domain("-foo.com").is_err());
        assert!(parse_instance_domain("foo-.com").is_err());
        assert!(parse_instance_domain(".foo.com").is_err());
        assert!(parse_instance_domain("foo..com").is_err());
        assert!(parse_instance_domain("foo.com.").is_err());
    }

    #[test]
    fn blocks_loopback_v4() {
        assert!(is_blocked_ip_literal("127.0.0.1"));
        assert!(is_blocked_ip_literal("127.255.255.254"));
    }

    #[test]
    fn blocks_rfc1918_v4() {
        assert!(is_blocked_ip_literal("10.0.0.1"));
        assert!(is_blocked_ip_literal("172.16.0.1"));
        assert!(is_blocked_ip_literal("192.168.1.1"));
    }

    #[test]
    fn blocks_link_local_and_metadata() {
        assert!(is_blocked_ip_literal("169.254.169.254")); // AWS/Azure metadata
        assert!(is_blocked_ip_literal("169.254.0.1"));
    }

    #[test]
    fn blocks_cgnat_v4() {
        assert!(is_blocked_ip_literal("100.64.0.1"));
        assert!(is_blocked_ip_literal("100.127.255.255"));
        // Just outside CGNAT range.
        assert!(!is_blocked_ip_literal("100.63.255.255"));
        assert!(!is_blocked_ip_literal("100.128.0.1"));
    }

    #[test]
    fn blocks_loopback_and_link_local_v6() {
        assert!(is_blocked_ip_literal("::1"));
        assert!(is_blocked_ip_literal("fe80::1"));
        assert!(is_blocked_ip_literal("fc00::1"));
    }

    #[test]
    fn blocks_v4_mapped_v6_loopback() {
        // Attempt to smuggle 127.0.0.1 through a v4-mapped v6.
        assert!(is_blocked_ip_literal("::ffff:127.0.0.1"));
    }

    #[test]
    fn passes_public_ips_and_hostnames() {
        assert!(!is_blocked_ip_literal("example.com"));
        assert!(!is_blocked_ip_literal("8.8.8.8"));
        assert!(!is_blocked_ip_literal("2001:db8::1"));
    }
}
