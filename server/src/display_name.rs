use unicode_security::confusable_detection::skeleton;

use crate::validation::{NameRules, validate_name};

const RULES: NameRules = NameRules {
    label: "display name",
    min_chars: 3,
    max_chars: 20,
    max_bytes: 64,
    allowed_separators: &['_', '-'],
    allowed_chars_description: "letters, numbers, hyphens, and underscores",
};

/// Validate and normalize a display name.
///
/// Rules (applied after trim + NFC normalization):
/// - Length: 3–20 Unicode scalar values, max 64 bytes UTF-8
/// - Every character must be alphabetic, a digit, `_`, or `-`
/// - At least one alphabetic character required
/// - Must not start or end with `_` or `-`
/// - No consecutive separators (`--`, `__`, `-_`, `_-`)
/// - No whitespace, control characters, format characters, zero-width chars
/// - No emoji, symbols, or punctuation
/// - No private-use or surrogate codepoints
/// - Non-ASCII names must not mix scripts (prevents homograph attacks)
///
/// Returns the normalized display name on success, or a human-readable error.
pub fn validate_display_name(raw: &str) -> Result<String, &'static str> {
    validate_name(raw, &RULES).map_err(|_| match () {
        _ if raw.trim().is_empty() => "display name must not be empty",
        _ => {
            let normalized: String = {
                use unicode_normalization::UnicodeNormalization;
                raw.trim().nfc().collect()
            };
            classify_display_name_error(&normalized)
        }
    })
}

/// Map a failed display name to the most specific static error message.
///
/// This preserves the original static `&str` error messages for backward
/// compatibility with existing frontend/test expectations.
fn classify_display_name_error(normalized: &str) -> &'static str {
    use unicode_normalization::UnicodeNormalization;
    use unicode_security::MixedScript;

    let nfc: String = normalized.nfc().collect();

    let mut has_alpha = false;
    let mut has_bad_char = false;
    for ch in nfc.chars() {
        if ch.is_alphabetic() {
            has_alpha = true;
        } else if ch.is_ascii_digit() || ch == '_' || ch == '-' {
            // ok
        } else {
            has_bad_char = true;
        }
    }

    if has_bad_char {
        return "display name may only contain letters, numbers, hyphens, and underscores";
    }
    if !has_alpha {
        return "display name must contain at least one letter";
    }

    let char_count = nfc.chars().count();
    if char_count < 3 {
        return "display name must be at least 3 characters";
    }
    if char_count > 20 {
        return "display name must be at most 20 characters";
    }
    if nfc.len() > 64 {
        return "display name is too long";
    }

    let first = nfc.chars().next().unwrap();
    let last = nfc.chars().next_back().unwrap();
    if matches!(first, '_' | '-') || matches!(last, '_' | '-') {
        return "display name must not start or end with a hyphen or underscore";
    }

    if crate::validation::has_consecutive_separators(&nfc, &['_', '-']) {
        return "display name must not contain consecutive hyphens or underscores";
    }

    if !nfc.is_ascii() && !nfc.is_single_script() {
        return "display name must not mix characters from different scripts";
    }

    "invalid display name"
}

/// Compute the confusable skeleton of a display name for lookalike detection.
///
/// Runs UTS #39 confusable mapping first (which normalizes visual confusables
/// like uppercase I → lowercase l), then lowercases the result for
/// case-insensitive comparison. Two names with identical skeletons are
/// visually confusable (e.g. "alice", "aIice", "аlice" all produce the
/// same skeleton).
pub fn display_name_skeleton(name: &str) -> String {
    let skel: String = skeleton(name).collect();
    skel.to_lowercase().replace('-', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ascii_names() {
        assert_eq!(validate_display_name("alice").unwrap(), "alice");
        assert_eq!(validate_display_name("Bob_123").unwrap(), "Bob_123");
        assert_eq!(validate_display_name("cool-name").unwrap(), "cool-name");
    }

    #[test]
    fn valid_unicode_names() {
        assert_eq!(validate_display_name("タロウ").unwrap(), "タロウ");
        assert_eq!(validate_display_name("Ñoño").unwrap(), "Ñoño");
        assert_eq!(validate_display_name("café").unwrap(), "café");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(validate_display_name("  alice  ").unwrap(), "alice");
    }

    #[test]
    fn rejects_internal_whitespace() {
        assert!(validate_display_name("hello world").is_err());
        assert!(validate_display_name("hello\tworld").is_err());
    }

    #[test]
    fn rejects_empty_and_short() {
        assert!(validate_display_name("").is_err());
        assert!(validate_display_name("   ").is_err());
        assert!(validate_display_name("ab").is_err());
        assert!(validate_display_name("abc").is_ok());
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(21);
        assert!(validate_display_name(&long).is_err());
        assert!(validate_display_name(&"a".repeat(20)).is_ok());
    }

    #[test]
    fn requires_at_least_one_alpha() {
        assert!(validate_display_name("123").is_err());
        assert!(validate_display_name("1-2").is_err());
        assert!(validate_display_name("1_2").is_err());
        assert!(validate_display_name("1a2").is_ok());
    }

    #[test]
    fn rejects_leading_trailing_separator() {
        assert!(validate_display_name("-alice").is_err());
        assert!(validate_display_name("alice-").is_err());
        assert!(validate_display_name("_alice").is_err());
        assert!(validate_display_name("alice_").is_err());
        assert!(validate_display_name("a-b").is_ok());
        assert!(validate_display_name("a_b").is_ok());
    }

    #[test]
    fn rejects_consecutive_separators() {
        assert!(validate_display_name("mark__r").is_err());
        assert!(validate_display_name("mark--r").is_err());
        assert!(validate_display_name("abc-_123").is_err());
        assert!(validate_display_name("abc_-123").is_err());
        assert!(validate_display_name("mark_r").is_ok());
        assert!(validate_display_name("mark-r").is_ok());
    }

    #[test]
    fn rejects_control_characters() {
        assert!(validate_display_name("hello\x00world").is_err());
        assert!(validate_display_name("test\x7F").is_err());
    }

    #[test]
    fn rejects_zero_width_characters() {
        assert!(validate_display_name("hel\u{200B}lo").is_err());
        assert!(validate_display_name("hel\u{200D}lo").is_err());
        assert!(validate_display_name("hel\u{FEFF}lo").is_err());
    }

    #[test]
    fn rejects_mixed_script() {
        assert!(validate_display_name("аlice").is_err()); // Cyrillic 'а' + Latin
    }

    #[test]
    fn rejects_punctuation_universally() {
        assert!(validate_display_name("alice@bob").is_err());
        assert!(validate_display_name("alice/bob").is_err());
        assert!(validate_display_name("<script>").is_err());
        assert!(validate_display_name("café@home").is_err());
        assert!(validate_display_name("ñ!test").is_err());
        assert!(validate_display_name("über.cool").is_err());
    }

    #[test]
    fn rejects_emoji() {
        assert!(validate_display_name("🎮name").is_err());
        assert!(validate_display_name("cool💀").is_err());
        assert!(validate_display_name("🎮🎮🎮").is_err());
    }

    #[test]
    fn rejects_degenerate_names() {
        assert!(validate_display_name("-").is_err());
        assert!(validate_display_name("_").is_err());
        assert!(validate_display_name("---").is_err());
        assert!(validate_display_name("-_-_-_-_-_-_-_-_-_-").is_err());
    }

    #[test]
    fn skeleton_normalizes_separators() {
        assert_eq!(
            display_name_skeleton("mark-r"),
            display_name_skeleton("mark_r")
        );
    }

    #[test]
    fn nfc_normalization() {
        let decomposed = "caf\u{0065}\u{0301}";
        let composed = "café";
        assert_eq!(
            validate_display_name(decomposed).unwrap(),
            validate_display_name(composed).unwrap()
        );
    }

    #[test]
    fn skeleton_catches_lookalikes() {
        let s1 = display_name_skeleton("alice");
        let s2 = display_name_skeleton("aIice"); // capital I looks like lowercase l
        assert_eq!(s1, s2);

        // Cyrillic 'а' confusable with Latin 'a'
        let s3 = display_name_skeleton("alice");
        let s4 = display_name_skeleton("\u{0430}lice"); // Cyrillic а
        assert_eq!(s3, s4);
    }

    #[test]
    fn skeleton_case_insensitive() {
        assert_eq!(
            display_name_skeleton("Alice"),
            display_name_skeleton("alice")
        );
    }

    #[test]
    fn skeleton_distinct_for_different_names() {
        assert_ne!(display_name_skeleton("alice"), display_name_skeleton("bob"));
    }
}
