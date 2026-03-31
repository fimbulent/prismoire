/// Shared validation helpers for display names and topic names.
///
/// Both name types share common rules (NFC normalization, character-class
/// checks, mixed-script detection, consecutive-separator rejection) but
/// differ in which separators are allowed and in length bounds.
use unicode_normalization::UnicodeNormalization;
use unicode_security::MixedScript;

/// Configuration for name validation.
pub struct NameRules {
    pub label: &'static str,
    pub min_chars: usize,
    pub max_chars: usize,
    pub max_bytes: usize,
    /// Characters (besides alphabetic and digits) that are allowed between words.
    pub allowed_separators: &'static [char],
    pub allowed_chars_description: &'static str,
}

/// Trim, NFC-normalize, and validate a name against the given rules.
///
/// Returns the normalized string on success or a human-readable error.
pub fn validate_name(raw: &str, rules: &NameRules) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{} must not be empty", rules.label));
    }

    let normalized: String = trimmed.nfc().collect();

    let mut has_alpha = false;

    for ch in normalized.chars() {
        if ch.is_alphabetic() {
            has_alpha = true;
        } else if ch.is_ascii_digit() || rules.allowed_separators.contains(&ch) {
            // allowed non-alpha character
        } else {
            return Err(format!(
                "{} may only contain {}",
                rules.label, rules.allowed_chars_description
            ));
        }
    }

    if !has_alpha {
        return Err(format!("{} must contain at least one letter", rules.label));
    }

    let char_count = normalized.chars().count();
    if char_count < rules.min_chars {
        return Err(format!(
            "{} must be at least {} characters",
            rules.label, rules.min_chars
        ));
    }
    if char_count > rules.max_chars {
        return Err(format!(
            "{} must be at most {} characters",
            rules.label, rules.max_chars
        ));
    }
    if normalized.len() > rules.max_bytes {
        return Err(format!("{} is too long", rules.label));
    }

    let first = normalized.chars().next().unwrap();
    let last = normalized.chars().next_back().unwrap();
    if rules.allowed_separators.contains(&first) || rules.allowed_separators.contains(&last) {
        return Err(format!(
            "{} must not start or end with a separator",
            rules.label
        ));
    }

    if has_consecutive_separators(&normalized, rules.allowed_separators) {
        return Err(format!(
            "{} must not contain consecutive separators",
            rules.label
        ));
    }

    if !normalized.is_ascii() && !normalized.is_single_script() {
        return Err(format!(
            "{} must not mix characters from different scripts",
            rules.label
        ));
    }

    Ok(normalized)
}

/// Returns true if the string contains two adjacent separator characters.
pub fn has_consecutive_separators(s: &str, separators: &[char]) -> bool {
    let mut prev_sep = false;
    for ch in s.chars() {
        let is_sep = separators.contains(&ch);
        if is_sep && prev_sep {
            return true;
        }
        prev_sep = is_sep;
    }
    false
}
