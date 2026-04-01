/// Room name validation and slug generation.
///
/// Rules (applied after trim + NFC normalization):
/// - Length: 3–30 Unicode scalar values, max 120 bytes UTF-8
/// - Every character must be alphabetic, a digit, space, or `-`
/// - No underscores (reserved as the space replacement in slugs)
/// - At least one alphabetic character required
/// - Must not start or end with a space or `-`
/// - No consecutive separators (spaces, hyphens, or any mix)
/// - No emoji, symbols, or punctuation
/// - No private-use or surrogate codepoints
/// - Non-ASCII names must not mix scripts
///
/// The slug (used for URLs and uniqueness) is the lowercase name with spaces
/// and hyphens replaced by underscores: "Tech News" → "tech_news".
use crate::validation::{NameRules, validate_name};

const RULES: NameRules = NameRules {
    label: "room name",
    min_chars: 3,
    max_chars: 30,
    max_bytes: 120,
    allowed_separators: &[' ', '-'],
    allowed_chars_description: "letters, numbers, spaces, and hyphens",
};

/// Slugs reserved for API routes and future features.
const RESERVED_SLUGS: &[&str] = &["top", "all", "favorites"];

/// Validate and normalize a room name.
///
/// Returns the NFC-normalized name on success, or a human-readable error.
/// Rejects names whose slug would collide with reserved API routes.
pub fn validate_room_name(raw: &str) -> Result<String, String> {
    let name = validate_name(raw, &RULES)?;
    let slug = room_slug(&name);
    if RESERVED_SLUGS.contains(&slug.as_str()) {
        return Err(format!("room name \"{name}\" is reserved"));
    }
    Ok(name)
}

/// Compute the URL slug for a room name.
///
/// Lowercases all characters, replaces spaces and hyphens with underscores.
/// Two rooms with identical slugs are considered duplicates.
pub fn room_slug(name: &str) -> String {
    name.to_lowercase().replace([' ', '-'], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_simple_names() {
        assert_eq!(validate_room_name("Tech News").unwrap(), "Tech News");
        assert_eq!(validate_room_name("gaming").unwrap(), "gaming");
        assert_eq!(validate_room_name("Board Games").unwrap(), "Board Games");
    }

    #[test]
    fn valid_with_hyphens() {
        assert_eq!(
            validate_room_name("Sci-Fi Movies").unwrap(),
            "Sci-Fi Movies"
        );
    }

    #[test]
    fn valid_unicode() {
        assert_eq!(validate_room_name("café culture").unwrap(), "café culture");
        assert_eq!(validate_room_name("日本語").unwrap(), "日本語");
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(validate_room_name("  Tech News  ").unwrap(), "Tech News");
    }

    #[test]
    fn rejects_underscores() {
        assert!(validate_room_name("tech_news").is_err());
    }

    #[test]
    fn rejects_empty_and_short() {
        assert!(validate_room_name("").is_err());
        assert!(validate_room_name("   ").is_err());
        assert!(validate_room_name("ab").is_err());
        assert!(validate_room_name("abc").is_ok());
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(31);
        assert!(validate_room_name(&long).is_err());
        assert!(validate_room_name(&"a".repeat(30)).is_ok());
    }

    #[test]
    fn requires_at_least_one_alpha() {
        assert!(validate_room_name("123").is_err());
        assert!(validate_room_name("1 2 3").is_err());
        assert!(validate_room_name("1a2").is_ok());
    }

    #[test]
    fn rejects_leading_trailing_hyphen() {
        assert!(validate_room_name("-Tech").is_err());
        assert!(validate_room_name("Tech-").is_err());
        assert!(validate_room_name("- Tech News").is_err());
        assert!(validate_room_name("Tech News -").is_err());
    }

    #[test]
    fn rejects_consecutive_separators() {
        assert!(validate_room_name("Tech  News").is_err());
        assert!(validate_room_name("Tech--News").is_err());
        assert!(validate_room_name("Tech -News").is_err());
        assert!(validate_room_name("Tech- News").is_err());
    }

    #[test]
    fn rejects_emoji() {
        assert!(validate_room_name("Gaming 🎮").is_err());
    }

    #[test]
    fn rejects_punctuation() {
        assert!(validate_room_name("Tech & Science").is_err());
        assert!(validate_room_name("Q&A").is_err());
        assert!(validate_room_name("Hello!").is_err());
    }

    #[test]
    fn rejects_mixed_script() {
        assert!(validate_room_name("Tеch News").is_err()); // Cyrillic 'е'
    }

    #[test]
    fn rejects_reserved_slugs() {
        assert!(validate_room_name("top").is_err());
        assert!(validate_room_name("Top").is_err());
        assert!(validate_room_name("all").is_err());
        assert!(validate_room_name("ALL").is_err());
        assert!(validate_room_name("favorites").is_err());
        assert!(validate_room_name("Favorites").is_err());
    }

    #[test]
    fn slug_basic() {
        assert_eq!(room_slug("Tech News"), "tech_news");
        assert_eq!(room_slug("Board Games"), "board_games");
        assert_eq!(room_slug("gaming"), "gaming");
    }

    #[test]
    fn slug_with_hyphens() {
        assert_eq!(room_slug("Sci-Fi Movies"), "sci_fi_movies");
    }

    #[test]
    fn slug_case_insensitive() {
        assert_eq!(room_slug("TECH NEWS"), room_slug("tech news"));
    }

    #[test]
    fn slug_collides_space_vs_hyphen() {
        assert_eq!(room_slug("Tech News"), room_slug("Tech-News"));
    }

    #[test]
    fn slug_unicode() {
        assert_eq!(room_slug("café culture"), "café_culture");
    }

    #[test]
    fn nfc_normalization() {
        let decomposed = "caf\u{0065}\u{0301} news";
        let composed = "café news";
        assert_eq!(
            validate_room_name(decomposed).unwrap(),
            validate_room_name(composed).unwrap()
        );
    }
}
