/// Room slug validation.
///
/// Room names are now slugs directly: lowercase ASCII letters, digits,
/// and underscores. Users type the slug form in the "new thread" form.
///
/// Rules (applied after trim + lowercase):
/// - Length: 3–30 ASCII characters
/// - Every character must be a lowercase ASCII letter, digit, or underscore
/// - At least one ASCII letter required
/// - Must not start or end with an underscore
/// - No consecutive underscores
const MIN_CHARS: usize = 3;
const MAX_CHARS: usize = 30;

/// Slugs reserved for API routes and UI paths.
const RESERVED_SLUGS: &[&str] = &["top", "all", "favorites", "new", "public"];

/// The single reserved room whose threads are visible to all authenticated
/// users and where only admins can create threads.
pub const ANNOUNCEMENTS_SLUG: &str = "announcements";

/// Check whether a room slug is the announcements room.
pub fn is_announcements(slug: &str) -> bool {
    slug == ANNOUNCEMENTS_SLUG
}

/// Validate and normalize a room slug.
///
/// Returns the normalized slug on success, or a human-readable error.
pub fn validate_room_slug(raw: &str) -> Result<String, String> {
    let slug = raw.trim().to_ascii_lowercase();
    if slug.is_empty() {
        return Err("room name must not be empty".into());
    }

    let mut has_alpha = false;

    for ch in slug.chars() {
        if ch.is_ascii_lowercase() {
            has_alpha = true;
        } else if ch.is_ascii_digit() || ch == '_' {
            // allowed
        } else {
            return Err(
                "room name may only contain lowercase letters, numbers, and underscores".into(),
            );
        }
    }

    if !has_alpha {
        return Err("room name must contain at least one letter".into());
    }

    let char_count = slug.len();
    if char_count < MIN_CHARS {
        return Err(format!("room name must be at least {MIN_CHARS} characters"));
    }
    if char_count > MAX_CHARS {
        return Err(format!("room name must be at most {MAX_CHARS} characters"));
    }

    if slug.starts_with('_') || slug.ends_with('_') {
        return Err("room name must not start or end with an underscore".into());
    }

    if slug.contains("__") {
        return Err("room name must not contain consecutive underscores".into());
    }

    if RESERVED_SLUGS.contains(&slug.as_str()) {
        return Err(format!("room name \"{slug}\" is reserved"));
    }

    Ok(slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_simple_slugs() {
        assert_eq!(validate_room_slug("tech_news").unwrap(), "tech_news");
        assert_eq!(validate_room_slug("gaming").unwrap(), "gaming");
        assert_eq!(validate_room_slug("board_games").unwrap(), "board_games");
    }

    #[test]
    fn lowercases_input() {
        assert_eq!(validate_room_slug("Tech_News").unwrap(), "tech_news");
        assert_eq!(validate_room_slug("GAMING").unwrap(), "gaming");
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(validate_room_slug("  tech_news  ").unwrap(), "tech_news");
    }

    #[test]
    fn rejects_spaces_and_hyphens() {
        assert!(validate_room_slug("tech news").is_err());
        assert!(validate_room_slug("tech-news").is_err());
    }

    #[test]
    fn rejects_empty_and_short() {
        assert!(validate_room_slug("").is_err());
        assert!(validate_room_slug("   ").is_err());
        assert!(validate_room_slug("ab").is_err());
        assert!(validate_room_slug("abc").is_ok());
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(31);
        assert!(validate_room_slug(&long).is_err());
        assert!(validate_room_slug(&"a".repeat(30)).is_ok());
    }

    #[test]
    fn requires_at_least_one_alpha() {
        assert!(validate_room_slug("123").is_err());
        assert!(validate_room_slug("1_2_3").is_err());
        assert!(validate_room_slug("1a2").is_ok());
    }

    #[test]
    fn rejects_leading_trailing_underscore() {
        assert!(validate_room_slug("_tech").is_err());
        assert!(validate_room_slug("tech_").is_err());
    }

    #[test]
    fn rejects_consecutive_underscores() {
        assert!(validate_room_slug("tech__news").is_err());
    }

    #[test]
    fn rejects_emoji() {
        assert!(validate_room_slug("gaming🎮").is_err());
    }

    #[test]
    fn rejects_punctuation() {
        assert!(validate_room_slug("tech&science").is_err());
        assert!(validate_room_slug("hello!").is_err());
    }

    #[test]
    fn rejects_reserved_slugs() {
        assert!(validate_room_slug("top").is_err());
        assert!(validate_room_slug("all").is_err());
        assert!(validate_room_slug("favorites").is_err());
        assert!(validate_room_slug("new").is_err());
        assert!(validate_room_slug("NEW").is_err());
    }

    #[test]
    fn allows_announcements() {
        assert!(validate_room_slug("announcements").is_ok());
    }

    #[test]
    fn is_announcements_check() {
        assert!(is_announcements("announcements"));
        assert!(!is_announcements("technology"));
    }
}
