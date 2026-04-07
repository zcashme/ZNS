//! ZNS name validation.
//!
//! Lifted verbatim from `ZNS/src/memo.rs::validate_name`. Keep this
//! file and that function in lockstep — if they diverge, clients will
//! accept names the indexer will reject, or vice versa.
//!
//! Rules:
//! - 1 to 62 characters inclusive
//! - lowercase ASCII letters and digits only (no hyphens, no underscores, no unicode)

/// Returns `true` if `name` is a valid ZNS name.
pub fn is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 62
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_common_names() {
        assert!(is_valid("alice"));
        assert!(is_valid("bob"));
        assert!(is_valid("user42"));
        assert!(is_valid("a"));
    }

    #[test]
    fn rejects_empty() {
        assert!(!is_valid(""));
    }

    #[test]
    fn rejects_uppercase() {
        assert!(!is_valid("Alice"));
        assert!(!is_valid("BOB"));
    }

    #[test]
    fn rejects_hyphens() {
        assert!(!is_valid("my-name"));
        assert!(!is_valid("-alice"));
        assert!(!is_valid("alice-"));
        assert!(!is_valid("my--name"));
    }

    #[test]
    fn rejects_non_ascii_and_specials() {
        assert!(!is_valid("alice_bob"));
        assert!(!is_valid("alice.bob"));
        assert!(!is_valid("alice bob"));
        assert!(!is_valid("café"));
    }

    #[test]
    fn accepts_max_length() {
        let max = "a".repeat(62);
        assert!(is_valid(&max));
    }

    #[test]
    fn rejects_too_long() {
        let too_long = "a".repeat(63);
        assert!(!is_valid(&too_long));
    }
}
