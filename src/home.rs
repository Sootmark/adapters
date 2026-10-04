//! Whose home a file is in, from its path: databases in a profile belong
//! to the account the profile is under.

/// The account whose home the file is in: `Users/<name>/…` (Windows,
/// macOS) or `home/<name>/…` (Linux).
pub(crate) fn profile_owner(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split(['/', '\\']).collect();
    parts
        .windows(2)
        .find(|pair| pair[0].eq_ignore_ascii_case("Users") || pair[0] == "home")
        .map(|pair| pair[1].to_owned())
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owners_from_paths() {
        assert_eq!(
            profile_owner(r"C\Users\alice\AppData\Local\Google\Chrome\User Data\Default\History"),
            Some("alice".to_owned())
        );
        assert_eq!(
            profile_owner("[root]/home/bob/.mozilla/firefox/x.default/places.sqlite"),
            Some("bob".to_owned())
        );
        assert_eq!(
            profile_owner(
                "Users/carol/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
            ),
            Some("carol".to_owned())
        );
        assert_eq!(profile_owner("places.sqlite"), None);
    }
}
