//! Field names taken from the data: hunts query fields by name, and a name
//! may hold only ASCII letters and digits, `_`, `-` and `.`.

/// `raw` as a field name, every other character replaced by `_`; `_` for
/// an empty name.
pub(crate) fn field_name(raw: &str) -> String {
    let name: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name.is_empty() {
        "_".to_owned()
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
    use super::field_name;

    #[test]
    fn names_keep_only_what_hunts_accept() {
        assert_eq!(field_name("kMDItemFileName"), "kMDItemFileName");
        assert_eq!(field_name("user.name-2"), "user.name-2");
        assert_eq!(field_name("Date créée (x)"), "Date_cr__e__x_");
        assert_eq!(field_name(""), "_");
    }
}
