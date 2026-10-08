//! The folder a directory's own stream describes (an NTFS `$I30`, a FAT
//! directory's entries), from the stream's path: its entries' paths are
//! that folder's.

/// The folder a directory stream at `name` belongs to: the path without
/// its last part (`C/Users/$I30` → `C/Users`); empty at the top.
pub(crate) fn folder_of_stream(name: &str) -> &str {
    name.rfind(['/', '\\']).map_or("", |at| &name[..at])
}

/// The folder and name joined with the folder's own separator, or the name
/// alone at the top.
pub(crate) fn join(folder: &str, name: &str) -> String {
    let separator = if folder.contains('\\') { '\\' } else { '/' };
    if folder.is_empty() {
        name.to_owned()
    } else {
        format!("{folder}{separator}{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_join_the_folder() {
        assert_eq!(folder_of_stream("C/Users/$I30"), "C/Users");
        assert_eq!(join(folder_of_stream("$I30"), "a.txt"), "a.txt");
        assert_eq!(join("C/Users", "a.txt"), "C/Users/a.txt");
        assert_eq!(join("C:\\Users", "a.txt"), "C:\\Users\\a.txt");
    }
}
