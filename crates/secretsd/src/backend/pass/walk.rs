//! Walking a `pass`-compatible store directory into a flat list of items.
//!
//! An item is one `*.gpg` file; its [`ItemPath`] is the file's path
//! relative to the store root, directory separators becoming segments,
//! the `.gpg` extension stripped. Everything else in the tree —
//! `.gpg-id` (recipient scoping, relevant only to *encrypting* new
//! entries, never to reading existing ones — see ADR-019), `.git*`
//! (a `pass`/`gopass` store is very often also a git repository), and
//! any other dotfile/dir — is walked over and ignored, never emitted as
//! an item. Pure and PGP-free by design: this module never looks at a
//! file's contents, only its path, so it works identically whether the
//! store is locked or unlocked.

use std::path::{Path, PathBuf};

use secrets_core::ItemPath;

/// The file extension every `pass` entry uses.
const ENTRY_EXTENSION: &str = "gpg";

/// One entry found while walking the store: its logical [`ItemPath`] and
/// its actual on-disk location (needed by the caller to read+decrypt it;
/// kept separate from [`ItemPath`] since the latter is a `secret://`-
/// facing concept that never carries a filesystem path).
pub struct Entry {
    pub path: ItemPath,
    pub file: PathBuf,
}

/// Walk `store_dir` and return every `*.gpg` file found, in no
/// particular order (callers that need a stable order sort by
/// [`ItemPath`] themselves).
///
/// # Errors
///
/// Returns [`std::io::Error`] if `store_dir` (or a directory beneath it)
/// cannot be read — a store directory that does not exist at all is
/// [`crate::backend::pass::PassBackend::open`]'s own concern, not this
/// function's, so this only ever fails for permission/IO problems on an
/// otherwise-valid path.
pub fn items(store_dir: &Path) -> std::io::Result<Vec<Entry>> {
    let mut found = Vec::new();
    walk(store_dir, &mut Vec::new(), &mut found)?;
    Ok(found)
}

fn walk(dir: &Path, segments: &mut Vec<String>, found: &mut Vec<Entry>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            // Non-UTF-8 file names cannot become an `ItemPath` segment
            // (see `secrets_core::uri`) — skip rather than fail the
            // whole walk over one oddly-named file.
            continue;
        };
        if name.starts_with('.') {
            // `.gpg-id`, `.git`, `.gitattributes`, and similar — never
            // items, and `.gpg-id` in particular is deliberately never
            // even opened here (see this module's own doc comment).
            continue;
        }

        if file_type.is_dir() {
            segments.push(name.to_string());
            walk(&entry.path(), segments, found)?;
            segments.pop();
            continue;
        }

        if !file_type.is_file() {
            // Symlinks and other special files: not a documented part
            // of the `pass` format, skip rather than guess.
            continue;
        }
        let Some(stem) = name.strip_suffix(&format!(".{ENTRY_EXTENSION}")) else {
            continue;
        };
        if stem.is_empty() {
            // A file literally named ".gpg" — degenerate, skip rather
            // than construct an empty `ItemPath` segment.
            continue;
        }

        let mut path_segments = segments.clone();
        path_segments.push(stem.to_string());
        let Ok(path) = ItemPath::new(path_segments) else {
            // Defensive: `ItemPath::new` rejects empty segment lists,
            // which cannot happen here since `stem` was just checked
            // non-empty, but never panics on a real store either way.
            continue;
        };
        found.push(Entry {
            path,
            file: entry.path(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tempfile::tempdir;

    fn paths(entries: &[Entry]) -> Vec<String> {
        let mut names: Vec<String> = entries
            .iter()
            .map(|e| e.path.segments().join("/"))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_top_level_entry_is_found() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("gmail.gpg"), b"").unwrap();

        let entries = items(dir.path()).unwrap();
        assert_eq!(paths(&entries), vec!["gmail"]);
    }

    #[test]
    fn nested_directories_produce_multi_segment_item_paths() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Personal/Email")).unwrap();
        std::fs::write(dir.path().join("Personal/Email/gmail.gpg"), b"").unwrap();

        let entries = items(dir.path()).unwrap();
        assert_eq!(paths(&entries), vec!["Personal/Email/gmail"]);
    }

    #[test]
    fn gpg_id_and_git_files_are_never_reported_as_items() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(".gpg-id"), b"fixture@example.invalid").unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/config"), b"").unwrap();
        std::fs::write(dir.path().join("gmail.gpg"), b"").unwrap();

        let entries = items(dir.path()).unwrap();
        assert_eq!(paths(&entries), vec!["gmail"]);
    }

    #[test]
    fn non_gpg_files_are_ignored() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("README.md"), b"").unwrap();
        std::fs::write(dir.path().join("gmail.gpg"), b"").unwrap();

        let entries = items(dir.path()).unwrap();
        assert_eq!(paths(&entries), vec!["gmail"]);
    }

    #[test]
    fn a_nested_gpg_id_override_does_not_break_walking_past_it() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Servers")).unwrap();
        std::fs::write(dir.path().join("Servers/.gpg-id"), b"other@example.invalid").unwrap();
        std::fs::write(dir.path().join("Servers/db.gpg"), b"").unwrap();

        let entries = items(dir.path()).unwrap();
        assert_eq!(paths(&entries), vec!["Servers/db"]);
    }

    #[test]
    fn an_empty_store_directory_reports_no_items() {
        let dir = tempdir().unwrap();
        let entries = items(dir.path()).unwrap();
        assert!(entries.is_empty());
    }
}
