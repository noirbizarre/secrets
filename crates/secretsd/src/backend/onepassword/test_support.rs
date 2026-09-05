//! Shared test-only helper: compiles an ad hoc C fixture into a shared
//! library at test time, via the system `cc`, never as a committed
//! binary. Lets the `ffi`/`ipc`/`session` test suites exercise real
//! `dlopen`/`dlsym` behavior against known, controlled native code
//! instead of needing 1Password Desktop installed.

use std::path::{Path, PathBuf};

/// Compiles `source` (a complete C translation unit) into a shared
/// library under `dir`, returning its path.
///
/// Returns `None` (skipping the calling test, not failing it) if no C
/// compiler is available at all — every environment this project's CI
/// runs on has one, but a developer machine stripped of `cc` should not
/// see a false failure unrelated to the module under test.
pub(crate) fn compile_fixture(dir: &Path, source: &str) -> Option<PathBuf> {
    if std::process::Command::new("cc")
        .arg("--version")
        .output()
        .is_err()
    {
        return None;
    }

    let source_path = dir.join("fixture.c");
    std::fs::write(&source_path, source).unwrap();
    let library_path = dir.join("libfixture.so");
    let output = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&library_path)
        .arg(&source_path)
        .output()
        .expect("cc is available (checked above)");
    assert!(
        output.status.success(),
        "fixture compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(library_path)
}
