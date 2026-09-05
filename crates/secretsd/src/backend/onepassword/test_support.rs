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

/// Compiles a fixture that returns each of `responses` in order (one per
/// call, clamped to the last one if more calls happen than provided) —
/// lets a test simulate a specific *sequence* of raw envelope responses
/// (e.g. `init_client`'s, then `VaultsList`'s) without the fixture
/// needing to parse request content: call order alone selects the
/// response, matching each test's own deterministic call sequence.
///
/// Same `None`-on-no-compiler behavior as [`compile_fixture`].
pub(crate) fn compile_sequenced_fixture(dir: &Path, responses: &[Vec<u8>]) -> Option<PathBuf> {
    let mut source = String::from(
        "#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n\nstatic int call_count = 0;\n\n",
    );

    source.push_str("static const unsigned char *RESPONSES[] = {\n");
    for response in responses {
        let bytes_literal: String = response
            .iter()
            .map(|byte| format!("0x{byte:02x},"))
            .collect();
        source.push_str(&format!("  (const unsigned char[]){{{bytes_literal}}},\n"));
    }
    source.push_str("};\n");

    source.push_str("static const size_t RESPONSE_LENS[] = {");
    for response in responses {
        source.push_str(&format!("{},", response.len()));
    }
    source.push_str("};\n");
    source.push_str(&format!(
        "static const size_t RESPONSE_COUNT = {};\n",
        responses.len()
    ));

    source.push_str(
        r#"
int op_sdk_ipc_send_message(const uint8_t *req_ptr, size_t req_len,
                             uint8_t **out_buf, size_t *out_len, size_t *out_cap) {
    (void)req_ptr; (void)req_len;
    size_t index = (size_t)call_count;
    if (index >= RESPONSE_COUNT) { index = RESPONSE_COUNT - 1; }
    call_count++;
    size_t len = RESPONSE_LENS[index];
    uint8_t *buf = (uint8_t *)malloc(len > 0 ? len : 1);
    if (len > 0) { memcpy(buf, RESPONSES[index], len); }
    *out_buf = buf;
    *out_len = len;
    *out_cap = len;
    return 0;
}

void op_sdk_ipc_free_response(uint8_t *buf, size_t len, size_t cap) {
    (void)len;
    (void)cap;
    free(buf);
}
"#,
    );

    compile_fixture(dir, &source)
}
