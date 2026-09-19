//! Integration tests for the live Secret Service topology (ADR-015):
//! `secretsd::secret_service::refresh`'s background scan reconciles the
//! registered `Collection`/`Item` objects with whatever the backend
//! currently reports, instead of the object set being fixed once at
//! startup — and a backend failing during that scan must never crash
//! `secretsd` itself.
//!
//! Both scenarios below are exactly the two real-world problems that
//! motivated ADR-015: a local vault created for the first time while
//! `secretsd` is already running (previously required a restart to become
//! visible over Secret Service), and a backend erroring during discovery
//! (previously fatal to the whole daemon, including `org.secrets.Manager`
//! and the SSH agent, neither of which needs this topology at all).

mod support;

use std::path::Path;
use std::time::Duration;

use secretsd::backend::onepassword::ffi::LIBRARY_PATH_OVERRIDE_ENV;
use secretsd::secret_service::collection_path;
use support::TestDaemon;

#[test]
fn unlocking_for_the_first_time_registers_the_new_vaults_without_a_restart() {
    let daemon = TestDaemon::start_without_a_vault();

    // A fresh install: no vault file exists yet, so there is nothing for
    // the very first background scan to find.
    assert!(
        daemon.service().collections().unwrap().is_empty(),
        "a daemon started with no vault file yet must report no collections, not fail to start"
    );

    // Subscribed before `Unlock`, so the signal — emitted from
    // `refresh::reconcile`, reactively triggered by `Manager.Unlock`
    // itself (see `ManagerIface::unlock`) — cannot arrive before this
    // iterator exists to catch it.
    let mut created = daemon
        .service()
        .receive_collection_created()
        .expect("subscribe to CollectionCreated");

    // Creates and seeds the demo vault for the first time — exactly what
    // a fresh install's very first `secrets unlock` does.
    daemon
        .unlock(support::DEMO_PASSPHRASE)
        .expect("unlock creates the vault file on first call");

    // Bounded well under `refresh::REFRESH_INTERVAL` (30s): if the
    // reactive trigger from `Manager.Unlock` did not work and only the
    // periodic scan eventually picked this up, this would time out long
    // before that — proving the trigger, not just that a scan eventually
    // happens at all.
    daemon.wait_until_collections(&[
        collection_path("Personal"),
        collection_path("Infrastructure"),
    ]);

    // The signal itself arrived too, not just the end state — a real
    // libsecret-based client relies on this to invalidate its own cache
    // without polling.
    let signal = created
        .next()
        .expect("CollectionCreated must have been emitted for at least one of the two new vaults");
    let args = signal.args().expect("CollectionCreated's argument decodes");
    assert!(
        *args.collection() == collection_path("Personal")
            || *args.collection() == collection_path("Infrastructure"),
        "the signal's argument must be one of the two newly-created collections"
    );

    daemon.assert_no_secrets_leaked();
}

/// A fixture whose every native IPC call is rejected — the simplest
/// possible "this backend is unreachable" stand-in, reused from
/// `secretsd::backend::onepassword::ipc`'s own unit test fixture (not
/// importable directly: that module's fixture helpers are `pub(crate)`,
/// inaccessible from an external integration test).
const ALWAYS_REJECTS_FIXTURE: &str = r#"
#include <stdint.h>
#include <stddef.h>

int op_sdk_ipc_send_message(const uint8_t *req_ptr, size_t req_len,
                             uint8_t **out_buf, size_t *out_len, size_t *out_cap) {
    (void)req_ptr; (void)req_len; (void)out_buf; (void)out_len; (void)out_cap;
    return 7;
}

void op_sdk_ipc_free_response(uint8_t *buf, size_t len, size_t cap) {
    (void)buf; (void)len; (void)cap;
}
"#;

/// Compiles [`ALWAYS_REJECTS_FIXTURE`] into a shared library under `dir`,
/// or `None` (skipping the calling test, not failing it) if no C compiler
/// is available — same convention as the unit-level fixtures this
/// mirrors.
fn compile_always_rejects_fixture(dir: &Path) -> Option<std::path::PathBuf> {
    if std::process::Command::new("cc")
        .arg("--version")
        .output()
        .is_err()
    {
        return None;
    }
    let source_path = dir.join("fixture.c");
    std::fs::write(&source_path, ALWAYS_REJECTS_FIXTURE).unwrap();
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

#[test]
fn a_backend_that_fails_during_topology_discovery_does_not_crash_the_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let Some(fixture_path) = compile_always_rejects_fixture(dir.path()) else {
        eprintln!("skipping: no C compiler available");
        return;
    };

    // `OnePasswordBackend::open` performs no round trip itself (see its
    // own doc comment) — it succeeds even against a fixture that will
    // reject every real call, so `secretsd` starts normally and only the
    // background refresher's first scan (`list_vaults`) actually fails.
    let config = "[backend]\ntype = \"1password\"\naccount_name = \"fixture-account\"\n";
    let fixture_path = fixture_path.to_str().unwrap();
    let daemon =
        TestDaemon::start_with_backend_config(config, &[(LIBRARY_PATH_OVERRIDE_ENV, fixture_path)]);

    // The direct regression guard: `secretsd` is alive and answering
    // `org.secrets.Manager` (which needs no Secret Service topology, and
    // the 1Password backend's `AlwaysUnlocked` lock controller needs no
    // IPC call to answer `Status` either) even though its one and only
    // configured backend cannot be listed at all.
    assert_eq!(daemon.manager().status().unwrap(), "unlocked");

    // The topology itself simply stayed empty — a failed scan is logged,
    // not silently pretended-successful, and never crashes the refresher
    // thread (confirmed by giving it time to have retried at least once
    // more below).
    assert!(daemon.service().collections().unwrap().is_empty());

    std::thread::sleep(Duration::from_millis(200));
    assert!(
        daemon
            .captured_output()
            .contains("Secret Service topology refresh failed"),
        "a failed scan must be logged, not silently swallowed; captured output:\n{}",
        daemon.captured_output()
    );
}
