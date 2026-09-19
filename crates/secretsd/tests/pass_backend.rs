//! End-to-end coverage for the `pass`/`gopass` backend (#26, ADR-019): a
//! real `secretsd` process, configured against the checked-in
//! `gopass`-initialized fixture store (`src/backend/pass/testdata/
//! gopass-fixture/`, generated once with real `gpg`/`gopass` binaries —
//! see that directory's own `README.md`), driven purely over
//! `org.secrets.Manager` — the surface `secrets-cli` itself uses.
//!
//! Unit-level coverage (locked/unlocked field metadata, wrong
//! passphrase, path-traversal rejection, the undecryptable-nested-item
//! fallback, ...) already lives in `backend::pass::backend::tests`; this
//! file only proves the acceptance criterion the unit tests cannot:
//! that this backend is reachable through the real D-Bus wire protocol,
//! wired up exactly the way an operator's own `secretsd.toml` would.

mod support;

use support::TestDaemon;

/// The remote D-Bus error name a `zbus::Error` carries, if it is a method
/// error reply at all — duplicated from `multi_store.rs`'s identical
/// helper (each integration test binary compiles independently, so
/// there is no shared, non-`support`, cross-file module to place this
/// in without widening `support`'s own surface for one helper).
fn dbus_error_name<T>(result: &zbus::Result<T>) -> Option<&str> {
    match result {
        Err(zbus::Error::MethodError(name, ..)) => Some(name.as_str()),
        _ => None,
    }
}

/// The fixture store's own default vault name — `PassBackend`'s
/// zero-config default is the store directory's basename with a single
/// leading `.` stripped, and the checked-in fixture's directory is
/// literally named `store` (no leading dot), so it stays `"store"`
/// unchanged. See `testdata/gopass-fixture/README.md`.
const FIXTURE_VAULT: &str = "store";

/// The fixture secret key's passphrase — see
/// `src/backend/pass/testdata/gopass-fixture/README.md`.
const FIXTURE_PASSPHRASE: &str = "fixture passphrase";

fn pass_backend_config() -> String {
    let fixture_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/backend/pass/testdata/gopass-fixture");
    format!(
        "[store.default]\ntype = \"pass\"\nstore_dir = {:?}\nsecret_key_path = {:?}\n",
        fixture_dir.join("store"),
        fixture_dir.join("key.asc"),
    )
}

#[test]
fn a_pass_backed_store_is_listed_and_queried_end_to_end() {
    let daemon = TestDaemon::start_with_backend_config(&pass_backend_config(), &[]);

    // Starts locked, same as every other real (non-`AlwaysUnlocked`)
    // lock controller — `PassBackend`'s own `LockController` impl,
    // wired through `state::build_store_entry`'s `Pass` arm.
    assert_eq!(daemon.manager().status().unwrap(), "locked");

    // Always store-qualified (`Manager.ListVaults` aggregates across
    // every configured store, ADR-018), even with only one configured.
    let vaults = daemon.manager().list_vaults().unwrap();
    assert_eq!(vaults, vec![format!("default@{FIXTURE_VAULT}")]);

    // Listing works before unlocking (metadata only) — the store's own
    // `.gpg` file names are visible without decrypting anything, exactly
    // like `LocalBackend`'s vault-file metadata.
    let items = daemon.manager().list_items(FIXTURE_VAULT).unwrap();
    assert!(items.iter().any(|item| item.contains("GitHub")));

    daemon
        .unlock(FIXTURE_PASSPHRASE)
        .expect("the fixture's own passphrase unlocks its secret key");
    assert_eq!(daemon.manager().status().unwrap(), "unlocked");

    let uri = format!("secret://{FIXTURE_VAULT}/Personal/GitHub/password");
    assert_eq!(
        daemon.manager().get(&uri).unwrap(),
        "correct horse battery staple"
    );
    daemon
        .manager()
        .resolve(&format!(
            "secret://{FIXTURE_VAULT}/Personal/GitHub/username"
        ))
        .expect("the username field exists on the fixture's GitHub entry");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn an_incorrect_passphrase_is_rejected_over_the_manager_interface() {
    let daemon = TestDaemon::start_with_backend_config(&pass_backend_config(), &[]);

    let result = daemon.manager().unlock("definitely the wrong passphrase");
    // `secretsd::error::DaemonError::IncorrectKeyPassphrase` maps onto
    // the same wire error every other wrong-passphrase case does — see
    // `ManagerIface`'s own `map_lock_error`.
    assert_eq!(
        dbus_error_name(&result),
        Some("org.secrets.Error.PermissionDenied"),
        "expected PermissionDenied, got: {result:?}"
    );
    assert_eq!(daemon.manager().status().unwrap(), "locked");

    daemon.assert_no_secrets_leaked();
}
