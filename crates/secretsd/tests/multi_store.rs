//! Integration tests for multi-store support (ADR-018): two configured
//! `local` stores, each with its own seeded demo vault, addressed
//! independently over `org.secrets.Manager` and the standard Secret
//! Service interfaces, with no collisions despite both defining
//! same-named vaults (`"Personal"`, `"Infrastructure"`).
//!
//! Every test here runs a real `secretsd` binary — see
//! `tests/support/mod.rs` for the harness and why.

mod support;

use secrets_core::ItemPath;
use secretsd::secret_service::collection_path;
use support::{STORE_A_PASSPHRASE, TestDaemon};

/// The remote D-Bus error name a `zbus::Error` carries, if it is a method
/// error reply at all — see `secret_service.rs`'s identical helper.
fn dbus_error_name<T>(result: &zbus::Result<T>) -> Option<&str> {
    match result {
        Err(zbus::Error::MethodError(name, ..)) => Some(name.as_str()),
        _ => None,
    }
}

#[test]
fn two_local_stores_are_both_listed_and_independently_locked() {
    let daemon = TestDaemon::start_with_two_local_stores();

    let mut stores = daemon.manager().list_stores().unwrap();
    stores.sort();
    assert_eq!(stores, vec!["a".to_string(), "b".to_string()]);

    // Neither store is unlocked yet.
    assert_eq!(daemon.manager().status_store("a").unwrap(), "locked");
    assert_eq!(daemon.manager().status_store("b").unwrap(), "locked");

    daemon.unlock_store("a", STORE_A_PASSPHRASE).unwrap();

    // Unlocking "a" must not affect "b" — the core per-store lock
    // guarantee ADR-018 exists for.
    assert_eq!(daemon.manager().status_store("a").unwrap(), "unlocked");
    assert_eq!(daemon.manager().status_store("b").unwrap(), "locked");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn list_vaults_returns_every_store_qualified_and_an_unqualified_collision_is_ambiguous() {
    let daemon = TestDaemon::start_with_two_local_stores();

    let mut vaults = daemon.manager().list_vaults().unwrap();
    vaults.sort();
    assert_eq!(
        vaults,
        vec![
            "a@Infrastructure".to_string(),
            "a@Personal".to_string(),
            "b@Infrastructure".to_string(),
            "b@Personal".to_string(),
        ]
    );

    // Unqualified: "Personal" exists in both "a" and "b" — ambiguous.
    let result = daemon.manager().list_items("Personal");
    assert_eq!(
        dbus_error_name(&result),
        Some("org.secrets.Error.AmbiguousVault"),
        "expected AmbiguousVault, got: {result:?}"
    );

    // Store-qualified: unambiguous, resolves to exactly that store.
    let items = daemon.manager().list_items("a@Personal").unwrap();
    assert!(items.contains(&"GitHub".to_string()));

    daemon.assert_no_secrets_leaked();
}

#[test]
fn two_stores_with_a_colliding_vault_name_are_reachable_at_distinct_collection_paths() {
    let daemon = TestDaemon::start_with_two_local_stores();

    let store_a = secrets_core::StoreId::new("a").unwrap();
    let store_b = secrets_core::StoreId::new("b").unwrap();
    let personal_a = collection_path(&store_a, "Personal");
    let personal_b = collection_path(&store_b, "Personal");

    // Nested-by-store paths are structurally distinct even though both
    // name the same vault — this is the whole point of ADR-018's
    // `/collection/<store>/<vault>` scheme.
    assert_ne!(personal_a, personal_b);

    daemon.wait_until_collections(&[
        personal_a.clone(),
        collection_path(&store_a, "Infrastructure"),
        personal_b.clone(),
        collection_path(&store_b, "Infrastructure"),
    ]);

    assert_eq!(daemon.collection(&personal_a).label().unwrap(), "Personal");
    assert_eq!(daemon.collection(&personal_b).label().unwrap(), "Personal");

    // Independently locked/unlocked (ADR-018 supersedes ADR-009's
    // "daemon-wide, not per-vault" framing on this exact point). A fresh
    // proxy is built either side of the state change — `Collection`'s
    // `Locked` property is not a caching-safe read across a mutation
    // this MVP never emits `PropertiesChanged` for (ADR-015's
    // documented gap), the same pattern `secret_service.rs`'s own tests
    // use throughout.
    assert!(daemon.collection(&personal_a).locked().unwrap());
    assert!(daemon.collection(&personal_b).locked().unwrap());
    daemon.unlock_store("a", STORE_A_PASSPHRASE).unwrap();
    assert!(
        !daemon.collection(&personal_a).locked().unwrap(),
        "store \"a\" is now unlocked"
    );
    assert!(
        daemon.collection(&personal_b).locked().unwrap(),
        "store \"b\" is untouched"
    );

    // Each collection's own items are its own — never the other store's,
    // despite sharing a vault name.
    let github = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
    let item_a = daemon.item(&secretsd::secret_service::item_path(
        &store_a, "Personal", &github, "password",
    ));
    let item_b = daemon.item(&secretsd::secret_service::item_path(
        &store_b, "Personal", &github, "password",
    ));
    assert!(!item_a.locked().unwrap());
    assert!(item_b.locked().unwrap());

    daemon.assert_no_secrets_leaked();
}

#[test]
fn a_legacy_backend_table_is_rejected_and_logged_actionably() {
    // `secretsd` exits before ever reaching D-Bus setup on a config
    // error (see `main.rs`), so `TestDaemon::start_with_backend_config`
    // itself panics (via `wait_until_ready`'s early-exit check) with the
    // captured output attached — catch that panic and inspect its
    // message instead of asserting on a running daemon that was never
    // supposed to start.
    let panic_message = std::panic::catch_unwind(|| {
        let _ = TestDaemon::start_with_backend_config("[backend]\ntype = \"local\"\n", &[]);
    })
    .expect_err("a daemon rejecting its own config must exit before becoming reachable");
    let message = panic_message
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic_message.downcast_ref::<&str>().copied())
        .expect("the panic carries a string message");
    assert!(
        message.contains("[store.default]") && message.contains("ADR-018"),
        "expected the [backend]-removal migration message in secretsd's own log output, got:\n{message}"
    );
}
