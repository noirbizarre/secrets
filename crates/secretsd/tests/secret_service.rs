//! Automated integration tests for `secretsd`'s standard
//! [freedesktop Secret Service](https://specifications.freedesktop.org/secret-service/latest/)
//! D-Bus surface — replacing the manual `dbus-run-session` validation
//! `PLAN.md` previously documented (issue #3).
//!
//! Every test here runs a real `secretsd` binary on a private D-Bus
//! session bus, over an isolated, temporary local-backend vault — see
//! `tests/support/mod.rs` for the harness and why it shells out to the
//! real binary rather than driving `DaemonState` in-process.
//!
//! Deliberately **not** covered here: `org.secrets.Manager`. Per the
//! issue and `docs/dbus/secrets-manager.md`, that is the extension
//! namespace, not the compatibility contract — it is only used below to
//! unlock/lock the daemon, the one thing the Secret Service interfaces
//! cannot do on their own (see `docs/dbus/secret-service.md`).

mod support;

use std::collections::{HashMap, HashSet};

use secrets_core::ItemPath;
use secrets_core::dbus::{STATUS_LOCKED, STATUS_UNLOCKED};
use secretsd::prompt::broker::PROMPT_TIMEOUT_OVERRIDE_ENV;
use secretsd::secret_service::{ALIAS_DEFAULT_PATH, SESSION_PATH, collection_path, item_path};
use support::{DEMO_PASSPHRASE, DEMO_PASSWORD, DEMO_TOTP, DEMO_USERNAME, MockProvider, TestDaemon};
use zbus::zvariant::{OwnedObjectPath, Value};

/// The demo vault's fixed object paths (see `LocalBackend::seed_demo_vault`
/// and `secretsd::secret_service`'s slugging scheme) — computed through
/// the same helpers `secretsd` itself uses to build its topology, so a
/// test failure here means the *wire* path a real client observed
/// disagrees with them, not that this file duplicated the slugging logic
/// incorrectly.
struct DemoTopology {
    personal: OwnedObjectPath,
    infrastructure: OwnedObjectPath,
    github_username: OwnedObjectPath,
    github_password: OwnedObjectPath,
    github_totp: OwnedObjectPath,
    production_ssh_key: OwnedObjectPath,
}

fn demo_topology() -> DemoTopology {
    let github = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
    let production = ItemPath::new(vec!["Production".to_string()]).unwrap();
    DemoTopology {
        personal: collection_path("Personal"),
        infrastructure: collection_path("Infrastructure"),
        github_username: item_path("Personal", &github, "username"),
        github_password: item_path("Personal", &github, "password"),
        github_totp: item_path("Personal", &github, "totp"),
        production_ssh_key: item_path("Infrastructure", &production, "ssh-key"),
    }
}

/// Open a "plain" session the way a real client would, for calls that
/// need a session object path (`Item.GetSecret`, `Service.GetSecrets`).
fn open_plain_session(daemon: &TestDaemon) -> OwnedObjectPath {
    let (_output, session) = daemon
        .service()
        .open_session("plain", &Value::from(""))
        .expect("OpenSession(\"plain\", ...) always succeeds");
    session
}

/// The remote D-Bus error name a `zbus::Error` carries, if it is a method
/// error reply at all.
///
/// A plain `zbus::Result<T>` proxy return type (used throughout
/// `support::proxies`, matching `secrets_core::dbus::Manager`'s own
/// convention) never decodes a method error reply into a `zbus::fdo::
/// Error` variant on its own — that only happens for proxy methods
/// declared to return `zbus::fdo::Result<T>`. Comparing the error *name*
/// string directly is therefore the correct way to assert on a standard
/// `org.freedesktop.DBus.Error.*` reply here, not a workaround.
fn dbus_error_name<T>(result: &zbus::Result<T>) -> Option<&str> {
    match result {
        Err(zbus::Error::MethodError(name, ..)) => Some(name.as_str()),
        _ => None,
    }
}

/// Assert a D-Bus call failed with `org.freedesktop.DBus.Error.NotSupported`
/// — the error every unimplemented write operation returns (see
/// `docs/dbus/secret-service.md`'s "What does not work").
fn assert_not_supported<T: std::fmt::Debug>(result: zbus::Result<T>) {
    assert_eq!(
        dbus_error_name(&result),
        Some("org.freedesktop.DBus.Error.NotSupported"),
        "expected org.freedesktop.DBus.Error.NotSupported, got: {result:?}"
    );
}

/// Assert a D-Bus call failed with `org.freedesktop.DBus.Error.Failed` —
/// what a locked-resource read returns (there is no dedicated
/// "VaultLocked" error on this standard interface; see
/// `docs/dbus/secret-service.md`'s "Errors" section).
fn assert_failed<T: std::fmt::Debug>(result: zbus::Result<T>) {
    assert_eq!(
        dbus_error_name(&result),
        Some("org.freedesktop.DBus.Error.Failed"),
        "expected org.freedesktop.DBus.Error.Failed, got: {result:?}"
    );
}

#[test]
fn collections_and_items_are_enumerable_and_stable_while_locked() {
    let daemon = TestDaemon::start();
    let topology = demo_topology();
    // The live topology (ADR-015) populates in the background, not
    // synchronously with `start()` returning — wait for the demo vault's
    // collections specifically before asserting anything about them.
    daemon.wait_until_collections(&[topology.personal.clone(), topology.infrastructure.clone()]);

    // Vault/item *names* are metadata, not secret material — available
    // even before the very first `Unlock` (see `LocalBackend::
    // list_vaults`/`list_items`'s own doc comments).
    let collections: HashSet<_> = daemon
        .service()
        .collections()
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(
        collections,
        HashSet::from([topology.personal.clone(), topology.infrastructure.clone()])
    );

    let personal = daemon.collection(&topology.personal);
    assert_eq!(personal.label().unwrap(), "Personal");
    assert!(personal.locked().unwrap(), "never unlocked yet");
    let items: HashSet<_> = personal
        .search_items(HashMap::new())
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(
        items,
        HashSet::from([
            topology.github_username.clone(),
            topology.github_password.clone(),
            topology.github_totp.clone()
        ])
    );

    let password_item = daemon.item(&topology.github_password);
    assert!(password_item.locked().unwrap());
    assert_eq!(password_item.label().unwrap(), "GitHub (password)");
    assert_eq!(
        password_item.attributes().unwrap(),
        HashMap::from([
            ("vault".to_string(), "Personal".to_string()),
            ("item".to_string(), "GitHub".to_string()),
            ("field".to_string(), "password".to_string()),
        ])
    );

    daemon.assert_no_secrets_leaked();
}

#[test]
fn reading_a_secret_while_locked_fails_and_reflects_locked_everywhere() {
    let daemon = TestDaemon::start();
    let topology = demo_topology();
    // The live topology (ADR-015) populates in the background, not
    // synchronously with `start()` returning — wait for the demo vault's
    // collections specifically before asserting anything about them.
    daemon.wait_until_collections(&[topology.personal.clone(), topology.infrastructure.clone()]);
    let session = open_plain_session(&daemon);

    assert_failed(
        daemon
            .item(&topology.github_password)
            .get_secret(session.clone()),
    );
    assert_failed(
        daemon
            .service()
            .get_secrets(vec![topology.github_password.clone()], session),
    );

    daemon.assert_no_secrets_leaked();
}

#[test]
fn unlocking_reveals_secrets_and_locking_hides_them_again() {
    let daemon = TestDaemon::start();
    let topology = demo_topology();
    // The live topology (ADR-015) populates in the background, not
    // synchronously with `start()` returning — wait for the demo vault's
    // collections specifically before asserting anything about them.
    daemon.wait_until_collections(&[topology.personal.clone(), topology.infrastructure.clone()]);

    daemon
        .unlock(DEMO_PASSPHRASE)
        .expect("unlock with the seeded passphrase");

    let session = open_plain_session(&daemon);
    let password_item = daemon.item(&topology.github_password);
    assert!(!password_item.locked().unwrap());
    assert!(!daemon.collection(&topology.personal).locked().unwrap());

    let secret = password_item.get_secret(session.clone()).unwrap();
    assert_eq!(secret.value, DEMO_PASSWORD.as_bytes());
    assert_eq!(secret.content_type, "text/plain");

    let batch = daemon
        .service()
        .get_secrets(
            vec![
                topology.github_username.clone(),
                topology.github_totp.clone(),
            ],
            session,
        )
        .unwrap();
    assert_eq!(
        batch.get(&topology.github_username).unwrap().value,
        DEMO_USERNAME.as_bytes()
    );
    assert_eq!(
        batch.get(&topology.github_totp).unwrap().value,
        DEMO_TOTP.as_bytes()
    );

    daemon.lock();
    assert!(daemon.item(&topology.github_password).locked().unwrap());
    assert_failed(
        daemon
            .item(&topology.github_password)
            .get_secret(open_plain_session(&daemon)),
    );

    daemon.assert_no_secrets_leaked();
}

#[test]
fn unlocking_with_the_wrong_passphrase_is_rejected_and_the_store_stays_locked() {
    let daemon = TestDaemon::start();
    let topology = demo_topology();
    // The live topology (ADR-015) populates in the background, not
    // synchronously with `start()` returning — wait for the demo vault's
    // collections specifically before asserting anything about them.
    daemon.wait_until_collections(&[topology.personal.clone(), topology.infrastructure.clone()]);

    let error = daemon
        .unlock("definitely not the right passphrase")
        .unwrap_err();
    assert!(
        matches!(error, secrets_core::dbus::ManagerError::PermissionDenied(_)),
        "expected PermissionDenied, got: {error:?}"
    );
    assert!(daemon.collection(&topology.personal).locked().unwrap());

    daemon.assert_no_secrets_leaked();
}

#[test]
fn search_items_splits_matches_by_lock_state_and_reports_none_for_unknown_attributes() {
    let daemon = TestDaemon::start();
    let topology = demo_topology();
    // The live topology (ADR-015) populates in the background, not
    // synchronously with `start()` returning — wait for the demo vault's
    // collections specifically before asserting anything about them.
    daemon.wait_until_collections(&[topology.personal.clone(), topology.infrastructure.clone()]);

    // Locked: every match lands in the "locked" half of the tuple.
    let (unlocked, locked) = daemon
        .service()
        .search_items(HashMap::from([(
            "field".to_string(),
            "password".to_string(),
        )]))
        .unwrap();
    assert!(unlocked.is_empty());
    assert_eq!(locked, vec![topology.github_password.clone()]);

    // An attribute set matching nothing: empty on both sides, not an
    // error — this is the "missing item" case for a search-based lookup.
    let (unlocked, locked) = daemon
        .service()
        .search_items(HashMap::from([(
            "field".to_string(),
            "does-not-exist".to_string(),
        )]))
        .unwrap();
    assert!(unlocked.is_empty() && locked.is_empty());

    daemon.unlock(DEMO_PASSPHRASE).unwrap();

    // Unlocked: the same match now lands in the "unlocked" half instead.
    let (unlocked, locked) = daemon
        .service()
        .search_items(HashMap::from([(
            "vault".to_string(),
            "Infrastructure".to_string(),
        )]))
        .unwrap();
    assert_eq!(unlocked, vec![topology.production_ssh_key.clone()]);
    assert!(locked.is_empty());

    daemon.assert_no_secrets_leaked();
}

#[test]
fn get_secrets_silently_omits_object_paths_outside_the_known_topology() {
    let daemon = TestDaemon::start();
    let topology = demo_topology();
    // The live topology (ADR-015) populates in the background, not
    // synchronously with `start()` returning — wait for the demo vault's
    // collections specifically before asserting anything about them.
    daemon.wait_until_collections(&[topology.personal.clone(), topology.infrastructure.clone()]);
    daemon.unlock(DEMO_PASSPHRASE).unwrap();
    let session = open_plain_session(&daemon);

    // A well-formed but nonexistent `Item` path — not a collection/item
    // this vault ever registered. This is "missing item" for the batch
    // API: silently absent from the result, not an error (matches
    // `ServiceIface::get_secrets`'s own documented behaviour).
    let bogus: OwnedObjectPath = "/org/freedesktop/secrets/collection/personal/does_not_exist"
        .try_into()
        .unwrap();

    let batch = daemon
        .service()
        .get_secrets(
            vec![topology.github_password.clone(), bogus.clone()],
            session,
        )
        .unwrap();
    assert!(batch.contains_key(&topology.github_password));
    assert!(!batch.contains_key(&bogus));

    daemon.assert_no_secrets_leaked();
}

#[test]
fn the_default_alias_resolves_to_the_first_vault_alphabetically() {
    let daemon = TestDaemon::start();
    let topology = demo_topology();
    // The live topology (ADR-015) populates in the background, not
    // synchronously with `start()` returning — wait for the demo vault's
    // collections specifically before asserting anything about them.
    daemon.wait_until_collections(&[topology.personal.clone(), topology.infrastructure.clone()]);

    // `LocalBackend::list_vaults` iterates a `BTreeMap`, so "Infrastructure"
    // sorts before "Personal" — asserted explicitly because a client
    // relying on `ReadAlias("default")` needs this to be *stable*, not
    // just "some vault".
    let alias_target = daemon.service().read_alias("default").unwrap();
    assert_eq!(alias_target, topology.infrastructure);

    // Also reachable at its own literal well-known path (spec §4/§12),
    // and it must be the very same collection.
    let default_alias_path: OwnedObjectPath = ALIAS_DEFAULT_PATH.try_into().unwrap();
    let via_alias_path = daemon.collection(&default_alias_path);
    let via_real_path = daemon.collection(&topology.infrastructure);
    assert_eq!(
        via_alias_path.items().unwrap(),
        via_real_path.items().unwrap()
    );

    // No other alias is recognised in this MVP: `ServiceIface::read_alias`
    // falls back to the root path.
    let root: OwnedObjectPath = "/".try_into().unwrap();
    assert_eq!(daemon.service().read_alias("unknown-alias").unwrap(), root);

    daemon.assert_no_secrets_leaked();
}

#[test]
fn every_write_operation_is_rejected_as_not_supported() {
    let daemon = TestDaemon::start();
    let topology = demo_topology();
    // The live topology (ADR-015) populates in the background, not
    // synchronously with `start()` returning — wait for the demo vault's
    // collections specifically before asserting anything about them.
    daemon.wait_until_collections(&[topology.personal.clone(), topology.infrastructure.clone()]);
    let service = daemon.service();

    assert_not_supported(service.create_collection(HashMap::new(), ""));
    assert_not_supported(service.set_alias("default", topology.personal.clone()));

    // `Secret` derives neither `Clone` nor `Copy` (it is the same wire
    // type `secretsd` itself serves, kept minimal on purpose) — built
    // fresh for each attempted write rather than shared.
    fn attempted_write_secret() -> secretsd::secret_service::Secret {
        secretsd::secret_service::Secret {
            session: SESSION_PATH.try_into().unwrap(),
            parameters: Vec::new(),
            value: b"attempted write".to_vec(),
            content_type: "text/plain".to_string(),
        }
    }

    let collection = daemon.collection(&topology.personal);
    assert_not_supported(collection.create_item(HashMap::new(), attempted_write_secret(), false));
    assert_not_supported(collection.delete());

    let item = daemon.item(&topology.github_password);
    assert_not_supported(item.set_secret(attempted_write_secret()));
    assert_not_supported(item.delete());

    daemon.assert_no_secrets_leaked();
}

#[test]
fn open_session_only_accepts_the_plain_algorithm() {
    let daemon = TestDaemon::start();
    let service = daemon.service();

    let (_output, session) = service.open_session("plain", &Value::from("")).unwrap();
    assert_eq!(session, OwnedObjectPath::try_from(SESSION_PATH).unwrap());

    assert_not_supported(
        service.open_session("dh-ietf1024-sha256-aes128-cbc-pkcs7", &Value::from("")),
    );

    daemon.assert_no_secrets_leaked();
}

#[test]
fn session_close_and_prompt_dismiss_are_harmless_no_ops() {
    let daemon = TestDaemon::start();

    daemon
        .session_object()
        .close()
        .expect("Session.Close is a no-op");
    daemon
        .prompt()
        .dismiss()
        .expect("Prompt.Dismiss is a no-op");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn prompting_immediately_reports_itself_dismissed() {
    let daemon = TestDaemon::start();
    let prompt = daemon.prompt();

    // Subscribe before calling `Prompt()`, so the signal — emitted
    // synchronously from inside that same call, per `PromptIface::prompt`
    // — cannot arrive before this iterator exists to catch it.
    let mut signals = prompt.receive_completed().expect("subscribe to Completed");
    prompt.prompt("").expect("Prompt() never fails in this MVP");

    let signal = signals
        .next()
        .expect("Completed is always emitted, immediately, by PromptIface::prompt");
    let args = signal.args().expect("Completed's arguments always decode");
    assert!(
        *args.dismissed(),
        "there is no GUI agent in this MVP to leave a prompt open"
    );

    daemon.assert_no_secrets_leaked();
}

#[test]
fn ssh_key_field_decrypts_to_a_valid_ed25519_private_key_and_never_leaks_to_logs() {
    let daemon = TestDaemon::start();
    let topology = demo_topology();
    // The live topology (ADR-015) populates in the background, not
    // synchronously with `start()` returning — wait for the demo vault's
    // collections specifically before asserting anything about them.
    daemon.wait_until_collections(&[topology.personal.clone(), topology.infrastructure.clone()]);
    daemon.unlock(DEMO_PASSPHRASE).unwrap();
    let session = open_plain_session(&daemon);

    let secret = daemon
        .item(&topology.production_ssh_key)
        .get_secret(session)
        .unwrap();
    let openssh =
        String::from_utf8(secret.value).expect("the demo SSH key is stored as UTF-8 PEM text");
    let key = ssh_key::PrivateKey::from_openssh(&openssh).expect("a valid OpenSSH private key");
    assert_eq!(key.algorithm(), ssh_key::Algorithm::Ed25519);

    // Generated fresh per test run (see `LocalBackend::
    // generate_demo_ssh_key`), so it cannot be a fixed constant in
    // `support` the way the other demo secrets are — checked here,
    // against the exact value this test just fetched, instead.
    assert!(
        !daemon.captured_output().contains(&openssh),
        "secretsd's own log output contained the demo SSH private key"
    );
}

#[test]
fn secretsd_shuts_down_promptly_on_sigterm() {
    let daemon = TestDaemon::start();
    // Exercise a bit of the daemon before asking it to stop, so a
    // shutdown-path regression that only shows up mid-session (e.g. a
    // handler that blocks in a `Mutex` used elsewhere) has a chance to
    // surface.
    daemon.unlock(DEMO_PASSPHRASE).unwrap();

    daemon.assert_shuts_down_cleanly();
}

// Prompt broker / provider protocol (ADR-017, issue #21). Every test
// below starts a `TestDaemon` deliberately left locked (`start()` seeds
// the demo vault's *file* but never calls the spawned daemon's own
// `unlock` — see `state.rs`'s own `a_fresh_state_reports_locked_before_
// unlocking` test for why that leaves it locked in memory), so
// `Service.Unlock` reaches the "daemon's own passphrase lock is the
// blocker" branch that starts a real prompt (see
// `secret_service::prompt::UnlockPrompt::begin`).

#[test]
fn unlocking_through_a_registered_provider_relays_the_passphrase_and_completes() {
    let daemon = TestDaemon::start();
    let provider = MockProvider::register(daemon.bus_address(), &["unlock"], 0);

    // Subscribe before calling `Prompt()`, so the signal — emitted from
    // whichever thread resolves the request, not synchronously from this
    // call — cannot arrive before this iterator exists to catch it (same
    // reasoning as `prompting_immediately_reports_itself_dismissed`).
    let mut completed = daemon
        .prompt()
        .receive_completed()
        .expect("subscribe to Completed");

    let (unlocked, _prompt) = daemon
        .service()
        .unlock(vec![])
        .expect("Service.Unlock never fails");
    assert!(
        unlocked.is_empty(),
        "still locked at the moment Unlock is called"
    );

    daemon
        .prompt()
        .prompt("")
        .expect("Prompt() never fails, provider or not");

    let request = provider.wait_for_request();
    assert_eq!(request.kind().unwrap(), "unlock");
    request
        .respond(Value::from(DEMO_PASSPHRASE))
        .expect("respond with the correct passphrase");

    let signal = completed
        .next()
        .expect("Completed is emitted once the provider answers");
    let args = signal.args().expect("Completed's arguments always decode");
    assert!(
        !*args.dismissed(),
        "a correct passphrase must report success, not dismissed"
    );
    assert_eq!(
        daemon.manager().status().unwrap(),
        STATUS_UNLOCKED,
        "the passphrase must actually have unlocked the daemon, not just dismissed the prompt"
    );

    daemon.assert_no_secrets_leaked();
}

#[test]
fn declining_the_unlock_prompt_leaves_the_daemon_locked() {
    let daemon = TestDaemon::start();
    let provider = MockProvider::register(daemon.bus_address(), &["unlock"], 0);
    let mut completed = daemon
        .prompt()
        .receive_completed()
        .expect("subscribe to Completed");

    daemon
        .service()
        .unlock(vec![])
        .expect("Service.Unlock never fails");
    daemon.prompt().prompt("").expect("Prompt() never fails");

    provider
        .wait_for_request()
        .decline()
        .expect("decline the request");

    let signal = completed
        .next()
        .expect("Completed is emitted once the provider declines");
    assert!(*signal.args().unwrap().dismissed());
    assert_eq!(daemon.manager().status().unwrap(), STATUS_LOCKED);
    daemon.assert_no_secrets_leaked();
}

#[test]
fn a_vanished_provider_mid_prompt_reports_dismissed_deterministically() {
    let daemon = TestDaemon::start();
    let provider = MockProvider::register(daemon.bus_address(), &["unlock"], 0);
    let mut completed = daemon
        .prompt()
        .receive_completed()
        .expect("subscribe to Completed");

    daemon
        .service()
        .unlock(vec![])
        .expect("Service.Unlock never fails");
    daemon.prompt().prompt("").expect("Prompt() never fails");

    // The provider is notified, then disappears without ever answering —
    // `secretsd::prompt::watcher` must detect the connection closing and
    // resolve the request deterministically rather than leaving it
    // pending forever. The request proxy itself borrows `provider`'s
    // connection, so it must be dropped before `vanish` can consume it.
    drop(provider.wait_for_request());
    provider.vanish();

    let signal = completed
        .next()
        .expect("Completed is emitted once the vanished provider is detected");
    assert!(*signal.args().unwrap().dismissed());
    assert_eq!(daemon.manager().status().unwrap(), STATUS_LOCKED);
    daemon.assert_no_secrets_leaked();
}

#[test]
fn an_unanswered_unlock_prompt_times_out_and_reports_dismissed() {
    // `PROMPT_TIMEOUT_OVERRIDE_ENV` shrinks the otherwise real-world-scale
    // timeout so this test stays fast — a real deployment never sets it.
    let daemon = TestDaemon::start_with_env(&[(PROMPT_TIMEOUT_OVERRIDE_ENV, "300")]);
    let provider = MockProvider::register(daemon.bus_address(), &["unlock"], 0);
    let mut completed = daemon
        .prompt()
        .receive_completed()
        .expect("subscribe to Completed");

    daemon
        .service()
        .unlock(vec![])
        .expect("Service.Unlock never fails");
    daemon.prompt().prompt("").expect("Prompt() never fails");

    // The provider is notified and simply never responds.
    let _request = provider.wait_for_request();

    let signal = completed
        .next()
        .expect("Completed is emitted once the shortened timeout elapses");
    assert!(*signal.args().unwrap().dismissed());
    assert_eq!(daemon.manager().status().unwrap(), STATUS_LOCKED);
    daemon.assert_no_secrets_leaked();
}

#[test]
fn unlocking_with_no_registered_provider_still_behaves_like_the_original_mvp() {
    // Regression guard for ADR-017's "a headless secretsd remains
    // functional" acceptance criterion: with no provider registered at
    // all, `Service.Unlock` followed by `Prompt.Prompt` must still
    // dismiss immediately, exactly like before this feature existed.
    let daemon = TestDaemon::start();
    let mut completed = daemon
        .prompt()
        .receive_completed()
        .expect("subscribe to Completed");

    let (unlocked, _prompt) = daemon
        .service()
        .unlock(vec![])
        .expect("Service.Unlock never fails");
    assert!(unlocked.is_empty());

    daemon.prompt().prompt("").expect("Prompt() never fails");

    let signal = completed
        .next()
        .expect("Completed is always emitted, immediately, with no provider registered");
    assert!(*signal.args().unwrap().dismissed());
    assert_eq!(daemon.manager().status().unwrap(), STATUS_LOCKED);
    daemon.assert_no_secrets_leaked();
}

#[test]
fn a_provider_can_register_and_unregister_explicitly() {
    let daemon = TestDaemon::start();
    let provider = MockProvider::register(daemon.bus_address(), &["unlock"], 0);
    // Explicit unregistration, not a vanish — verifies
    // `org.secrets.PromptBroker1.UnregisterProvider` itself works, over
    // the real wire, distinctly from the "connection closed" path the
    // vanish test above covers.
    provider.unregister();

    // With no provider registered anymore, a fresh Unlock/Prompt pair
    // must fall back to the original, immediately-dismissed behaviour.
    let mut completed = daemon
        .prompt()
        .receive_completed()
        .expect("subscribe to Completed");
    daemon
        .service()
        .unlock(vec![])
        .expect("Service.Unlock never fails");
    daemon.prompt().prompt("").expect("Prompt() never fails");
    let signal = completed.next().expect("Completed is emitted immediately");
    assert!(*signal.args().unwrap().dismissed());

    daemon.assert_no_secrets_leaked();
}
