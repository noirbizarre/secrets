//! End-to-end integration tests for the `secrets` CLI, over a real
//! `secretsd` binary on a private D-Bus session bus — see issue #4.
//!
//! Every test spawns its own daemon/bus (via `support::TestDaemon` or, for
//! the "daemon absent" case, `support::TestBus` alone) and drives the real
//! `secrets` binary through `assert_cmd` — no in-process shortcuts, so a
//! regression in argument parsing, output formatting, or error mapping
//! shows up the same way it would for a real user.
//!
//! Deliberately **not** re-tested here: the Secret Service wire protocol
//! itself (`crates/secretsd/tests/secret_service.rs`, issue #3) and
//! `demand`'s own masked-prompt rendering (a TTY-only code path this
//! suite's non-interactive stdin cannot exercise — see `support`'s module
//! doc on why piping a line to stdin is still a faithful test of `secrets
//! unlock` itself).
//!
//! Also not re-tested here: `secrets get`'s default refusal to print a
//! secret's value to a real terminal (see ADR-014 and
//! `secrets_cli::output::resolve_get_mode`'s own unit tests) —
//! `assert_cmd`'s pipes are never a real TTY, so every test below that
//! drives `get` with no output flag exercises the *other* branch of that
//! same rule (stdout not a terminal → print the bare value), which is
//! also this suite's existing, unchanged behaviour.

mod support;

use predicates::prelude::*;
use support::{DEMO_PASSPHRASE, DEMO_PASSWORD, DEMO_TOTP, DEMO_USERNAME, TestBus, TestDaemon};

#[test]
fn status_reports_locked_before_any_unlock() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .arg("status")
        .assert()
        .success()
        .stdout("locked\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn unlock_reports_success_and_status_reflects_it() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .arg("unlock")
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success()
        .stdout("unlocked\n");

    daemon
        .cli()
        .arg("status")
        .assert()
        .success()
        .stdout("unlocked\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn unlock_with_the_wrong_passphrase_is_rejected_and_the_store_stays_locked() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .arg("unlock")
        .write_stdin("definitely not the right passphrase\n")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains(
            "incorrect passphrase, or the vault file is corrupted",
        ));

    daemon
        .cli()
        .arg("status")
        .assert()
        .success()
        .stdout("locked\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn lock_relocks_an_unlocked_store() {
    let daemon = TestDaemon::start();
    daemon
        .cli()
        .arg("unlock")
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success();

    daemon
        .cli()
        .arg("lock")
        .assert()
        .success()
        .stdout("locked\n");

    daemon
        .cli()
        .arg("status")
        .assert()
        .success()
        .stdout("locked\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn list_without_a_vault_lists_vault_names_even_while_locked() {
    let daemon = TestDaemon::start();

    // Vault names are metadata, not secret material — listable before the
    // very first `unlock` (see `LocalBackend::list_vaults`'s own doc
    // comment, exercised at the wire level already by issue #3's suite).
    daemon
        .cli()
        .arg("list")
        .assert()
        .success()
        .stdout("default@Infrastructure\ndefault@Personal\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn list_with_a_vault_lists_its_item_paths_even_while_locked() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .args(["list", "Personal"])
        .assert()
        .success()
        .stdout("GitHub\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn list_with_an_unknown_vault_reports_not_found() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .args(["list", "NoSuchVault"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("NoSuchVault"));

    daemon.assert_no_secrets_leaked();
}

#[test]
fn get_while_locked_reports_vault_locked_with_an_unlock_hint() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .args(["get", "secret://Personal/GitHub/password"])
        .assert()
        .failure()
        .code(1)
        .stderr(
            predicate::str::contains("vault 'default@Personal' is locked")
                .and(predicate::str::contains("secrets unlock")),
        );

    daemon.assert_no_secrets_leaked();
}

#[test]
fn get_after_unlock_prints_exactly_the_secret_value_and_nothing_else() {
    let daemon = TestDaemon::start();
    daemon
        .cli()
        .arg("unlock")
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success();

    // The one place a demo secret value is expected to appear anywhere in
    // this suite's assertions — deliberately printed because the user
    // explicitly asked for it via `secrets get`.
    daemon
        .cli()
        .args(["get", "secret://Personal/GitHub/password"])
        .assert()
        .success()
        .stdout(format!("{DEMO_PASSWORD}\n"));

    // The daemon's own logs must still never contain it, even though this
    // very test just asked the CLI to print it.
    daemon.assert_no_secrets_leaked();
}

#[test]
fn get_with_an_unknown_field_reports_not_found() {
    let daemon = TestDaemon::start();
    daemon
        .cli()
        .arg("unlock")
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success();

    daemon
        .cli()
        .args(["get", "secret://Personal/GitHub/does-not-exist"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains(
            "secret not found: secret://default@Personal/GitHub/does-not-exist",
        ));

    daemon.assert_no_secrets_leaked();
}

#[test]
fn resolve_prints_the_canonicalised_uri_and_never_the_value() {
    let daemon = TestDaemon::start();
    daemon
        .cli()
        .arg("unlock")
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success();

    daemon
        .cli()
        .args(["resolve", "secret://Personal/GitHub/password"])
        .assert()
        .success()
        .stdout("secret://Personal/GitHub/password\n")
        .stdout(predicate::str::contains(DEMO_PASSWORD).not());

    daemon.assert_no_secrets_leaked();
}

#[test]
fn show_before_unlock_is_refused() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .args(["show", "secret://Personal/GitHub"])
        .assert()
        .failure()
        .code(1)
        .stderr(
            predicate::str::contains("vault 'default@Personal' is locked")
                .and(predicate::str::contains("secrets unlock")),
        );

    daemon.assert_no_secrets_leaked();
}

#[test]
fn show_after_unlock_reveals_safe_fields_and_obfuscates_secret_fields() {
    let daemon = TestDaemon::start();
    daemon
        .cli()
        .arg("unlock")
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success();

    // Field order is alphabetical (the local backend stores fields in a
    // `BTreeMap`): password, totp, username.
    daemon
        .cli()
        .args(["show", "secret://Personal/GitHub"])
        .assert()
        .success()
        .stdout(format!(
            "password (password): \u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\ntotp (totp): \u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\nusername (username): {DEMO_USERNAME}\n"
        ))
        .stdout(predicate::str::contains(DEMO_PASSWORD).not())
        .stdout(predicate::str::contains(DEMO_TOTP).not());

    daemon.assert_no_secrets_leaked();
}

#[test]
fn show_with_json_has_the_documented_shape() {
    let daemon = TestDaemon::start();
    daemon
        .cli()
        .arg("unlock")
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success();

    let placeholder = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";
    let expected = serde_json::json!({
        "uri": "secret://Personal/GitHub",
        "fields": [
            {"name": "password", "kind": "password", "value": placeholder},
            {"name": "totp", "kind": "totp", "value": placeholder},
            {"name": "username", "kind": "username", "value": DEMO_USERNAME},
        ],
    });

    let assert = daemon
        .cli()
        .args(["show", "secret://Personal/GitHub", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(DEMO_PASSWORD).not())
        .stdout(predicate::str::contains(DEMO_TOTP).not());

    // Compared as parsed JSON, not a raw string: `ShowPayload`'s field
    // declaration order (`uri` then `fields`) need not match `json!`'s
    // sorted-key `Value` rendering for the two to mean the same thing.
    let actual: serde_json::Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("valid JSON");
    assert_eq!(actual, expected);

    daemon.assert_no_secrets_leaked();
}

#[test]
fn show_of_an_unknown_item_is_not_found() {
    let daemon = TestDaemon::start();
    daemon
        .cli()
        .arg("unlock")
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success();

    daemon
        .cli()
        .args(["show", "secret://Personal/does-not-exist"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains(
            "item not found: secret://default@Personal/does-not-exist",
        ));

    daemon.assert_no_secrets_leaked();
}

#[test]
fn get_with_raw_prints_exactly_the_value_regardless_of_stdout() {
    let daemon = TestDaemon::start();
    daemon
        .cli()
        .arg("unlock")
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success();

    // `--raw` is an explicit ask, so it behaves the same whether or not
    // stdout happens to be a terminal — this suite can only drive the
    // "not a terminal" side of that, per this file's own module doc.
    daemon
        .cli()
        .args(["get", "secret://Personal/GitHub/password", "--raw"])
        .assert()
        .success()
        .stdout(format!("{DEMO_PASSWORD}\n"));

    daemon.assert_no_secrets_leaked();
}

#[test]
fn get_with_json_prints_the_uri_and_value_as_json() {
    let daemon = TestDaemon::start();
    daemon
        .cli()
        .arg("unlock")
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success();

    let expected = serde_json::json!({
        "uri": "secret://Personal/GitHub/password",
        "value": DEMO_PASSWORD,
    });

    daemon
        .cli()
        .args(["get", "secret://Personal/GitHub/password", "--json"])
        .assert()
        .success()
        .stdout(format!("{expected}\n"));

    daemon.assert_no_secrets_leaked();
}

#[test]
fn get_with_conflicting_output_flags_is_a_clap_usage_error() {
    // Clap's own `conflicts_with_all` rejects this before
    // `secrets_cli::run` ever sees it — no daemon needed, same rationale
    // as the missing-argument case below.
    let bus = TestBus::start();

    bus.cli()
        .args([
            "get",
            "secret://Personal/GitHub/password",
            "--raw",
            "--json",
        ])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn status_with_json_prints_a_json_object() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .args(["status", "--json"])
        .assert()
        .success()
        .stdout("{\"status\":\"locked\"}\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn list_with_json_prints_vault_names_as_json() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .args(["list", "--json"])
        .assert()
        .success()
        .stdout("{\"vaults\":[\"default@Infrastructure\",\"default@Personal\"]}\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn list_with_a_vault_and_json_prints_item_paths_as_json() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .args(["list", "Personal", "--json"])
        .assert()
        .success()
        .stdout("{\"vault\":\"Personal\",\"items\":[\"GitHub\"]}\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn resolve_with_json_prints_the_uri_as_json() {
    let daemon = TestDaemon::start();
    daemon
        .cli()
        .arg("unlock")
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success();

    daemon
        .cli()
        .args(["resolve", "secret://Personal/GitHub/password", "--json"])
        .assert()
        .success()
        .stdout("{\"uri\":\"secret://Personal/GitHub/password\"}\n")
        .stdout(predicate::str::contains(DEMO_PASSWORD).not());

    daemon.assert_no_secrets_leaked();
}

#[test]
fn resolve_with_a_malformed_uri_reports_invalid_uri() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .args(["resolve", "not-a-secret-uri"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("invalid secret:// reference"));

    daemon.assert_no_secrets_leaked();
}

#[test]
fn commands_report_daemon_unreachable_when_secretsd_is_not_running() {
    // A real, private session bus — just nothing owns `org.secrets.Daemon`
    // on it, which is exactly "the daemon is not running" from a client's
    // point of view.
    let bus = TestBus::start();

    bus.cli().arg("status").assert().failure().code(1).stderr(
        predicate::str::contains("could not reach secretsd on the session bus")
            .and(predicate::str::contains("systemctl --user status secretsd")),
    );
}

#[test]
fn get_with_a_missing_uri_argument_is_a_clap_usage_error() {
    // Clap's own argument-parsing failure — exits before `secrets_cli::run`
    // ever runs, so no daemon or bus is needed at all; `TestBus` is used
    // only so `.cli()` stays the one way every test builds this command.
    let bus = TestBus::start();

    bus.cli()
        .arg("get")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn stores_command_lists_the_default_store_with_its_status() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .arg("stores")
        .assert()
        .success()
        .stdout("default: locked\n");

    daemon
        .cli()
        .arg("unlock")
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success();

    daemon
        .cli()
        .arg("stores")
        .assert()
        .success()
        .stdout("default: unlocked\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn stores_with_json_prints_every_store_and_its_status() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .args(["stores", "--json"])
        .assert()
        .success()
        .stdout("{\"stores\":[{\"id\":\"default\",\"status\":\"locked\"}]}\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn list_with_store_filters_and_strips_the_store_prefix() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .args(["list", "--store", "default"])
        .assert()
        .success()
        .stdout("Infrastructure\nPersonal\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn lock_and_unlock_accept_an_explicit_store_flag() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .args(["unlock", "--store", "default"])
        .write_stdin(format!("{DEMO_PASSPHRASE}\n"))
        .assert()
        .success()
        .stdout("unlocked\n");

    daemon
        .cli()
        .args(["status", "--store", "default"])
        .assert()
        .success()
        .stdout("unlocked\n");

    daemon
        .cli()
        .args(["lock", "--store", "default"])
        .assert()
        .success()
        .stdout("locked\n");

    daemon
        .cli()
        .args(["status", "--store", "default"])
        .assert()
        .success()
        .stdout("locked\n");

    daemon.assert_no_secrets_leaked();
}

#[test]
fn an_explicit_but_unconfigured_store_is_reported_as_not_found() {
    let daemon = TestDaemon::start();

    daemon
        .cli()
        .args(["status", "--store", "ghost"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("no such store: ghost"));

    daemon.assert_no_secrets_leaked();
}
