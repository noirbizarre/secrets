//! Opt-in, end-to-end smoke test: `secrets status`/`list`/`get`/`resolve`
//! against a **real, installed 1Password Desktop** — the acceptance
//! criteria from issue #7, driven through the real `secrets` binary the
//! same way `end_to_end.rs` (issue #4) does for the local backend.
//!
//! `#[ignore]`d — never run in CI (no 1Password Desktop to authorize
//! against there), and **never with production credentials**: point the
//! env vars below at a dedicated development vault/item you control (see
//! `docs/backends/1password.md`), never a real personal or work vault.
//!
//! Run manually:
//!
//! ```text
//! SECRETS_OP_ACCOUNT_NAME="<account name>" \
//! SECRETS_OP_TEST_VAULT="<vault>" \
//! SECRETS_OP_TEST_ITEM="<item>" \
//! SECRETS_OP_TEST_FIELD="<field>" \
//! cargo test -p secrets-cli --test onepassword_smoke -- --ignored --nocapture
//! ```
//!
//! Optionally, also set `SECRETS_OP_TEST_SSH_ITEM`/`SECRETS_OP_TEST_SSH_FIELD`
//! to point at an `SshKey`-typed item/field in the same vault: this
//! actively confirms (or disproves) the assumption `secretsd::ssh_agent`
//! relies on — that 1Password resolves such a field as OpenSSH-formatted
//! text — against a real SSH item for the first time (see
//! `backend::onepassword::backend::field_kind`'s own doc comment).

mod support;

use support::TestDaemon;

/// Reads a required env var, panicking with a message that names this
/// opt-in test's own setup requirement rather than a bare `unwrap`.
fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("set {name} to run this opt-in test — see this test's own doc comment")
    })
}

#[test]
#[ignore = "requires a real, installed, unlocked 1Password Desktop with \"Integrate with other apps\" enabled, and a dedicated development vault/item — see docs/backends/1password.md"]
fn secrets_status_list_get_and_resolve_work_against_1password_desktop() {
    let account = required_env("SECRETS_OP_ACCOUNT_NAME");
    let vault = required_env("SECRETS_OP_TEST_VAULT");
    let item = required_env("SECRETS_OP_TEST_ITEM");
    let field = required_env("SECRETS_OP_TEST_FIELD");
    let uri = format!("secret://{vault}/{item}/{field}");

    // May block here for up to 60s if 1Password Desktop needs a human to
    // approve its "Integrate with other apps" prompt — see
    // `TestDaemon::start_with_1password`'s own doc comment.
    let daemon = TestDaemon::start_with_1password(&account);

    // 1Password Desktop has no daemon-wide passphrase lock of its own
    // (`AlwaysUnlocked` — see `state.rs`); "unlocked" here confirms the
    // daemon started and its own session is authenticated, not that a
    // passphrase was ever entered.
    daemon
        .cli()
        .arg("status")
        .assert()
        .success()
        .stdout("unlocked\n");

    daemon
        .cli()
        .args(["list", &vault])
        .assert()
        .success()
        .stdout(predicates::str::contains(item.as_str()));

    daemon
        .cli()
        .args(["resolve", &uri])
        .assert()
        .success()
        .stdout(format!("{uri}\n"));

    let output = daemon
        .cli()
        .args(["get", &uri, "--raw"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = String::from_utf8(output).expect("the resolved value is valid UTF-8");
    let value = value.trim_end_matches('\n');
    assert!(!value.is_empty(), "the resolved value must not be empty");

    // The one place this test's own resolved value is allowed to appear —
    // `secretsd`'s own logs must never contain it, exactly like
    // `end_to_end.rs`'s `assert_no_secrets_leaked` for the local backend's
    // fixed demo values, just parameterized on a value only known at
    // runtime here.
    let captured = daemon.captured_output();
    assert!(
        !captured.contains(value),
        "secretsd's own log output contained the resolved 1Password value"
    );

    // Optional, best-effort: confirms the SSH-key field format assumption
    // `secretsd::ssh_agent` relies on, if the caller also pointed this
    // test at a real SSH item.
    if let (Ok(ssh_item), Ok(ssh_field)) = (
        std::env::var("SECRETS_OP_TEST_SSH_ITEM"),
        std::env::var("SECRETS_OP_TEST_SSH_FIELD"),
    ) {
        let ssh_uri = format!("secret://{vault}/{ssh_item}/{ssh_field}");
        let output = daemon
            .cli()
            .args(["get", &ssh_uri, "--raw"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let ssh_value = String::from_utf8(output).expect("the resolved SSH value is valid UTF-8");
        assert!(
            ssh_value
                .trim_start()
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"),
            "1Password's SshKey field value did not look like an OpenSSH private key — \
             see `backend::onepassword::backend::field_kind`'s doc comment on this open question",
        );
    }
}
