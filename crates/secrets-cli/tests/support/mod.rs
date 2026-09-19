//! A harness that runs a real `secrets` binary against a real `secretsd`
//! binary, over a private D-Bus session bus and an isolated local-backend
//! vault — see issue #4.
//!
//! Unlike `crates/secretsd/tests/support` (built for issue #3), this
//! harness never speaks D-Bus/`zbus` itself: every interaction, including
//! `unlock`, goes through the `secrets` binary under test, because that
//! wire-level coverage already exists in `secretsd`'s own suite — the point
//! here is the CLI's argument parsing, output formatting and error mapping,
//! not the protocol underneath it.
//!
//! Two binaries are involved, resolved two different ways:
//! - `secrets` is in the *same* Cargo package as these tests, so
//!   `assert_cmd::cargo::cargo_bin` finds it via the `CARGO_BIN_EXE_secrets`
//!   environment variable Cargo sets automatically.
//! - `secretsd` is a *different* package. `CARGO_BIN_EXE_secretsd` is never
//!   set here — verified empirically that Cargo only sets `CARGO_BIN_EXE_*`
//!   for binaries in the same package as the test, even across a `path`
//!   dev-dependency, even under `cargo test --workspace` — so it is built
//!   and located explicitly with `escargot` instead, which works
//!   regardless of whether `secrets-cli`'s tests are run in isolation or as
//!   part of the whole workspace.
//!
//! Shared by more than one test binary (`end_to_end.rs`, `onepassword_smoke.rs`,
//! ...), each of which `mod support;`s and compiles its own copy — so
//! `dead_code` fires per binary for whichever items only the *other* one
//! uses (e.g. `start_with_1password` is dead from `end_to_end.rs`'s point
//! of view). Silenced crate-wide here rather than item-by-item, since
//! which items are "unused" depends on which binary is compiling this
//! module, not on this module itself.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command as StdCommand, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use tempfile::TempDir;

/// The passphrase every [`TestDaemon`] seeds its vault with. Any value
/// works on first unlock (see `LocalBackend::unlock`'s own doc comment);
/// fixed here only so tests that unlock don't each invent their own.
pub const DEMO_PASSPHRASE: &str = "test passphrase";

/// The demo vault's seeded values (see `LocalBackend::seed_demo_vault`),
/// duplicated here the same way `crates/secretsd/tests/support` does —
/// that module keeps them private, since they are values a test asserts
/// against, not part of its own public surface.
pub const DEMO_USERNAME: &str = "octocat";
pub const DEMO_PASSWORD: &str = "correct horse battery staple";
pub const DEMO_TOTP: &str = "JBSWY3DPEHPK3PXP";

/// A private `dbus-daemon` session bus, plus a `secrets` [`Command`]
/// factory wired to reach it. No `secretsd` involved — used alone for the
/// "daemon absent" scenario, and wrapped by [`TestDaemon`] for everything
/// else.
pub struct TestBus {
    _bus: PrivateBus,
    bus_address: String,
    // Isolates `secrets`' own `HOME`/`XDG_CONFIG_HOME` from the developer's
    // or CI runner's real one. Held only to keep the directory alive.
    _cli_home: TempDir,
}

impl TestBus {
    /// Start a private session bus. No `secretsd`, and no vault — the one
    /// thing this is for is a bus that answers D-Bus at all but has no
    /// owner for `org.secrets.Daemon`, i.e. "the daemon is not running".
    #[must_use]
    pub fn start() -> Self {
        let bus = PrivateBus::start();
        let cli_home = tempfile::tempdir().expect("create a temporary HOME for the secrets CLI");
        Self {
            bus_address: bus.address.clone(),
            _bus: bus,
            _cli_home: cli_home,
        }
    }

    /// A `secrets` [`Command`], isolated from the real environment and
    /// pointed at this harness's private bus. Stdin is left untouched
    /// (inherited) — only `unlock` ever reads it, and tests that need to
    /// feed it call `.write_stdin(..)` themselves.
    #[must_use]
    pub fn cli(&self) -> Command {
        let mut command = Command::cargo_bin("secrets")
            .expect("the `secrets` binary is built as part of this same package's test run");
        command
            // Full isolation: this suite must never read or be influenced
            // by the developer's/CI runner's real session bus, HOME, or
            // config — the same rationale as `secretsd`'s own harness
            // isolating its `XDG_*` directories.
            .env_clear()
            .env("DBUS_SESSION_BUS_ADDRESS", &self.bus_address)
            .env("HOME", self._cli_home.path())
            .env("XDG_CONFIG_HOME", self._cli_home.path().join(".config"));
        command
    }
}

/// A [`TestBus`] plus a real `secretsd` binary running against a freshly
/// seeded demo vault in isolated `XDG_*` temporary directories — the same
/// isolation approach as `crates/secretsd/tests/support::TestDaemon`,
/// adapted for cross-package binary lookup (`escargot`) and with no
/// Secret-Service-proxy surface, since nothing here talks raw D-Bus.
pub struct TestDaemon {
    bus: TestBus,
    // Held only to keep the directories alive for the daemon's lifetime;
    // never read after `start()`.
    _data_dir: TempDir,
    _config_dir: TempDir,
    _runtime_dir: TempDir,
    daemon: Child,
    /// `secretsd`'s combined stdout+stderr, captured continuously — see
    /// `crates/secretsd/tests/support`'s identical field for why this must
    /// be observed live, not read after the fact.
    output: Arc<Mutex<String>>,
}

impl TestDaemon {
    /// Seed a fresh demo vault, start a private session bus, build and
    /// start `secretsd` pointed at both, and wait until it answers `secrets
    /// status` through the CLI itself.
    ///
    /// # Panics
    ///
    /// If any step of setup fails, or `secretsd` does not become reachable
    /// within a few seconds — always with the captured output attached.
    #[must_use]
    pub fn start() -> Self {
        Self::start_with(None, Duration::from_secs(10))
    }

    /// Same as [`start`](Self::start), but writes a `secretsd.toml`
    /// selecting the 1Password Desktop backend before starting the
    /// daemon, and allows a much longer readiness timeout: the *first*
    /// call this backend makes (during `secretsd`'s own startup discovery)
    /// may block on a human approving 1Password's "Integrate with other
    /// apps" IPC prompt — see `docs/backends/1password.md`.
    ///
    /// Used only by the opt-in, `#[ignore]`d smoke test
    /// (`tests/onepassword_smoke.rs`) against a real, installed 1Password
    /// Desktop — never in CI, and never with production credentials (see
    /// `AGENTS.md`).
    ///
    /// # Panics
    ///
    /// Same as [`start`](Self::start), with a 60s readiness deadline
    /// instead of 10s.
    #[must_use]
    pub fn start_with_1password(account_name: &str) -> Self {
        let config =
            format!("[store.default]\ntype = \"1password\"\naccount_name = \"{account_name}\"\n");
        Self::start_with(Some(config), Duration::from_secs(60))
    }

    /// The shared implementation behind [`start`](Self::start) and
    /// [`start_with_1password`](Self::start_with_1password).
    ///
    /// `backend_config`, if given, is written as `secretsd.toml` before
    /// the daemon starts, selecting a non-default backend. The demo local
    /// vault is always seeded regardless — harmless when a different
    /// backend is configured (that backend simply never reads it), and
    /// keeps this one code path shared rather than duplicated per backend.
    fn start_with(backend_config: Option<String>, readiness_timeout: Duration) -> Self {
        let data_dir = tempfile::tempdir().expect("create a temporary XDG_DATA_HOME");
        let config_dir = tempfile::tempdir().expect("create a temporary XDG_CONFIG_HOME");
        let runtime_dir = tempfile::tempdir().expect("create a temporary XDG_RUNTIME_DIR");
        secure_runtime_dir(runtime_dir.path());

        // The Secret Service/Manager topology is fixed at `secretsd`
        // startup, so the demo vault must exist on disk first — same
        // ordering constraint as `crates/secretsd/tests/support`.
        let vault_dir = data_dir.path().join("secrets");
        std::fs::create_dir_all(&vault_dir).expect("create the vault file's parent directory");
        secretsd::backend::local::LocalBackend::open(vault_dir.join("vault.toml"))
            .expect("open a fresh vault file")
            .unlock(DEMO_PASSPHRASE)
            .expect("seed the demo vault on first unlock");

        if let Some(config) = backend_config {
            let config_subdir = config_dir.path().join("secrets");
            std::fs::create_dir_all(&config_subdir).expect("create secretsd's config directory");
            std::fs::write(config_subdir.join("secretsd.toml"), config)
                .expect("write a secretsd.toml selecting the configured backend");
        }

        let bus = TestBus::start();

        let mut command = StdCommand::new(secretsd_binary());
        command
            .env("XDG_DATA_HOME", data_dir.path())
            .env("XDG_CONFIG_HOME", config_dir.path())
            .env("XDG_RUNTIME_DIR", runtime_dir.path())
            .env("DBUS_SESSION_BUS_ADDRESS", &bus.bus_address)
            // "debug", not the daemon's default "info": a leaked secret
            // this suite failed to notice at the quiet default would be a
            // false negative, not a passing test.
            .env("RUST_LOG", "debug")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut daemon = command
            .spawn()
            .expect("spawn the secretsd binary escargot just built");

        let output = Arc::new(Mutex::new(String::new()));
        drain(daemon.stdout.take().expect("stdout was piped"), &output);
        drain(daemon.stderr.take().expect("stderr was piped"), &output);

        let harness = Self {
            bus,
            _data_dir: data_dir,
            _config_dir: config_dir,
            _runtime_dir: runtime_dir,
            daemon,
            output,
        };
        harness.wait_until_ready(readiness_timeout);
        harness
    }

    /// Block until `secrets status` succeeds against this daemon, or
    /// `timeout` elapses. Reuses the CLI under test as its own readiness
    /// probe, rather than pulling in a raw `zbus` proxy this harness would
    /// otherwise have no use for.
    fn wait_until_ready(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if self
                .cli()
                .arg("status")
                .output()
                .is_ok_and(|output| output.status.success())
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "secretsd did not become reachable within {timeout:?}; captured output so far:\n{}",
                self.captured_output()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// A `secrets` [`Command`] wired to reach this daemon's private bus.
    #[must_use]
    pub fn cli(&self) -> Command {
        self.bus.cli()
    }

    /// A snapshot of `secretsd`'s combined stdout+stderr captured so far.
    #[must_use]
    pub fn captured_output(&self) -> String {
        self.output.lock().expect("poisoned").clone()
    }

    /// Assert that none of the demo vault's known secret values ever
    /// appeared verbatim in `secretsd`'s own log output — mirrors
    /// `crates/secretsd/tests/support::TestDaemon::assert_no_secrets_leaked`,
    /// checked here too since this suite drives the daemon through a
    /// different path (the CLI) that could in principle log differently.
    pub fn assert_no_secrets_leaked(&self) {
        let output = self.captured_output();
        for secret in [DEMO_USERNAME, DEMO_PASSWORD, DEMO_TOTP] {
            assert!(
                !output.contains(secret),
                "secretsd's own log output contained a demo secret value: {output}"
            );
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        // A plain `SIGKILL` is enough here: this suite never asserts on
        // clean shutdown (that is `crates/secretsd/tests/secret_service.rs`'s
        // job, for issue #3) and a panicking test must not also panic in
        // `drop`.
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

/// Build (if needed) and locate the `secretsd` binary. `secretsd` is not a
/// binary dependency of this package, so Cargo never sets
/// `CARGO_BIN_EXE_secretsd` for these tests — `escargot` runs the
/// equivalent of `cargo build -p secretsd --bin secretsd` explicitly, on
/// demand, so this works whether `secrets-cli`'s tests are run alone or as
/// part of the whole workspace.
fn secretsd_binary() -> PathBuf {
    escargot::CargoBuild::new()
        .package("secretsd")
        .bin("secretsd")
        .run()
        .expect("build the secretsd binary this harness spawns")
        .path()
        .to_path_buf()
}

/// A private `dbus-daemon` session bus — see
/// `crates/secretsd/tests/support::PrivateBus`'s identical rationale for
/// `--print-address`/`--nofork` over `--fork`.
struct PrivateBus {
    child: Child,
    address: String,
    #[expect(
        dead_code,
        reason = "captured for parity with the daemon; not asserted on today"
    )]
    output: Arc<Mutex<String>>,
}

impl PrivateBus {
    fn start() -> Self {
        let mut command = StdCommand::new("dbus-daemon");
        command
            .args(["--session", "--print-address", "--nofork"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect(
            "spawn a private dbus-daemon for the test session bus — install the `dbus` package \
             (it provides `dbus-daemon`) to run this test suite",
        );

        let mut stdout = BufReader::new(child.stdout.take().expect("stdout was piped"));
        let mut address = String::new();
        stdout
            .read_line(&mut address)
            .expect("read dbus-daemon's printed address");
        let address = address.trim().to_string();
        assert!(!address.is_empty(), "dbus-daemon printed an empty address");

        let output = Arc::new(Mutex::new(String::new()));
        drain(stdout, &output);
        drain(child.stderr.take().expect("stderr was piped"), &output);

        Self {
            child,
            address,
            output,
        }
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn a background thread that appends everything read from `reader`
/// (line by line) to `sink`, until EOF or an error — so neither process
/// ever blocks writing to a pipe this harness stopped reading.
fn drain<R: std::io::Read + Send + 'static>(reader: R, sink: &Arc<Mutex<String>>) {
    let sink = Arc::clone(sink);
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => sink.lock().expect("poisoned").push_str(&line),
            }
        }
    });
}

/// `$XDG_RUNTIME_DIR` must be `0700` or `xdg::BaseDirectories` rejects it —
/// same requirement, same reasoning, as
/// `crates/secretsd/tests/support::secure_runtime_dir`.
fn secure_runtime_dir(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("set XDG_RUNTIME_DIR to the mode xdg::BaseDirectories requires");
}
