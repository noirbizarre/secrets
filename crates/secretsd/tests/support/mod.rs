//! A harness that runs a real `secretsd` binary against a real, private
//! D-Bus session bus, over an isolated local-backend vault — see issue #3.
//!
//! Why a real subprocess rather than driving `DaemonState`/the interface
//! structs in-process (the way `state.rs`'s own unit tests do): the point
//! of this suite is the standard Secret Service *wire* contract —
//! object paths, D-Bus error names, property values as an actual remote
//! client observes them — which only exists once `zbus` has serialized
//! and deserialized a real method call. Driving the Rust types directly
//! would test the same thing the unit tests already do, not the D-Bus
//! surface this crate promises to `secret-tool`/`libsecret` clients.
//!
//! Isolation, per the issue's scope:
//! - A private `dbus-daemon` session bus ([`PrivateBus`]), never the
//!   developer's/CI runner's real session bus.
//! - `XDG_DATA_HOME`/`XDG_CONFIG_HOME`/`XDG_RUNTIME_DIR` all point inside
//!   fresh [`tempfile::TempDir`]s, so `secretsd` never reads or writes a
//!   real vault, config file or SSH agent socket.
//! - No `secretsd.toml` is written by default, so the local backend (no
//!   external credentials) is what starts unless a test explicitly opts
//!   into a different one via [`TestDaemon::start_with_backend_config`] —
//!   see `secretsd::config`.
//!
//! Shared by more than one test binary (`secret_service.rs`,
//! `topology_refresh.rs`, ...), each of which `mod support;`s and compiles
//! its own copy — so `dead_code` fires per binary for whichever items only
//! the *other* one uses. Silenced crate-wide here rather than
//! item-by-item, since which items are "unused" depends on which binary
//! is compiling this module, not on this module itself (same convention
//! as `crates/secrets-cli/tests/support/mod.rs`). `unused_imports` gets
//! the same treatment, for the same reason — a `pub use` re-export (e.g.
//! `MockProvider`) that only one consuming binary (`secret_service.rs`)
//! actually names.
#![allow(dead_code, unused_imports)]

mod mock_provider;
mod proxies;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use secrets_core::dbus::{ManagerError, ManagerProxyBlocking};
use zbus::zvariant::OwnedObjectPath;

// `gen_async = false` on every trait in `proxies` means the macro names
// each blocking proxy plainly (`XProxy`, not `XProxyBlocking`) — see
// `zbus_macros::proxy`'s own naming rule for why.
pub use mock_provider::MockProvider;
pub use proxies::{CollectionProxy, ItemProxy, PromptProxy, SecretServiceProxy, SessionProxy};

/// The passphrase every [`TestDaemon`] seeds its vault with. Any value
/// works on first unlock (see `LocalBackend::unlock`'s own doc comment);
/// fixed here only so tests that unlock don't each invent their own.
pub const DEMO_PASSPHRASE: &str = "test passphrase";

/// The demo vault's seeded values (see `LocalBackend::seed_demo_vault`) —
/// duplicated here rather than imported, since `secretsd::backend::local`
/// keeps them private (they are the *values* a test asserts against, not
/// part of that module's own public surface). Used both to assert a
/// fetched secret is correct, and — the more important use — to assert
/// none of them ever appears in `secretsd`'s captured log output.
pub const DEMO_USERNAME: &str = "octocat";
pub const DEMO_PASSWORD: &str = "correct horse battery staple";
pub const DEMO_TOTP: &str = "JBSWY3DPEHPK3PXP";

/// A running `secretsd`, isolated on a private D-Bus session bus over a
/// throwaway local-backend vault. Dropping it terminates both the daemon
/// and the private bus — see [`terminate`].
pub struct TestDaemon {
    // Held only to keep the directories alive for the daemon's lifetime;
    // never read after `start()`.
    _data_dir: tempfile::TempDir,
    _config_dir: tempfile::TempDir,
    _runtime_dir: tempfile::TempDir,
    // Kept alive for its `Drop` (killing the private `dbus-daemon`), same
    // as the tempdirs above, but also read via `bus_address` — a mock
    // prompt provider (`mock_provider.rs`) needs its own, second
    // connection to this same private bus.
    bus: PrivateBus,
    daemon: Child,
    /// `secretsd`'s combined stdout+stderr, captured continuously by
    /// background threads — see [`captured_output`]'s doc comment on why
    /// this must be observed live, not read after the fact.
    output: Arc<Mutex<String>>,
    connection: zbus::blocking::Connection,
}

impl TestDaemon {
    /// Seed a fresh demo vault, start a private session bus, start
    /// `secretsd` pointed at both, and wait until it answers D-Bus calls.
    ///
    /// # Panics
    ///
    /// If any step of setup fails, or `secretsd` does not become
    /// reachable within a few seconds — always with the captured output
    /// attached, since a silent hang here would otherwise be nearly
    /// impossible to diagnose from CI alone.
    #[must_use]
    pub fn start() -> Self {
        Self::start_with(true, None, &[])
    }

    /// Same as [`start`](Self::start), but does **not** seed the demo
    /// vault first — `secretsd` starts with zero vaults, the same state a
    /// fresh install is in before the very first `secrets unlock`. Used
    /// to test the live topology refresher (ADR-015): since the Secret
    /// Service object topology is no longer fixed at startup, a vault
    /// created *after* `secretsd` is already running (exactly what
    /// `Manager.Unlock` does on its very first call, for the local
    /// backend) must become visible without a restart.
    #[must_use]
    pub fn start_without_a_vault() -> Self {
        Self::start_with(false, None, &[])
    }

    /// Same as [`start_without_a_vault`](Self::start_without_a_vault), but
    /// writes `secretsd.toml` with `config_contents` before starting
    /// (selecting a non-local backend), and sets `extra_env` on the
    /// spawned process — e.g. `SECRETS_OP_SDK_IPC_LIB`, to point the
    /// 1Password backend at a fixture library instead of a real Desktop
    /// installation. Used to test that a backend failing during topology
    /// discovery never crashes `secretsd` itself (see
    /// `topology_refresh.rs`, ADR-015).
    #[must_use]
    pub fn start_with_backend_config(config_contents: &str, extra_env: &[(&str, &str)]) -> Self {
        Self::start_with(false, Some(config_contents), extra_env)
    }

    /// Same as [`start`](Self::start) (seeded demo vault, default local
    /// backend), but sets `extra_env` on the spawned process — e.g.
    /// `secretsd::prompt::broker::PROMPT_TIMEOUT_OVERRIDE_ENV`, to shrink
    /// an otherwise real-world-scale timeout so a test exercising it
    /// stays fast.
    #[must_use]
    pub fn start_with_env(extra_env: &[(&str, &str)]) -> Self {
        Self::start_with(true, None, extra_env)
    }

    /// The shared implementation behind every `start*` constructor above.
    fn start_with(
        seed_vault: bool,
        config_contents: Option<&str>,
        extra_env: &[(&str, &str)],
    ) -> Self {
        let data_dir = tempfile::tempdir().expect("create a temporary XDG_DATA_HOME");
        let config_dir = tempfile::tempdir().expect("create a temporary XDG_CONFIG_HOME");
        let runtime_dir = tempfile::tempdir().expect("create a temporary XDG_RUNTIME_DIR");
        secure_runtime_dir(runtime_dir.path());

        // The Secret Service topology is live (ADR-015), populated by a
        // background scan shortly after startup rather than fixed before
        // it — so, unlike before, seeding here is no longer a *hard*
        // ordering requirement for the demo collections to eventually
        // appear. It stays the default (`seed_vault = true`) for every
        // existing test that still expects them present, to keep this
        // harness's behavior otherwise unchanged.
        if seed_vault {
            let vault_dir = data_dir.path().join("secrets");
            std::fs::create_dir_all(&vault_dir).expect("create the vault file's parent directory");
            secretsd::backend::local::LocalBackend::open(vault_dir.join("vault.toml"))
                .expect("open a fresh vault file")
                .unlock(DEMO_PASSPHRASE)
                .expect("seed the demo vault on first unlock");
        }

        if let Some(contents) = config_contents {
            let config_subdir = config_dir.path().join("secrets");
            std::fs::create_dir_all(&config_subdir)
                .expect("create secretsd's own config directory");
            std::fs::write(config_subdir.join("secretsd.toml"), contents)
                .expect("write a secretsd.toml selecting the configured backend");
        }

        let bus = PrivateBus::start();

        let mut command = Command::new(env!("CARGO_BIN_EXE_secretsd"));
        command
            .env("XDG_DATA_HOME", data_dir.path())
            .env("XDG_CONFIG_HOME", config_dir.path())
            .env("XDG_RUNTIME_DIR", runtime_dir.path())
            .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
            // "debug", not the daemon's default "info": the harness's own
            // no-secrets-in-logs assertion is only meaningful if it ran
            // against the noisiest log level a real deployment could
            // enable, not the quiet default that would pass trivially.
            .env("RUST_LOG", "debug")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in extra_env {
            command.env(key, value);
        }
        let mut daemon = command.spawn().expect(
            "spawn the secretsd binary under test (CARGO_BIN_EXE_secretsd, set by cargo for \
             integration tests in this package)",
        );

        let output = Arc::new(Mutex::new(String::new()));
        drain(daemon.stdout.take().expect("stdout was piped"), &output);
        drain(daemon.stderr.take().expect("stderr was piped"), &output);

        let connection = zbus::blocking::connection::Builder::address(bus.address.as_str())
            .expect("a dbus-daemon-printed address is always a valid zbus address")
            .build()
            .expect("connect to the private session bus as a second, client-side connection");

        let harness = Self {
            _data_dir: data_dir,
            _config_dir: config_dir,
            _runtime_dir: runtime_dir,
            bus,
            daemon,
            output,
            connection,
        };
        harness.wait_until_ready();
        harness
    }

    /// Block until `secretsd` answers a D-Bus call (`org.secrets.Manager`
    /// is served first, at startup, before the Secret Service topology —
    /// see `main.rs` — so it is the cheapest possible readiness probe).
    fn wait_until_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(proxy) = ManagerProxyBlocking::new(&self.connection)
                && proxy.status().is_ok()
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "secretsd did not become reachable on the private session bus within 10s; \
                 captured output so far:\n{}",
                self.captured_output()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Block until `Service.Collections()` matches `expected` exactly (as
    /// a set), or panic after a few seconds. The live topology (ADR-015)
    /// is populated by a background scan that starts immediately but
    /// asynchronously to `secretsd` reporting ready — a test asserting on
    /// specific collections must wait for it explicitly instead of
    /// assuming it is already done the instant `start()`/`wait_until_ready`
    /// returns.
    ///
    /// # Panics
    ///
    /// If `Service.Collections()` never matches `expected` within 10s.
    pub fn wait_until_collections(&self, expected: &[OwnedObjectPath]) {
        let expected: std::collections::HashSet<_> = expected.iter().cloned().collect();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(collections) = self.service().collections() {
                let collections: std::collections::HashSet<_> = collections.into_iter().collect();
                if collections == expected {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "Service.Collections() never matched the expected set within 10s; captured \
                 output so far:\n{}",
                self.captured_output()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// A snapshot of `secretsd`'s combined stdout+stderr captured so far.
    ///
    /// Captured continuously from the moment the process is spawned
    /// (rather than read once at the end) so a test that kills the
    /// daemon mid-scenario (`shutdown`) still sees everything it logged
    /// up to that point, and so a panic during `wait_until_ready` can
    /// still report it.
    #[must_use]
    pub fn captured_output(&self) -> String {
        self.output.lock().expect("poisoned").clone()
    }

    /// Assert that none of the demo vault's known secret values ever
    /// appeared verbatim in `secretsd`'s own log output — the issue's
    /// "assert that secret values never appear in logs" requirement.
    /// Call after exercising whatever operations a test cares about.
    ///
    /// Checked against the captured log text, not against any assertion
    /// message a *test itself* prints — the invariant under test is
    /// `secretsd`'s own logging discipline (AGENTS.md's "a `CoreError`/
    /// `ManagerError` never contains a secret's value"), not this
    /// harness's.
    pub fn assert_no_secrets_leaked(&self) {
        let output = self.captured_output();
        for secret in [DEMO_USERNAME, DEMO_PASSWORD, DEMO_TOTP] {
            assert!(
                !output.contains(secret),
                "secretsd's own log output contained a demo secret value — this is exactly the \
                 leak AGENTS.md's invariant #1 forbids, not a false positive: {output}"
            );
        }
    }

    /// A proxy for `org.secrets.Manager` — the only way to actually
    /// unlock/lock the daemon; see [`docs/dbus/secret-service.md`]'s
    /// "What does not work" section on why the Secret Service interfaces
    /// alone cannot do this.
    #[must_use]
    pub fn manager(&self) -> ManagerProxyBlocking<'_> {
        ManagerProxyBlocking::new(&self.connection)
            .expect("construct a Manager proxy over an already-open connection")
    }

    /// Unlock through `org.secrets.Manager`, mapped to the same
    /// `org.secrets.Error.*` variants a real client would see.
    ///
    /// # Errors
    ///
    /// See [`ManagerError`] — most commonly `PermissionDenied` for a
    /// wrong passphrase.
    pub fn unlock(&self, passphrase: &str) -> Result<(), ManagerError> {
        self.manager()
            .unlock(passphrase)
            .map_err(ManagerError::from)
    }

    /// Lock through `org.secrets.Manager`. Never fails (see
    /// `ManagerIface::lock`).
    pub fn lock(&self) {
        self.manager().lock().expect("Lock never fails");
    }

    /// A proxy for the root `org.freedesktop.Secret.Service` object.
    #[must_use]
    pub fn service(&self) -> SecretServiceProxy<'_> {
        SecretServiceProxy::new(&self.connection)
            .expect("construct a Service proxy over an already-open connection")
    }

    /// A proxy for the `org.freedesktop.Secret.Collection` at `path`.
    #[must_use]
    pub fn collection(&self, path: &OwnedObjectPath) -> CollectionProxy<'_> {
        CollectionProxy::builder(&self.connection)
            .path(path.clone())
            .expect("every collection path this harness builds is a valid object path")
            .build()
            .expect("build a Collection proxy")
    }

    /// A proxy for the `org.freedesktop.Secret.Item` at `path`.
    #[must_use]
    pub fn item(&self, path: &OwnedObjectPath) -> ItemProxy<'_> {
        ItemProxy::builder(&self.connection)
            .path(path.clone())
            .expect("every item path this harness builds is a valid object path")
            .build()
            .expect("build an Item proxy")
    }

    /// A proxy for the one shared `org.freedesktop.Secret.Session` object.
    #[must_use]
    pub fn session_object(&self) -> SessionProxy<'_> {
        SessionProxy::new(&self.connection)
            .expect("construct a Session proxy over an already-open connection")
    }

    /// A proxy for the one shared `org.freedesktop.Secret.Prompt` object.
    #[must_use]
    pub fn prompt(&self) -> PromptProxy<'_> {
        PromptProxy::new(&self.connection)
            .expect("construct a Prompt proxy over an already-open connection")
    }

    /// A proxy for `org.secrets.PromptBroker1` — the interface a prompt
    /// provider registers itself against (see ADR-017). Exposed for
    /// tests that exercise registration edge cases directly, in addition
    /// to [`MockProvider`], which wraps the common case.
    #[must_use]
    pub fn prompt_broker(&self) -> secrets_core::dbus::PromptBroker1ProxyBlocking<'_> {
        secrets_core::dbus::PromptBroker1ProxyBlocking::new(&self.connection)
            .expect("construct a PromptBroker1 proxy over an already-open connection")
    }

    /// The private session bus's own address — a [`MockProvider`] needs
    /// its own, second connection to the same bus this harness's own
    /// `connection` is on, so `secretsd` sees it as a distinct D-Bus
    /// peer with its own unique connection name (a real prompt provider
    /// is always a separate process).
    #[must_use]
    pub fn bus_address(&self) -> &str {
        &self.bus.address
    }

    /// Terminate `secretsd` and assert it exited promptly — the issue's
    /// "shut down the daemon cleanly" requirement made explicit as its
    /// own assertion, rather than only implicit in every test's `Drop`.
    ///
    /// # Panics
    ///
    /// If `secretsd` is still running 3s after `SIGTERM`.
    pub fn assert_shuts_down_cleanly(mut self) {
        let exited_on_its_own = terminate(&mut self.daemon);
        assert!(
            exited_on_its_own,
            "secretsd did not exit within 3s of SIGTERM and had to be SIGKILLed; captured \
             output:\n{}",
            self.captured_output()
        );
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        // Best-effort: a panicking test must not also panic in `drop`
        // (that aborts the process instead of reporting the original
        // failure) — `terminate`'s own return value is only meaningful
        // in `assert_shuts_down_cleanly`, which runs on the success path.
        terminate(&mut self.daemon);
    }
}

/// A private `dbus-daemon` session bus, printing its own address on
/// startup (`--print-address`) rather than `--fork`ing: a forked daemon
/// reparents to init and this harness would lose its only handle to kill
/// it — see this module's own doc comment on why isolation matters here.
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
        let mut command = Command::new("dbus-daemon");
        command
            .args(["--session", "--print-address", "--nofork"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect(
            "spawn a private dbus-daemon for the test session bus — install the `dbus` package \
             (it provides `dbus-daemon`) to run this test suite",
        );

        // The address is always dbus-daemon's very first line of
        // stdout — read it synchronously, before handing the same
        // reader off to a background thread for whatever it prints
        // afterwards (normally nothing else, but draining prevents a
        // filled pipe from ever blocking the daemon).
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
        terminate(&mut self.child);
    }
}

/// Spawn a background thread that appends everything read from `reader`
/// (line by line) to `sink`, until EOF or an error. Used for both
/// `secretsd`'s and the private `dbus-daemon`'s stdout/stderr, so neither
/// process ever blocks writing to a pipe this harness stopped reading.
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

/// `$XDG_RUNTIME_DIR` must be `0700` or `xdg::BaseDirectories` rejects it
/// (see `xdg`'s own `XdgRuntimeDirInsecure`) — `secretsd::paths::
/// ssh_agent_socket` would then fail and `main.rs` would exit before ever
/// reaching the D-Bus setup this suite tests. `tempfile::tempdir()`
/// already creates directories `0700` on Unix; this makes that a
/// documented requirement of this harness, not an accident of
/// `tempfile`'s current defaults.
fn secure_runtime_dir(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("set XDG_RUNTIME_DIR to the mode xdg::BaseDirectories requires");
}

/// `SIGTERM`, then wait up to 3s, then `SIGKILL` as a last resort.
/// Returns whether the process exited on its own (before `SIGKILL`).
///
/// Neither `secretsd` nor `dbus-daemon` installs its own `SIGTERM`
/// handler, so the default disposition (terminate) is the only "clean
/// shutdown" this MVP has — `std::process::Child::kill()` alone only
/// offers `SIGKILL`, which this harness reserves for a genuine hang.
fn terminate(child: &mut Child) -> bool {
    // Already exited (e.g. a prior call in the same `Drop`): nothing to
    // signal, and `try_wait` on an already-reaped child would be
    // meaningless.
    if matches!(child.try_wait(), Ok(Some(_))) {
        return true;
    }

    // SAFETY: `kill(2)` on a pid this process owns (its own child) is
    // always safe to call; a negative/zero return only ever means the
    // process already exited, which the wait loop below handles either
    // way.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }

    let _ = child.kill();
    let _ = child.wait();
    false
}
