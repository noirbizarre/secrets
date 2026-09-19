//! `secretsd` — the Secrets user-session daemon.
//!
//! Owns the secret store, session/lock state and access control. Exposes
//! the standard `org.freedesktop.Secret.*` interfaces (the primary,
//! interoperable contract) and the `org.secrets.*` extension namespace
//! over the D-Bus session bus, plus a standard SSH agent socket. See
//! `docs/architecture/overview.md` for the full picture and
//! [ADR-013](../../../docs/adr/013-standard-secret-service-and-extension-namespace.md)
//! for how the two D-Bus surfaces relate.
//!
//! Deliberately synchronous everywhere except the SSH agent (see
//! `ssh_agent.rs`) and the Secret Service topology refresher (see
//! `secret_service::refresh`, [ADR-015](../../../docs/adr/015-live-secret-service-topology.md)):
//! the D-Bus connection uses `zbus`'s **blocking** API, so
//! `org.secrets.Manager` and the Secret Service compatibility objects are
//! plain, ordinary method calls into [`state::DaemonState`] — no
//! `#[tokio::main]`, no executor to reason about for the daemon's core
//! logic. The refresher needs no executor of its own either — see its own
//! module doc for why.

use std::sync::Arc;
use std::sync::mpsc;

use secrets_core::dbus::{MANAGER_PATH, SERVICE_NAME};
use secretsd::error::DaemonError;
use secretsd::manager::ManagerIface;
use secretsd::secret_service::prompt::PromptIface;
use secretsd::secret_service::service::ServiceIface;
use secretsd::secret_service::session::SessionIface;
use secretsd::secret_service::{LiveTopology, PROMPT_PATH, SERVICE_PATH, SESSION_PATH, Topology};
use secretsd::{paths, secret_service, ssh_agent, state};
use zbus::fdo::{RequestNameFlags, RequestNameReply};

fn run() -> Result<(), DaemonError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let state = Arc::new(state::open_default_state()?);

    // The Secret Service compatibility layer's object topology is *live*
    // (ADR-015), not fixed at startup: it starts empty here and is
    // populated by `secret_service::refresh::spawn`'s background thread
    // below, immediately but never fatally — a backend error during any
    // one scan (e.g. a 1Password vault larger than an undocumented IPC
    // limit, or Desktop authorization denied) is only ever logged, never
    // fatal to `secretsd` starting or to `org.secrets.Manager`/the SSH
    // agent, neither of which needs this topology at all.
    let topology = LiveTopology::new(Topology::default());
    let (refresh_trigger_tx, refresh_trigger_rx) = mpsc::channel();

    // `org.secrets.Daemon` is the only name this call chain is guaranteed
    // to own — it is exclusively ours, so any failure here is fatal
    // startup error (propagated by `?`, as before).
    let connection = zbus::blocking::connection::Builder::session()?
        .serve_at(
            MANAGER_PATH,
            ManagerIface::new(state.clone(), refresh_trigger_tx),
        )?
        .serve_at(
            SERVICE_PATH,
            ServiceIface::new(state.clone(), topology.clone()),
        )?
        .serve_at(PROMPT_PATH, PromptIface)?
        .serve_at(SESSION_PATH, SessionIface)?
        .name(SERVICE_NAME)?
        .build()?;
    tracing::info!("secretsd listening on the session bus as {SERVICE_NAME}");

    // Populates every vault's `Collection` and every field's `Item` (plus
    // the `"default"` alias) from here on — see `secret_service::refresh`.
    let _topology_refresher = secret_service::refresh::spawn(
        connection.clone(),
        state.clone(),
        topology,
        refresh_trigger_rx,
    );

    // `org.freedesktop.secrets` is the name real Secret Service clients
    // (`secret-tool`, `libsecret`'s `SECRET_SERVICE_BUS_NAME`) hardcode —
    // requested *after* startup, best-effort, and deliberately without
    // `AllowReplacement`/`ReplaceExisting`: a desktop session may already
    // run GNOME Keyring or KWallet's `ksecretsd` owning it, and `secretsd`
    // must neither fail to start nor steal the name from a legitimate
    // provider over that. `DoNotQueue` makes the outcome immediate rather
    // than waiting in a queue that may never be served.
    match connection.request_name_with_flags(
        secret_service::BUS_NAME,
        RequestNameFlags::DoNotQueue.into(),
    ) {
        Ok(RequestNameReply::PrimaryOwner) => {
            tracing::info!(
                "also registered as {} for standard Secret Service clients",
                secret_service::BUS_NAME
            );
        }
        Ok(reply) => {
            tracing::warn!(
                "{} is already owned by another Secret Service provider ({reply}) — \
                 likely GNOME Keyring or KWallet; standard clients that hardcode this bus \
                 name will reach that service instead of secretsd. Point them at \
                 {SERVICE_NAME} explicitly, or stop the other provider, to use secretsd's \
                 Secret Service compatibility layer",
                secret_service::BUS_NAME
            );
        }
        Err(error) => {
            tracing::warn!(
                "failed to request {}: {error} — secretsd remains reachable as {SERVICE_NAME}",
                secret_service::BUS_NAME
            );
        }
    }

    let socket_path = paths::ssh_agent_socket()?;
    let _ssh_agent = ssh_agent::spawn(state.clone(), socket_path);

    // The blocking `Connection` dispatches on its own background thread;
    // this thread just needs to stay alive for as long as the process
    // should keep running (systemd stops it with a signal, same as any
    // other daemon).
    loop {
        std::thread::park();
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // Rendered here, not returned as a `miette::Result`, so the
            // exit code is chosen explicitly — see rust.tpl's own
            // `secrets-cli` main.rs for the same pattern.
            eprintln!("{:?}", miette::Report::new(error));
            std::process::ExitCode::FAILURE
        }
    }
}
