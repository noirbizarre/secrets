//! `secretsd` — the Secrets user-session daemon.
//!
//! Owns the secret store, session/lock state and access control. Exposes
//! `org.secrets.Manager` and the `org.freedesktop.Secret.*` compatibility
//! interfaces over the D-Bus session bus, and a standard SSH agent socket.
//! See `docs/architecture/overview.md` for the full picture.
//!
//! Deliberately synchronous everywhere except the SSH agent (see
//! `ssh_agent.rs`): the D-Bus connection uses `zbus`'s **blocking** API, so
//! `org.secrets.Manager` and the Secret Service compatibility objects are
//! plain, ordinary method calls into [`state::DaemonState`] — no
//! `#[tokio::main]`, no executor to reason about for the daemon's core
//! logic.

use std::sync::Arc;

use secrets_core::dbus::{MANAGER_PATH, SERVICE_NAME};
use secretsd::error::DaemonError;
use secretsd::manager::ManagerIface;
use secretsd::secret_service::collection::CollectionIface;
use secretsd::secret_service::item::ItemIface;
use secretsd::secret_service::prompt::PromptIface;
use secretsd::secret_service::service::ServiceIface;
use secretsd::secret_service::session::SessionIface;
use secretsd::secret_service::{PROMPT_PATH, SERVICE_PATH, SESSION_PATH, collection_path};
use secretsd::{paths, secret_service, ssh_agent, state};

fn run() -> Result<(), DaemonError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let state = Arc::new(state::open_default_state()?);

    // The Secret Service compatibility layer's object topology is fixed at
    // startup — see the module-level doc on `secret_service` for why.
    let topology =
        secret_service::discover(&state).map_err(|error| DaemonError::VaultFileUnreadable {
            path: std::path::PathBuf::new(),
            reason: error.to_string(),
        })?;

    let mut builder = zbus::blocking::connection::Builder::session()?
        .serve_at(MANAGER_PATH, ManagerIface::new(state.clone()))?
        .serve_at(
            SERVICE_PATH,
            ServiceIface::new(state.clone(), topology.clone()),
        )?
        .serve_at(PROMPT_PATH, PromptIface)?
        .serve_at(SESSION_PATH, SessionIface)?;

    for vault in &topology.vaults {
        let items: Vec<_> = topology
            .items
            .iter()
            .filter(|known| &known.vault == vault)
            .cloned()
            .collect();
        builder = builder.serve_at(
            collection_path(vault),
            CollectionIface::new(state.clone(), vault.clone(), items),
        )?;
    }
    for known in &topology.items {
        builder = builder.serve_at(
            known.path.clone(),
            ItemIface::new(
                state.clone(),
                known.vault.clone(),
                known.item.clone(),
                known.field.clone(),
            ),
        )?;
    }

    let _connection = builder.name(SERVICE_NAME)?.build()?;
    tracing::info!("secretsd listening on the session bus as {SERVICE_NAME}");

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
