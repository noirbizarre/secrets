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
use secretsd::secret_service::{
    ALIAS_DEFAULT_PATH, PROMPT_PATH, SERVICE_PATH, SESSION_PATH, collection_path,
};
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

    // The Secret Service compatibility layer's object topology is fixed at
    // startup — see the module-level doc on `secret_service` for why.
    //
    // `discover`'s error isn't specifically about "the vault file" —
    // that was only ever true when `LocalBackend` was the only backend;
    // any backend's `list_vaults`/`list_items` can fail here now (e.g. a
    // 1Password backend whose Desktop authorization was denied), so this
    // maps to the generic, accurate `BackendUnavailable` instead of
    // mislabeling every possible cause as a vault file problem.
    let topology = secret_service::discover(&state)
        .map_err(|error| DaemonError::BackendUnavailable(error.to_string()))?;

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

    // The "default" alias's collection, additionally reachable at its own
    // literal well-known path (spec §4/§12) — a client that hardcodes this
    // path rather than calling `ReadAlias("default")` still reaches it.
    // Only the first vault has one in this MVP (see `ServiceIface::read_alias`).
    if let Some(default_vault) = topology.vaults.first() {
        let items: Vec<_> = topology
            .items
            .iter()
            .filter(|known| &known.vault == default_vault)
            .cloned()
            .collect();
        builder = builder.serve_at(
            ALIAS_DEFAULT_PATH,
            CollectionIface::new(state.clone(), default_vault.clone(), items),
        )?;
    }

    // `org.secrets.Daemon` is the only name this call chain is guaranteed
    // to own — it is exclusively ours, so any failure here is fatal
    // startup error (propagated by `?`, as before).
    let connection = builder.name(SERVICE_NAME)?.build()?;
    tracing::info!("secretsd listening on the session bus as {SERVICE_NAME}");

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
