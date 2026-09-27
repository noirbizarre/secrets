//! XDG Base Directory paths the daemon needs.
//!
//! Kept in one place because getting either of these wrong has security
//! consequences: the vault file must live under `XDG_DATA_HOME` (persistent,
//! user-private), the SSH agent socket under `XDG_RUNTIME_DIR` (tmpfs,
//! cleared on logout, never persisted to disk).

use std::path::PathBuf;

use secrets_core::StoreId;

use crate::error::{DaemonError, Result};

/// The local backend's file name for the implicit/explicit `"default"`
/// store, within `$XDG_DATA_HOME/secrets/` — today's only vault file name,
/// kept fixed so neither a pre-ADR-018 zero-config install nor someone
/// writing `[store.default] type = "local"` explicitly ever ends up
/// pointed at a differently-named file.
const VAULT_FILE_NAME: &str = "vault.toml";

/// The store id [`vault_file`] maps to [`VAULT_FILE_NAME`] rather than
/// `"<id>.toml"`.
const DEFAULT_STORE_ID: &str = "default";

/// The SSH agent socket's name within `$XDG_RUNTIME_DIR/secrets/`.
///
/// Namespaced under `secrets/` rather than dropped directly in
/// `XDG_RUNTIME_DIR`, so it cannot collide with another agent's
/// `ssh-agent.sock` and is trivially found by anything iterating the
/// directory. One socket total, aggregating identities across every
/// configured store (ADR-018) — the SSH agent protocol has no store
/// concept and does not need to grow one.
const SSH_AGENT_SOCKET_NAME: &str = "ssh-agent.sock";

/// Resolve (and create the parent directory for) one local store's vault
/// file path.
///
/// # Errors
///
/// Returns [`DaemonError::XdgUnavailable`] if `XDG_DATA_HOME` (or its
/// fallback `~/.local/share`) cannot be determined or created.
pub fn vault_file(store: &StoreId) -> Result<PathBuf> {
    let xdg = xdg::BaseDirectories::with_prefix("secrets");
    let name = if store.as_str() == DEFAULT_STORE_ID {
        VAULT_FILE_NAME.to_string()
    } else {
        format!("{store}.toml")
    };
    xdg.place_data_file(name)
        .map_err(|error| DaemonError::XdgUnavailable(error.to_string()))
}

/// Resolve (and create the parent directory for) the SSH agent socket path.
///
/// # Errors
///
/// Returns [`DaemonError::XdgUnavailable`] if `XDG_RUNTIME_DIR` is not set —
/// which normally means no active login session, and so nothing would be
/// listening on the other end anyway.
pub fn ssh_agent_socket() -> Result<PathBuf> {
    let xdg = xdg::BaseDirectories::with_prefix("secrets");
    xdg.place_runtime_file(SSH_AGENT_SOCKET_NAME)
        .map_err(|error| DaemonError::XdgUnavailable(error.to_string()))
}

/// `pass`'s own default store location, used when `[store.<id>] type =
/// "pass"` omits `store_dir` — not an XDG path (`pass` predates the XDG
/// convention and has never followed it), so this is deliberately
/// `$HOME`-relative, not `xdg`-crate-derived like every other path in
/// this module.
///
/// # Errors
///
/// Returns [`DaemonError::BackendUnavailable`] if the home directory
/// cannot be determined (no `$HOME`, no known passwd entry) — the same
/// failure-at-startup treatment `PassBackend::open` already gives a
/// misconfigured or missing store path.
pub fn default_pass_store_dir() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|home| home.join(".password-store"))
        .ok_or_else(|| {
            DaemonError::BackendUnavailable(
                "could not determine the home directory for the default pass store location \
                 ($HOME); set store_dir explicitly instead"
                    .to_string(),
            )
        })
}
