//! XDG Base Directory paths the daemon needs.
//!
//! Kept in one place because getting either of these wrong has security
//! consequences: the vault file must live under `XDG_DATA_HOME` (persistent,
//! user-private), the SSH agent socket under `XDG_RUNTIME_DIR` (tmpfs,
//! cleared on logout, never persisted to disk).

use std::path::PathBuf;

use crate::error::{DaemonError, Result};

/// The vault file's name within `$XDG_DATA_HOME/secrets/`.
const VAULT_FILE_NAME: &str = "vault.toml";

/// The SSH agent socket's name within `$XDG_RUNTIME_DIR/secrets/`.
///
/// Namespaced under `secrets/` rather than dropped directly in
/// `XDG_RUNTIME_DIR`, so it cannot collide with another agent's
/// `ssh-agent.sock` and is trivially found by anything iterating the
/// directory.
const SSH_AGENT_SOCKET_NAME: &str = "ssh-agent.sock";

/// Resolve (and create the parent directory for) the vault file path.
///
/// # Errors
///
/// Returns [`DaemonError::XdgUnavailable`] if `XDG_DATA_HOME` (or its
/// fallback `~/.local/share`) cannot be determined or created.
pub fn vault_file() -> Result<PathBuf> {
    let xdg = xdg::BaseDirectories::with_prefix("secrets");
    xdg.place_data_file(VAULT_FILE_NAME)
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
