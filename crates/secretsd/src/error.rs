//! The daemon's own error type: everything that can fail outside of a
//! single secret resolution (which uses [`secrets_core::CoreError`]
//! instead).

/// Errors from daemon startup, storage and cryptography.
///
/// `miette` at this binary's edge (see `main.rs`), same split as
/// `secrets-core`'s `thiserror`-only `CoreError`.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum DaemonError {
    /// Could not determine or create an XDG directory (data, runtime).
    #[error("could not resolve XDG directories: {0}")]
    #[diagnostic(code(secrets::daemon::xdg_unavailable))]
    XdgUnavailable(String),

    /// The vault file exists but could not be read or parsed.
    ///
    /// Carries only the path and a description, never file contents — the
    /// file is exactly the thing that might contain ciphertext we must not
    /// echo back.
    #[error("could not read vault file at {path}: {reason}")]
    #[diagnostic(code(secrets::daemon::vault_file_unreadable))]
    VaultFileUnreadable {
        /// The path that failed to load.
        path: std::path::PathBuf,
        /// What went wrong, in human terms.
        reason: String,
    },

    /// The vault file could not be written.
    #[error("could not write vault file at {path}: {reason}")]
    #[diagnostic(code(secrets::daemon::vault_file_unwritable))]
    VaultFileUnwritable {
        /// The path that failed to save.
        path: std::path::PathBuf,
        /// What went wrong, in human terms.
        reason: String,
    },

    /// The supplied passphrase did not decrypt the vault.
    ///
    /// Never says *why* beyond that — a more specific message would help an
    /// attacker distinguish "wrong passphrase" from "corrupted file".
    #[error("incorrect passphrase, or the vault file is corrupted")]
    #[diagnostic(code(secrets::daemon::incorrect_passphrase))]
    IncorrectPassphrase,

    /// A D-Bus connection or registration step failed.
    ///
    /// SSH agent socket failures are logged rather than surfaced here (see
    /// `ssh_agent.rs`): a daemon that cannot bind its SSH socket should
    /// still serve `org.secrets.Manager`, not refuse to start entirely.
    #[error("D-Bus setup failed: {0}")]
    #[diagnostic(code(secrets::daemon::dbus_setup))]
    DBusSetup(#[from] zbus::Error),

    /// The daemon's own config file (`[backend]` and friends) exists but
    /// could not be read or parsed.
    #[error("could not read configuration at {path}: {reason}")]
    #[diagnostic(code(secrets::daemon::config_unreadable))]
    ConfigUnreadable {
        /// The configuration file's path.
        path: std::path::PathBuf,
        /// What went wrong, in human terms.
        reason: String,
    },

    /// `[backend] type = "1password"` is set, but a required field for
    /// that backend (e.g. `account_name`) is missing.
    #[error("invalid backend configuration: {0}")]
    #[diagnostic(
        code(secrets::daemon::invalid_backend_config),
        help("see docs/architecture/1password-integration.md for the required [backend] fields")
    )]
    InvalidBackendConfig(String),

    /// The configured backend could not be started (e.g. 1Password
    /// Desktop's native IPC library could not be loaded).
    #[error("backend unavailable at startup: {0}")]
    #[diagnostic(code(secrets::daemon::backend_unavailable))]
    BackendUnavailable(String),
}

/// The daemon's result alias.
pub type Result<T> = std::result::Result<T, DaemonError>;
