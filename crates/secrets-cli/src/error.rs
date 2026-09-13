//! The CLI's own error type: connection failures and the D-Bus error names
//! defined in `secrets_core::dbus` (re-exported as `secrets_client::Error`),
//! translated into actionable messages.

use secrets_client::Error as ManagerError;

/// Everything that can go wrong running a `secrets` command.
///
/// `thiserror` here, `miette` at `main.rs`'s edge — same split as
/// `secretsd` and as documented in `rust.tpl`'s own `AGENTS.md`.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum CliError {
    /// Could not reach `secretsd` on the session bus at all.
    #[error("could not reach secretsd on the session bus: {0}")]
    #[diagnostic(
        code(secrets::cli::daemon_unreachable),
        help("is secretsd running? try: systemctl --user status secretsd")
    )]
    DaemonUnreachable(#[source] zbus::Error),

    /// The `secret://` reference was rejected — by the CLI's own parser,
    /// before ever reaching the daemon, or by the daemon's.
    #[error("invalid secret:// reference: {0}")]
    #[diagnostic(code(secrets::cli::invalid_uri))]
    InvalidUri(String),

    /// The referenced vault is locked.
    #[error("{0}")]
    #[diagnostic(code(secrets::cli::vault_locked), help("run: secrets unlock"))]
    VaultLocked(String),

    /// The referenced secret does not exist.
    #[error("{0}")]
    #[diagnostic(code(secrets::cli::not_found))]
    NotFound(String),

    /// The daemon refused the operation for permission reasons (including
    /// an incorrect unlock passphrase).
    #[error("{0}")]
    #[diagnostic(code(secrets::cli::permission_denied))]
    PermissionDenied(String),

    /// The requested operation does not make sense in this context.
    #[error("{0}")]
    #[diagnostic(code(secrets::cli::invalid_operation))]
    InvalidOperation(String),

    /// The daemon's backend is unavailable.
    #[error("{0}")]
    #[diagnostic(code(secrets::cli::backend_unavailable))]
    BackendUnavailable(String),

    /// The active backend has its own session/authentication requirement
    /// that is not currently satisfied (distinct from `VaultLocked`: the
    /// daemon itself may be unlocked).
    #[error("{0}")]
    #[diagnostic(code(secrets::cli::backend_requires_authentication))]
    BackendRequiresAuthentication(String),

    /// A command whose structure exists for forward-compatibility, but
    /// whose behaviour is not yet implemented.
    #[error("`secrets {command}` is not implemented yet")]
    #[diagnostic(code(secrets::cli::not_yet_implemented))]
    NotYetImplemented {
        /// The subcommand name, for the error message.
        command: &'static str,
    },

    /// Reading the interactive passphrase prompt failed or was cancelled.
    #[error("passphrase entry cancelled")]
    #[diagnostic(code(secrets::cli::prompt_cancelled))]
    PromptCancelled,

    /// The configuration file exists but could not be parsed.
    #[error("could not read configuration at {path}: {reason}")]
    #[diagnostic(code(secrets::cli::config_unreadable))]
    ConfigUnreadable {
        /// The configuration file's path.
        path: std::path::PathBuf,
        /// What went wrong, in human terms.
        reason: String,
    },

    /// `secrets get` was run with no output flag and stdout is a real
    /// terminal — see ADR-014. Not raised when stdout is piped/redirected.
    #[error("refusing to print a secret's value to a terminal")]
    #[diagnostic(
        code(secrets::cli::refused_terminal_output),
        help(
            "pass --raw to print anyway, --json for structured output, or --clipboard to copy it without printing"
        )
    )]
    RefusedTerminalOutput,

    /// `secrets get --clipboard` could not reach a clipboard (no display,
    /// or the platform's clipboard mechanism is otherwise unavailable).
    #[error("could not access the clipboard: {0}")]
    #[diagnostic(code(secrets::cli::clipboard_unavailable))]
    ClipboardUnavailable(String),
}

impl From<zbus::Error> for CliError {
    fn from(error: zbus::Error) -> Self {
        Self::DaemonUnreachable(error)
    }
}

impl From<ManagerError> for CliError {
    fn from(error: ManagerError) -> Self {
        match error {
            ManagerError::Zbus(inner) => Self::DaemonUnreachable(inner),
            ManagerError::InvalidUri(message) => Self::InvalidUri(message),
            ManagerError::VaultLocked(message) => Self::VaultLocked(message),
            ManagerError::NotFound(message) => Self::NotFound(message),
            ManagerError::PermissionDenied(message) => Self::PermissionDenied(message),
            ManagerError::InvalidOperation(message) => Self::InvalidOperation(message),
            ManagerError::BackendUnavailable(message) => Self::BackendUnavailable(message),
            ManagerError::BackendRequiresAuthentication(message) => {
                Self::BackendRequiresAuthentication(message)
            }
        }
    }
}

/// The CLI's result alias.
pub type Result<T> = std::result::Result<T, CliError>;
