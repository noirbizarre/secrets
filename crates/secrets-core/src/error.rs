//! The crate's error type.
//!
//! Every variant here is safe to display to a user, log, or send back over
//! D-Bus as an error message: none of them may ever be constructed with a
//! secret *value* inside them. Vault/item/field *names* are fine — they are
//! identifiers, not secrets — but the field's content never is.

use crate::uri::UriError;

/// Everything that can go wrong resolving or managing secrets.
///
/// Library-only: no `miette::Diagnostic` here (see AGENTS.md's "thiserror
/// for the library, miette at the binary edge"). Each variant maps to a
/// named `org.secrets.Error.*` D-Bus error in [`crate::dbus::ManagerError`]
/// instead — that mapping is this type's public, grep-able identifier.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// The `secret://` reference itself was malformed.
    #[error("invalid secret:// URI: {0}")]
    InvalidUri(#[from] UriError),

    /// The vault exists but the daemon is locked, so its contents are
    /// unreadable. Distinct from `NotFound` so a client can tell "try
    /// unlocking" apart from "this doesn't exist".
    #[error("vault '{vault}' is locked")]
    VaultLocked {
        /// The vault that is locked.
        vault: String,
    },

    /// The vault, item or field named in the URI does not exist.
    #[error("secret not found: secret://{vault}/{item}/{field}")]
    NotFound {
        /// The vault that was searched.
        vault: String,
        /// The item path that was searched, already joined for display.
        item: String,
        /// The field that was requested.
        field: String,
    },

    /// The caller is not allowed to read this secret.
    ///
    /// Reserved for a future access-control layer; the MVP backend never
    /// returns this, but the error shape exists so callers can already match
    /// on it without a breaking change later.
    #[error("permission denied for secret://{vault}/{item}/{field}")]
    PermissionDenied {
        /// The vault involved.
        vault: String,
        /// The item path involved, already joined for display.
        item: String,
        /// The field involved.
        field: String,
    },

    /// The operation itself does not make sense (e.g. writing to a
    /// read-only backend), independent of locking or permissions.
    #[error("invalid operation: {0}")]
    InvalidOperation(String),

    /// The backend could not be reached or is misconfigured.
    ///
    /// Carries only a description, never the underlying data — a backend
    /// error might otherwise leak a file path containing a passphrase, for
    /// instance.
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),
}

/// The crate's result alias.
pub type Result<T> = std::result::Result<T, CoreError>;
