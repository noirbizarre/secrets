//! Shared D-Bus surface: names, the `org.secrets.Manager` proxy trait, and
//! error mapping.
//!
//! `secret://` is the resource-reference scheme; D-Bus is the transport.
//! This module owns the second half — the parts that must be identical in
//! `secretsd` (which implements the interface) and every client (which
//! proxies it), so the two can never drift apart. See
//! `docs/dbus/secrets-manager.md` for the full contract.

use crate::error::CoreError;

/// The well-known bus name `secretsd` registers on the session bus.
pub const SERVICE_NAME: &str = "org.secrets.Daemon";

/// The object path the `Manager` interface is served at.
pub const MANAGER_PATH: &str = "/org/secrets/Manager";

/// The daemon's session/lock state, as returned by
/// [`ManagerProxyBlocking::status`].
pub const STATUS_LOCKED: &str = "locked";

/// The daemon's session/lock state, as returned by
/// [`ManagerProxyBlocking::status`].
pub const STATUS_UNLOCKED: &str = "unlocked";

/// The native Secrets D-Bus API.
///
/// Defined once here and consumed on both ends: `secretsd` implements it
/// (`#[zbus::interface(name = "org.secrets.Manager")]` over the same method
/// set) and every client uses the generated `ManagerProxyBlocking` /
/// `ManagerProxy` to call it. Method names are plain (non-`async`) on
/// purpose — the `#[zbus::proxy]` macro generates both a blocking and an
/// async proxy from the same trait, so `secrets-client` (and `secrets-cli`
/// through it) never needs an async runtime just to talk to the daemon.
///
/// Additions are additive: new methods or properties can be appended
/// without breaking existing clients, since D-Bus dispatches by name. Do
/// not change an existing method's signature; add a new one instead.
#[zbus::proxy(
    interface = "org.secrets.Manager",
    default_service = "org.secrets.Daemon",
    default_path = "/org/secrets/Manager"
)]
pub trait Manager {
    /// Current session state: `"locked"` or `"unlocked"`
    /// ([`STATUS_LOCKED`] / [`STATUS_UNLOCKED`]).
    fn status(&self) -> zbus::Result<String>;

    /// Unlock the store with the master passphrase.
    fn unlock(&self, passphrase: &str) -> zbus::Result<()>;

    /// Lock the store, dropping any decrypted material from memory.
    fn lock(&self) -> zbus::Result<()>;

    /// List the names of every vault the active backend exposes.
    ///
    /// Available while locked: vault names are not secret material.
    fn list_vaults(&self) -> zbus::Result<Vec<String>>;

    /// List the item paths within a vault (e.g. `"GitHub"`,
    /// `"Production/database"`), joined the same way they appear in a
    /// `secret://` URI's item segment.
    ///
    /// Available while locked: item paths are not secret material.
    fn list_items(&self, vault: &str) -> zbus::Result<Vec<String>>;

    /// Validate and canonicalise a `secret://` reference, confirming the
    /// vault, item and field exist, without returning the field's value.
    ///
    /// Requires the store to be unlocked, since confirming a field exists
    /// is itself information about the unlocked contents.
    fn resolve(&self, uri: &str) -> zbus::Result<String>;

    /// Fetch a field's value.
    ///
    /// The only method that returns secret material — the plaintext
    /// crosses the bus here and nowhere else. Requires the store to be
    /// unlocked.
    fn get(&self, uri: &str) -> zbus::Result<String>;
}

/// The `org.secrets.Error.*` D-Bus error names.
///
/// One variant per [`CoreError`] case, so a client can match on a specific
/// failure (`org.secrets.Error.VaultLocked`) rather than parsing a message
/// string. Diagnostic codes are public identifiers — renaming one is a
/// breaking change to every client.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.secrets.Error")]
pub enum ManagerError {
    /// Wraps a transport-level D-Bus failure (connection lost, timeout,
    /// ...), distinct from every application-level error below.
    #[zbus(error)]
    Zbus(zbus::Error),

    /// The `secret://` reference itself was malformed.
    InvalidUri(String),

    /// The referenced vault exists but the store is locked.
    VaultLocked(String),

    /// The vault, item or field does not exist.
    NotFound(String),

    /// The caller is not allowed to read this secret.
    PermissionDenied(String),

    /// The requested operation does not make sense in this context.
    InvalidOperation(String),

    /// The backend could not be reached.
    BackendUnavailable(String),

    /// The active backend has its own session/authentication concept
    /// (see [`crate::backend::BackendSession`]) and it is missing,
    /// expired, or otherwise unsatisfied.
    BackendRequiresAuthentication(String),
}

impl From<CoreError> for ManagerError {
    /// `CoreError`'s `Display` never includes a secret value (see its own
    /// doc comment), so it is always safe to forward as the D-Bus error's
    /// description here.
    fn from(error: CoreError) -> Self {
        let message = error.to_string();
        match error {
            CoreError::InvalidUri(_) => Self::InvalidUri(message),
            CoreError::VaultLocked { .. } => Self::VaultLocked(message),
            CoreError::NotFound { .. } => Self::NotFound(message),
            CoreError::PermissionDenied { .. } => Self::PermissionDenied(message),
            CoreError::InvalidOperation(_) => Self::InvalidOperation(message),
            CoreError::BackendUnavailable(_) => Self::BackendUnavailable(message),
            CoreError::BackendRequiresAuthentication(_) => {
                Self::BackendRequiresAuthentication(message)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uri::UriError;

    #[test]
    fn a_core_error_never_carries_its_own_variant_name_only_context() {
        // Regression guard: mapping must preserve the message, not just the
        // discriminant, so a client's error report is still actionable.
        let error = CoreError::NotFound {
            vault: "Personal".to_string(),
            item: "GitHub".to_string(),
            field: "password".to_string(),
        };
        let mapped: ManagerError = error.into();
        assert!(matches!(mapped, ManagerError::NotFound(msg) if msg.contains("Personal")));
    }

    #[test]
    fn an_invalid_uri_maps_to_the_invalid_uri_dbus_error() {
        let error = CoreError::InvalidUri(UriError::EmptyVault);
        let mapped: ManagerError = error.into();
        assert!(matches!(mapped, ManagerError::InvalidUri(_)));
    }

    #[test]
    fn a_backend_auth_requirement_maps_to_its_own_dbus_error_not_vault_locked() {
        // Regression guard: a backend's own session requirement must stay
        // distinguishable from the daemon's lock (ADR-0009) — a client
        // that only knows to retry "unlock" would otherwise loop forever
        // against a backend problem "unlock" cannot fix.
        let error = CoreError::BackendRequiresAuthentication(
            "1Password Desktop session expired".to_string(),
        );
        let mapped: ManagerError = error.into();
        assert!(matches!(
            mapped,
            ManagerError::BackendRequiresAuthentication(msg) if msg.contains("1Password")
        ));
    }
}
