//! The `org.secrets.Manager` D-Bus interface implementation.
//!
//! Thin on purpose: every method forwards straight to [`DaemonState`],
//! translating [`secrets_core::CoreError`]/[`DaemonError`] into the D-Bus
//! error names defined in `secrets_core::dbus`. See
//! `docs/dbus/secrets-manager.md` for the wire contract.

use std::sync::Arc;

use secrets_core::SecretUri;
use secrets_core::dbus::ManagerError;

use crate::error::DaemonError;
use crate::state::DaemonState;

/// The object served at `secrets_core::dbus::MANAGER_PATH`.
pub struct ManagerIface {
    state: Arc<DaemonState>,
}

impl ManagerIface {
    /// Wrap shared daemon state as a servable interface.
    #[must_use]
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

#[zbus::interface(name = "org.secrets.Manager")]
impl ManagerIface {
    /// See [`secrets_core::dbus::Manager::status`].
    fn status(&self) -> String {
        self.state.status().to_string()
    }

    /// See [`secrets_core::dbus::Manager::unlock`].
    fn unlock(&self, passphrase: &str) -> Result<(), ManagerError> {
        self.state.unlock(passphrase).map_err(|error| match error {
            // A wrong passphrase is the caller's fault, not the backend's —
            // distinct D-Bus error name so a client does not retry blindly.
            DaemonError::IncorrectPassphrase => ManagerError::PermissionDenied(error.to_string()),
            other => ManagerError::BackendUnavailable(other.to_string()),
        })
    }

    /// See [`secrets_core::dbus::Manager::lock`].
    fn lock(&self) {
        self.state.lock();
    }

    /// See [`secrets_core::dbus::Manager::list_vaults`].
    fn list_vaults(&self) -> Result<Vec<String>, ManagerError> {
        Ok(self
            .state
            .list_vaults()?
            .into_iter()
            .map(|vault| vault.name)
            .collect())
    }

    /// See [`secrets_core::dbus::Manager::list_items`].
    fn list_items(&self, vault: &str) -> Result<Vec<String>, ManagerError> {
        Ok(self
            .state
            .list_items(vault)?
            .into_iter()
            .map(|item| item.path.to_string())
            .collect())
    }

    /// See [`secrets_core::dbus::Manager::resolve`].
    fn resolve(&self, uri: &str) -> Result<String, ManagerError> {
        let parsed =
            SecretUri::parse(uri).map_err(|error| ManagerError::InvalidUri(error.to_string()))?;
        self.state.resolve(&parsed)?;
        Ok(parsed.to_string())
    }

    /// See [`secrets_core::dbus::Manager::get`].
    fn get(&self, uri: &str) -> Result<String, ManagerError> {
        let parsed =
            SecretUri::parse(uri).map_err(|error| ManagerError::InvalidUri(error.to_string()))?;
        let value = self.state.get(&parsed)?;
        Ok(value.expose_secret().to_string())
    }
}
